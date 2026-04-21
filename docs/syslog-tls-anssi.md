# Syslog TLS/mTLS ANSSI — Documentation technique

Ce document décrit l'implémentation du transport syslog chiffré avec authentification mutuelle (mTLS), conforme aux recommandations ANSSI pour la journalisation sécurisée.

---

## Table des matières

1. [Architecture](#1-architecture)
2. [État courant — Deux modes de déploiement](#2-état-courant--deux-modes-de-déploiement)
3. [Pourquoi le syslog TLS a été temporairement désactivé](#3-pourquoi-le-syslog-tls-a-été-temporairement-désactivé)
4. [Activer le mode TLS](#4-activer-le-mode-tls)
5. [Tester le mode TLS](#5-tester-le-mode-tls)
6. [Dashboards Grafana](#6-dashboards-grafana)
7. [Limites et sécurité](#7-limites-et-sécurité)
8. [Dépannage](#8-dépannage)

---

## 1. Architecture

```
Sources syslog                 Fluent Bit                   Loki
(clients TLS)   ──TCP/TLS──►  Port 5140                ───► Port 3100
                               syslog-rfc5424                (HTTP)
                               mTLS activé

Fichiers locaux  ──tail──►    Fluent Bit               ───► Loki
/var/log-analyzer/            (inputs fichiers)              /fluent-bit
nginx, auth.log               toujours actifs

Loki  ──────────────────────────────────────────────────►  Grafana
                                                             Port 3000
```

### Services impliqués

| Service | Rôle | Port exposé |
|---|---|---|
| Fluent Bit | Collecte, parse, enrichit les logs | 2020 (HTTP API), 5140 (syslog TLS — mode TLS seulement) |
| Loki | Stockage et indexation des logs bruts | 3100 |
| Grafana | Visualisation | 3000 |
| API FastAPI | Orchestration, analyse LangGraph | 8000 |
| Ollama | LLM local (Mistral 7B) | interne uniquement |

---

## 2. État courant — Deux modes de déploiement

### Mode stable (par défaut)

Utilise `config/fluent-bit.conf`.

- Collecte par lecture de fichiers locaux (tail)
- Syslog TLS **désactivé** (INPUT commenté)
- Fonctionne **sans certificats**
- Validé en production sur Raspberry Pi

```bash
# Démarrage mode stable (défaut)
docker compose up -d
```

### Mode TLS/mTLS (ANSSI-ready)

Utilise `config/fluent-bit-tls.conf` via `docker-compose.tls.yml`.

- Collecte par lecture de fichiers locaux (tail) **+** écoute syslog TCP/TLS port 5140
- Authentification mutuelle : le client syslog doit présenter un certificat signé par le CA
- **Nécessite** `./certs/ca.crt`, `./certs/server.crt`, `./certs/server.key` dans le répertoire local `./certs/`
- Transport chiffré : aucun log en clair sur le réseau

> **ANSSI-ready ≠ ANSSI-compliant**
>
> Cette configuration implémente les mécanismes techniques requis (TLS 1.2+, mTLS, RFC 5424)
> mais **ne constitue pas une conformité ANSSI complète**. Les éléments manquants sont listés
> en [section 7](#7-limites-et-sécurité).

```bash
# Démarrage mode TLS
docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d fluent-bit
```

---

## 3. Pourquoi le syslog TLS a été temporairement désactivé

### Chronologie

1. Configuration initiale : syslog TLS INPUT activé dans `fluent-bit.conf`
2. Problème : le volume Docker `certs` était vide (aucun certificat présent sur le Raspberry Pi)
3. Comportement de Fluent Bit : **crash au démarrage** dès que `tls.ca_file` pointe vers un fichier absent
4. Décision : commenter le bloc syslog TLS pour stabiliser la stack
5. D'autres problèmes (`Label_keys`, `Labels job=$TAG`) ont été corrigés en parallèle
6. La stack a été validée en mode dégradé fonctionnel (Fluent Bit → Loki opérationnel via tail uniquement)

### Ce qui manquait

- Les fichiers `ca.crt`, `server.crt`, `server.key` dans le volume `certs`
- Une stratégie d'activation explicite (éviter une config ambiguë qui plante silencieusement)

### Solution retenue

Deux configs distinctes au lieu d'un bloc commenté :
- `fluent-bit.conf` → mode stable, toujours fonctionnel
- `fluent-bit-tls.conf` → mode TLS, activé explicitement via `docker-compose.tls.yml`

---

## 4. Activer le mode TLS

### Étape 1 — Générer les certificats (labo uniquement)

```bash
# Générer les certificats auto-signés de labo dans ./certs/
./scripts/gen_certs.sh ./certs

# Fichiers générés :
# certs/ca.crt         — CA racine
# certs/ca.key         — clé CA (ne jamais distribuer)
# certs/server.crt     — certificat serveur Fluent Bit
# certs/server.key     — clé privée serveur
# certs/client.crt     — certificat client syslog
# certs/client.key     — clé privée client
```

### Étape 2 — Vérifier le contenu de ./certs/

```bash
ls -la ./certs/
# Attendu : ca.crt, server.crt, server.key (et client.crt, client.key pour les tests mTLS)
```

Le répertoire `./certs/` est monté directement comme bind mount dans le conteneur (`./certs:/certs:ro`).
Aucune copie dans un volume Docker nommé n'est nécessaire.

### Étape 3 — Démarrer Fluent Bit en mode TLS

```bash
docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d fluent-bit
```

### Étape 4 — Vérifier le démarrage

```bash
# Logs Fluent Bit (doit montrer "syslog.secure" input initialisé sur 5140)
docker logs log-fluent-bit --tail 30

# Vérifier que le port 5140 est ouvert
ss -tlnp | grep 5140
# ou
docker compose -f docker-compose.yml -f docker-compose.tls.yml ps
```

### Retour au mode stable

```bash
# Recréer fluent-bit SANS l'override TLS → utilise fluent-bit.conf par défaut
docker compose up -d --force-recreate fluent-bit
```

---

## 5. Tester le mode TLS

### 5.1 Validation démarrage Fluent Bit

```bash
# Vérifier qu'aucune erreur TLS n'apparaît dans les logs
docker logs log-fluent-bit 2>&1 | grep -i -E "tls|error|failed|cert"

# Vérifier que l'input syslog est bien en écoute
docker logs log-fluent-bit 2>&1 | grep -i "syslog"
```

Sortie attendue (sans erreur) :
```
[2024/xx/xx xx:xx:xx] [ info] [input:syslog:syslog.secure.0] listening on 0.0.0.0:5140
```

### 5.2 Envoyer un message syslog test — options par ordre de disponibilité

#### Option A — `logger` (util-linux ≥ 2.33 avec support TLS)

```bash
# Disponible sur Debian 11+, Ubuntu 22.04+, Raspberry Pi OS Bullseye+
# Vérifier la disponibilité : logger --help 2>&1 | grep -i tls

logger \
  --server localhost \
  --port 5140 \
  --tcp \
  --rfc5424 \
  --tls \
  --tls-ca-cert ./certs/ca.crt \
  --tls-cert ./certs/client.crt \
  --tls-key ./certs/client.key \
  "Test syslog TLS ANSSI — $(date)"
```

> Si `logger` ne supporte pas `--tls`, utiliser `socat` (option B) ou `openssl` (option C).

#### Option B — `socat` (disponible sur la plupart des distributions Linux)

```bash
# Installation si absent : sudo apt install socat
MSG="<165>1 $(date -u +%Y-%m-%dT%H:%M:%SZ) $(hostname) myapp $$ - - Test socat TLS"
echo "$MSG" | socat - \
  OPENSSL:localhost:5140,\
cert=./certs/client.crt,\
key=./certs/client.key,\
cafile=./certs/ca.crt,\
verify=1
```

#### Option C — `openssl s_client` (référence, toujours disponible)

```bash
# Méthode de référence, portable partout où openssl est installé
echo "<165>1 $(date -u +%Y-%m-%dT%H:%M:%SZ) testhost testapp 1234 - - Test syslog TLS ANSSI" | \
  openssl s_client \
    -connect localhost:5140 \
    -cert ./certs/client.crt \
    -key ./certs/client.key \
    -CAfile ./certs/ca.crt \
    -quiet 2>/dev/null
```

#### Option D — rsyslog (usage production, client Linux existant)

Ajouter dans `/etc/rsyslog.d/99-fluent-bit.conf` sur la machine source :

```
# Envoi vers Fluent Bit en TLS (RFC 5424)
*.* action(
    type="omfwd"
    target="<IP_FLUENT_BIT>"
    port="5140"
    protocol="tcp"
    StreamDriver="gtls"
    StreamDriverMode="1"
    StreamDriverAuthMode="x509/certvalid"
    StreamDriverPermittedPeers="server"
)
```

Puis copier `ca.crt`, `client.crt`, `client.key` sur la machine source et configurer `$DefaultNetstreamDriverCAFile`, `$DefaultNetstreamDriverCertFile`, `$DefaultNetstreamDriverKeyFile` dans la config rsyslog globale.

### 5.3 Validation côté Loki

```bash
# Vérifier que des logs syslog arrivent dans Loki
curl -sG http://localhost:3100/loki/api/v1/query_range \
  --data-urlencode 'query={job="fluent-bit"}' \
  --data-urlencode 'limit=20' | python3 -m json.tool | grep -A2 '"values"'

# Vérifier les labels disponibles
curl -s http://localhost:3100/loki/api/v1/labels
```

### 5.4 Validation côté Grafana

1. Ouvrir http://localhost:3000
2. Dashboard "Log Analyzer ANSSI — Observabilité Fluent Bit v2"
3. Panel "Volume de logs (5 min)" → doit afficher un compteur non nul
4. Panel "Logs bruts récents" → doit afficher les messages syslog envoyés

### 5.5 Exemple de client syslog Python (labo)

```python
#!/usr/bin/env python3
"""Client syslog TLS minimal pour tester l'input Fluent Bit."""
import ssl, socket, datetime

msg = (
    f"<165>1 {datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} "
    f"testhost myapp 1234 - - [test] Connexion syslog TLS validée\n"
)

ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="./certs/ca.crt")
ctx.load_cert_chain(certfile="./certs/client.crt", keyfile="./certs/client.key")

with socket.create_connection(("localhost", 5140)) as raw:
    with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
        tls.sendall(msg.encode())
        print("Message envoyé :", msg.strip())
```

---

## 6. Dashboards Grafana

### Dashboard v2 — `grafana_anssi_dashboard_v2.json`

Chargé automatiquement via le provisioning Grafana (volume `./config/grafana/dashboards`).

| Panel | Type | Requête Loki |
|---|---|---|
| Volume de logs (5 min) | Stat | `sum(count_over_time({job="fluent-bit"}[5m]))` |
| Erreurs détectées (5 min) | Stat | `sum(count_over_time({job="fluent-bit"} \|= "error"[5m]))` |
| Tentatives SSH échouées (15 min) | Stat | `sum(count_over_time({job="fluent-bit"} \|= "Failed password"[15m]))` |
| Débit de logs | Timeseries | `sum(count_over_time({job="fluent-bit"}[1m]))` |
| Événements sensibles | Timeseries | erreurs + SSH (deux séries) |
| Logs d'erreur récents | Logs | `{job="fluent-bit"} \|= "error"` |
| Logs bruts récents | Logs | `{job="fluent-bit"}` |

### Pourquoi `sum(count_over_time(...))` pour les panels Stat

Les panels **Stat** Grafana attendent une valeur numérique scalaire.
`count_over_time({job="fluent-bit"}[5m])` retourne une série temporelle (vecteur).
`sum(...)` la réduit en scalaire → compatible avec le type Stat.

Sans `sum(...)`, le panel Stat afficherait une erreur ou "No data".

Les panels **Logs** utilisent directement `{job="fluent-bit"}` sans agrégation — ils affichent les entrées de logs brutes, pas des métriques.

### Import manuel du dashboard

Si Grafana ne charge pas automatiquement le dashboard (volume non monté) :

1. Aller sur http://localhost:3000
2. Menu **Dashboards → Import**
3. **Upload JSON file** → sélectionner `config/grafana/dashboards/grafana_anssi_dashboard_v2.json`
4. Sélectionner la datasource **Loki** dans le champ correspondant
5. **Import**

---

## 7. Limites et sécurité

### ANSSI-ready ≠ ANSSI-compliant

Cette implémentation fournit les **mécanismes techniques** du transport sécurisé (TLS 1.2+, mTLS, RFC 5424), mais n'est **pas une mise en conformité ANSSI complète**. Différences :

| Exigence ANSSI | État actuel | Ce qu'il faudrait |
|---|---|---|
| PKI d'entreprise | CA auto-signée (labo) | PKI interne ou EJBCA/Vault PKI |
| Révocation certificats | Absente | CRL ou OCSP |
| Validation hostname stricte | `tls.verify On` côté INPUT Fluent Bit ✓ | Idem côté Loki (actuellement `tls.verify Off`) |
| Stockage clés privées | Fichiers système | HSM ou gestionnaire de secrets |
| Rotation automatique | Manuelle | Automatisée (certbot, Vault PKI) |
| Durée maximale des certs | 365 jours (gen_certs.sh) | Selon politique PKI interne |
| Audit de la PKI | Non réalisé | Audit annuel recommandé |
| Séparation CA/RA | Non applicable (labo) | CA racine hors ligne |

### Mode labo vs production

| Point | Labo (gen_certs.sh) | Production ANSSI |
|---|---|---|
| CA | Auto-signée, 10 ans | PKI d'entreprise, CA racine hors ligne |
| Durée des certs | 365 jours | Selon politique PKI (≤ 1 an) |
| Stockage clés | Fichiers `./certs/` | HSM ou Vault |
| Rotation | Manuelle | Automatisée |
| `tls.verify` Fluent Bit INPUT | On ✓ | On obligatoire |
| `tls.verify` Fluent Bit → Loki | Off (Loki sans cert valide) | On avec cert Loki signé |
| Révocation | Non implémenté | CRL ou OCSP |
| Validation hostname | Partielle (SAN dans gen_certs.sh) | Stricte + vérification CN |

### Ce qui reste à faire pour une conformité plus stricte

- Activer `tls.verify On` côté OUTPUT Loki (nécessite un certificat serveur Loki valide signé par le CA)
- Mettre en place une rotation automatique des certificats (Vault PKI, certbot, step-ca)
- Implémenter la révocation (CRL publiée ou endpoint OCSP)
- Configurer des alertes Grafana sur les patterns d'erreur critiques
- Activer Row Level Security sur la table `audit_trail` PostgreSQL
- Exposer les métriques Fluent Bit (port 2021) vers un Prometheus pour alerting

### Évolution des labels Loki

**État actuel** : un seul label fiable → `job=fluent-bit`.
Les tentatives précédentes avec `Label_keys` ont cassé Fluent Bit 3.0 (champs inexistants dans les records).

**Enrichissement implémenté dans `fluent-bit-tls.conf`** :
Le filtre `modify` copie `ident` → `service` dans le corps du log (pas un label Loki).
Ce champ apparaît dans les logs bruts mais n'est pas indexé.

**Prochaine étape possible** (quand la structure de labels est stabilisée) :
Ajouter `service` comme label Loki dans l'OUTPUT uniquement **après** avoir vérifié
que le champ est présent dans tous les records syslog :

```
# À NE PAS activer avant validation — teste d'abord avec :
# curl -s http://localhost:3100/loki/api/v1/label/service/values
Labels  job=fluent-bit,service=$service
```

Ne jamais utiliser `Label_keys` avec des champs optionnels sur Fluent Bit 3.0.

---

## 8. Dépannage

### Fluent Bit crash loop au démarrage

**Symptôme** : `docker logs log-fluent-bit` montre une erreur TLS au démarrage, le conteneur redémarre en boucle.

**Cause typique** : `/certs` vide ou fichier manquant.

```bash
# Diagnostic — vérifier le contenu du répertoire local
ls -la ./certs/

# Solution A — Revenir au mode stable immédiatement
docker compose up -d --force-recreate fluent-bit

# Solution B — Générer les certs puis relancer en mode TLS
./scripts/gen_certs.sh ./certs
docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d fluent-bit
```

### ca.crt absent

```
[error] [tls] error loading CA certificate: /certs/ca.crt: No such file or directory
```

→ Le répertoire `./certs/` ne contient pas `ca.crt`. Relancer `./scripts/gen_certs.sh ./certs`.

### Clé/cert incohérents

```
[error] [tls] private key does not match the certificate public key
```

→ `server.crt` et `server.key` ne correspondent pas (re-générer avec `gen_certs.sh`).

### Pas de logs dans Loki après démarrage TLS

```bash
# Vérifier que Fluent Bit a bien démarré sans erreur
docker logs log-fluent-bit --tail 20

# Vérifier que Loki est healthy
curl -s http://localhost:3100/ready

# Vérifier les labels disponibles (doit contenir "fluent-bit")
curl -s http://localhost:3100/loki/api/v1/label/job/values

# Forcer un message test
echo "<165>1 $(date -u +%Y-%m-%dT%H:%M:%SZ) host app 0 - - test" | \
  openssl s_client -connect localhost:5140 \
    -cert ./certs/client.crt -key ./certs/client.key \
    -CAfile ./certs/ca.crt -quiet 2>/dev/null
```

### Client syslog rejeté (mTLS)

```
SSL routines:ssl3_read_bytes:sslv3 alert certificate unknown
```

→ Le client ne présente pas de certificat, ou son certificat n'est pas signé par `ca.crt`.
→ Vérifier que le client utilise `client.crt` + `client.key` générés par `gen_certs.sh`.

### Commandes de diagnostic générales

```bash
# État des conteneurs
docker compose ps

# Logs de tous les services
docker compose logs --tail 20

# Vérifier la connectivité Fluent Bit → Loki
docker exec log-fluent-bit wget -q --spider http://loki:3100/ready && echo "OK" || echo "KO"

# Vérifier l'API
curl http://localhost:8000/health

# Requête Loki directe
curl -sG http://localhost:3100/loki/api/v1/query_range \
  --data-urlencode 'query={job="fluent-bit"}' \
  --data-urlencode 'limit=5'
```
