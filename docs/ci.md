# CI/CD — log-analyzer-anssi

Documentation des workflows d'intégration continue et de validation locale.

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Workflow principal — ci-stack.yml](#2-workflow-principal--ci-stackyml)
3. [Workflow TLS — ci-tls-syslog.yml](#3-workflow-tls--ci-tls-syslogyml)
4. [Validation locale — validate_stack.sh](#4-validation-locale--validate_stacksh)
5. [Mode stable vs mode TLS](#5-mode-stable-vs-mode-tls)
6. [Limites connues](#6-limites-connues)
7. [Variables d'environnement requises](#7-variables-denvironnement-requises)

---

## 1. Vue d'ensemble

| Workflow | Déclencheur | Durée | Ce qu'il valide |
|---|---|---|---|
| `ci-stack.yml` | push, pull_request | ~4 min | Stack observabilité + scans sécurité |
| `ci-tls-syslog.yml` | workflow_dispatch | ~4 min | Mode syslog TLS/mTLS end-to-end |

Deux jobs parallèles dans `ci-stack.yml` :
- `stack-validation` : démarrage Docker, checks fonctionnels, ingestion Loki
- `security-scan` : Gitleaks (secrets), Trivy (filesystem + image Docker)

---

## 2. Workflow principal — ci-stack.yml

### Ce qu'il valide

```
Checkout
  └─ Créer /tmp/log-analyzer/{app,archive,fluent-bit-storage}
  └─ docker compose up (fluent-bit + api + dépendances)
       ├─ loki          healthcheck : GET /ready
       ├─ postgres      healthcheck : pg_isready
       ├─ ntp           condition : service_started
       ├─ ollama STUB   healthcheck : true (immédiat)
       ├─ fluent-bit    depends_on : loki(healthy) + ntp(started)
       └─ api           depends_on : postgres(healthy) + ollama(healthy) + loki(healthy)
  └─ Attendre Loki + API (retry 30×5s)
  └─ Validation GET /ready (Loki)
  └─ Validation GET /health (API) — vérifie status + loki=healthy
  └─ Validation GET /labels (Loki)
  └─ Injection log JSON → /tmp/log-analyzer/app/test.log
  └─ Attendre 15s (flush Fluent Bit)
  └─ Query Loki — vérifier présence du log

Scans (job parallèle) :
  └─ Gitleaks — historique git + fichiers non commités
  └─ Trivy filesystem — répertoire courant (HIGH/CRITICAL, exit-code 1)
  └─ docker build api → Trivy image (HIGH/CRITICAL, exit-code 0 = warning)
```

### Stub Ollama

En CI, Ollama est remplacé par un container `alpine:3.19` qui répond immédiatement au healthcheck (`CMD: true`). L'API FastAPI démarre et répond à `/health` avec `status=degraded` pour ollama — c'est le comportement attendu en CI (Ollama non fonctionnel, mais le reste de la stack validé).

**Fichier** : `docker-compose.ci.yml`

### Déclencheurs

```yaml
on:
  push:        # toutes branches
  pull_request:
```

### Variables d'environnement

Définies dans le workflow avec des valeurs CI par défaut. Pour un projet réel, utiliser des GitHub Secrets :

```
POSTGRES_PASSWORD → secrets.POSTGRES_PASSWORD
HMAC_SECRET_KEY   → secrets.HMAC_SECRET_KEY
GRAFANA_PASSWORD  → secrets.GRAFANA_PASSWORD
```

---

## 3. Workflow TLS — ci-tls-syslog.yml

### Ce qu'il valide

```
Checkout
  └─ Générer certificats de labo (./scripts/gen_certs.sh ./certs)
  └─ Vérifier cohérence certs (openssl verify)
  └─ Démarrer Loki + attendre /ready
  └─ Démarrer Fluent Bit en mode TLS
       (docker-compose.yml + docker-compose.ci.yml + docker-compose.tls.yml)
  └─ Attendre port 5140 (écoute syslog TLS)
  └─ Vérifier absence d'erreur TLS dans les logs Fluent Bit
  └─ Envoyer message syslog RFC 5424 via openssl s_client (mTLS)
  └─ Attendre 20s
  └─ Vérifier présence du log dans Loki
```

### Déclencheur

```yaml
on:
  workflow_dispatch:
    inputs:
      debug:
        description: "Afficher les logs Fluent Bit détaillés"
        default: "false"
```

Déclenché manuellement depuis l'interface GitHub (Actions → CI — Mode syslog TLS/mTLS → Run workflow).

### Pourquoi séparé du CI principal

- Nécessite la génération de certificats (étape supplémentaire)
- Valide un scénario distinct (transport sécurisé) pas nécessaire à chaque push
- Le test openssl s_client peut fermer la connexion avec un code non nul (comportement normal quand le serveur ferme la connexion TLS après réception) — pas souhaitable en CI systématique

---

## 4. Validation locale — validate_stack.sh

Reproduit la logique du CI principal localement. Plus rapide qu'une exécution GitHub Actions complète.

### Usage

```bash
# Validation stack de base (mode CI — sans Ollama réel)
./scripts/validate_stack.sh

# Validation avec test TLS en plus (génère les certs si absents)
./scripts/validate_stack.sh --tls

# Validation + nettoyage automatique après
./scripts/validate_stack.sh --clean

# TLS + nettoyage
./scripts/validate_stack.sh --tls --clean
```

### Ce que le script valide

1. Création de `/tmp/log-analyzer/{app,archive,fluent-bit-storage}`
2. `docker compose up` (mode CI)
3. Attente Loki + API
4. `GET /health` → vérifie `status` présent et `loki=healthy`
5. `GET /loki/api/v1/labels` → vérifie statut Loki
6. Injection log JSON dans `/tmp/log-analyzer/app/test.log`
7. Attente 15s + query Loki pour vérifier présence du log
8. (Optionnel `--tls`) Génération certs + démarrage TLS + envoi syslog + vérification Loki

### Variables d'environnement

Le script utilise des valeurs par défaut CI si les variables ne sont pas définies :

```bash
# Surcharger pour les tests avec des valeurs plus proches de la prod
export POSTGRES_PASSWORD=mon-vrai-mot-de-passe
export HMAC_SECRET_KEY=ma-vraie-cle-hmac
./scripts/validate_stack.sh
```

---

## 5. Mode stable vs mode TLS

| Point | Mode stable (CI principal) | Mode TLS (ci-tls-syslog) |
|---|---|---|
| Fluent Bit config | `fluent-bit.conf` | `fluent-bit-tls.conf` |
| Compose files | `docker-compose.yml` + `docker-compose.ci.yml` | + `docker-compose.tls.yml` |
| Certificats | Non requis | `./certs/{ca,server,client}.{crt,key}` |
| Port syslog | Non exposé | 5140/TCP |
| Déclencheur CI | push, pull_request | workflow_dispatch |
| Tag Loki | `syslog.*` (depuis fichiers) | `syslog.secure` (depuis TLS) |

---

## 6. Limites connues

### Stack CI

- **Ollama non validé** : le stub alpine remplace le service. Le LLM et le pipeline LangGraph ne sont pas testés en CI (trop lourd pour un runner standard).
- **Grafana non démarré** : l'interface de visualisation n'est pas validée en CI. Si le provisioning Grafana change, les tests doivent être lancés manuellement.
- **NTP** : le service NTP démarre mais peut échouer à synchroniser sur les runners CI (port 123 parfois filtré). Le comportement de `service_started` fait que fluent-bit démarre quand même.
- **Tests unitaires non exécutés** : ajouter un job `pytest tests/unit/` si des tests doivent être intégrés au pipeline.

### Vérification Loki

- La vérification du marker dans Loki peut échouer si Fluent Bit n'a pas flushé dans les 15s (intervalle de flush = 5s dans la config, mais la chaîne Fluent Bit → Loki + indexation peut prendre plus longtemps). Le workflow affiche un avertissement mais ne bloque pas.
- Si Loki n'a reçu aucun log, le check `status=success` passe mais les streams sont vides — le marker ne sera pas trouvé.

### Scans de sécurité

- **Gitleaks** : peut générer des faux positifs sur des chaînes qui ressemblent à des secrets (ex: exemples dans la doc). Ajouter un fichier `.gitleaks.toml` pour configurer les exclusions si nécessaire.
- **Trivy image** : `exit-code: 0` pour le scan d'image (avertissement seulement). Les CVE proviennent souvent de la base Python et ne sont pas actionnables immédiatement. Passer à `exit-code: 1` quand la politique de remédiation est établie.
- **Trivy filesystem** : `exit-code: 1` pour HIGH/CRITICAL — la CI bloque si des vulnérabilités non corrigées sont trouvées dans les dépendances Python.

### Workflow TLS

- `openssl s_client` peut retourner un code non nul quand le serveur TLS ferme la connexion proprement après réception. C'est un comportement normal de Fluent Bit (TCP half-close). Le workflow affiche un avertissement mais ne bloque pas sur ce code de retour.
- La vérification du marker TLS dans Loki (20s d'attente) peut être insuffisante si Loki est lent à indexer.

---

## 7. Variables d'environnement requises

Docker Compose valide ces variables à la lecture du fichier (syntaxe `:?`) même si le service n'est pas démarré.

| Variable | Utilisée par | Valeur CI par défaut |
|---|---|---|
| `POSTGRES_PASSWORD` | postgres, api | `ci-postgres-password-ci` |
| `HMAC_SECRET_KEY` | api | `ci-hmac-secret-key-must-be-long-enough` |
| `GRAFANA_PASSWORD` | grafana (non démarré) | `ci-grafana-password` |

Pour les déploiements réels, ces variables doivent être dans des **GitHub Secrets** ou un gestionnaire de secrets (Vault, etc.).
