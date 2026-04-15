# log-analyzer-anssi

SIEM léger de détection BYOVD/ransomware pour Raspberry Pi 4 (ARM64).
Conforme ANSSI · NIS2 Art.21 · LLM 100% local (granite3.1:2b via Ollama).

---

## Architecture

```
Sysmon XML / auditd / Zeek conn.log
          │
          ▼
┌─────────────────────────────────────────────────────┐
│  src/collectors/                                    │
│  ├── BYOVDDetector   ← loldrivers.io (SHA256)       │
│  │   EventID 6 (driver load) + EventID 10 (EDR)     │
│  └── NetworkCollector ← Zeek / tcpdump              │
│      beaconing · Tor · DoH                          │
└──────────────┬──────────────────────────────────────┘
               │  alerts[]
               ▼
┌─────────────────────────────────────────────────────┐
│  src/langgraph_pipeline/nodes.py (LangGraph)        │
│  httpx → Ollama granite3.1:2b  (timeout 30s)        │
│  fallback statique si Ollama KO                     │
│  SQLite checkpoint · HMAC-SHA256 signature          │
└──────────────┬──────────────────────────────────────┘
               │  notification_payload
               ▼
┌─────────────────────────────────────────────────────┐
│  src/collectors/integrity.py                        │
│  HMAC-SHA256 sur chaque événement (NIS2 Art.21.2.h) │
└──────────────┬──────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────┐
│  Stack observabilité                                │
│  Fluent-bit → Loki → Grafana :3000                  │
│  PostgreSQL + pgvector (stockage structuré)         │
│  NTP (sync temporelle ANSSI)                        │
└──────────────┬──────────────────────────────────────┘
               │
               ▼
         Raspberry Pi 4 — ARM64
         api :8000 · ollama :11434 · grafana :3000
```

---

## Couverture MITRE ATT&CK

| Technique | ID | Détecteur |
|---|---|---|
| Exploit Public-Facing App / priv-esc | T1068 | BYOVDDetector (EventID 6) |
| Impair Defenses — Disable/Mod Tools | T1562.001 | BYOVDDetector (EventID 10) |
| Command & Scripting Interpreter | T1059 | langgraph_pipeline/nodes.py |
| Data Encrypted for Impact | T1486 | langgraph_pipeline/nodes.py |
| Inhibit System Recovery | T1490 | langgraph_pipeline/nodes.py |
| Lateral Tool Transfer | T1021 | langgraph_pipeline/nodes.py |
| Application Layer Protocol | T1071 | NetworkCollector (beaconing) |
| Proxy — Tor | T1090.003 | NetworkCollector (ports 9001/9030) |
| DNS over HTTPS | T1071.004 | NetworkCollector (DoH suspicion) |

---

## Conformité NIS2 / ANSSI

| Exigence | Implémentation |
|---|---|
| NIS2 Art.21.2.h — intégrité journaux | HMAC-SHA256 sur chaque événement (`src/collectors/integrity.py`) |
| LLM local uniquement | Ollama sur le RPi — aucune donnée cloud |
| Pas de secret au build | `HMAC_SECRET_KEY` obligatoire à runtime, aucun default |
| Signature des alertes | `sign_event()` sur chaque alerte avant stockage |
| Rétention configurable | `LOG_RETENTION_DAYS` (min 365j ANSSI prod) |
| Isolation réseau | Docker Compose réseaux séparés : collect-net / analyze-net / storage-net |
| Mise à jour des IoC | `scripts/update_loldrivers.sh` (cron hebdomadaire) |
| Audit trail | PostgreSQL + pgvector, table initialisée via `scripts/init_db.sql` |
| Synchronisation temporelle | Service NTP dédié (pool.ntp.org + time.cloudflare.com) |

---

## Déploiement Raspberry Pi 4

### Prérequis

- Raspberry Pi 4 (4 Go RAM minimum)
- Raspberry Pi OS 64-bit (Bookworm)
- Docker 24+ et Docker Compose v2 installés
- SSH configuré : `gloaguen@192.168.1.31`

### 1. Choix du modèle LLM

Budget RAM disponible sur RPi 4 (4 Go) après OS + Docker :

| Modèle | RAM Q4_K_M | Swap requis | Recommandation |
|---|---|---|---|
| `llama3.2:1b` | ~0.9 Go | non | minimal, précision faible |
| **`granite3.1:2b`** | **~1.5 Go** | **non** | **recommandé** |
| `phi3.5:mini` | ~2.3 Go | 2 Go | si plus de précision souhaitée |
| `granite3.3:8b` | ~5.0 Go | 4 Go+ | déconseillé SD (wear) |

### 2. Swap 2 Go (optionnel — `phi3.5:mini` uniquement)

> Swap 4 Go déconseillé sur SD card : cycles d'écriture élevés → usure prématurée.

```bash
sudo dphys-swapfile swapoff
sudo sed -i 's/CONF_SWAPSIZE=.*/CONF_SWAPSIZE=2048/' /etc/dphys-swapfile
sudo dphys-swapfile setup && sudo dphys-swapfile swapon
free -h  # vérifier : Swap ~2G
```

### 3. Variables d'environnement

Créer le fichier `.env` manuellement (pas de `.env.example` — à générer via `make init` si disponible) :

```bash
cat > .env << 'EOF'
# PostgreSQL
POSTGRES_DB=log_analyzer
POSTGRES_USER=loguser
POSTGRES_PASSWORD=

# Sécurité
HMAC_SECRET_KEY=

# Grafana
GRAFANA_USER=admin
GRAFANA_PASSWORD=

# Tuning
LOG_RETENTION_DAYS=90
ANOMALY_THRESHOLD=0.75
EOF

# Générer les secrets automatiquement
POSTGRES_PWD=$(openssl rand -hex 16)
HMAC=$(openssl rand -hex 32)
GRAFANA_PWD=$(openssl rand -hex 12)

sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$POSTGRES_PWD/" .env
sed -i "s/HMAC_SECRET_KEY=.*/HMAC_SECRET_KEY=$HMAC/" .env
sed -i "s/GRAFANA_PASSWORD=.*/GRAFANA_PASSWORD=$GRAFANA_PWD/" .env

echo "✅ Secrets générés — noter le mot de passe Grafana :"
grep GRAFANA_PASSWORD .env
```

### 4. Certificats TLS (réseau local)

```bash
mkdir -p certs && cd certs

# CA
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=log-analyzer-CA" -out ca.crt

# Serveur
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=log-analyzer" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 3650 -sha256

cd ..
echo "✅ Certificats générés"
```

### 5. Premier démarrage

```bash
# Créer le dossier de données (volume bind)
mkdir -p /tmp/log-analyzer

# Build de l'image siem sur le RPi (5-10 min la première fois)
docker compose build siem

# Démarrage de tous les services
docker compose up -d

# Vérifier que tout est vert
docker compose ps
```

### 6. Télécharger le modèle LLM

```bash
# Pull du modèle (3-5 min selon connexion)
docker compose exec ollama ollama pull granite3.1:2b

# Vérifier
docker compose exec ollama ollama list
```

### 7. Vérification des services

```bash
# État global
docker compose ps

# API FastAPI
curl http://192.168.1.31:8000/health

# Ollama
curl http://192.168.1.31:11434/api/version

# Grafana (ouvrir dans navigateur)
# http://192.168.1.31:3000  →  admin / <GRAFANA_PASSWORD>
```

### 8. Surveiller la mémoire

```bash
# Consommation par conteneur (temps réel)
docker stats --format "table {{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}"

# Si log-ollama dépasse 2.5 Go → basculer sur llama3.2:1b
# Éditer docker-compose.yml : remplacer granite3.1:2b par llama3.2:1b
# puis : docker compose restart ollama
```

### 9. Mise à jour hebdomadaire LOLDrivers (cron)

```bash
# Ajouter au crontab du RPi :
(crontab -l 2>/dev/null; echo "0 3 * * 0 /opt/log-analyzer-anssi/scripts/update_loldrivers.sh >> /var/log/loldrivers-update.log 2>&1") | crontab -

# Vérifier
crontab -l
```

---

## Commandes Make

| Commande | Description |
|---|---|
| `make run` | Démarrer les services Docker Compose |
| `make stop` | Arrêter les services |
| `make test` | Tous les tests + couverture HTML |
| `make test-unit` | Tests unitaires uniquement |
| `make lint` | Vérification style ruff |
| `make typecheck` | mypy --strict |
| `make update-loldrivers` | Mettre à jour le cache loldrivers.io |
| `make deploy-rpi` | Déployer sur gloaguen@192.168.1.31 |
| `make clean` | Supprimer artefacts (htmlcov, caches) |

---

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `HMAC_SECRET_KEY` | *obligatoire* | Clé HMAC-SHA256 — `openssl rand -hex 32` |
| `POSTGRES_DB` | `log_analyzer` | Nom de la base PostgreSQL |
| `POSTGRES_USER` | `loguser` | Utilisateur PostgreSQL |
| `POSTGRES_PASSWORD` | *obligatoire* | Mot de passe PostgreSQL |
| `GRAFANA_USER` | `admin` | Utilisateur Grafana |
| `GRAFANA_PASSWORD` | *obligatoire* | Mot de passe Grafana |
| `OLLAMA_BASE_URL` | `http://ollama:11434` | URL Ollama local |
| `ANOMALY_THRESHOLD` | `0.75` | Seuil de détection d'anomalie |
| `LOG_RETENTION_DAYS` | `90` | Rétention logs (min 365j en prod ANSSI) |
| `ZEEK_LOG_DIR` | `/var/log/zeek/current` | Logs Zeek (conn.log) |
| `TCPDUMP_IFACE` | `eth0` | Interface tcpdump fallback |

---

## Structure du projet

```
log-analyzer-anssi/
├── src/
│   ├── api/
│   │   ├── main.py                 # FastAPI — point d'entrée :8000
│   │   ├── routes/
│   │   │   ├── analysis.py         # Endpoints analyse SIEM
│   │   │   └── health.py           # /health healthcheck
│   │   └── schemas.py              # Modèles Pydantic
│   ├── collectors/
│   │   ├── log_collector.py        # Ingestion Sysmon/auditd/syslog
│   │   ├── integrity.py            # HMAC-SHA256 NIS2 Art.21.2.h
│   │   └── pg_writer.py            # Écriture PostgreSQL async
│   ├── langgraph_pipeline/
│   │   ├── graph.py                # Définition StateGraph LangGraph
│   │   ├── nodes.py                # Nœuds : BYOVD, ransomware analyst
│   │   ├── state.py                # TypedDict état du pipeline
│   │   ├── conditions.py           # Edges conditionnels
│   │   └── llm_client.py           # Client Ollama httpx async
│   └── models/
│       ├── log_entry.py            # Modèle entrée de log
│       └── report.py               # Modèle rapport d'analyse
├── config/
│   ├── fluent-bit.conf             # Collecte TLS mutuel ANSSI
│   ├── fluent-bit-parsers.conf     # Parseurs Fluent-bit
│   ├── loki-config.yml             # Stockage et indexation logs
│   └── grafana/
│       ├── dashboards/             # JSON dashboards
│       └── provisioning/           # Datasources auto-provisionnées
├── tests/
│   ├── unit/
│   │   ├── test_api.py
│   │   ├── test_integrity.py
│   │   └── test_nodes.py
│   └── integration/
│       └── test_pipeline.py
├── scripts/
│   ├── init_db.sql                 # Initialisation schéma PostgreSQL
│   ├── gen_certs.sh                # Génération certificats TLS
│   └── update_loldrivers.sh        # Cron hebdomadaire IoC
├── certs/                          # Certificats TLS (généré localement)
├── data/                           # Cache LOLDrivers, SQLite DB
├── .github/workflows/
│   ├── ci.yml                      # lint + test ≥80% + Gitleaks + Bandit
│   ├── build-check.yml             # Docker buildx ARM64 + SBOM syft
│   └── deploy-notify.yml           # Notification ntfy on main push
├── docker-compose.yml              # ntp + postgres + loki + fluent-bit +
│                                   # ollama + api + grafana (ARM64)
├── Dockerfile                      # python:3.11-slim-bookworm
├── Makefile
├── requirements.txt
├── pytest.ini
└── CLAUDE.md                       # Instructions Claude Code
```

---

## En cas de problème

```bash
# Logs d'un service spécifique
docker compose logs api
docker compose logs ollama
docker compose logs postgres

# Redémarrage propre
docker compose down && docker compose up -d

# Vérifier la mémoire disponible
free -h
docker stats --no-stream
```

---

## Licence

MIT — Voir `LICENSE`
