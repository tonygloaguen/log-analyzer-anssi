# log-analyzer-anssi

Système d'analyse de journaux conforme aux recommandations ANSSI (Guide de recommandations
de sécurité pour l'architecture d'un système de journalisation, 2022).

**Stack** : Python 3.11 · LangGraph · Ollama/Mistral 7B · FastAPI · PostgreSQL+pgvector · Loki · Fluent Bit · Grafana · Docker Compose

---

## Architecture

```
                    ┌─────────────────────────────────────┐
Sources de logs     │  Fluent Bit (TLS mutuel — ANSSI)    │
nginx / ssh /  ───► │  Collecte, parse, enrichit          │
auditd / apps       └────────────┬────────────────────────┘
                                 │
                    ┌────────────▼────────────────────────┐
                    │  Loki              PostgreSQL        │
                    │  (logs bruts)  +   (logs structurés)│
                    └────────────┬────────────────────────┘
                                 │  POST /analyze
                    ┌────────────▼────────────────────────────────────┐
                    │  LangGraph Pipeline                              │
                    │                                                  │
                    │  normalize ──► detect_anomalies ──► classify    │
                    │                                         │        │
                    │              score < 0.75 ◄─────────── │        │
                    │                   │             score ≥ 0.75    │
                    │            auto_report          human_escalation │
                    └──────────────────┬──────────────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────────────┐
                    │  FastAPI REST API                                │
                    │  GET /health · POST /analyze · GET /reports     │
                    └──────────────────┬──────────────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────────────┐
                    │  Grafana Dashboards (temps réel)                 │
                    └─────────────────────────────────────────────────┘
```

### Pipeline LangGraph — 4 nœuds

| Nœud | Rôle |
|---|---|
| `normalize` | Parse les logs bruts → `LogEntry` typé |
| `detect_anomalies` | Pattern matching (brute-force, SQLi, traversal…) + score de risque |
| `classify_severity` | Sévérité finale + analyse contextuelle Mistral 7B |
| `auto_report` / `human_escalation` | Routage conditionnel selon score |

---

## Conformité ANSSI

| Exigence | Implémentation |
|---|---|
| Transport chiffré | TLS mutuel (mTLS) Fluent Bit → Loki |
| Partition dédiée | Volume Docker dédié `/var/log-analyzer` |
| Intégrité des fichiers | HMAC-SHA256 sur chaque archive (`.hmac` adjacent) |
| Rotation | Quotidienne avec compression gzip |
| Rétention configurable | `LOG_RETENTION_DAYS` (défaut 90j) |
| Synchronisation NTP | Service NTP dédié dans Docker Compose |
| Séparation des rôles | Réseaux Docker isolés (collect / analyze / storage) |
| Traçabilité | Table `audit_trail` PostgreSQL + piste d'audit dans chaque rapport |
| LLM local uniquement | Ollama/Mistral 7B — aucune donnée envoyée vers des services cloud |

---

## Modes de déploiement

Le projet supporte deux modes de fonctionnement :

| Mode | Config Fluent Bit | Syslog TLS | Certificats requis |
|---|---|---|---|
| **Stable (défaut)** | `fluent-bit.conf` | Désactivé | Non |
| **TLS/mTLS ANSSI** | `fluent-bit-tls.conf` | Activé (port 5140) | Oui (`ca.crt`, `server.crt`, `server.key`) |

Le mode stable est validé en production. Le mode TLS est activable explicitement une fois les certificats en place.

> **Documentation complète :** [docs/syslog-tls-anssi.md](docs/syslog-tls-anssi.md)

---

## Démarrage rapide

### Prérequis

- Docker 24+ et Docker Compose v2
- 8 Go RAM minimum (Mistral 7B)
- `openssl` (pour la génération des certificats TLS)

### Installation — Mode stable (sans certificats)

```bash
# 1. Cloner et configurer
git clone <url> log-analyzer-anssi
cd log-analyzer-anssi

# 2. Variables d'environnement
cp .env.example .env.local
# Éditer .env.local : définir POSTGRES_PASSWORD, HMAC_SECRET_KEY, GRAFANA_PASSWORD, etc.

# 3. Créer le répertoire de logs (ANSSI : partition dédiée)
mkdir -p /tmp/log-analyzer

# 4. Démarrer les services
docker compose --env-file .env.local up -d

# 5. Télécharger Mistral 7B (première exécution — ~4 Go)
# Automatique via le service ollama-init, surveiller avec :
docker logs log-ollama-init -f

# 6. Vérifier l'état
curl http://localhost:8000/health | jq
```

### Activation du mode TLS/mTLS ANSSI

```bash
# 1. Générer les certificats de labo
./scripts/gen_certs.sh ./certs

# 2. Peupler le volume Docker 'certs'
docker run --rm -v $(pwd)/certs:/src -v certs:/dest alpine cp -r /src/. /dest/

# 3. Démarrer Fluent Bit en mode TLS
docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d fluent-bit

# 4. Vérifier le démarrage (doit montrer l'input syslog sur port 5140)
docker logs log-fluent-bit --tail 20

# Retour au mode stable si besoin
docker compose up -d --force-recreate fluent-bit
```

> Voir [docs/syslog-tls-anssi.md](docs/syslog-tls-anssi.md) pour les procédures complètes de test et de dépannage.

### Endpoints API

```bash
# Santé des services
GET  http://localhost:8000/health

# Déclencher une analyse (logs depuis Loki, dernière heure)
POST http://localhost:8000/analyze
{
  "source": "nginx",
  "time_range": "1h"
}

# Avec logs fournis directement
POST http://localhost:8000/analyze
{
  "source": "*",
  "time_range": "1h",
  "raw_logs": [
    {"timestamp": "2024-01-15T10:30:00Z", "message": "...", "source": "nginx", "host": "web01"}
  ]
}

# Lister les rapports
GET  http://localhost:8000/reports?limit=20&offset=0

# Récupérer un rapport
GET  http://localhost:8000/reports/{id}

# Documentation interactive
GET  http://localhost:8000/docs
```

### Interfaces

| Service | URL | Credentials |
|---|---|---|
| API FastAPI | http://localhost:8000/docs | — |
| Grafana | http://localhost:3000 | admin / voir `.env.local` |
| Loki | http://localhost:3100 | — |

---

## Dashboards Grafana

Le projet inclut deux dashboards, chargés automatiquement via le provisioning Grafana.

### Dashboard v2 — Observabilité Fluent Bit (recommandé)

Fichier : `config/grafana/dashboards/grafana_anssi_dashboard_v2.json`

Cohérent avec l'état réel de la stack (`job="fluent-bit"`) :

| Panel | Type | Description |
|---|---|---|
| Volume de logs (5 min) | Stat | Compteur total de logs reçus |
| Erreurs détectées (5 min) | Stat | Logs contenant "error" |
| Tentatives SSH échouées (15 min) | Stat | Logs contenant "Failed password" |
| Débit de logs | Timeseries | Évolution du volume par minute |
| Événements sensibles | Timeseries | Erreurs + SSH sur le temps |
| Logs d'erreur récents | Logs | Affichage brut des erreurs |
| Logs bruts récents | Logs | Tous les logs Fluent Bit |

**Import manuel** (si le provisioning ne charge pas automatiquement) :
Grafana → Dashboards → Import → Upload `config/grafana/dashboards/grafana_anssi_dashboard_v2.json` → sélectionner datasource Loki.

### Dashboard v1 — Vue d'ensemble (legacy)

Fichier : `config/grafana/dashboards/log-analyzer-overview.json`

Dépend de PostgreSQL et de données structurées — à utiliser uniquement quand la base est peuplée.

---

## Développement

```bash
# Installer les dépendances
pip install -r requirements.txt

# Tests unitaires
pytest tests/unit/ -v

# Tests d'intégration (pipeline complet, Ollama mocké)
pytest tests/integration/ -v

# Tous les tests avec couverture
pytest tests/ --cov=src --cov-report=html

# Linter / type check
mypy src/ --strict
```

### Structure du projet

```
log-analyzer-anssi/
├── CLAUDE.md                          # Instructions Claude Code
├── docker-compose.yml                 # Orchestration Docker (mode stable)
├── docker-compose.tls.yml             # Override Docker Compose pour le mode TLS
├── Dockerfile                         # Image API
├── requirements.txt
├── pytest.ini
├── src/
│   ├── langgraph_pipeline/
│   │   ├── graph.py                   # Définition + compilation du graphe
│   │   ├── nodes.py                   # 4 nœuds : normalize, detect, classify, report
│   │   ├── state.py                   # LogAnalysisState (TypedDict)
│   │   ├── conditions.py              # Routage conditionnel (route_by_risk)
│   │   └── llm_client.py             # Client Ollama async
│   ├── api/
│   │   ├── main.py                    # Application FastAPI
│   │   ├── schemas.py                 # Modèles Pydantic
│   │   └── routes/
│   │       ├── analysis.py            # POST /analyze, GET /reports
│   │       └── health.py              # GET /health
│   ├── collectors/
│   │   ├── log_collector.py           # Client Loki async
│   │   ├── pg_writer.py               # Écriture PostgreSQL async
│   │   └── integrity.py               # HMAC + rotation + rétention
│   └── models/
│       ├── log_entry.py               # Modèle log normalisé
│       └── report.py                  # Modèle rapport d'analyse
├── config/
│   ├── fluent-bit.conf                # Config stable (mode défaut, sans syslog TLS)
│   ├── fluent-bit-tls.conf            # Config TLS (syslog mTLS activé, port 5140)
│   ├── fluent-bit-parsers.conf        # Parsers (nginx, syslog, json)
│   ├── loki-config.yml                # Config Loki + rétention
│   └── grafana/
│       ├── provisioning/              # Datasources + dashboards auto
│       └── dashboards/
│           ├── grafana_anssi_dashboard_v2.json   # Dashboard Fluent Bit/Loki (recommandé)
│           └── log-analyzer-overview.json        # Dashboard complet (nécessite PostgreSQL)
├── docs/
│   └── syslog-tls-anssi.md           # Documentation technique TLS/mTLS ANSSI
├── scripts/
│   ├── gen_certs.sh                   # Génération certificats TLS labo
│   └── init_db.sql                    # Schéma PostgreSQL + pgvector
├── certs/
│   └── README.md                      # Structure attendue des certificats
├── tests/
│   ├── unit/                          # Tests nœuds, intégrité, API
│   └── integration/                   # Tests pipeline end-to-end
```

---

## Sécurité et production

> Ces instructions s'appliquent pour un déploiement en production conforme ANSSI.

1. **Certificats TLS** : remplacer les certificats auto-signés par des certificats émis par une PKI d'entreprise
2. **Secrets** : stocker `HMAC_SECRET_KEY` et `POSTGRES_PASSWORD` dans un gestionnaire de secrets (Vault, AWS Secrets Manager…)
3. **Rétention** : porter `LOG_RETENTION_DAYS` à 365 minimum (recommandation ANSSI)
4. **Partition dédiée** : monter `/var/log-analyzer` sur une partition physique dédiée
5. **Réseau** : les services `postgres` et `loki` ne doivent pas exposer de ports à l'extérieur
6. **Ollama** : s'assurer que le service n'a pas accès à Internet (conformité ANSSI : LLM local uniquement)
7. **Audit trail** : activer Row Level Security sur la table `audit_trail` PostgreSQL

---

## Licence

MIT — Voir `LICENSE`
