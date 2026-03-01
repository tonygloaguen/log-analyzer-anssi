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

## Démarrage rapide

### Prérequis

- Docker 24+ et Docker Compose v2
- 8 Go RAM minimum (Mistral 7B)
- `openssl` (pour la génération des certificats TLS)

### Installation

```bash
# 1. Cloner et configurer
git clone <url> log-analyzer-anssi
cd log-analyzer-anssi

# 2. Variables d'environnement
cp .env.example .env.local
# Éditer .env.local : définir POSTGRES_PASSWORD, HMAC_SECRET_KEY, etc.

# 3. Générer les certificats TLS de développement
./scripts/gen_certs.sh ./certs

# 4. Créer le répertoire de logs (ANSSI : partition dédiée)
mkdir -p /tmp/log-analyzer

# 5. Démarrer les services
docker compose --env-file .env.local up -d

# 6. Télécharger Mistral 7B (première exécution — ~4 Go)
# Automatique via le service ollama-init, surveiller avec :
docker logs log-ollama-init -f

# 7. Vérifier l'état
curl http://localhost:8000/health | jq
```

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
├── CLAUDE.md                    # Instructions Claude Code
├── docker-compose.yml           # Orchestration Docker
├── Dockerfile                   # Image API
├── requirements.txt
├── pytest.ini
├── src/
│   ├── langgraph_pipeline/
│   │   ├── graph.py             # Définition + compilation du graphe
│   │   ├── nodes.py             # 4 nœuds : normalize, detect, classify, report
│   │   ├── state.py             # LogAnalysisState (TypedDict)
│   │   ├── conditions.py        # Routage conditionnel (route_by_risk)
│   │   └── llm_client.py       # Client Ollama async
│   ├── api/
│   │   ├── main.py              # Application FastAPI
│   │   ├── schemas.py           # Modèles Pydantic
│   │   └── routes/
│   │       ├── analysis.py      # POST /analyze, GET /reports
│   │       └── health.py        # GET /health
│   ├── collectors/
│   │   ├── log_collector.py     # Client Loki async
│   │   ├── pg_writer.py         # Écriture PostgreSQL async
│   │   └── integrity.py         # HMAC + rotation + rétention
│   └── models/
│       ├── log_entry.py         # Modèle log normalisé
│       └── report.py            # Modèle rapport d'analyse
├── config/
│   ├── fluent-bit.conf          # Config collecte TLS
│   ├── fluent-bit-parsers.conf  # Parsers (nginx, syslog, json)
│   ├── loki-config.yml          # Config Loki + rétention
│   └── grafana/
│       ├── provisioning/        # Datasources + dashboards auto
│       └── dashboards/          # JSON dashboards
├── scripts/
│   ├── gen_certs.sh             # Génération certificats TLS dev
│   └── init_db.sql              # Schéma PostgreSQL + pgvector
├── tests/
│   ├── unit/                    # Tests nœuds, intégrité, API
│   └── integration/             # Tests pipeline end-to-end
└── certs/                       # Certificats TLS (gitignorés)
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
