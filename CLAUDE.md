# CLAUDE.md — log-analyzer-anssi

## Contexte du projet

Système d'analyse de journaux conforme aux recommandations ANSSI (Guide de recommandations
de sécurité pour l'architecture d'un système de journalisation, 2022).

Objectif : collecter, normaliser, analyser et alerter sur des logs de sécurité en utilisant
un pipeline LangGraph piloté par un LLM local (Mistral 7B via Ollama).

## Architecture

```
Fluent Bit (TLS) → Loki + PostgreSQL/pgvector
                              ↓
                    LangGraph Pipeline:
                    normalize → detect_anomalies → classify_severity
                              ↓                           ↓
                    auto_report (bas risque)   human_escalation (haut risque)
                              ↓
                    FastAPI REST API ← Grafana Dashboards
```

## Stack technique

- **Python 3.11+** — runtime principal
- **LangGraph 0.2+** — orchestration du pipeline d'analyse
- **Ollama + Mistral 7B** — LLM local pour analyse contextuelle (pas de données cloud)
- **FastAPI** — API REST pour déclencher analyses et récupérer rapports
- **PostgreSQL 16 + pgvector** — stockage structuré + recherche vectorielle
- **Loki** — stockage et indexation des logs bruts
- **Fluent Bit** — collecte et acheminement des logs (TLS mutuel)
- **Grafana** — dashboards temps réel
- **Docker Compose** — orchestration des services

## Contraintes ANSSI critiques

1. **Transport chiffré** : TLS mutuel (mTLS) entre tous les agents de collecte
2. **Partition dédiée** : `/var/log-analyzer` sur partition séparée (simulée via volume Docker)
3. **Intégrité des fichiers** : HMAC-SHA256 sur chaque fichier de log archivé
4. **Rotation** : rotation quotidienne avec compression gzip
5. **Rétention** : configurable via `LOG_RETENTION_DAYS` (défaut : 90 jours)
6. **Synchronisation temporelle** : NTP configuré dans tous les conteneurs
7. **Séparation des rôles** : collecteurs ≠ analyseurs ≠ archiveurs
8. **Traçabilité** : chaque action d'analyse est elle-même journalisée

## Structure des modules

```
src/
├── langgraph_pipeline/
│   ├── graph.py          # Définition du graphe LangGraph
│   ├── nodes.py          # Nœuds : normalize, detect_anomalies, classify_severity
│   ├── state.py          # LogAnalysisState (TypedDict)
│   ├── conditions.py     # Routage conditionnel
│   └── llm_client.py     # Client Ollama local
├── api/
│   ├── main.py           # Application FastAPI
│   ├── routes/
│   │   ├── analysis.py   # POST /analyze, GET /reports
│   │   └── health.py     # GET /health
│   └── schemas.py        # Modèles Pydantic
├── collectors/
│   ├── log_collector.py  # Interface Loki
│   ├── pg_writer.py      # Écriture PostgreSQL
│   └── integrity.py      # HMAC + rotation
└── models/
    ├── log_entry.py      # Modèle log normalisé
    └── report.py         # Modèle rapport d'analyse
```

## Commandes de développement

```bash
# Démarrer l'environnement complet
docker compose up -d

# Générer les certificats TLS de dev
./scripts/gen_certs.sh

# Lancer les tests
pytest tests/ -v

# Lancer l'API en mode dev
uvicorn src.api.main:app --reload --port 8000

# Vérifier un fichier de log (intégrité HMAC)
python -m src.collectors.integrity verify /var/log-analyzer/logs/app.log

# Déclencher une analyse manuelle
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"source": "nginx", "time_range": "1h"}'
```

## Variables d'environnement clés

| Variable | Défaut | Description |
|---|---|---|
| `LOG_RETENTION_DAYS` | `90` | Rétention des logs (ANSSI min. 1 an recommandé en prod) |
| `OLLAMA_BASE_URL` | `http://ollama:11434` | URL du service Ollama |
| `POSTGRES_DSN` | voir compose | Connexion PostgreSQL |
| `LOKI_URL` | `http://loki:3100` | URL du service Loki |
| `HMAC_SECRET_KEY` | obligatoire | Clé HMAC pour intégrité (32 bytes min.) |
| `TLS_CERT_PATH` | `/certs/server.crt` | Certificat TLS serveur |
| `TLS_KEY_PATH` | `/certs/server.key` | Clé privée TLS |
| `TLS_CA_PATH` | `/certs/ca.crt` | CA pour validation mTLS |
| `ANOMALY_THRESHOLD` | `0.75` | Seuil de score pour escalade humaine |
| `NTP_SERVER` | `pool.ntp.org` | Serveur NTP |

## Conventions de code

- Typage strict (`mypy --strict`)
- Docstrings en français pour les modules métier
- Tests unitaires pour chaque nœud LangGraph
- Logs d'audit dans la table `audit_trail` PostgreSQL
- Pas d'appels réseau externes (conformité ANSSI : LLM local uniquement)

## Sécurité

- Ne jamais committer de secrets (utiliser `.env.local` gitignorés)
- Les certificats TLS de prod sont dans `/certs/` (hors git)
- La clé HMAC doit être stockée dans un HSM ou gestionnaire de secrets en production
- Revue obligatoire pour tout changement dans `src/collectors/integrity.py`
