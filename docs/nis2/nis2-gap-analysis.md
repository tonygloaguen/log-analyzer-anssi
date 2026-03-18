# Analyse des écarts NIS2 — log-analyzer-anssi

> **Méthode** : Chaque thème est évalué uniquement à partir de preuves constatées
> dans le dépôt (code, config, tests, documentation). Aucun contrôle n'est déclaré
> "couvert" sans référence explicite à un fichier et une ligne.
>
> **Date d'analyse** : 2026-03-18
> **Branche analysée** : `claude/nis2-devsecops-implementation-O9xdv`

---

## Thème 1 — Gouvernance minimale et responsabilités

| Attribut | Valeur |
|---|---|
| **Objectif NIS2** | Art. 20 — La direction approuve les mesures de cybersécurité et est responsable de leur mise en œuvre |
| **État actuel** | Non démontrable dans ce dépôt |
| **Preuves existantes** | `CLAUDE.md` documente les conventions de code et les contraintes ANSSI |
| **Lacunes** | Pas de RACI, pas de politique de sécurité formelle, pas de registre des actifs, pas de désignation de responsable sécurité |
| **Actions recommandées** | Créer `docs/governance/security-policy.md` avec RACI minimal et périmètre ; noter que ce document est organisationnel et non démontrable par du code seul |
| **Priorité** | P3 |
| **Effort estimé** | Faible (documentation) |
| **Impact sécurité** | Indirect — cadre réglementaire |

---

## Thème 2 — Gestion des risques

| Attribut | Valeur |
|---|---|
| **Objectif NIS2** | Art. 21.2a — Politiques d'analyse des risques et de sécurité des systèmes d'information |
| **État actuel** | Partiel |
| **Preuves existantes** | Score de risque calculé [0.0–1.0] dans `src/langgraph_pipeline/nodes.py:222-228` ; seuil `ANOMALY_THRESHOLD` configurable (`docker-compose.yml:196`) ; 7 patterns IOC documentés `nodes.py:27-77` |
| **Lacunes** | Pas de registre des risques formalisé ; pas de threat modeling documenté ; le score de risque est technique mais non lié à un registre EBIOS RM ou ISO 27005 ; pas de processus de revue périodique des risques |
| **Actions recommandées** | Créer `docs/nis2/threat-model.md` avec les scénarios de menace couverts par le pipeline ; documenter les limites du modèle de risque ; ajouter commentaire dans `nodes.py` liant les patterns IOC aux scénarios de menace |
| **Priorité** | P3 |
| **Effort estimé** | Moyen (documentation + annotations code) |
| **Impact sécurité** | Indirect — qualité du modèle de détection |

---

## Thème 3 — Gestion des incidents

| Attribut | Valeur |
|---|---|
| **Objectif NIS2** | Art. 21.2b — Gestion des incidents ; Art. 23 — Notification dans les 72h |
| **État actuel** | Partiel |
| **Preuves existantes** | Escalade humaine implémentée : `src/langgraph_pipeline/nodes.py:396-430` ; routage conditionnel `src/langgraph_pipeline/conditions.py` ; rapport `ReportStatus.ESCALATED` avec `requires_human_review=True` ; audit trail par nœud |
| **Lacunes** | Pas de notification automatique (webhook, email, SIEM) lors d'une escalade ; pas de runbook de réponse aux incidents ; pas de procédure de déclaration ANSSI (72h) ; pas de tableau de bord des incidents escaladés dans Grafana |
| **Actions recommandées** | Documenter un runbook minimal dans `docs/nis2/incident-runbook.md` ; ajouter endpoint webhook configurable pour notifications escalade ; créer dashboard Grafana "Incidents escaladés" |
| **Priorité** | P2 |
| **Effort estimé** | Moyen (code notification + doc) |
| **Impact sécurité** | Élevé — délai de réponse aux incidents |

---

## Thème 4 — Continuité, sauvegarde et reprise

| Attribut | Valeur |
|---|---|
| **Objectif NIS2** | Art. 21.2c — Continuité des activités, gestion des sauvegardes, reprise après sinistre |
| **État actuel** | Manquant |
| **Preuves existantes** | Volumes Docker nommés définis (`docker-compose.yml:32-42`) — persistance des données ; rotation des logs avec compression gzip (`src/collectors/integrity.py:100-148`) |
| **Lacunes** | Pas de script de sauvegarde PostgreSQL ; pas de procédure de restauration documentée ; pas de test de restauration ; rétention par défaut 90j (ANSSI recommande 1 an minimum en production) ; Loki sans politique de sauvegarde externe |
| **Actions recommandées** | Créer `scripts/backup_postgres.sh` avec `pg_dump` chiffré ; documenter procédure de restauration ; créer test de restauration dans `tests/` ; ajouter warning dans `.env.example` sur `LOG_RETENTION_DAYS` |
| **Priorité** | P2 |
| **Effort estimé** | Moyen (scripts + doc + tests) |
| **Impact sécurité** | Élevé — perte de données probante en cas d'incident |

---

## Thème 5 — Sécurité de la chaîne d'approvisionnement

| Attribut | Valeur |
|---|---|
| **Objectif NIS2** | Art. 21.2d — Sécurité de la chaîne d'approvisionnement (fournisseurs et prestataires) |
| **État actuel** | Manquant |
| **Preuves existantes** | `requirements.txt` liste les dépendances Python avec versions minimales ; `Dockerfile` utilise `python:3.11-slim` ; `PIP_NO_CACHE_DIR=1` dans Dockerfile |
| **Lacunes** | Images Docker non pinnées par digest SHA256 ; pas de SBOM (Software Bill of Materials) ; pas de scan de vulnérabilités des dépendances (`pip-audit`, `safety`) ; pas de scan d'images Docker (Trivy, Grype) ; pas de vérification d'intégrité des images |
| **Actions recommandées** | Ajouter `pip-audit` dans CI ; générer SBOM avec `syft` ; configurer Trivy dans GitHub Actions ; pinner les images Docker par digest dans `docker-compose.yml` (commenté pour dev, obligatoire en prod) |
| **Priorité** | P1 |
| **Effort estimé** | Faible (CI) — Moyen (SBOM) |
| **Impact sécurité** | Élevé — dépendances vulnérables = vecteur d'attaque fréquent |

---

## Thème 6 — Sécurité du développement et de la maintenance

| Attribut | Valeur |
|---|---|
| **Objectif NIS2** | Art. 21.2e — Sécurité dans le développement et la maintenance des systèmes |
| **État actuel** | Partiel |
| **Preuves existantes** | Typage strict `mypy --strict` documenté dans `CLAUDE.md` et `README.md` ; Pydantic v2 pour validation des entrées API (`src/api/schemas.py`) ; tests unitaires présents (`tests/unit/`) avec 33+ tests ; `structlog` JSON pour logs d'audit ; validation HMAC avec `compare_digest` (protection timing attack) `integrity.py:69` |
| **Lacunes** | Pas de pipeline CI/CD exécutant les tests automatiquement ; pas de linter sécurité (`bandit`) ; pas de pre-commit hooks ; pas de politique de revue de code (branch protection) ; `mypy --strict` non exécuté automatiquement ; pas de DAST |
| **Actions recommandées** | Créer `.github/workflows/ci.yml` avec : pytest, mypy, bandit, pip-audit ; configurer `.pre-commit-config.yaml` ; documenter politique de revue de code dans `CLAUDE.md` |
| **Priorité** | P1 |
| **Effort estimé** | Faible (CI YAML) |
| **Impact sécurité** | Élevé — non-régression sécurité à chaque commit |

---

## Thème 7 — Gestion des vulnérabilités

| Attribut | Valeur |
|---|---|
| **Objectif NIS2** | Art. 21.2e — Divulgation des vulnérabilités, gestion des correctifs |
| **État actuel** | Manquant |
| **Preuves existantes** | Versions minimales dans `requirements.txt` ; `cryptography>=42.0.0` (version récente) |
| **Lacunes** | Pas de processus documenté de mise à jour des dépendances ; pas de scan automatique CVE (`pip-audit`, Dependabot) ; pas de `SECURITY.md` ; pas de politique de divulgation responsable |
| **Actions recommandées** | Créer `SECURITY.md` avec politique de divulgation ; configurer Dependabot ou Renovate pour `requirements.txt` ; ajouter `pip-audit` dans CI avec seuil bloquant (CVSS >= 7.0) |
| **Priorité** | P2 |
| **Effort estimé** | Faible |
| **Impact sécurité** | Élevé — dépendances non patchées = risque permanent |

---

## Thème 8 — Journalisation, détection et traçabilité

| Attribut | Valeur |
|---|---|
| **Objectif NIS2** | Art. 21.2f — Politiques et procédures d'évaluation de l'efficacité des mesures |
| **État actuel** | Fortement couvert — lacunes ponctuelles |
| **Preuves existantes** | `structlog` JSON configuré `src/api/main.py:25-44` ; `audit_events` tracés dans chaque nœud LangGraph `src/langgraph_pipeline/nodes.py:106-113, 230-236, 317-323` ; table `audit_trail` PostgreSQL `scripts/init_db.sql:61-73` ; `PostgresWriter.insert_audit_event()` `src/collectors/pg_writer.py:98-114` ; `compute_hmac` + `verify_hmac` + rotation `src/collectors/integrity.py` ; 13 tests unitaires HMAC `tests/unit/test_integrity.py` ; NTP service `docker-compose.yml:48-62` ; Loki + Grafana provisionnés |
| **Lacunes** | `_reports_store` en mémoire dans `src/api/routes/analysis.py:26` — rapports perdus au redémarrage ; `insert_report()` et `insert_audit_event()` du `pg_writer` non appelés depuis l'API ; `tls.verify Off` dans `config/fluent-bit.conf:108` — TLS output non vérifié ; rétention 90j par défaut (recommandation ANSSI : 1 an prod) |
| **Actions recommandées** | Connecter `pg_writer` dans l'endpoint `/analyze` pour persistance réelle ; corriger `tls.verify` avec commentaire explicite prod/dev ; porter `LOG_RETENTION_DAYS=365` en exemple prod dans `.env.example` |
| **Priorité** | P1 |
| **Effort estimé** | Moyen (intégration pg_writer) |
| **Impact sécurité** | Critique — traçabilité brisée sans persistance |

---

## Thème 9 — Contrôle d'accès et gestion des secrets

| Attribut | Valeur |
|---|---|
| **Objectif NIS2** | Art. 21.2i — Contrôle d'accès, authentification multifacteur |
| **État actuel** | Partiel |
| **Preuves existantes** | `POSTGRES_PASSWORD:?` et `HMAC_SECRET_KEY:?` obligatoires dans `docker-compose.yml:73,194` (erreur au démarrage si absents) ; `POSTGRES_INITDB_ARGS: "--auth-host=scram-sha-256"` `docker-compose.yml:74` ; validation `HMAC_SECRET_KEY` dans `src/api/main.py:55-59` ; CORS restreint aux méthodes GET/POST `src/api/main.py:87-93` ; container non-root `Dockerfile:32-35` |
| **Lacunes** | Pas d'authentification sur l'API FastAPI (pas de JWT, pas d'API key) ; `CORS_ORIGINS` par défaut `http://localhost:3000` sans validation de format ; pas de `.env.example` dans le dépôt ; pas de rotation de secrets documentée ; `GRAFANA_PASSWORD:?` obligatoire mais pas de politique de complexité |
| **Actions recommandées** | Créer `.env.example` avec toutes les variables documentées ; ajouter middleware d'authentification API (optionnel mais documenté) ; documenter rotation des secrets dans `docs/nis2/` |
| **Priorité** | P1 |
| **Effort estimé** | Faible (.env.example) — Moyen (auth API) |
| **Impact sécurité** | Élevé — API ouverte sans authentification en prod |

---

## Thème 10 — Hygiène cyber et configuration sécurisée

| Attribut | Valeur |
|---|---|
| **Objectif NIS2** | Art. 21.2 — Hygiène informatique de base et formation à la cybersécurité |
| **État actuel** | Partiel |
| **Preuves existantes** | Dockerfile non-root avec `appuser` `Dockerfile:32-35` ; `PIP_DISABLE_PIP_VERSION_CHECK=1` `Dockerfile:13` ; réseaux Docker isolés avec sous-réseaux dédiés `docker-compose.yml:17-30` ; PostgreSQL sans port externe exposé `docker-compose.yml:86-87` ; `GF_ANALYTICS_REPORTING_ENABLED=false` et `GF_ANALYTICS_CHECK_FOR_UPDATES=false` dans Grafana `docker-compose.yml:232-233` ; `storage.checksum On` Fluent Bit `config/fluent-bit.conf:18` ; permissions 600 sur clés TLS `scripts/gen_certs.sh:50` |
| **Lacunes** | `tls.verify Off` pour output Loki dans Fluent Bit `config/fluent-bit.conf:108` ; pas de politique `read_only: true` sur les containers ; pas de `security_opt: no-new-privileges` dans compose ; Ollama expose potentiellement un accès réseau non restreint ; pas de scan CIS Benchmark |
| **Actions recommandées** | Corriger `tls.verify` avec note prod/dev ; ajouter `read_only` et `no-new-privileges` sur les services critiques dans compose ; documenter les exceptions dans des commentaires |
| **Priorité** | P1 (tls.verify) — P3 (hardening compose) |
| **Effort estimé** | Très faible (config) |
| **Impact sécurité** | Moyen à élevé selon le point |

---

## Thème 11 — Mesure d'efficacité, tests et revues

| Attribut | Valeur |
|---|---|
| **Objectif NIS2** | Art. 21.2f — Politiques et procédures d'évaluation de l'efficacité des mesures de gestion des risques |
| **État actuel** | Partiel |
| **Preuves existantes** | 33+ tests unitaires dans `tests/unit/` ; 6 tests d'intégration dans `tests/integration/test_pipeline.py` (Ollama mocké — exécutables sans infra) ; `pytest.ini` configuré ; couverture avec `--cov=src` documentée dans `README.md` |
| **Lacunes** | Pas de seuil de couverture minimum imposé (`fail_under` absent de `pytest.ini`) ; pas de CI exécutant les tests à chaque push ; pas de rapport de couverture publié ; pas de tests de non-régression sur les exigences sécurité spécifiques (rétention, intégrité, secrets) ; tests de validation config absents |
| **Actions recommandées** | Ajouter `--cov-fail-under=80` dans `pytest.ini` ; créer CI GitHub Actions ; ajouter `tests/unit/test_config_validation.py` ; ajouter `tests/unit/test_retention_policy.py` |
| **Priorité** | P1 |
| **Effort estimé** | Faible |
| **Impact sécurité** | Élevé — régression sécurité non détectée sans CI |

---

## Tableau de synthèse

| # | Thème | Niveau | Priorité globale |
|---|---|---|---|
| 1 | Gouvernance et responsabilités | Manquant | P3 |
| 2 | Gestion des risques | Partiel | P3 |
| 3 | Gestion des incidents | Partiel | P2 |
| 4 | Continuité / sauvegarde / reprise | Manquant | P2 |
| 5 | Sécurité supply chain | Manquant | P1 |
| 6 | Sécurité du développement | Partiel | P1 |
| 7 | Gestion des vulnérabilités | Manquant | P2 |
| 8 | Journalisation / détection / traçabilité | Couvert (lacunes) | P1 |
| 9 | Contrôle d'accès / secrets | Partiel | P1 |
| 10 | Hygiène cyber / config sécurisée | Partiel | P1 (tls.verify) |
| 11 | Mesure d'efficacité / tests / revues | Partiel | P1 |
