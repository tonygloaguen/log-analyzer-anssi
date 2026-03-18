# Plan d'implémentation NIS2 — log-analyzer-anssi

> **Version** : 1.0 — 2026-03-18
> **Méthode** : chaque phase liste les tâches précises, les fichiers à modifier,
> les critères d'acceptation mesurables, et les preuves attendues dans le dépôt.

---

## Phase 1 — Baseline sécurité et traçabilité

**Objectif** : Corriger les lacunes critiques qui invalident les preuves existantes.

### Tâches

| Tâche | Fichier(s) concerné(s) | Critère d'acceptation | Preuve attendue |
|---|---|---|---|
| 1.1 Créer `.env.example` avec toutes les variables documentées | `.env.example` (nouveau) | Toutes les variables de `docker-compose.yml` présentes avec valeurs d'exemple et commentaires | Fichier créé, checké dans git |
| 1.2 Corriger `tls.verify Off` → `tls.verify On` avec note explicite | `config/fluent-bit.conf` | Commentaire clair dev/prod ; valeur prod documentée | Config modifiée + note |
| 1.3 Étendre la validation des variables au démarrage FastAPI | `src/api/main.py` | Variables `POSTGRES_DSN`, `LOKI_URL`, `OLLAMA_BASE_URL` vérifiées au boot | Test `test_config_validation.py` passe |
| 1.4 Connecter `pg_writer` dans `/analyze` pour persistance réelle | `src/api/routes/analysis.py` | Rapports écrits en PostgreSQL ; `_reports_store` utilisé comme cache uniquement | Test d'intégration + code review |
| 1.5 Créer CI GitHub Actions minimal | `.github/workflows/ci.yml` | Tests unitaires et intégration passent à chaque push sur `main` | Badge CI vert |

**Tests à exécuter** :
```bash
pytest tests/unit/ -v
pytest tests/integration/ -v
```

---

## Phase 2 — Hardening DevSecOps

**Objectif** : Automatiser les contrôles sécurité dans le cycle de développement.

### Tâches

| Tâche | Fichier(s) concerné(s) | Critère d'acceptation | Preuve attendue |
|---|---|---|---|
| 2.1 Ajouter `pip-audit` dans CI | `.github/workflows/ci.yml` | Scan CVE bloquant si CVSS >= 7.0 | Étape CI verte / rouge selon vulnérabilités |
| 2.2 Ajouter `bandit` (SAST Python) | `.github/workflows/ci.yml` | Aucune issue de sévérité HIGH/CRITICAL | Rapport bandit dans artefacts CI |
| 2.3 Configurer pre-commit hooks | `.pre-commit-config.yaml` | `bandit`, `mypy`, `ruff` exécutés localement avant commit | `.pre-commit-config.yaml` dans repo |
| 2.4 Ajouter seuil de couverture minimum | `pytest.ini` | `--cov-fail-under=80` — CI échoue en dessous | Badge coverage dans README |
| 2.5 Hardening Dockerfile | `Dockerfile` | `--no-install-recommends`, health check, USER avant EXPOSE | Dockerfile mis à jour |
| 2.6 Hardening docker-compose | `docker-compose.yml` | `read_only: true` sur volumes sensibles ; `no-new-privileges` sur services critiques | Compose mis à jour avec commentaires |
| 2.7 Créer `SECURITY.md` | `SECURITY.md` | Politique de divulgation, contact, versions supportées | Fichier dans repo |

**Tests à exécuter** :
```bash
bandit -r src/ -l -ii
mypy src/ --strict
pip-audit
pre-commit run --all-files
```

---

## Phase 3 — Détection, incidents et réponse

**Objectif** : Renforcer le pipeline de détection et outiller la réponse aux incidents.

### Tâches

| Tâche | Fichier(s) concerné(s) | Critère d'acceptation | Preuve attendue |
|---|---|---|---|
| 3.1 Notification webhook sur escalade | `src/api/routes/analysis.py`, `src/api/main.py` | Variable `ALERT_WEBHOOK_URL` optionnelle ; POST HTTP sur chaque `human_escalation` | Test mocké du webhook |
| 3.2 Ajouter patterns IOC supplémentaires | `src/langgraph_pipeline/nodes.py` | Couverture LFI, XSS, log4shell, reverse shell | Tests unitaires dédiés |
| 3.3 Créer runbook incident | `docs/nis2/incident-runbook.md` | Procédures pour les 4 niveaux de sévérité ; contacts ; checklist ANSSI 72h | Document créé |
| 3.4 Dashboard Grafana "Incidents escaladés" | `config/grafana/dashboards/` | Vue des rapports `status=escalated` en temps réel | JSON dashboard créé |
| 3.5 Row Level Security sur `audit_trail` | `scripts/init_db.sql` | RLS activé : INSERT autorisé, UPDATE/DELETE interdits | SQL + test d'intégrité |

**Tests à exécuter** :
```bash
pytest tests/unit/test_nodes.py -v -k "escalation or notification"
pytest tests/integration/ -v
```

---

## Phase 4 — Résilience, sauvegarde et continuité

**Objectif** : Démontrer la capacité de reprise après incident.

### Tâches

| Tâche | Fichier(s) concerné(s) | Critère d'acceptation | Preuve attendue |
|---|---|---|---|
| 4.1 Script de sauvegarde PostgreSQL | `scripts/backup_postgres.sh` | `pg_dump` chiffré avec GPG ; nom de fichier horodaté ; HMAC calculé | Script exécutable + test de restauration |
| 4.2 Script de restauration | `scripts/restore_postgres.sh` | Restauration depuis backup chiffré ; vérification HMAC avant import | Script + procédure documentée |
| 4.3 Documenter la procédure de reprise | `docs/nis2/recovery-procedure.md` | Étapes pas-à-pas : arrêt services, restauration, vérification intégrité, redémarrage | Document créé |
| 4.4 Test de restauration automatisé | `tests/integration/test_backup_restore.py` | Script s'exécute en CI avec PostgreSQL de test ; données restaurées vérifiées | Test CI vert |
| 4.5 Porter `LOG_RETENTION_DAYS=365` en valeur prod | `.env.example` | Valeur d'exemple 365 avec commentaire ANSSI | Exemple mis à jour |

**Tests à exécuter** :
```bash
bash scripts/backup_postgres.sh
bash scripts/restore_postgres.sh <fichier_backup>
pytest tests/integration/test_backup_restore.py -v
```

---

## Phase 5 — Conformité démontrable et auditabilité

**Objectif** : Produire automatiquement des preuves exploitables pour un audit.

### Tâches

| Tâche | Fichier(s) concerné(s) | Critère d'acceptation | Preuve attendue |
|---|---|---|---|
| 5.1 Script d'inventaire des contrôles | `scripts/compliance/inventory_controls.py` | Rapport JSON listant chaque contrôle avec statut et preuve fichier | Exécutable sans erreur |
| 5.2 Script de vérification des variables | `scripts/compliance/check_env_vars.py` | Vérifie présence et format des variables critiques ; exit code 1 si manquant | Intégrable dans CI |
| 5.3 Rapport de couverture NIS2 | `scripts/compliance/generate_nis2_coverage_report.py` | Rapport HTML/Markdown avec statut par contrôle | Rapport généré automatiquement |
| 5.4 Script de collecte de preuves | `scripts/compliance/collect_evidence.sh` | Archive les fichiers de preuves pour audit : logs, configs, hashes | Archive `.tar.gz` produite |
| 5.5 Générer SBOM | `scripts/compliance/generate_sbom.sh` | SBOM au format SPDX ou CycloneDX ; inclus dans CI | Fichier `sbom.json` produit |
| 5.6 Mettre à jour la matrice de contrôles | `docs/nis2/nis2-control-matrix.csv` | Tous les champs `evidence_files` pointent vers des fichiers existants | CSV vérifié manuellement |

**Tests à exécuter** :
```bash
python scripts/compliance/check_env_vars.py
python scripts/compliance/inventory_controls.py
python scripts/compliance/generate_nis2_coverage_report.py
bash scripts/compliance/collect_evidence.sh
```

---

## Priorisation globale

```
Phase 1 : Baseline         ████████████ IMMÉDIAT  (lacunes critiques)
Phase 2 : Hardening        ████████░░░░ COURT TERME (< 1 mois)
Phase 3 : Détection        ██████░░░░░░ MOYEN TERME (1-3 mois)
Phase 4 : Résilience       ████░░░░░░░░ MOYEN TERME (1-3 mois)
Phase 5 : Auditabilité     ██████████░░ CONTINU    (accompagne chaque phase)
```

## Indicateurs de succès

| Indicateur | Cible | Méthode de mesure |
|---|---|---|
| Couverture tests | ≥ 80% | `pytest --cov-fail-under=80` |
| Zéro vulnérabilité CVSS ≥ 7 | 0 | `pip-audit` en CI |
| Zéro finding SAST HIGH | 0 | `bandit -ll` en CI |
| Contrôles NIS2 "covered" | ≥ 60% | `generate_nis2_coverage_report.py` |
| Rapports persistés en PostgreSQL | 100% | Vérification `analysis_reports` table |
| TLS vérifié sur tous les transports | 100% | Revue manuelle des configs |
