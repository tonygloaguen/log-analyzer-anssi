# scripts/compliance/ — Outillage de conformité NIS2

Scripts Python et Bash pour collecter, vérifier et documenter les preuves
de conformité NIS2/ANSSI du projet `log-analyzer-anssi`.

## Scripts disponibles

### `check_env_vars.py` — Vérification des variables d'environnement

Vérifie que les variables critiques sont définies, avec longueur minimale et
détection des valeurs non sécurisées (`changeme`, `password`…).

```bash
# Vérifier l'environnement courant
python scripts/compliance/check_env_vars.py

# Vérifier un fichier .env
python scripts/compliance/check_env_vars.py --env-file .env.local

# Vérifier le .env.example (sans valider les valeurs)
python scripts/compliance/check_env_vars.py --env-file .env.example --check-example

# Sortie JSON pour intégration CI
python scripts/compliance/check_env_vars.py --json
```

Contrôles NIS2 : `NIS2-SEC-01`, `NIS2-SEC-02`, `NIS2-SEC-03`, `NIS2-LOG-04`

---

### `inventory_controls.py` — Inventaire des contrôles NIS2

Lit `docs/nis2/nis2-control-matrix.csv` et vérifie que les fichiers de preuve
référencés existent dans le dépôt.

```bash
# Vue complète
python scripts/compliance/inventory_controls.py

# Filtrer par statut
python scripts/compliance/inventory_controls.py --filter covered
python scripts/compliance/inventory_controls.py --filter missing

# Sortie JSON
python scripts/compliance/inventory_controls.py --json
```

---

### `generate_nis2_coverage_report.py` — Rapport de couverture NIS2

Génère un rapport Markdown lisible depuis la matrice de contrôles, avec
barres de progression par domaine et liste des actions prioritaires.

```bash
# Afficher le rapport (stdout)
python scripts/compliance/generate_nis2_coverage_report.py

# Sauvegarder dans un fichier
python scripts/compliance/generate_nis2_coverage_report.py \
    --output docs/nis2/coverage-report.md

# Sortie JSON (scores par domaine)
python scripts/compliance/generate_nis2_coverage_report.py --json
```

---

### `validate_local_config.py` — Validation de la configuration locale

Vérifie que l'environnement local est prêt : fichiers obligatoires, variables,
outils installés, permissions TLS, gitignore.

```bash
# Mode développement
python scripts/compliance/validate_local_config.py

# Mode strict (critères production — LOG_RETENTION_DAYS >= 365)
python scripts/compliance/validate_local_config.py --strict

# Sortie JSON
python scripts/compliance/validate_local_config.py --json
```

---

### `collect_evidence.sh` — Collecte de preuves pour audit

Produit une archive datée contenant les fichiers de configuration, les rapports
de conformité générés, les informations git et un MANIFEST SHA256.

```bash
bash scripts/compliance/collect_evidence.sh
# → /tmp/log-analyzer-evidence-YYYYMMDD-HHMMSS.tar.gz
# → /tmp/log-analyzer-evidence-YYYYMMDD-HHMMSS.tar.gz.sha256

# Répertoire de sortie personnalisé
bash scripts/compliance/collect_evidence.sh /path/to/audit-output
```

---

## Utilisation en CI/CD

Ces scripts sont intégrés dans `.github/workflows/ci.yml` (job `compliance-check`).

Pour une exécution locale similaire à la CI :

```bash
# Vérification .env.example (ne requiert pas de vraie configuration)
python scripts/compliance/check_env_vars.py --env-file .env.example --check-example

# Vérification documentation NIS2
test -f docs/nis2/nis2-control-matrix.csv && echo "OK" || echo "MANQUANT"
test -f docs/nis2/nis2-gap-analysis.md && echo "OK" || echo "MANQUANT"
```

## Références

- Matrice de contrôles : [`docs/nis2/nis2-control-matrix.csv`](../../docs/nis2/nis2-control-matrix.csv)
- Gap analysis : [`docs/nis2/nis2-gap-analysis.md`](../../docs/nis2/nis2-gap-analysis.md)
- Plan d'implémentation : [`docs/nis2/nis2-implementation-plan.md`](../../docs/nis2/nis2-implementation-plan.md)
