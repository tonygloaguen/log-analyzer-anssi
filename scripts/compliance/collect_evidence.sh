#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Collecte de preuves pour audit NIS2 — log-analyzer-anssi
#
# Produit une archive datée contenant :
# - Les fichiers de configuration et de sécurité
# - Les résultats des scripts de conformité
# - La documentation NIS2
# - Le hash SHA256 de chaque fichier inclus
#
# Usage :
#   bash scripts/compliance/collect_evidence.sh
#   bash scripts/compliance/collect_evidence.sh --output /tmp/audit-2026-03
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMESTAMP=$(date -u +"%Y%m%d-%H%M%S")
DEFAULT_OUTPUT="/tmp/log-analyzer-evidence-${TIMESTAMP}"
OUTPUT_DIR="${1:-${DEFAULT_OUTPUT}}"

echo "═══════════════════════════════════════════════════════════════"
echo "COLLECTE DE PREUVES D'AUDIT NIS2 — log-analyzer-anssi"
echo "Date : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "Dépôt : ${REPO_ROOT}"
echo "Sortie : ${OUTPUT_DIR}"
echo "═══════════════════════════════════════════════════════════════"
echo

mkdir -p "${OUTPUT_DIR}/config"
mkdir -p "${OUTPUT_DIR}/docs"
mkdir -p "${OUTPUT_DIR}/scripts"
mkdir -p "${OUTPUT_DIR}/compliance-reports"

# ── 1. Documentation NIS2 ─────────────────────────────────────────────────
echo "→ Copie de la documentation NIS2..."
if [ -d "${REPO_ROOT}/docs/nis2" ]; then
    cp -r "${REPO_ROOT}/docs/nis2" "${OUTPUT_DIR}/docs/"
    echo "  ✓ docs/nis2/"
else
    echo "  ⚠ docs/nis2/ absent"
fi

# ── 2. Fichiers de configuration ──────────────────────────────────────────
echo "→ Copie des fichiers de configuration..."
for f in \
    "docker-compose.yml" \
    "Dockerfile" \
    "requirements.txt" \
    "pytest.ini" \
    ".env.example" \
    "config/fluent-bit.conf" \
    "config/loki-config.yml"; do
    if [ -f "${REPO_ROOT}/${f}" ]; then
        cp "${REPO_ROOT}/${f}" "${OUTPUT_DIR}/config/$(basename "${f}")"
        echo "  ✓ ${f}"
    else
        echo "  ⚠ ${f} absent"
    fi
done

# ── 3. Scripts de sécurité ────────────────────────────────────────────────
echo "→ Copie des scripts de sécurité..."
for f in \
    "scripts/gen_certs.sh" \
    "scripts/init_db.sql"; do
    if [ -f "${REPO_ROOT}/${f}" ]; then
        cp "${REPO_ROOT}/${f}" "${OUTPUT_DIR}/scripts/$(basename "${f}")"
        echo "  ✓ ${f}"
    fi
done

# ── 4. Rapports de conformité ─────────────────────────────────────────────
echo "→ Génération des rapports de conformité..."

if command -v python3 &>/dev/null; then
    # Inventaire des contrôles
    python3 "${REPO_ROOT}/scripts/compliance/inventory_controls.py" \
        > "${OUTPUT_DIR}/compliance-reports/inventory_controls.txt" 2>&1 || true
    echo "  ✓ inventory_controls.txt"

    # Rapport de couverture NIS2
    python3 "${REPO_ROOT}/scripts/compliance/generate_nis2_coverage_report.py" \
        --output "${OUTPUT_DIR}/compliance-reports/nis2-coverage-report.md" 2>/dev/null || true
    echo "  ✓ nis2-coverage-report.md"

    # Vérification config locale
    python3 "${REPO_ROOT}/scripts/compliance/validate_local_config.py" \
        > "${OUTPUT_DIR}/compliance-reports/validate_local_config.txt" 2>&1 || true
    echo "  ✓ validate_local_config.txt"
else
    echo "  ⚠ Python3 non disponible — rapports de conformité ignorés"
fi

# ── 5. Informations git ───────────────────────────────────────────────────
echo "→ Collecte des informations git..."
{
    echo "=== Git Log ==="
    git -C "${REPO_ROOT}" log --oneline -20 2>/dev/null || echo "N/A"
    echo ""
    echo "=== Git Status ==="
    git -C "${REPO_ROOT}" status 2>/dev/null || echo "N/A"
    echo ""
    echo "=== Branche active ==="
    git -C "${REPO_ROOT}" branch --show-current 2>/dev/null || echo "N/A"
} > "${OUTPUT_DIR}/compliance-reports/git-info.txt"
echo "  ✓ git-info.txt"

# ── 6. Manifest avec hashes SHA256 ───────────────────────────────────────
echo "→ Calcul des hashes SHA256..."
MANIFEST="${OUTPUT_DIR}/MANIFEST.sha256"
find "${OUTPUT_DIR}" -type f ! -name "MANIFEST.sha256" | sort | while read -r f; do
    sha256sum "${f}" | sed "s|${OUTPUT_DIR}/||" >> "${MANIFEST}"
done
echo "  ✓ MANIFEST.sha256"

# ── 7. Métadonnées d'audit ────────────────────────────────────────────────
cat > "${OUTPUT_DIR}/AUDIT-METADATA.txt" <<EOF
═══════════════════════════════════════════════════════════════
MÉTADONNÉES DE COLLECTE DE PREUVES
═══════════════════════════════════════════════════════════════
Date de collecte  : $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Système           : $(uname -a)
Utilisateur       : $(whoami)
Dépôt             : ${REPO_ROOT}
Branche git       : $(git -C "${REPO_ROOT}" branch --show-current 2>/dev/null || echo "N/A")
Commit            : $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo "N/A")
─────────────────────────────────────────────────────────────
Objet             : Preuves de conformité NIS2 / ANSSI
Démonstrateur     : log-analyzer-anssi
Référence         : docs/nis2/README.md
═══════════════════════════════════════════════════════════════
EOF

# ── 8. Archive finale ─────────────────────────────────────────────────────
ARCHIVE="${OUTPUT_DIR}.tar.gz"
tar -czf "${ARCHIVE}" -C "$(dirname "${OUTPUT_DIR}")" "$(basename "${OUTPUT_DIR}")"
echo "  ✓ Archive : ${ARCHIVE}"

# Hash de l'archive
sha256sum "${ARCHIVE}" > "${ARCHIVE}.sha256"
echo "  ✓ Hash archive : ${ARCHIVE}.sha256"

echo
echo "═══════════════════════════════════════════════════════════════"
echo "COLLECTE TERMINÉE"
echo "Archive  : ${ARCHIVE}"
echo "Hash     : $(cat "${ARCHIVE}.sha256")"
echo "═══════════════════════════════════════════════════════════════"
