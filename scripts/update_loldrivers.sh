#!/usr/bin/env bash
# update_loldrivers.sh — Mise à jour hebdomadaire de la base loldrivers.io
#
# Télécharge le catalogue JSON des pilotes vulnérables connus depuis
# loldrivers.io et le stocke dans data/loldrivers_cache.json.
#
# Usage :
#   ./scripts/update_loldrivers.sh [--output-dir <dir>]
#
# Variables d'environnement :
#   LOLDRIVERS_URL    URL source (défaut : API officielle loldrivers.io)
#   LOLDRIVERS_CACHE  Chemin du cache (défaut : data/loldrivers_cache.json)
#   HMAC_SECRET_KEY   Clé HMAC pour signer le cache téléchargé
#
# Cron recommandé (hebdomadaire, dimanche 03:00) :
#   0 3 * * 0 /opt/log-analyzer-anssi/scripts/update_loldrivers.sh >> /var/log/loldrivers-update.log 2>&1
#
# Conformité ANSSI : vérification TLS + signature HMAC du fichier téléchargé.

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

LOLDRIVERS_URL="${LOLDRIVERS_URL:-https://www.loldrivers.io/api/drivers.json}"
LOLDRIVERS_CACHE="${LOLDRIVERS_CACHE:-${REPO_ROOT}/data/loldrivers_cache.json}"
HMAC_SECRET_KEY="${HMAC_SECRET_KEY:-}"

TEMP_FILE="$(mktemp /tmp/loldrivers_XXXXXX.json)"
LOG_TAG="[update_loldrivers]"

# ─── Fonctions ───────────────────────────────────────────────────────────────

log_info()  { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ${LOG_TAG} INFO  $*"; }
log_warn()  { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ${LOG_TAG} WARN  $*" >&2; }
log_error() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ${LOG_TAG} ERROR $*" >&2; }

cleanup() {
    rm -f "${TEMP_FILE}"
}
trap cleanup EXIT

check_dependencies() {
    # Vérifie que curl et jq sont disponibles
    local missing=()
    command -v curl >/dev/null 2>&1 || missing+=("curl")
    command -v jq   >/dev/null 2>&1 || missing+=("jq")
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Dépendances manquantes : ${missing[*]}"
        exit 1
    fi
}

download_loldrivers() {
    log_info "Téléchargement depuis ${LOLDRIVERS_URL}"
    # --fail : erreur si HTTP ≥ 400
    # --tlsv1.2 : TLS 1.2 minimum (ANSSI)
    # --retry 3 : 3 tentatives en cas d'erreur réseau temporaire
    curl \
        --fail \
        --silent \
        --show-error \
        --tlsv1.2 \
        --retry 3 \
        --retry-delay 5 \
        --max-time 120 \
        --output "${TEMP_FILE}" \
        "${LOLDRIVERS_URL}"
    log_info "Téléchargement terminé ($(wc -c < "${TEMP_FILE}") octets)"
}

validate_json() {
    log_info "Validation du JSON téléchargé"
    if ! jq empty "${TEMP_FILE}" 2>/dev/null; then
        log_error "Le fichier téléchargé n'est pas un JSON valide"
        exit 1
    fi
    local driver_count
    driver_count=$(jq 'length' "${TEMP_FILE}" 2>/dev/null || echo 0)
    log_info "${driver_count} pilotes dans la base loldrivers"
    if [[ "${driver_count}" -lt 100 ]]; then
        log_warn "Nombre de pilotes anormalement bas (${driver_count} < 100) — vérifier la source"
    fi
}

sign_cache() {
    # Calcule et stocke la signature HMAC-SHA256 du cache (conformité ANSSI)
    if [[ -z "${HMAC_SECRET_KEY}" ]]; then
        log_warn "HMAC_SECRET_KEY non définie — signature du cache ignorée"
        return
    fi
    local sig
    sig=$(echo -n "${HMAC_SECRET_KEY}" | openssl dgst -sha256 -hmac "${HMAC_SECRET_KEY}" -hex "${TEMP_FILE}" | awk '{print $2}')
    echo "${sig}  loldrivers_cache.json" > "${LOLDRIVERS_CACHE}.hmac"
    log_info "Signature HMAC-SHA256 écrite : ${LOLDRIVERS_CACHE}.hmac"
}

install_cache() {
    local cache_dir
    cache_dir="$(dirname "${LOLDRIVERS_CACHE}")"
    mkdir -p "${cache_dir}"

    # Backup de l'ancien cache si présent
    if [[ -f "${LOLDRIVERS_CACHE}" ]]; then
        cp "${LOLDRIVERS_CACHE}" "${LOLDRIVERS_CACHE}.bak"
        log_info "Ancien cache sauvegardé : ${LOLDRIVERS_CACHE}.bak"
    fi

    mv "${TEMP_FILE}" "${LOLDRIVERS_CACHE}"
    log_info "Cache installé : ${LOLDRIVERS_CACHE}"
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    log_info "=== Début mise à jour loldrivers.io ==="
    check_dependencies
    download_loldrivers
    validate_json
    sign_cache
    install_cache
    log_info "=== Mise à jour terminée avec succès ==="
}

main "$@"
