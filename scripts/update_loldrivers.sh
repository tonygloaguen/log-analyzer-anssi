#!/bin/bash
# update_loldrivers.sh — Mise à jour hebdomadaire de la base loldrivers.io
#
# Cron recommandé (dimanche 03:00) :
#   0 3 * * 0 /opt/log-analyzer-anssi/scripts/update_loldrivers.sh >> /var/log/loldrivers-update.log 2>&1
#
# Variables d'environnement :
#   LOLDRIVERS_URL    URL source (défaut : API officielle loldrivers.io)
#   LOLDRIVERS_CACHE  Chemin du cache (défaut : data/loldrivers_cache.json)
#   HMAC_SECRET       Clé HMAC pour signer le cache (optionnel)

set -euo pipefail

URL="${LOLDRIVERS_URL:-https://www.loldrivers.io/api/drivers.json}"
DEST="${LOLDRIVERS_CACHE:-$(dirname "$0")/../data/loldrivers_cache.json}"
TMP=$(mktemp)

# Nettoyage automatique du fichier temporaire
trap 'rm -f "$TMP"' EXIT

# Téléchargement avec TLS 1.2 minimum, timeout 30s
curl -fsSL --tlsv1.2 --max-time 30 --retry 3 --retry-delay 5 "$URL" -o "$TMP"

# Validation JSON basique
python3 -c "import json,sys; data=json.load(open('$TMP')); print(f'{len(data)} drivers loaded')" || {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Validation JSON échouée — abandon" >&2
    exit 1
}

# Création du répertoire destination si nécessaire
mkdir -p "$(dirname "$DEST")"

# Backup de l'ancien cache
if [ -f "$DEST" ]; then
    cp "$DEST" "${DEST}.bak"
fi

mv "$TMP" "$DEST"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] LOLDrivers updated: $(wc -c < "$DEST") bytes → $DEST"

# Signature HMAC optionnelle (si HMAC_SECRET défini)
if [ -n "${HMAC_SECRET:-}" ] && command -v openssl >/dev/null 2>&1; then
    SIG=$(openssl dgst -sha256 -hmac "$HMAC_SECRET" "$DEST" | awk '{print $2}')
    echo "${SIG}  loldrivers_cache.json" > "${DEST}.hmac"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Signature HMAC écrite : ${DEST}.hmac"
fi
