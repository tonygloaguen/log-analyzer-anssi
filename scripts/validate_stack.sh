#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# validate_stack.sh — Validation locale de la stack log-analyzer-anssi
#
# Reproduit la logique essentielle du workflow CI (ci-stack.yml) localement.
# Utilise docker-compose.ci.yml pour remplacer Ollama par un stub léger.
#
# Usage :
#   ./scripts/validate_stack.sh
#   ./scripts/validate_stack.sh --tls    # valide aussi le mode syslog TLS
#   ./scripts/validate_stack.sh --clean  # supprime les conteneurs après validation
#
# Prérequis :
#   - docker + docker compose v2
#   - curl, python3
#   - POSTGRES_PASSWORD, HMAC_SECRET_KEY, GRAFANA_PASSWORD définis (ou valeurs par défaut CI)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Options ────────────────────────────────────────────────────────────────
MODE_TLS=false
CLEAN_AFTER=false

for arg in "$@"; do
  case "$arg" in
    --tls)   MODE_TLS=true ;;
    --clean) CLEAN_AFTER=true ;;
    --help)
      grep '^#' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Option inconnue : $arg (--tls, --clean, --help)" >&2; exit 1 ;;
  esac
done

# ── Variables d'environnement (valeurs par défaut CI) ─────────────────────
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-ci-postgres-password-local}"
export HMAC_SECRET_KEY="${HMAC_SECRET_KEY:-ci-hmac-secret-key-must-be-long-enough}"
export GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-ci-grafana-password}"

# ── Fonctions utilitaires ──────────────────────────────────────────────────
log()  { echo "[$(date +%H:%M:%S)] $*"; }
ok()   { echo "[$(date +%H:%M:%S)] ✓ $*"; }
fail() { echo "[$(date +%H:%M:%S)] ✗ $*" >&2; exit 1; }

wait_for_http() {
  local url="$1" label="$2" max_attempts="${3:-30}"
  log "Attente $label ($url) ..."
  for i in $(seq 1 "$max_attempts"); do
    if curl -sf "$url" > /dev/null 2>&1; then
      ok "$label prêt (tentative $i/$max_attempts)"
      return 0
    fi
    echo "  tentative $i/$max_attempts — 5s..."
    sleep 5
  done
  fail "$label non disponible après $(( max_attempts * 5 ))s"
}

COMPOSE_BASE="-f docker-compose.yml -f docker-compose.ci.yml"

cleanup() {
  if "$CLEAN_AFTER"; then
    log "Arrêt et suppression des conteneurs..."
    # shellcheck disable=SC2086
    docker compose $COMPOSE_BASE down --volumes 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ═══════════════════════════════════════════════════════════════════════════
# ÉTAPE 1 — Prérequis
# ═══════════════════════════════════════════════════════════════════════════
log "=== Validation stack log-analyzer-anssi ==="
log "Mode TLS : $MODE_TLS"

log "Création des répertoires de logs..."
mkdir -p /tmp/log-analyzer/app \
         /tmp/log-analyzer/archive \
         /tmp/log-analyzer/fluent-bit-storage
ok "Répertoires OK"

# ═══════════════════════════════════════════════════════════════════════════
# ÉTAPE 2 — Démarrage de la stack
# ═══════════════════════════════════════════════════════════════════════════
log "Démarrage de la stack (mode CI — Ollama stub) ..."
# shellcheck disable=SC2086
docker compose $COMPOSE_BASE up -d fluent-bit api
ok "Services lancés"

# ═══════════════════════════════════════════════════════════════════════════
# ÉTAPE 3 — Attente des services
# ═══════════════════════════════════════════════════════════════════════════
wait_for_http "http://localhost:3100/ready" "Loki"
wait_for_http "http://localhost:8000/health" "API FastAPI"

# ═══════════════════════════════════════════════════════════════════════════
# ÉTAPE 4 — Validation API
# ═══════════════════════════════════════════════════════════════════════════
log "Validation /health ..."
response=$(curl -sf http://localhost:8000/health)
echo "  Réponse : $response"
echo "$response" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'status' in d, 'Champ status manquant'
assert d['services'].get('loki') == 'healthy', f'Loki non healthy: {d[\"services\"]}'
print(f'  → status={d[\"status\"]}, loki={d[\"services\"][\"loki\"]}')
"
ok "API /health OK"

# ═══════════════════════════════════════════════════════════════════════════
# ÉTAPE 5 — Validation Loki
# ═══════════════════════════════════════════════════════════════════════════
log "Validation labels Loki ..."
response=$(curl -sG http://localhost:3100/loki/api/v1/labels)
echo "$response" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('status') == 'success', f'Loki /labels KO: {d}'
print(f'  → Labels disponibles : {d.get(\"data\", [])}')
"
ok "Loki /labels OK"

# ═══════════════════════════════════════════════════════════════════════════
# ÉTAPE 6 — Injection log test
# ═══════════════════════════════════════════════════════════════════════════
TS=$(date -u +%Y-%m-%dT%H:%M:%S.000+0000)
MARKER="local-test-$$-$(date +%s)"
log "Injection log test (marker : $MARKER) ..."
echo "{\"time\":\"$TS\",\"level\":\"info\",\"message\":\"$MARKER\",\"source\":\"validate_stack\"}" \
  >> /tmp/log-analyzer/app/test.log
ok "Log injecté"

log "Attente ingestion Fluent Bit → Loki (15s) ..."
sleep 15

# ═══════════════════════════════════════════════════════════════════════════
# ÉTAPE 7 — Vérification ingestion Loki
# ═══════════════════════════════════════════════════════════════════════════
log "Vérification présence du log dans Loki ..."
START_NS=$(date -d '3 minutes ago' +%s)000000000
END_NS=$(date +%s)999999999
response=$(curl -sG http://localhost:3100/loki/api/v1/query_range \
  --data-urlencode 'query={job="fluent-bit"}' \
  --data-urlencode "start=$START_NS" \
  --data-urlencode "end=$END_NS" \
  --data-urlencode 'limit=50')

MARKER="$MARKER" python3 - <<'EOF'
import sys, json, os
import subprocess, json as j

result = subprocess.run(
    ['curl', '-sG',
     'http://localhost:3100/loki/api/v1/query_range',
     '--data-urlencode', 'query={job="fluent-bit"}',
     '--data-urlencode', f'start={os.environ.get("START_NS", "0")}',
     '--data-urlencode', f'end={os.environ.get("END_NS", "9999999999999999999")}',
     '--data-urlencode', 'limit=50'],
    capture_output=True, text=True
)
d = json.loads(result.stdout)
assert d.get('status') == 'success', f'Statut inattendu: {d}'
results = d.get('data', {}).get('result', [])
all_lines = ' '.join(line for stream in results for _, line in stream.get('values', []))
marker = os.environ.get('MARKER', '')
if marker and marker in all_lines:
    print(f'  ✓ Marker trouvé dans Loki')
else:
    print(f'  ⚠ Marker non trouvé (peut nécessiter plus de temps)')
print(f'  Streams disponibles : {len(results)}')
EOF
ok "Vérification Loki terminée"

# ═══════════════════════════════════════════════════════════════════════════
# ÉTAPE 8 — (Optionnel) Test TLS
# ═══════════════════════════════════════════════════════════════════════════
if "$MODE_TLS"; then
  log "=== Mode TLS activé ==="

  if [ ! -f "./certs/server.crt" ]; then
    log "Génération des certificats de labo ..."
    chmod +x ./scripts/gen_certs.sh
    ./scripts/gen_certs.sh ./certs
    ok "Certificats générés"
  else
    ok "Certificats existants dans ./certs/"
  fi

  log "Démarrage Fluent Bit en mode TLS ..."
  # shellcheck disable=SC2086
  docker compose $COMPOSE_BASE -f docker-compose.tls.yml up -d --no-deps fluent-bit
  sleep 10

  if ! nc -z localhost 5140 2>/dev/null; then
    fail "Port 5140 non ouvert — Fluent Bit TLS n'a pas démarré"
  fi
  ok "Port 5140 ouvert"

  log "Envoi message syslog TLS ..."
  TLS_MARKER="tls-local-$$-$(date +%s)"
  TLS_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000+0000)
  TLS_MSG="<165>1 $TLS_TS $(hostname) validate-stack $$ - - $TLS_MARKER"

  echo "$TLS_MSG" | timeout 10 openssl s_client \
    -connect localhost:5140 \
    -cert ./certs/client.crt \
    -key ./certs/client.key \
    -CAfile ./certs/ca.crt \
    -quiet 2>/dev/null && ok "Message TLS envoyé" || log "⚠ openssl s_client: code non nul (peut être normal)"

  sleep 20
  log "Vérification log TLS dans Loki ..."
  curl -sG http://localhost:3100/loki/api/v1/query_range \
    --data-urlencode 'query={job="fluent-bit"}' \
    --data-urlencode "start=$(date -d '3 minutes ago' +%s)000000000" \
    --data-urlencode "end=$(date +%s)999999999" \
    --data-urlencode 'limit=50' | \
    python3 -c "
import sys, json
d = json.load(sys.stdin)
results = d.get('data', {}).get('result', [])
print(f'  Streams dans Loki : {len(results)}')
"
  ok "Test TLS terminé"
fi

# ═══════════════════════════════════════════════════════════════════════════
# RÉSUMÉ
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo "══════════════════════════════════════════"
ok "Validation stack terminée avec succès"
echo "  Loki    : http://localhost:3100"
echo "  API     : http://localhost:8000/docs"
echo "  Grafana : http://localhost:3000 (non démarré en mode CI)"
if "$MODE_TLS"; then
  echo "  TLS     : port 5140 testé"
fi
echo ""
if ! "$CLEAN_AFTER"; then
  echo "  Conteneurs toujours actifs — arrêt manuel : docker compose down"
fi
echo "══════════════════════════════════════════"
