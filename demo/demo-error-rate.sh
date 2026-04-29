#!/usr/bin/env bash
# demo-error-rate.sh — Demo 8: ERROR_RATE_ANOMALY
#
# Story: The DB is taken down briefly, causing customers-service to throw
# CannotCreateTransactionException on every DB call. After 10+ error spans
# accumulate (MinErrorRateSamples), the OTel processor detects error rate
# above 5% threshold and emits "error rate anomaly detected" — faster and
# more targeted than waiting for APM metric thresholds to fire.
#
# Note: this demo also produces NEW_ERROR_SIGNATURE events (first occurrence
# of DB exception). ERROR_RATE_ANOMALY is the *metric* signal — it shows that
# even if the error was seen before, the *rate* of it is now anomalous.
#
# Usage:
#   ./demo/demo-error-rate.sh          # kill DB → watch → auto-restore after 90s
#   ./demo/demo-error-rate.sh --keep   # kill DB and leave it down (manual restore)
#   ./demo/demo-error-rate.sh --restore # restore DB only

set -eo pipefail

_REPO="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$_REPO/.env" ]; then set -a; source "$_REPO/.env"; set +a; fi

: "${EC2_IP:?EC2_IP not set}"
: "${EC2_PASSWORD:?EC2_PASSWORD not set}"
: "${ENV:?ENV not set}"

K="sshpass -p $EC2_PASSWORD ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@$EC2_IP"

KEEP=false
RESTORE=false
for arg in "$@"; do
  case "$arg" in
    --keep)    KEEP=true ;;
    --restore) RESTORE=true ;;
  esac
done

# ── Restore mode ──────────────────────────────────────────────────────────────
if [ "$RESTORE" = "true" ]; then
  echo "=== Restoring petclinic-db ==="
  $K "kubectl scale deployment petclinic-db --replicas=1" \
    2>/dev/null | grep -v '▀\|█\|▄' || true
  $K "kubectl rollout status deployment/petclinic-db --timeout=60s" \
    2>/dev/null | grep -v '▀\|█\|▄' || true
  echo "  DB restored. Waiting 15s for services to reconnect..."
  sleep 15
  echo "  Done."
  exit 0
fi

echo "=== Demo 8: ERROR_RATE_ANOMALY — env=$ENV ==="
echo ""
echo "  Method : Kill petclinic-db → customers-service errors on every DB call"
echo "  Signal : ERROR_RATE_ANOMALY fires when error rate > 5% over 10+ samples"
echo "  Also   : NEW_ERROR_SIGNATURE fires on first occurrence (no threshold)"
echo ""

# ── Step 1: Verify DB and customers-service are running ───────────────────────
echo "[1] Verifying services are running..."
$K "kubectl get deployment petclinic-db customers-service \
    -o custom-columns='NAME:.metadata.name,READY:.status.readyReplicas'" \
  2>/dev/null | grep -v '▀\|█\|▄' || true
echo ""

# ── Step 2: Start watching in background reminder ─────────────────────────────
echo "[2] Tip: run this in a second terminal to see events as they fire:"
echo "    python3 -u demo/poll_drift_events.py"
echo ""

# ── Step 3: Kill the DB ────────────────────────────────────────────────────────
echo "[3] Killing petclinic-db..."
$K "kubectl scale deployment petclinic-db --replicas=0" \
  2>/dev/null | grep -v '▀\|█\|▄' || true
echo "    DB down. customers-service will start throwing DB errors within ~5s."
echo ""
echo "    Expected signals (in order):"
echo "      ~10s  : NEW_ERROR_SIGNATURE  — first CannotCreateTransactionException"
echo "      ~30s  : ERROR_RATE_ANOMALY   — error rate > 5% over 10+ error samples"
echo ""

if [ "$KEEP" = "true" ]; then
  echo "=== DB left down (--keep). To restore: ./demo/demo-error-rate.sh --restore ==="
  echo ""
  echo "Watch for anomalies:"
  echo "  python3 -u demo/poll_drift_events.py"
  echo ""
  echo "Run triage:"
  echo "  python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV"
  exit 0
fi

# ── Step 4: Wait for ERROR_RATE_ANOMALY then auto-restore ─────────────────────
echo "[4] Waiting 90s for error accumulation, then auto-restoring DB..."
echo "    Watch the live stream terminal for events."
echo ""

# Wait in chunks and show countdown
for i in 9 8 7 6 5 4 3 2 1; do
  echo "    ${i}0s remaining..."
  sleep 10
done
echo ""

echo "[5] Restoring petclinic-db..."
$K "kubectl scale deployment petclinic-db --replicas=1" \
  2>/dev/null | grep -v '▀\|█\|▄' || true
$K "kubectl rollout status deployment/petclinic-db --timeout=60s" \
  2>/dev/null | grep -v '▀\|█\|▄' || true
echo "    DB restored. Waiting 20s for services to reconnect..."
sleep 20
echo ""

echo "[6] Running triage from OTel events (--triage mode)..."
echo ""
python3 "$_REPO/demo/poll_drift_events.py" --triage --environment "$ENV" \
  | python3 "$_REPO/agent.py" --environment "$ENV"
