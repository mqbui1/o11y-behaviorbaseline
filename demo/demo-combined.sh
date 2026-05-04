#!/usr/bin/env bash
# demo-combined.sh — Demo 9: Combined structural + metric anomaly
#
# Story: Two things go wrong simultaneously:
#   1. vets-service is killed       → MISSING_SERVICE (structural drift, ~15s)
#   2. DB is killed                 → ERROR_RATE_ANOMALY + NEW_ERROR_SIGNATURE (~30s)
#
# Claude receives all three signal types in one triage window and correlates them:
#   - Structural absence (vets-service gone from traces)
#   - Metric anomaly (DB errors pushing error rate above threshold on customers-service)
#   - New error signatures (DB exceptions never seen before)
# Together: INCIDENT, HIGH confidence — names both mysql:petclinic and vets-service.
#
# This is the "full picture" demo showing all three detection tiers firing together.
#
# Usage:
#   ./demo/demo-combined.sh           # full demo (kill both → triage → restore)
#   ./demo/demo-combined.sh --restore # restore all services

set -eo pipefail

_REPO="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$_REPO/.env" ]; then set -a; source "$_REPO/.env"; set +a; fi

: "${EC2_IP:?EC2_IP not set}"
: "${EC2_PASSWORD:?EC2_PASSWORD not set}"
: "${ENV:?ENV not set}"

K="sshpass -p $EC2_PASSWORD ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@$EC2_IP"

RESTORE=false
for arg in "$@"; do
  case "$arg" in
    --restore) RESTORE=true ;;
  esac
done

# ── Restore mode ──────────────────────────────────────────────────────────────
if [ "$RESTORE" = "true" ]; then
  echo "=== Restoring all services ==="
  $K "kubectl scale deployment vets-service petclinic-db --replicas=1" \
    2>/dev/null | grep -v '▀\|█\|▄' || true
  $K "kubectl rollout status deployment/vets-service petclinic-db --timeout=60s" \
    2>/dev/null | grep -v '▀\|█\|▄' || true
  echo "  Waiting 20s for DB reconnect..."
  sleep 20
  echo "  All services restored."
  exit 0
fi

echo "=== Demo 8: Combined Signal — Structural + Metric Anomaly — env=$ENV ==="
echo ""
echo "  Kill 1 : vets-service      → MISSING_SERVICE (structural, ~15s)"
echo "  Kill 2 : petclinic-db      → ERROR_RATE_ANOMALY + NEW_ERROR_SIGNATURE (~30s)"
echo ""
echo "  Claude will correlate all signals in one triage pass and identify"
echo "  both mysql:petclinic and vets-service as root causes."
echo ""

# ── Step 1: Verify services ───────────────────────────────────────────────────
echo "[1] Verifying services are running..."
$K "kubectl get deployment vets-service petclinic-db customers-service \
    -o custom-columns='NAME:.metadata.name,READY:.status.readyReplicas'" \
  2>/dev/null | grep -v '▀\|█\|▄' || true
echo ""

# ── Step 2: Open live stream reminder ─────────────────────────────────────────
echo "[2] Tip: run this in a second terminal to watch all events fire in real time:"
echo "    python3 -u demo/poll_drift_events.py"
echo ""

# ── Step 3: Kill both simultaneously ─────────────────────────────────────────
echo "[3] Killing vets-service AND petclinic-db simultaneously..."
$K "kubectl scale deployment vets-service --replicas=0 && \
    kubectl scale deployment petclinic-db --replicas=0" \
  2>/dev/null | grep -v '▀\|█\|▄' || true
echo ""
echo "    Both down. Expected timeline:"
echo "      ~10s  : NEW_ERROR_SIGNATURE  — DB exceptions on customers-service"
echo "      ~15s  : MISSING_SERVICE      — vets-service absent from traces"
echo "      ~30s  : ERROR_RATE_ANOMALY   — error rate > 5% on customers-service"
echo ""

# ── Step 4: Triage (collect events for 90s to catch all three signal types) ───
echo "[4] Running triage — collecting events for up to 90s..."
echo "    Using --min-collect-seconds 75 to catch MISSING_SERVICE (~60s) + ERROR_RATE (~30s)"
echo ""
python3 "$_REPO/demo/poll_drift_events.py" \
  --triage \
  --environment "$ENV" \
  --settle-seconds 10 \
  --min-collect-seconds 75 \
  --timeout-seconds 120 \
  | python3 "$_REPO/agent.py" --environment "$ENV"

# ── Step 5: Restore ───────────────────────────────────────────────────────────
echo ""
echo "[5] Restoring services..."
$K "kubectl scale deployment vets-service petclinic-db --replicas=1" \
  2>/dev/null | grep -v '▀\|█\|▄' || true
$K "kubectl rollout status deployment/vets-service petclinic-db --timeout=60s" \
  2>/dev/null | grep -v '▀\|█\|▄' || true
echo "  Waiting 20s for DB reconnect..."
sleep 20
echo ""
echo "=== Demo complete. Run demo-between.sh --db before next demo. ==="
