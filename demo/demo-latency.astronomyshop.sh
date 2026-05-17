#!/usr/bin/env bash
# demo-latency.astronomyshop.sh — Demo 6: LATENCY_ANOMALY (Astronomy Shop)
#
# Story: product-catalog is running normally. The OTel processor learns its
# latency baseline over ~30 traces (~2 min of traffic from the load generator).
# We then inject 3s of network delay into the pod via tc-netem (run from the
# k3d node using nsenter), causing span durations to spike from ~4ms to ~892ms.
# The processor detects a z-score >3 and emits "latency anomaly detected".
# Claude triages: DEGRADED, product-catalog slowdown.
#
# Usage:
#   ./demo/demo-latency.astronomyshop.sh              # full demo (inject → watch → triage)
#   ./demo/demo-latency.astronomyshop.sh --inject     # just start the slowdown
#   ./demo/demo-latency.astronomyshop.sh --stop       # remove tc delay, restore normal latency

set -eo pipefail

_REPO="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$_REPO/.env" ]; then set -a; source "$_REPO/.env"; set +a; fi

: "${EC2_IP:?EC2_IP not set}"
: "${EC2_PASSWORD:?EC2_PASSWORD not set}"
: "${ENV:?ENV not set}"

K="sshpass -p $EC2_PASSWORD ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@$EC2_IP"

TARGET="product-catalog"
DELAY_MS=3000   # 3s added to every network call — easily exceeds 3σ above ~4ms baseline

INJECT=false
STOP=false
for arg in "$@"; do
  case "$arg" in
    --inject) INJECT=true ;;
    --stop)   STOP=true ;;
  esac
done

_get_pod_netns_pid() {
  # Find the host PID of the target pod's main container via cgroup membership.
  # Works on k3d/containerd without requiring crictl on the PATH.
  local pod cid_short
  pod=$($K "kubectl get pods -l app=$TARGET -o jsonpath='{.items[0].metadata.name}'" 2>/dev/null | grep -v '▀\|█\|▄')
  if [ -z "$pod" ]; then echo ""; return; fi
  cid_short=$($K "kubectl get pod $pod -o jsonpath='{.status.containerStatuses[0].containerID}'" 2>/dev/null \
    | grep -v '▀\|█\|▄' | sed 's|containerd://||' | cut -c1-12)
  if [ -z "$cid_short" ]; then echo ""; return; fi
  $K "grep -rl $cid_short /proc/*/cgroup 2>/dev/null | head -1 | grep -oP '(?<=/proc/)\d+'" \
    2>/dev/null | grep -v '▀\|█\|▄' || echo ""
}

_inject_delay() {
  local pid="$1"
  $K "sudo nsenter -t $pid -n -- tc qdisc add dev eth0 root netem delay ${DELAY_MS}ms 2>/dev/null || \
      sudo nsenter -t $pid -n -- tc qdisc change dev eth0 root netem delay ${DELAY_MS}ms 2>/dev/null; \
      echo 'tc netem delay applied'" 2>/dev/null | grep -v '▀\|█\|▄' || true
}

_remove_delay() {
  local pid="$1"
  $K "sudo nsenter -t $pid -n -- tc qdisc del dev eth0 root 2>/dev/null; echo 'tc netem removed'" \
    2>/dev/null | grep -v '▀\|█\|▄' || true
}

# ── Stop mode ─────────────────────────────────────────────────────────────────
if [ "$STOP" = "true" ]; then
  echo "=== Removing latency injection from $TARGET ==="
  PID=$(_get_pod_netns_pid)
  if [ -n "$PID" ]; then
    _remove_delay "$PID"
  else
    echo "  Could not find pod PID — may already be clean."
  fi
  echo "  $TARGET back to normal latency."
  exit 0
fi

echo "=== Demo 6: LATENCY_ANOMALY — env=$ENV ==="
echo ""
echo "  Target service : $TARGET"
echo "  Injected delay : ${DELAY_MS}ms per network call"
echo "  Detection      : z-score > 3σ above learned baseline"
echo ""

# ── Step 1: Verify service is running ─────────────────────────────────────────
echo "[1] Verifying $TARGET is running..."
READY=$($K "kubectl get deployment $TARGET -o jsonpath='{.status.readyReplicas}'" \
  2>/dev/null | grep -v '▀\|█\|▄' || echo "0")
if [ "${READY:-0}" -lt 1 ]; then
  echo "ERROR: $TARGET has 0 ready replicas. Start it first."
  exit 1
fi
echo "    Ready replicas: $READY"
echo ""

# ── Step 2: Learn phase check ─────────────────────────────────────────────────
echo "[2] Learn phase check:"
echo "    The OTel processor needs 30 traces for $TARGET to build a latency baseline."
echo "    With the Astronomy Shop load generator at 10 users, this takes ~2 minutes."
echo "    Current uptime of otelcol-aggregator pods (detection runs here):"
$K "kubectl get pods -l app=otelcol-aggregator -o custom-columns='NAME:.metadata.name,AGE:.metadata.creationTimestamp' 2>/dev/null" \
  2>/dev/null | grep -v '▀\|█\|▄' || true
echo ""
echo "    If pods are <2 min old, wait before injecting."
echo ""

# ── Step 3: Get pod network namespace PID ─────────────────────────────────────
echo "[3] Locating $TARGET pod network namespace..."
NS_PID=$(_get_pod_netns_pid)
if [ -z "$NS_PID" ]; then
  echo "ERROR: Could not get network namespace PID for $TARGET."
  echo "  Ensure the pod is running and /proc/<pid>/cgroup is accessible on the k3d node."
  exit 1
fi
echo "    Network namespace PID: $NS_PID"
echo ""

# ── Step 4: Inject delay ──────────────────────────────────────────────────────
echo "[4] Injecting ${DELAY_MS}ms network delay into $TARGET via tc-netem (sudo nsenter)..."
_inject_delay "$NS_PID"
echo "    Delay active. $TARGET spans will spike from ~4ms baseline to ~892ms."
echo "    Expected: LATENCY_ANOMALY fires within ~10s (z-score >3σ on first affected trace)."
echo ""

if [ "$INJECT" = "true" ]; then
  echo "=== Injection active. Watch for LATENCY_ANOMALY: ==="
  echo "    python3 -u demo/poll_drift_events.py"
  echo ""
  echo "    Then triage:"
  echo "    python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV"
  echo ""
  echo "To stop: ./demo/demo-latency.astronomyshop.sh --stop"
  exit 0
fi

# ── Step 5: Triage ────────────────────────────────────────────────────────────
echo "[5] Running triage — waiting for LATENCY_ANOMALY events..."
echo ""
python3 "$_REPO/demo/poll_drift_events.py" \
  --triage \
  --environment "$ENV" \
  --settle-seconds 5 \
  --timeout-seconds 60 \
  | python3 "$_REPO/agent.py" --environment "$ENV"

# ── Step 6: Remove delay ──────────────────────────────────────────────────────
echo ""
echo "[6] Removing latency injection..."
_remove_delay "$NS_PID"
echo "    $TARGET back to normal latency."
echo ""
echo "=== Demo complete. Run demo-between.sh before next demo. ==="
