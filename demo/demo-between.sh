#!/usr/bin/env bash
# demo-between.sh — Run between demos to restore cluster + clear state.
#
# Faster than demo-reset.sh: skips the 30s DB wait and Python watch verify
# unless a service was killed in the previous demo.
#
# Usage:
#   ./demo-between.sh           # after Demo 2/3/5 (service killed, no DB)
#   ./demo-between.sh --db      # after Demo 1/4 (DB was killed — waits for reconnect)
#   ./demo-between.sh --quick   # local state only, no cluster ops (same as demo-quick-reset.sh)

set -eo pipefail

_REPO="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$_REPO/.env" ]; then set -a; source "$_REPO/.env"; set +a; fi

: "${EC2_IP:?EC2_IP not set}"
: "${EC2_PASSWORD:?EC2_PASSWORD not set}"
: "${ENV:?ENV not set}"

K="sshpass -p $EC2_PASSWORD ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@$EC2_IP"

DB_WAIT=false
QUICK=false
for arg in "$@"; do
  case "$arg" in
    --db)    DB_WAIT=true ;;
    --quick) QUICK=true ;;
  esac
done

echo "=== demo-between.sh: env=$ENV ==="

# ── Always: clear local state ─────────────────────────────────────────────────
echo "[1] Clearing local state (alerts.log, error baseline, dedup)..."
cat /dev/null > "$_REPO/data/alerts.log"
python3 -c "
import json, pathlib, datetime, os, sys
repo = sys.argv[1]
e = os.environ['ENV']
pathlib.Path(f'{repo}/data/error_baseline.{e}.json').write_text(
    json.dumps({'signatures':{},'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'environment':e}))
cleared = []
for f in pathlib.Path(f'{repo}/data').glob(f'*dedup*{e}*'):
    f.write_text('{}'); cleared.append(f.name)
print(f'  Error baseline wiped. Dedup cleared: {cleared}')
" "$_REPO"

if [ "$QUICK" = "true" ]; then
    echo "=== Quick reset done (local only). ==="
    exit 0
fi

# ── Restore all services ──────────────────────────────────────────────────────
echo "[2] Restoring services to replicas=1..."
$K "kubectl scale deployment petclinic-db vets-service visits-service customers-service --replicas=1 2>/dev/null; true" 2>/dev/null | grep -v '▀\|█\|▄' || true
$K "kubectl rollout status deployment/vets-service visits-service customers-service --timeout=60s 2>/dev/null; true" 2>/dev/null | grep -v '▀\|█\|▄' || true

# ── DB wait (only when DB was killed) ─────────────────────────────────────────
if [ "$DB_WAIT" = "true" ]; then
    echo "[3] Waiting 30s for DB reconnect..."
    $K "kubectl rollout status deployment/petclinic-db --timeout=60s 2>/dev/null; true" 2>/dev/null | grep -v '▀\|█\|▄' || true
    sleep 30
    $K "kubectl exec deployment/petclinic-loadgen-deployment -- curl -s http://api-gateway:82/api/vet/vets --max-time 8 | head -c 50" 2>/dev/null | grep -v '▀\|█\|▄' || true
    echo "  (check above for JSON vets data)"
fi

# ── Inject clean baselines directly into pods (no restart needed) ─────────────
# Processor reloads from disk every 60s (baseline_reload_interval).
# Direct file injection takes effect on the next reload tick — within 60s.
# Sync auto-promoted hashes from cluster first so they're baked in locally.
echo "[4] Syncing + injecting clean baselines into OTel pods..."

# Pull auto-promoted hashes from cluster, merge into local baseline
PROMOTED_JSON=$($K "pod=\$(kubectl get pods -l app=otelcol-fingerprint -o jsonpath='{.items[0].metadata.name}'); kubectl exec \$pod -c otelcol -- cat /baseline/baseline.json 2>/dev/null" 2>/dev/null | grep -v '▀\|█\|▄' || echo "{}")
python3 -c "
import json, sys, os
from pathlib import Path
from datetime import datetime, timezone
repo = sys.argv[1]; e = os.environ['ENV']
local_path = Path(f'{repo}/data/baseline.{e}.json')
if not local_path.exists(): sys.exit(0)
try: otel = json.loads(sys.argv[2])
except Exception: sys.exit(0)
local = json.loads(local_path.read_text())
now = datetime.now(timezone.utc).isoformat()
added = 0
for h, entry in otel.get('fingerprints', {}).items():
    if h not in local['fingerprints'] and entry.get('auto_promoted'):
        local['fingerprints'][h] = {
            'hash': h, 'root_op': entry.get('root_op',''),
            'path': entry.get('path', entry.get('root_op','')),
            'services': entry.get('services',[]),
            'span_count': entry.get('span_count',1), 'edge_count': entry.get('edge_count',0),
            'occurrences': 1, 'watch_hits': 0, 'auto_promoted': True,
            'promoted_at': now, 'first_seen': now,
        }
        added += 1
if added:
    local_path.write_text(json.dumps(local, indent=2))
    print(f'  Synced {added} auto-promoted hash(es) from cluster')
" "$_REPO" "$PROMOTED_JSON"

# Push merged baseline + empty error baseline into all pods
sshpass -p "$EC2_PASSWORD" scp -P 2222 -o StrictHostKeyChecking=no \
  "$_REPO/data/baseline.$ENV.json" "splunk@$EC2_IP:/tmp/baseline.json" 2>/dev/null
sshpass -p "$EC2_PASSWORD" scp -P 2222 -o StrictHostKeyChecking=no \
  "$_REPO/data/error_baseline.$ENV.json" "splunk@$EC2_IP:/tmp/error_baseline.json" 2>/dev/null
$K "BB64=\$(base64 -w 0 /tmp/baseline.json); EB64=\$(base64 -w 0 /tmp/error_baseline.json); \
    for pod in \$(kubectl get pods -l app=otelcol-fingerprint -o jsonpath='{.items[*].metadata.name}'); do \
      kubectl exec \$pod -c otelcol -- sh -c \"echo '\$BB64' | base64 -d > /baseline/baseline.json && echo '\$EB64' | base64 -d > /baseline/error_baseline.json\" 2>/dev/null \
      && echo \"  injected: \$pod\"; \
    done" 2>/dev/null | grep -v '▀\|█\|▄' || true

# ── Re-clear local state ───────────────────────────────────────────────────────
cat /dev/null > "$_REPO/data/alerts.log"
python3 -c "
import json, pathlib, os, sys
repo = sys.argv[1]; e = os.environ['ENV']
for f in pathlib.Path(f'{repo}/data').glob(f'*dedup*{e}*'):
    f.write_text('{}')
" "$_REPO"

# ── Wait for OTel processor to reload baseline (60s interval) ─────────────────
echo "[5] Waiting for OTel processor to reload clean baseline (~15s)..."
sleep 15
DRIFT_COUNT=$($K "for p in \$(kubectl get pods -l app=otelcol-fingerprint -o jsonpath='{.items[*].metadata.name}'); do kubectl logs \$p -c otelcol --since=10s 2>/dev/null; done" 2>/dev/null \
    | grep -cE 'trace drift detected|new trace fingerprint|new error signature' || echo "0")
DRIFT_COUNT=$(echo "$DRIFT_COUNT" | tr -d ' \n')
if [ "${DRIFT_COUNT:-0}" -eq 0 ] 2>/dev/null; then
    echo "  OTel processor: 0 drift events — steady state"
else
    echo "  WARNING: ${DRIFT_COUNT} drift event(s) still firing — wait another 30s before starting next demo"
fi

echo ""
echo "=== Ready for next demo. ==="
