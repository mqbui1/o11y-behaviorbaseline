#!/usr/bin/env bash
# demo-reset.sh — Full demo reset: restore cluster, clean baselines, verify 0 anomalies
#
# Usage:
#   source .env && export ENV=mbtest-45a9-workshop
#   ./demo-reset.sh
#
# Run this before EACH demo (or between demos) to guarantee a clean slate.
# Takes ~2-3 minutes including wait times.

set -euo pipefail

: "${EC2_IP:?EC2_IP not set — source .env first}"
: "${EC2_PASSWORD:?EC2_PASSWORD not set}"
: "${ENV:?ENV not set — export ENV=<your-environment>}"
: "${SPLUNK_ACCESS_TOKEN:?SPLUNK_ACCESS_TOKEN not set}"

K="sshpass -p $EC2_PASSWORD ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@$EC2_IP"

echo "=== demo-reset.sh: env=$ENV ==="

# ── Step 1: Restore all services ──────────────────────────────────────────────
echo "[1/8] Restoring all services..."
$K "kubectl scale deployment petclinic-db vets-service visits-service customers-service --replicas=1 2>/dev/null; true"
$K "kubectl rollout status deployment/petclinic-db vets-service visits-service --timeout=90s" 2>/dev/null || true

# ── Step 2: Wait for DB reconnect ─────────────────────────────────────────────
echo "[2/8] Waiting 30s for services to reconnect to DB..."
sleep 30

# ── Step 3: Clear alert log ───────────────────────────────────────────────────
echo "[3/8] Clearing alert log..."
cat /dev/null > data/alerts.log

# ── Step 4: Wipe error baseline ───────────────────────────────────────────────
echo "[4/8] Wiping error baseline..."
python3 -c "
import json, pathlib, datetime, os
e = os.environ['ENV']
pathlib.Path(f'data/error_baseline.{e}.json').write_text(
    json.dumps({'signatures':{},'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'environment':e})
)
print(f'  Error baseline wiped (data/error_baseline.{e}.json)')
"

# Push wiped error baseline to cluster so OTel processor resets too
sshpass -p "$EC2_PASSWORD" scp -P 2222 -o StrictHostKeyChecking=no \
  "data/error_baseline.$ENV.json" "splunk@$EC2_IP:/tmp/error_baseline.json" 2>/dev/null
$K "kubectl delete configmap behavioral-baseline --ignore-not-found && \
    kubectl create configmap behavioral-baseline \
      --from-file=baseline.json=/tmp/baseline.json \
      --from-file=error_baseline.json=/tmp/error_baseline.json" 2>/dev/null
# Inject into pods immediately (don't wait for 60s reload)
$K "EB64=\$(base64 -w 0 /tmp/error_baseline.json); \
    for pod in \$(kubectl get pods -l app=otelcol-fingerprint -o jsonpath='{.items[*].metadata.name}'); do \
      kubectl exec \$pod -c otelcol -- sh -c \"echo '\$EB64' | base64 -d > /baseline/error_baseline.json\" 2>/dev/null && echo \"  error_baseline injected: \$pod\"; \
    done" 2>/dev/null || true
echo "  Error baseline pushed to cluster."

# ── Step 5: Clear dedup state ─────────────────────────────────────────────────
echo "[5/8] Clearing dedup state..."
python3 -c "
import json, pathlib, os
e = os.environ['ENV']
cleared = []
for f in pathlib.Path('data').glob(f'*dedup_state*{e}*'):
    f.write_text('{}')
    cleared.append(f.name)
print(f'  Cleared: {cleared}')
"

# ── Step 6: Strip watch-contaminated trace fingerprints ───────────────────────
echo "[6/8] Cleaning trace baseline (removing watch-contaminated entries)..."
python3 -c "
import json, pathlib, os
e = os.environ['ENV']
p = pathlib.Path(f'data/baseline.{e}.json')
if not p.exists():
    print('  No trace baseline found — skipping')
    exit()
d = json.loads(p.read_text())
before = len(d['fingerprints'])
d['fingerprints'] = {h: fp for h, fp in d['fingerprints'].items()
                     if fp.get('watch_hits', 0) == 0 and fp.get('occurrences', fp.get('seen', 0)) >= 2}
p.write_text(json.dumps(d, indent=2))
print(f'  Trace baseline: {before} -> {len(d[\"fingerprints\"])} fingerprints')
"

# ── Step 7: Verify 0 trace anomalies ─────────────────────────────────────────
echo "[7/8] Verifying 0 trace anomalies (Python watch)..."
result=$(python3 core/trace_fingerprint.py --environment "$ENV" watch --window-minutes 5 2>&1)
if echo "$result" | grep -q "All trace paths match baseline"; then
    echo "  0 trace anomalies"
elif echo "$result" | grep -q "0 anomalies"; then
    echo "  0 trace anomalies"
else
    echo "  WARNING: Anomalies detected — may need to wait longer or re-learn baseline"
    echo "$result" | grep "ANOMALY\|anomalies detected" | head -5
fi

# ── Step 8: Verify 0 OTel events ─────────────────────────────────────────────
echo "[8/8] Verifying 0 OTel events in Splunk (last 3m)..."
n=$(python3 watch_otel_events.py --environment "$ENV" --window-minutes 3 --no-dedup 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['anomalies']))" 2>/dev/null || echo "?")
if [ "$n" = "0" ]; then
    echo "  0 OTel events"
elif [ "$n" = "?" ]; then
    echo "  WARNING: Could not check OTel events"
else
    echo "  WARNING: $n OTel event(s) still in window — wait ~3m and re-run if needed"
fi

echo ""
echo "=== Reset complete. Ready for demo. ==="
echo ""
echo "Quick check commands:"
echo "  python3 core/trace_fingerprint.py --environment \$ENV show"
echo "  python3 core/error_fingerprint.py --environment \$ENV show"
echo "  python3 core/trace_fingerprint.py --environment \$ENV watch --window-minutes 5"
