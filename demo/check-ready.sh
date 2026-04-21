#!/usr/bin/env bash
# check-ready.sh — Pre-flight check before demos. Verifies everything is healthy.
# Run this once before starting the demo session.
#
# Usage: source .env && ./check-ready.sh

set -eo pipefail

_REPO="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$_REPO/.env" ]; then set -a; source "$_REPO/.env"; set +a; fi

: "${EC2_IP:?EC2_IP not set}"
: "${EC2_PASSWORD:?EC2_PASSWORD not set}"
: "${ENV:?ENV not set}"
: "${SPLUNK_ACCESS_TOKEN:?SPLUNK_ACCESS_TOKEN not set}"

K="sshpass -p $EC2_PASSWORD ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@$EC2_IP"

PASS=0; FAIL=0
ok()   { echo "  ✓  $*"; PASS=$((PASS+1)); }
fail() { echo "  ✗  $*"; FAIL=$((FAIL+1)); }
warn() { echo "  ⚠  $*"; }

echo "=== Pre-flight check: env=$ENV ==="
echo ""

# ── 1. AWS credentials ────────────────────────────────────────────────────────
echo "[1/6] AWS credentials..."
if python3 -c "
import boto3, os
c = boto3.client('sts', region_name='us-west-2')
r = c.get_caller_identity()
print('    ARN:', r['Arn'][:60])
" 2>/dev/null; then
    ok "AWS credentials valid"
else
    fail "AWS credentials expired — run: python3 \$_REPO/refresh_aws_creds.py  (in Claude Code terminal)"
fi

# ── 2. Cluster pods ───────────────────────────────────────────────────────────
echo "[2/6] Cluster pod health..."
_POD_OUT=$($K "kubectl get pods --no-headers 2>/dev/null" 2>/dev/null || true)
NOT_RUNNING=$(echo "$_POD_OUT" | grep -vE 'Running|Completed|^$' | grep -cE '^[a-z]' || true)
FP_PODS=$(echo "$_POD_OUT" | grep 'otelcol-fingerprint' | grep -c Running || true)
if [ "${NOT_RUNNING:-0}" -eq 0 ] 2>/dev/null; then
    ok "All pods Running"
else
    fail "${NOT_RUNNING} pod(s) not in Running state — check: kubectl get pods"
fi
if [ "${FP_PODS:-0}" -eq 3 ] 2>/dev/null; then
    ok "otelcol-fingerprint: 3/3 pods running"
else
    fail "otelcol-fingerprint: only ${FP_PODS:-0}/3 pods running"
fi

# ── 3. Baseline fingerprints (local + cluster ConfigMap) ─────────────────────
echo "[3/6] Baseline..."
FP_COUNT=$(python3 -c "
import json, sys
from pathlib import Path
p = Path(sys.argv[1]) / 'data' / 'baseline.$ENV.json'
if p.exists():
    d = json.loads(p.read_text())
    fps = d.get('fingerprints', {})
    promoted = sum(1 for v in fps.values() if v.get('auto_promoted'))
    print(f'{len(fps)} fingerprints ({promoted} promoted)')
else:
    print('MISSING')
" "$_REPO" 2>/dev/null)
if echo "$FP_COUNT" | grep -q MISSING; then
    fail "Local baseline file missing — run learn + promote"
else
    ok "Local baseline: $FP_COUNT"
fi
# Also verify cluster ConfigMap has the baseline loaded (what OTel processor actually sees)
CM_FP=$($K "kubectl get configmap behavioral-baseline -o jsonpath='{.data.baseline\\.json}' 2>/dev/null | python3 -c \"import json,sys; d=json.loads(sys.stdin.read()); print(len(d.get('fingerprints',{})))\" 2>/dev/null" 2>/dev/null | tr -d ' \n' || echo "0")
if [ "${CM_FP:-0}" -gt 0 ] 2>/dev/null; then
    ok "Cluster ConfigMap baseline: ${CM_FP} fingerprints loaded"
else
    fail "Cluster ConfigMap baseline empty or missing — run demo/demo-reset.sh to push baseline"
fi

# ── 4. Splunk API connectivity ────────────────────────────────────────────────
echo "[4/6] Splunk API connectivity..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-SF-Token: $SPLUNK_ACCESS_TOKEN" \
    "https://api.us1.signalfx.com/v2/organization" 2>/dev/null)
if [ "$HTTP_CODE" = "200" ]; then
    ok "Splunk API reachable (HTTP $HTTP_CODE)"
else
    fail "Splunk API returned HTTP $HTTP_CODE — check SPLUNK_ACCESS_TOKEN"
fi

# ── 5. OTel processor steady state (cluster pod logs, last 30s) ───────────────
echo "[5/6] OTel processor steady state (cluster logs)..."
DRIFT_COUNT=$($K "for p in \$(kubectl get pods -l app=otelcol-fingerprint -o jsonpath='{.items[*].metadata.name}'); do kubectl logs \$p -c otelcol --since=30s 2>/dev/null; done" 2>/dev/null \
    | grep -cE 'trace drift detected|new trace fingerprint|new error signature' || echo "0")
DRIFT_COUNT=$(echo "$DRIFT_COUNT" | tr -d ' \n')
if [ "${DRIFT_COUNT:-0}" -eq 0 ] 2>/dev/null; then
    ok "OTel processor: 0 drift events in last 30s — steady state"
else
    warn "OTel processor: ${DRIFT_COUNT} drift event(s) in last 30s — wait for steady state or run demo-reset.sh"
fi

# ── 6. OTel events in Splunk (last 3m) ───────────────────────────────────────
echo "[6/6] OTel events in Splunk (last 3m)..."
EVENT_COUNT=$(python3 -c "
import urllib.request, urllib.parse, json, time, os
token = os.environ.get('SPLUNK_ACCESS_TOKEN','')
realm = os.environ.get('SPLUNK_REALM','us1')
env   = os.environ.get('ENV','')
now   = int(time.time() * 1000)
start = now - 3 * 60 * 1000
params = urllib.parse.urlencode({
    'query': f'sf_environment:{env} AND (eventType:trace.path.drift OR eventType:error.signature.drift)',
    'startTime': start, 'endTime': now, 'limit': 5,
})
req = urllib.request.Request(
    f'https://api.{realm}.signalfx.com/v2/event?' + params,
    headers={'X-SF-Token': token}
)
with urllib.request.urlopen(req, timeout=10) as r:
    d = json.loads(r.read())
    print(len(d.get('results', [])))
" 2>/dev/null || echo "?")
if [ "$EVENT_COUNT" = "0" ] || [ "$EVENT_COUNT" = "?" ]; then
    ok "No stale OTel events in Splunk"
else
    warn "$EVENT_COUNT OTel event(s) still in 3m window — wait ~3m or they won't affect demos"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -eq 0 ]; then
    echo "    Ready to demo. Start with: demo/demo-reset.sh"
else
    echo "    Fix the failures above before starting."
    exit 1
fi
