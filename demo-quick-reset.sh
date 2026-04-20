#!/usr/bin/env bash
# demo-quick-reset.sh — Fast local reset between demos (~5 seconds, no cluster ops)
#
# Clears local state so the next demo starts clean:
#   - Wipes error baseline (local + staged to /tmp for next SCP)
#   - Clears OTel dedup state (so same events fire again)
#   - Clears alerts.log
#
# Does NOT: restore services, push to cluster, or verify anomaly count.
# Use demo-reset.sh for a full reset (before first demo or after a messy run).
#
# Usage:
#   source .env && export ENV=mbtest-45a9-workshop
#   ./demo-quick-reset.sh

set -eo pipefail

_REPO="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$_REPO/.env" ]; then
    set -a; source "$_REPO/.env"; set +a
fi

: "${ENV:?ENV not set — export ENV=<your-environment>}"

echo "=== demo-quick-reset.sh: env=$ENV ==="

# ── Step 1: Clear alerts.log ──────────────────────────────────────────────────
echo "[1/3] Clearing alert log..."
cat /dev/null > "$_REPO/data/alerts.log"

# ── Step 2: Wipe error baseline (local only) ──────────────────────────────────
echo "[2/3] Wiping error baseline..."
python3 -c "
import json, pathlib, datetime, os
e = os.environ['ENV']
pathlib.Path('data/error_baseline.' + e + '.json').write_text(
    json.dumps({'signatures':{},'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'environment':e})
)
print(f'  Error baseline wiped (data/error_baseline.{e}.json)')
"

# ── Step 3: Clear dedup state ─────────────────────────────────────────────────
echo "[3/3] Clearing dedup state..."
python3 -c "
import json, pathlib, os
e = os.environ['ENV']
cleared = []
for f in pathlib.Path('data').glob('*dedup*' + e + '*'):
    f.write_text('{}')
    cleared.append(f.name)
print(f'  Cleared: {cleared}')
"

echo ""
echo "=== Quick reset done. Ready for next demo. ==="
echo ""
echo "NOTE: Services are NOT restored and baselines are NOT pushed to cluster."
echo "      If you need a full reset, run: ./demo-reset.sh"
