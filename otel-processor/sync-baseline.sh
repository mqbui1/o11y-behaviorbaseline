#!/bin/bash
# sync-baseline.sh — push current baseline JSON files into the Kubernetes
# ConfigMap so the collector pods reload them within 60 seconds.
#
# Usage:
#   ./otel-processor/sync-baseline.sh <environment>
#   ./otel-processor/sync-baseline.sh petclinicmbtest
#   ./otel-processor/sync-baseline.sh bdf-7fdc-workshop
#
# Run this after each 'python3 core/trace_fingerprint.py learn' or
# 'python3 core/error_fingerprint.py learn' cycle.

set -euo pipefail

ENVIRONMENT="${1:-}"
if [ -z "$ENVIRONMENT" ]; then
  echo "Usage: $0 <environment>"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="${SCRIPT_DIR}/data"
BASELINE="${DATA_DIR}/baseline.${ENVIRONMENT}.json"
ERROR_BASELINE="${DATA_DIR}/error_baseline.${ENVIRONMENT}.json"

if [ ! -f "$BASELINE" ]; then
  echo "Error: baseline file not found: $BASELINE"
  echo "Run: python3 core/trace_fingerprint.py --environment $ENVIRONMENT learn"
  exit 1
fi

if [ ! -f "$ERROR_BASELINE" ]; then
  echo "Warning: error baseline not found ($ERROR_BASELINE) — creating empty baseline"
  echo '{"signatures":{}}' > "$ERROR_BASELINE"
fi

echo "Syncing baseline for environment: $ENVIRONMENT"
echo "  Trace baseline:  $BASELINE"
echo "  Error baseline:  $ERROR_BASELINE"

kubectl create configmap behavioral-baseline \
  --from-file=baseline.json="$BASELINE" \
  --from-file=error_baseline.json="$ERROR_BASELINE" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Done. Collector pods will reload within 60 seconds."
