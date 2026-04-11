#!/bin/bash
# deploy.sh — Build, push, and deploy the otelcol-fingerprint DaemonSet.
#
# Usage (run from the repo root on the EC2 host):
#   ./otel-processor/deploy.sh <environment>
#   ./otel-processor/deploy.sh bdf-7fdc-workshop
#
# What it does:
#   1. Build the collector image and push to the local k3d registry
#   2. Seed the behavioral-baseline ConfigMap from current baseline files
#   3. Create/update the baseline-sync-scripts ConfigMap from the sidecar script
#   4. Apply daemonset.yaml (DaemonSet, collector config, RBAC)
#   5. Restart the DaemonSet so pods pick up all changes

set -euo pipefail

ENVIRONMENT="${1:-}"
if [ -z "$ENVIRONMENT" ]; then
  echo "Usage: $0 <environment>"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="$REPO_DIR/data"
K8S_DIR="$SCRIPT_DIR/k8s"

REGISTRY="${REGISTRY:-localhost:9999}"
IMAGE="$REGISTRY/otelcol-fingerprint:latest"

echo "=== otelcol-fingerprint deploy ==="
echo "  Environment : $ENVIRONMENT"
echo "  Registry    : $REGISTRY"
echo "  Image       : $IMAGE"
echo ""

# ── Step 1: Build and push image ──────────────────────────────────────────────
echo "--- Step 1: Build image ---"
docker build -t "$IMAGE" "$SCRIPT_DIR"
docker push "$IMAGE"
echo ""

# ── Step 2: Seed behavioral-baseline ConfigMap ────────────────────────────────
echo "--- Step 2: Seed baseline ConfigMap ---"
BASELINE="$DATA_DIR/baseline.${ENVIRONMENT}.json"
ERROR_BASELINE="$DATA_DIR/error_baseline.${ENVIRONMENT}.json"

if [ ! -f "$BASELINE" ]; then
  echo "Error: baseline not found: $BASELINE"
  echo "Run: python3 core/trace_fingerprint.py --environment $ENVIRONMENT learn"
  exit 1
fi
if [ ! -f "$ERROR_BASELINE" ]; then
  echo "Warning: error baseline not found — creating empty baseline"
  echo '{"signatures":{}}' > "$ERROR_BASELINE"
fi

kubectl create configmap behavioral-baseline \
  --from-file=baseline.json="$BASELINE" \
  --from-file=error_baseline.json="$ERROR_BASELINE" \
  --dry-run=client -o yaml | kubectl apply -f -
echo ""

# ── Step 3: Create baseline-sync-scripts ConfigMap ────────────────────────────
echo "--- Step 3: Create sync-scripts ConfigMap ---"
kubectl create configmap baseline-sync-scripts \
  --from-file=baseline-sync-sidecar.py="$K8S_DIR/baseline-sync-sidecar.py" \
  --dry-run=client -o yaml | kubectl apply -f -
echo ""

# ── Step 4: Apply daemonset.yaml ──────────────────────────────────────────────
echo "--- Step 4: Apply DaemonSet manifests ---"
kubectl apply -f "$K8S_DIR/daemonset.yaml"
echo ""

# ── Step 5: Restart DaemonSet ─────────────────────────────────────────────────
echo "--- Step 5: Restart DaemonSet ---"
kubectl rollout restart daemonset/otelcol-fingerprint
kubectl rollout status daemonset/otelcol-fingerprint --timeout=120s
echo ""

echo "=== Deploy complete ==="
echo "  Pods will load baseline from emptyDir (seeded from ConfigMap at startup)."
echo "  The baseline-sync sidecar will patch the ConfigMap after each auto-promotion."
echo "  All pods reload the updated baseline within baseline_reload_interval (60s)."
