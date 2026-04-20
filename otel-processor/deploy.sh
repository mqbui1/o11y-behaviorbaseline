#!/bin/bash
# deploy.sh — Build, push, and deploy the otelcol-fingerprint DaemonSet.
#
# Usage:
#   Run Steps 0 (learn/promote) locally on your Mac, then Steps 1-6 on EC2.
#   Or run the whole script on EC2 if python3 + Splunk API access is available there.
#
#   Local (Mac) — learn + promote only:
#     python3 core/trace_fingerprint.py --environment <env> learn --window-minutes 30
#     python3 core/trace_fingerprint.py --environment <env> promote
#     sshpass scp -P 2222 data/baseline.<env>.json splunk@<EC2_IP>:/tmp/
#     # Then on EC2: ./otel-processor/deploy.sh <environment> --skip-learn
#
#   EC2 (all steps at once, requires Splunk API access from EC2):
#     ./otel-processor/deploy.sh <environment>
#
# Flags:
#   --skip-learn   Skip the learn/promote step (use existing baseline files)
#   --skip-build   Skip docker build/push (re-deploy config changes only)
#
# What it does:
#   0. Learn + promote baseline from live APM data (unless --skip-learn)
#   1. Build the collector image and push to the local k3d registry
#   2. Seed the behavioral-baseline ConfigMap (delete+create, never apply)
#   3. Create/update the baseline-sync-scripts ConfigMap
#   4. Patch the OTel Operator Instrumentation CR so app pods send traces
#      directly to otelcol-fingerprint (no Helm relay patch needed)
#   5. Apply daemonset.yaml (DaemonSet, collector config, RBAC)
#   6. Restart the DaemonSet so pods pick up all changes
#   7. Inject baseline directly into running pods (no need to wait 60s reload)

set -euo pipefail

ENVIRONMENT=""
SKIP_LEARN=false
SKIP_BUILD=false

for arg in "$@"; do
  case "$arg" in
    --skip-learn) SKIP_LEARN=true ;;
    --skip-build) SKIP_BUILD=true ;;
    --*) echo "Unknown flag: $arg"; exit 1 ;;
    *) ENVIRONMENT="$arg" ;;
  esac
done

if [ -z "$ENVIRONMENT" ]; then
  echo "Usage: $0 <environment> [--skip-learn] [--skip-build]"
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
echo "  Skip learn  : $SKIP_LEARN"
echo "  Skip build  : $SKIP_BUILD"
echo ""

# ── Step 0: Learn + promote baseline ──────────────────────────────────────────
BASELINE="$DATA_DIR/baseline.${ENVIRONMENT}.json"
ERROR_BASELINE="$DATA_DIR/error_baseline.${ENVIRONMENT}.json"

if [ "$SKIP_LEARN" = "false" ]; then
  echo "--- Step 0: Learn + promote baseline ---"
  cd "$REPO_DIR"
  python3 core/trace_fingerprint.py --environment "$ENVIRONMENT" learn --window-minutes 30
  python3 core/trace_fingerprint.py --environment "$ENVIRONMENT" promote
  echo ""
fi

if [ ! -f "$BASELINE" ]; then
  echo "Error: baseline not found: $BASELINE"
  echo "Run without --skip-learn, or: python3 core/trace_fingerprint.py --environment $ENVIRONMENT learn"
  exit 1
fi
if [ ! -f "$ERROR_BASELINE" ]; then
  echo "Warning: error baseline not found — creating empty baseline"
  echo '{"signatures":{}}' > "$ERROR_BASELINE"
fi

# ── Step 1: Build and push image ──────────────────────────────────────────────
if [ "$SKIP_BUILD" = "false" ]; then
  echo "--- Step 1: Build image ---"
  docker build -t "$IMAGE" "$SCRIPT_DIR"
  docker push "$IMAGE"
  echo ""
else
  echo "--- Step 1: Skipping build ---"
  echo ""
fi

# ── Step 2: Seed behavioral-baseline ConfigMap ────────────────────────────────
# IMPORTANT: always use delete+create, never kubectl apply — apply silently
# uses the last-applied-configuration annotation and ignores the new data.
echo "--- Step 2: Seed baseline ConfigMap ---"
kubectl delete configmap behavioral-baseline --ignore-not-found
kubectl create configmap behavioral-baseline \
  --from-file=baseline.json="$BASELINE" \
  --from-file=error_baseline.json="$ERROR_BASELINE"
echo ""

# ── Step 3: Create baseline-sync-scripts ConfigMap ────────────────────────────
echo "--- Step 3: Create sync-scripts ConfigMap ---"
kubectl delete configmap baseline-sync-scripts --ignore-not-found
kubectl create configmap baseline-sync-scripts \
  --from-file=baseline-sync-sidecar.py="$K8S_DIR/baseline-sync-sidecar.py"
echo ""

# ── Step 4: Point Instrumentation CR at otelcol-fingerprint ──────────────────
# The OTel Operator's Instrumentation CR controls where auto-instrumented app
# pods send their traces. We patch it to point at otelcol-fingerprint directly,
# so traces go: app → otelcol-fingerprint (fingerprint+forward) → Splunk APM.
# This replaces the old approach of patching the Helm relay ConfigMap.
# Idempotent — safe to run on every deploy.
echo "--- Step 4: Patch Instrumentation CR ---"
INSTR_NAME=$(kubectl get instrumentation -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -z "$INSTR_NAME" ]; then
  echo "  No Instrumentation CR found — skipping (apps may not be auto-instrumented)"
else
  FP_GRPC="http://otelcol-fingerprint.default.svc.cluster.local:4317"
  FP_HTTP="http://otelcol-fingerprint.default.svc.cluster.local:4318"
  CURRENT=$(kubectl get instrumentation "$INSTR_NAME" \
    -o jsonpath='{.spec.exporter.endpoint}' 2>/dev/null || echo "")
  if [ "$CURRENT" = "$FP_GRPC" ]; then
    echo "  Instrumentation CR '$INSTR_NAME' already points to otelcol-fingerprint — skipping"
  else
    kubectl patch instrumentation "$INSTR_NAME" --type=merge -p \
      "{\"spec\":{\"exporter\":{\"endpoint\":\"$FP_GRPC\"},\"java\":{\"env\":[{\"name\":\"OTEL_EXPORTER_OTLP_ENDPOINT\",\"value\":\"$FP_HTTP\"}]}}}"
    echo "  Patched '$INSTR_NAME': exporter → otelcol-fingerprint"
    echo "  NOTE: restart app deployments to pick up the new endpoint:"
    echo "    kubectl rollout restart deployment/<your-app-deployments>"
  fi
fi
echo ""

# ── Step 5: Apply daemonset.yaml ──────────────────────────────────────────────
echo "--- Step 5: Apply DaemonSet manifests ---"
kubectl apply -f "$K8S_DIR/daemonset.yaml"
echo ""

# ── Step 6: Restart DaemonSet ─────────────────────────────────────────────────
echo "--- Step 6: Restart DaemonSet ---"
kubectl rollout restart daemonset/otelcol-fingerprint
kubectl rollout status daemonset/otelcol-fingerprint --timeout=120s
echo ""

# ── Step 7: Inject baseline directly into running pods ────────────────────────
# The init container seeds /baseline from the ConfigMap at pod start. But since
# we want the baseline active immediately (not after the next 60s reload cycle),
# we write it directly into each pod's emptyDir volume via kubectl cp.
# kubectl cp works reliably on both Linux and macOS (no base64 line-wrap issues).
echo "--- Step 7: Inject baseline into running pods ---"
for pod in $(kubectl get pods -l app=otelcol-fingerprint --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'); do
  echo -n "  $pod: "
  kubectl cp "$BASELINE" "$pod:/baseline/baseline.json" -c otelcol 2>&1 && echo "ok" || echo "skipped (pod not ready)"
done
echo ""

echo "=== Deploy complete ==="
echo "  Baseline    : $(python3 -c "import json; d=json.load(open('$BASELINE')); print(len(d['fingerprints']), 'fingerprints')" 2>/dev/null || echo 'unknown')"
echo "  Detection starts immediately — baseline is active in all pods."
echo "  The baseline-sync sidecar patches the ConfigMap after each auto-promotion."
