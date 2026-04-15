#!/bin/bash
# deploy.sh — Build, push, and deploy the otelcol-fingerprint DaemonSet.
#
# Usage:
#   Run Steps 0 (learn/promote) locally on your Mac, then Steps 1-7 on EC2.
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
#   4. Patch the splunk-otel-collector-agent relay to forward traces to the
#      fingerprint processor via otlphttp/fingerprint
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

# ── Step 4: Patch splunk-otel-collector-agent relay ───────────────────────────
# Adds otlphttp/fingerprint exporter to the agent's traces pipeline so petclinic
# traces are forwarded to otelcol-fingerprint in addition to Splunk.
# The patch is idempotent — safe to run on every deploy.
echo "--- Step 4: Patch agent relay config ---"
python3 - <<'PYEOF'
import sys, yaml, json

CM = "splunk-otel-collector-otel-agent"
import subprocess

result = subprocess.run(
    ["kubectl", "get", "configmap", CM, "-o", "json"],
    capture_output=True, text=True
)
if result.returncode != 0:
    print(f"  Warning: ConfigMap {CM} not found — skipping relay patch")
    sys.exit(0)

cm = json.loads(result.stdout)
relay_yaml = cm["data"].get("relay", "")
if not relay_yaml:
    print(f"  Warning: no 'relay' key in {CM} — skipping")
    sys.exit(0)

config = yaml.safe_load(relay_yaml)

# Add fingerprint exporter
config.setdefault("exporters", {})["otlphttp/fingerprint"] = {
    "traces_endpoint": "http://otelcol-fingerprint.default.svc.cluster.local:4318/v1/traces"
}

# Add to traces pipeline exporters (idempotent)
traces = config.get("service", {}).get("pipelines", {}).get("traces", {})
exporters = traces.get("exporters", [])
if "otlphttp/fingerprint" not in exporters:
    exporters.append("otlphttp/fingerprint")
    traces["exporters"] = exporters
    print("  Added otlphttp/fingerprint to traces pipeline")
else:
    print("  otlphttp/fingerprint already in traces pipeline")

cm["data"]["relay"] = yaml.dump(config, default_flow_style=False)

patch_result = subprocess.run(
    ["kubectl", "apply", "-f", "-"],
    input=json.dumps(cm),
    capture_output=True, text=True
)
if patch_result.returncode != 0:
    print(f"  Warning: patch failed: {patch_result.stderr}")
else:
    print(f"  Patched {CM}")
    # Restart agent pods to pick up new config
    subprocess.run(["kubectl", "rollout", "restart", "daemonset/splunk-otel-collector-agent"], check=False)
    print("  Restarted splunk-otel-collector-agent")
PYEOF
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
# we write it directly into each pod's emptyDir volume.
echo "--- Step 7: Inject baseline into running pods ---"
# base64 -w 0 disables line-wrapping on Linux; macOS base64 ignores -w
B64=$(base64 -w 0 "$BASELINE" 2>/dev/null || base64 "$BASELINE" | tr -d '\n')
for pod in $(kubectl get pods -l app=otelcol-fingerprint --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'); do
  echo -n "  $pod: "
  kubectl exec "$pod" -c otelcol -- sh -c "echo '$B64' | base64 -d > /baseline/baseline.json && echo ok" 2>&1 || echo "skipped (pod not ready)"
done
echo ""

echo "=== Deploy complete ==="
echo "  Baseline    : $(python3 -c "import json; d=json.load(open('$BASELINE')); print(len(d['fingerprints']), 'fingerprints')" 2>/dev/null || echo 'unknown')"
echo "  Detection starts immediately — baseline is active in all pods."
echo "  The baseline-sync sidecar patches the ConfigMap after each auto-promotion."
