#!/bin/bash
# deploy.sh — Build, push/import, and deploy the otelcol-fingerprint DaemonSet.
#
# ── Astronomy Shop (fastest path — full deploy from scratch ~10 min) ──────────
#
#   On EC2 (after app pods are running and load gen is active):
#     cd ~/o11y-behaviorbaseline
#     K3D_CLUSTER=astronomyshop-84f5-cluster \
#       ./otel-processor/deploy.sh astronomyshop-84f5-workshop \
#       --app astronomy-shop --otel-bootstrap
#
#   What this does end-to-end:
#     1. Builds otelcol-fingerprint image + imports into k3d (~3 min)
#     2. Deploys aggregator + DaemonSet with empty baseline
#     3. Patches all 16 astronomy shop app deployments to send traces through
#        otelcol-fingerprint (OTEL_EXPORTER_OTLP_ENDPOINT) and waits for rollout
#     4. Waits 5 min for OTel aggregator bootstrap to learn fingerprints from live traffic
#     5. Pulls merged baseline from both aggregator pods, promotes + pushes to all pods
#   Total: ~10 min, no APM API token required for learning step.
#
#   Re-deploy (image already built, just update config/baseline):
#     K3D_CLUSTER=astronomyshop-84f5-cluster \
#       ./otel-processor/deploy.sh astronomyshop-84f5-workshop \
#       --app astronomy-shop --otel-bootstrap --skip-build
#
# ── Other usage ───────────────────────────────────────────────────────────────
#
#   Local (Mac) — learn + promote only (requires APM API token):
#     python3 core/trace_fingerprint.py --environment <env> learn --bootstrap --window-minutes 30
#     python3 core/trace_fingerprint.py --environment <env> promote
#     sshpass scp -P 2222 data/baseline.<env>.json splunk@<EC2_IP>:/tmp/
#     # Then on EC2: K3D_CLUSTER=<name> ./otel-processor/deploy.sh <environment> --skip-learn
#
#   EC2 / k3d cluster (no local registry):
#     K3D_CLUSTER=<cluster-name> ./otel-processor/deploy.sh <environment>
#
#   Cluster with a local registry:
#     REGISTRY=localhost:9999 ./otel-processor/deploy.sh <environment>
#
#   FAST PATH — no APM API calls, learns directly from live traffic (~6 min):
#     K3D_CLUSTER=<name> ./otel-processor/deploy.sh <environment> --otel-bootstrap
#
# Flags:
#   --skip-learn        Skip the learn/promote step (use existing baseline files)
#   --skip-build        Skip docker build/push (re-deploy config changes only)
#   --otel-bootstrap    Fast path: learn baseline from OTel pods (no APM API needed)
#   --app <name>        App-specific wiring: astronomy-shop | petclinic (default: auto-detect)
#
# What it does:
#   0. Learn + promote baseline from live APM data (unless --skip-learn/--otel-bootstrap)
#   1. Build the collector image; import into k3d (K3D_CLUSTER set) or push to registry
#   2. Seed the behavioral-baseline ConfigMap (delete+create, never apply)
#   3. Create/update the baseline-sync-scripts ConfigMap
#   4. Patch the OTel Operator Instrumentation CR so app pods send traces
#      directly to otelcol-fingerprint; clean up stale direct env vars; restart apps
#   5. Create otelcol-fingerprint ServiceAccount + deploy aggregator StatefulSet
#   6. Apply daemonset.yaml (DaemonSet, collector config, RBAC)
#   7. Restart the DaemonSet so pods pick up all changes
#   8. Inject baseline directly into running pods (DaemonSet + aggregator)
#   9. (--otel-bootstrap only) Wait for OTel bootstrap window, pull baseline from pods

set -euo pipefail

ENVIRONMENT=""
SKIP_LEARN=false
SKIP_BUILD=false
OTEL_BOOTSTRAP=false
APP=""  # astronomy-shop | petclinic | "" (auto-detect)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-learn) SKIP_LEARN=true; shift ;;
    --skip-build) SKIP_BUILD=true; shift ;;
    --otel-bootstrap) OTEL_BOOTSTRAP=true; SKIP_LEARN=true; shift ;;
    --app) APP="$2"; shift 2 ;;
    --*) echo "Unknown flag: $1"; exit 1 ;;
    *) ENVIRONMENT="$1"; shift ;;
  esac
done

# Auto-detect app if not specified
if [ -z "$APP" ]; then
  if kubectl get deployment frontend-proxy &>/dev/null && \
     kubectl get deployment checkout &>/dev/null; then
    APP="astronomy-shop"
  elif kubectl get deployment api-gateway &>/dev/null 2>/dev/null; then
    APP="petclinic"
  fi
fi

if [ -z "$ENVIRONMENT" ]; then
  echo "Usage: $0 <environment> [--skip-learn] [--skip-build]"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="$REPO_DIR/data"
K8S_DIR="$SCRIPT_DIR/k8s"

# For k3d clusters there is no local registry — images are imported directly
# into k3d node containerd via `k3d image import`.  Set REGISTRY=localhost:9999
# only if your cluster actually has a registry running on that port.
REGISTRY="${REGISTRY:-}"
IMAGE="${REGISTRY:+$REGISTRY/}otelcol-fingerprint:latest"
K3D_CLUSTER="${K3D_CLUSTER:-}"   # set to cluster name to use k3d image import

echo "=== otelcol-fingerprint deploy ==="
echo "  Environment    : $ENVIRONMENT"
echo "  Image          : $IMAGE"
echo "  K3D_CLUSTER    : ${K3D_CLUSTER:-(not set — using docker push)}"
echo "  App            : ${APP:-(none / manual)}"
echo "  Skip learn     : $SKIP_LEARN"
echo "  Skip build     : $SKIP_BUILD"
echo "  OTel bootstrap : $OTEL_BOOTSTRAP"
echo ""

# ── Step 0: Learn + promote baseline ──────────────────────────────────────────
BASELINE="$DATA_DIR/baseline.${ENVIRONMENT}.json"
ERROR_BASELINE="$DATA_DIR/error_baseline.${ENVIRONMENT}.json"

if [ "$SKIP_LEARN" = "false" ]; then
  echo "--- Step 0: Learn + promote baseline ---"
  echo "  NOTE: Run this at least 15 min after app pods start — DB query patterns"
  echo "  need warm traffic to stabilize. If you get <15 fingerprints, wait and rerun."
  cd "$REPO_DIR"
  python3 core/trace_fingerprint.py --environment "$ENVIRONMENT" learn --bootstrap --window-minutes 30
  python3 core/trace_fingerprint.py --environment "$ENVIRONMENT" promote
  echo ""
fi

if [ "$OTEL_BOOTSTRAP" = "true" ]; then
  echo "--- Step 0: OTel bootstrap mode — seeding empty baseline ---"
  echo "  The aggregator will learn from live traffic during its 5-min bootstrap window."
  echo "  Step 9 will wait for that window to complete and pull the baseline from pods."
  echo '{"fingerprints":{}}' > "$BASELINE"
  echo '{"signatures":{}}' > "$ERROR_BASELINE"
  echo ""
fi

if [ ! -f "$BASELINE" ]; then
  echo "Error: baseline not found: $BASELINE"
  echo "Options:"
  echo "  1. Run without --skip-learn to learn from APM API"
  echo "  2. Use --otel-bootstrap to learn directly from OTel pods (fast, no API)"
  exit 1
fi
if [ ! -f "$ERROR_BASELINE" ]; then
  echo "Warning: error baseline not found — creating empty baseline"
  echo '{"signatures":{}}' > "$ERROR_BASELINE"
fi

# ── Step 1: Build and push/import image ───────────────────────────────────────
if [ "$SKIP_BUILD" = "false" ]; then
  echo "--- Step 1: Build image ---"
  docker build --no-cache -t "$IMAGE" "$SCRIPT_DIR"
  if [ -n "$K3D_CLUSTER" ]; then
    echo "  Importing into k3d cluster '$K3D_CLUSTER' (no registry needed)..."
    k3d image import "$IMAGE" -c "$K3D_CLUSTER"
    # Patch daemonset.yaml to use the plain image name + Never pull policy
    sed -i.bak \
      -e "s|imagePullPolicy: IfNotPresent|imagePullPolicy: Never|g" \
      "$K8S_DIR/daemonset.yaml"
  elif [ -n "$REGISTRY" ]; then
    docker push "$IMAGE"
  else
    echo "  WARNING: K3D_CLUSTER and REGISTRY are both unset."
    echo "  Image was built but not pushed/imported. Set one of:"
    echo "    K3D_CLUSTER=<name>   for k3d clusters (uses k3d image import)"
    echo "    REGISTRY=<host:port> for clusters with a registry"
    exit 1
  fi
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

# ── Step 4: Route app traces through otelcol-fingerprint ─────────────────────
# Two strategies depending on app type:
#   astronomy-shop: SDK-instrumented, set OTEL_EXPORTER_OTLP_ENDPOINT directly on each deployment
#   petclinic:      operator-injected, patch Instrumentation CR + remove stale direct env vars
echo "--- Step 4: Route app traces through otelcol-fingerprint ---"
FP_GRPC="http://otelcol-fingerprint.default.svc.cluster.local:4317"
FP_HTTP="http://otelcol-fingerprint.default.svc.cluster.local:4318"

if [ "$APP" = "astronomy-shop" ]; then
  # Astronomy Shop uses its own built-in OTel SDK — no operator injection.
  # Set OTEL_EXPORTER_OTLP_ENDPOINT on each app deployment directly.
  ASTRO_DEPLOYMENTS="accounting ad cart checkout currency email fraud-detection frontend frontend-proxy image-provider llm load-generator payment product-catalog product-reviews quote recommendation shipping"
  echo "  Patching ${#ASTRO_DEPLOYMENTS} astronomy shop deployments..."
  for svc in $ASTRO_DEPLOYMENTS; do
    if kubectl get deployment "$svc" &>/dev/null; then
      CURRENT_EP=$(kubectl get deployment "$svc" \
        -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="OTEL_EXPORTER_OTLP_ENDPOINT")].value}' 2>/dev/null || echo "")
      if [ "$CURRENT_EP" != "$FP_GRPC" ]; then
        kubectl set env deployment/"$svc" OTEL_EXPORTER_OTLP_ENDPOINT="$FP_GRPC" 2>/dev/null \
          && echo "    Patched $svc" || echo "    Skipped $svc (error)"
      else
        echo "    $svc already points to otelcol-fingerprint"
      fi
    fi
  done
  echo "  Waiting for all astronomy shop rollouts..."
  for svc in $ASTRO_DEPLOYMENTS; do
    kubectl get deployment "$svc" &>/dev/null && \
      kubectl rollout status deployment/"$svc" --timeout=120s 2>&1 | tail -1 || true
  done

elif [ "$APP" = "petclinic" ] || [ -z "$APP" ]; then
  # PetClinic / default: patch Instrumentation CR, remove stale direct env vars
  INSTR_NAME=$(kubectl get instrumentation -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  if [ -z "$INSTR_NAME" ]; then
    echo "  No Instrumentation CR found — skipping (apps may not be auto-instrumented)"
  else
    CURRENT=$(kubectl get instrumentation "$INSTR_NAME" \
      -o jsonpath='{.spec.exporter.endpoint}' 2>/dev/null || echo "")
    if [ "$CURRENT" != "$FP_GRPC" ]; then
      kubectl patch instrumentation "$INSTR_NAME" --type=merge -p \
        "{\"spec\":{\"exporter\":{\"endpoint\":\"$FP_GRPC\"},\"java\":{\"env\":[{\"name\":\"OTEL_EXPORTER_OTLP_ENDPOINT\",\"value\":\"$FP_HTTP\"}]}}}"
      echo "  Patched '$INSTR_NAME': exporter → otelcol-fingerprint"
    else
      echo "  Instrumentation CR '$INSTR_NAME' already points to otelcol-fingerprint"
    fi
    # Remove stale direct env vars that prevent operator re-injection
    APP_DEPLOYMENTS=$(kubectl get deployments -o jsonpath='{.items[*].metadata.name}' 2>/dev/null \
      | tr ' ' '\n' | grep -vE 'otelcol|splunk|config-server|discovery-server|petclinic-db|petclinic-load' || true)
    if [ -n "$APP_DEPLOYMENTS" ]; then
      NEEDS_RESTART=false
      for svc in $APP_DEPLOYMENTS; do
        HAS_VAR=$(kubectl get deployment "$svc" \
          -o jsonpath='{.spec.template.spec.containers[*].env[*].name}' 2>/dev/null \
          | tr ' ' '\n' | grep -c OTEL_EXPORTER_OTLP_ENDPOINT || true)
        if [ "${HAS_VAR:-0}" -gt 0 ]; then
          kubectl set env deployment/"$svc" OTEL_EXPORTER_OTLP_ENDPOINT- 2>/dev/null || true
          echo "  Removed stale OTEL_EXPORTER_OTLP_ENDPOINT from $svc"
          NEEDS_RESTART=true
        fi
      done
      if [ "$NEEDS_RESTART" = "true" ]; then
        echo "  Restarting app deployments so OTel operator re-injects..."
        for svc in $APP_DEPLOYMENTS; do
          kubectl rollout restart deployment/"$svc" 2>/dev/null || true
        done
      fi
    fi
  fi
fi
echo ""

# ── Step 5: Deploy aggregator StatefulSet (must be ready before DaemonSet) ────
echo "--- Step 5: Deploy aggregator StatefulSet ---"
# The aggregator StatefulSet uses serviceAccountName: otelcol-fingerprint.
# That SA is defined in daemonset.yaml but we need it BEFORE applying aggregator.
# Create it idempotently here so the StatefulSet controller can start pods.
kubectl create serviceaccount otelcol-fingerprint --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "$K8S_DIR/aggregator.yaml"
echo "  Waiting for aggregator pods to be ready..."
kubectl rollout status statefulset/otelcol-aggregator --timeout=120s
echo ""

# ── Step 6: Apply daemonset.yaml ──────────────────────────────────────────────
echo "--- Step 6: Apply DaemonSet manifests ---"
kubectl apply -f "$K8S_DIR/daemonset.yaml"
echo ""

# ── Step 7: Restart DaemonSet ─────────────────────────────────────────────────
echo "--- Step 7: Restart DaemonSet ---"
kubectl rollout restart daemonset/otelcol-fingerprint
kubectl rollout status daemonset/otelcol-fingerprint --timeout=120s
echo ""

# ── Step 8: Inject baseline into all running pods (DaemonSet + aggregator) ────
echo "--- Step 8: Inject baseline into running pods ---"
for pod in $(kubectl get pods -l app=otelcol-fingerprint --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'); do
  echo -n "  [daemonset] $pod: "
  kubectl cp "$BASELINE" "$pod:/baseline/baseline.json" -c otelcol 2>&1 && echo "ok" || echo "skipped (pod not ready)"
done
for pod in $(kubectl get pods -l app=otelcol-aggregator --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'); do
  echo -n "  [aggregator] $pod: "
  kubectl cp "$BASELINE" "$pod:/baseline/baseline.json" -c otelcol 2>&1 && echo "ok" || echo "skipped (pod not ready)"
done
echo ""

# ── Step 9: OTel bootstrap — wait for aggregator bootstrap window, pull baseline ─
if [ "$OTEL_BOOTSTRAP" = "true" ]; then
  echo "--- Step 9: Waiting for OTel aggregator bootstrap window (5 min) ---"
  echo "  Aggregator is learning fingerprints from live traffic..."
  echo "  Make sure app traffic is flowing to otelcol-fingerprint:4317 now."
  echo ""

  # Wait for the bootstrap_learning_window_complete log line (emitted at 5 min)
  BOOTSTRAP_DURATION=300
  ELAPSED=0
  POLL=10
  AGGREGATOR_POD=$(kubectl get pods -l app=otelcol-aggregator -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

  if [ -z "$AGGREGATOR_POD" ]; then
    echo "  WARNING: No aggregator pod found — skipping bootstrap wait"
  else
    while [ $ELAPSED -lt $((BOOTSTRAP_DURATION + 30)) ]; do
      DONE=$(kubectl logs "$AGGREGATOR_POD" -c otelcol 2>/dev/null \
        | grep -c "bootstrap learning window complete" || true)
      if [ "${DONE:-0}" -gt 0 ]; then
        echo "  Bootstrap window complete after ${ELAPSED}s"
        break
      fi
      printf "  Waiting... %ds elapsed\r" "$ELAPSED"
      sleep $POLL
      ELAPSED=$((ELAPSED + POLL))
    done
    echo ""

    # Pull merged baseline from both aggregator pods
    echo "--- Pulling learned baseline from aggregator pods ---"
    MERGED="$DATA_DIR/baseline.${ENVIRONMENT}.otel.json"
    echo '{"fingerprints":{}}' > "$MERGED"
    for pod in $(kubectl get pods -l app=otelcol-aggregator -o jsonpath='{.items[*].metadata.name}'); do
      POD_BASELINE=$(kubectl exec "$pod" -c otelcol -- cat /baseline/baseline.json 2>/dev/null || echo "")
      if [ -n "$POD_BASELINE" ] && echo "$POD_BASELINE" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        # Merge: combine fingerprints from pod into merged file
        echo "$POD_BASELINE" | python3 -c "
import sys, json
pod_data = json.load(sys.stdin)
with open('$MERGED') as f:
    merged = json.load(f)
merged_fps = merged.setdefault('fingerprints', {})
for h, fp in pod_data.get('fingerprints', {}).items():
    if h not in merged_fps:
        merged_fps[h] = fp
    else:
        # Keep the one with higher occurrences
        if fp.get('occurrences', 0) > merged_fps[h].get('occurrences', 0):
            merged_fps[h] = fp
with open('$MERGED', 'w') as f:
    json.dump(merged, f, indent=2)
print(f'  Merged from $pod: {len(pod_data.get(\"fingerprints\",{}))} fps')
"
      else
        echo "  Skipped $pod (no baseline or parse error)"
      fi
    done

    FP_COUNT=$(python3 -c "import json; d=json.load(open('$MERGED')); print(len(d.get('fingerprints',{})))" 2>/dev/null || echo "0")
    echo "  Total merged fingerprints: $FP_COUNT"

    if [ "$FP_COUNT" -gt 0 ]; then
      # Promote all OTel-learned fingerprints (mark auto_promoted + no_missing_service)
      python3 -c "
import json
with open('$MERGED') as f:
    d = json.load(f)
for h, fp in d.get('fingerprints', {}).items():
    fp['auto_promoted'] = True
    fp['no_missing_service'] = True
    if 'promoted_at' not in fp:
        import time
        fp['promoted_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
with open('$BASELINE', 'w') as f:
    json.dump(d, f, indent=2)
print(f'Promoted {len(d[\"fingerprints\"])} OTel-learned fingerprints to $BASELINE')
"
      # Push updated baseline to ConfigMap + all pods
      kubectl delete configmap behavioral-baseline --ignore-not-found
      kubectl create configmap behavioral-baseline \
        --from-file=baseline.json="$BASELINE" \
        --from-file=error_baseline.json="$ERROR_BASELINE"

      echo "  Injecting into all pods..."
      for pod in $(kubectl get pods -l app=otelcol-aggregator --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'); do
        kubectl cp "$BASELINE" "$pod:/baseline/baseline.json" -c otelcol 2>&1 && echo "    [aggregator] $pod: ok" || echo "    [aggregator] $pod: skipped"
      done
      for pod in $(kubectl get pods -l app=otelcol-fingerprint --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'); do
        kubectl cp "$BASELINE" "$pod:/baseline/baseline.json" -c otelcol 2>&1 && echo "    [daemonset] $pod: ok" || echo "    [daemonset] $pod: skipped"
      done
    else
      echo "  WARNING: No fingerprints learned — is traffic flowing to otelcol-fingerprint:4317?"
      echo "  Check: kubectl exec deployment/<app> -- env | grep OTEL_EXPORTER_OTLP_ENDPOINT"
    fi
  fi
  echo ""
fi

echo "=== Deploy complete ==="
echo "  Baseline    : $(python3 -c "import json; d=json.load(open('$BASELINE')); print(len(d.get('fingerprints',{})), 'fingerprints')" 2>/dev/null || echo 'unknown')"
echo "  Topology    : DaemonSet (forwarder) → aggregator StatefulSet (fingerprinter)"
echo "  TraceID routing: consistent hash — all spans for a trace land on the same aggregator pod"
echo "  Detection starts immediately — baseline is active in all pods."
echo "  The baseline-sync sidecar patches the ConfigMap after each auto-promotion."
