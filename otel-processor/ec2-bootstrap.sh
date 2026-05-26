#!/bin/bash
# ec2-bootstrap.sh — Full one-command deploy of Astronomy Shop + otelcol-fingerprint
# from your Mac to a fresh workshop EC2.
#
# Usage:
#   ./otel-processor/ec2-bootstrap.sh <ec2-ip> \
#     --ingest-token <token> \
#     --api-token <token> \
#     [--realm us1] \
#     [--port 2222] \
#     [--password Sp1unkH00di3] \
#     [--env <override-env-name>]
#
# What it does end-to-end (~10 min):
#   1. Validates ingest + API tokens (fail fast)
#   2. Detects k3d cluster name + registry from EC2
#   3. SCPs repo (tar, ~400KB, excludes videos/data)
#   4. Creates all K8s secrets correctly
#   5. Adds helm repos + installs Astronomy Shop
#   6. Builds + pushes otelcol-fingerprint image to registry
#   7. Patches aggregator.yaml + daemonset.yaml for registry pull policy
#   8. Deploys aggregator StatefulSet + DaemonSet (seeds empty ConfigMap)
#   9. Waits for OTel bootstrap window (5 min) — does NOT wipe aggregator pods
#  10. Merges baseline from aggregator pods, pushes to all pods + ConfigMap
#  11. Updates local .env + data/ with new env name + baseline
#
# Requirements on Mac: sshpass, ssh, scp, tar, curl, python3
# Requirements on EC2: docker, k3d, kubectl, helm (all pre-installed on workshop EC2s)

set -euo pipefail

# ── Parse args ────────────────────────────────────────────────────────────────
EC2_IP=""
INGEST_TOKEN=""
API_TOKEN=""
REALM="us1"
EC2_PORT="2222"
EC2_PASS="Sp1unkH00di3"
ENV_OVERRIDE=""

usage() {
  grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \?//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ingest-token) INGEST_TOKEN="$2"; shift 2 ;;
    --api-token)    API_TOKEN="$2";    shift 2 ;;
    --realm)        REALM="$2";        shift 2 ;;
    --port)         EC2_PORT="$2";     shift 2 ;;
    --password)     EC2_PASS="$2";     shift 2 ;;
    --env)          ENV_OVERRIDE="$2"; shift 2 ;;
    --help|-h)      usage ;;
    --*)            echo "Unknown flag: $1"; usage ;;
    *)              EC2_IP="$1"; shift ;;
  esac
done

if [[ -z "$EC2_IP" || -z "$INGEST_TOKEN" || -z "$API_TOKEN" ]]; then
  echo "ERROR: ec2-ip, --ingest-token, and --api-token are required"
  usage
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SSH_OPTS="-p $EC2_PORT -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ConnectTimeout=10"
SSH="sshpass -p $EC2_PASS ssh $SSH_OPTS splunk@$EC2_IP"
SCP="sshpass -p $EC2_PASS scp $SSH_OPTS"

log()  { echo "[$(date +%H:%M:%S)] $*"; }
ok()   { echo "[$(date +%H:%M:%S)] ✓ $*"; }
fail() { echo "[$(date +%H:%M:%S)] ✗ $*" >&2; exit 1; }

# ── Step 1: Validate tokens ───────────────────────────────────────────────────
log "Step 1: Validating tokens against realm=$REALM..."

INGEST_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "https://ingest.${REALM}.signalfx.com/v2/event" \
  -H "X-SF-Token: $INGEST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[]' 2>/dev/null || echo "000")
if [[ "$INGEST_STATUS" != "200" ]]; then
  fail "Ingest token rejected (HTTP $INGEST_STATUS). Check --ingest-token and --realm."
fi
ok "Ingest token valid"

API_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  "https://api.${REALM}.signalfx.com/v2/organization" \
  -H "X-SF-Token: $API_TOKEN" 2>/dev/null || echo "000")
if [[ "$API_STATUS" != "200" ]]; then
  fail "API token rejected (HTTP $API_STATUS). Check --api-token and --realm."
fi
ok "API token valid"

# ── Step 2: Detect cluster name + registry on EC2 ────────────────────────────
log "Step 2: Detecting k3d cluster + registry on EC2..."

CLUSTER_NAME=$($SSH 'k3d cluster list --no-headers 2>/dev/null | head -1 | awk "{print \$1}"' 2>/dev/null || echo "")
[[ -z "$CLUSTER_NAME" ]] && fail "No k3d cluster found on EC2. Create one first with: k3d cluster create <name> --agents 2"
ok "k3d cluster: $CLUSTER_NAME"

# Derive env name from cluster name (replace -cluster suffix with -workshop)
if [[ -n "$ENV_OVERRIDE" ]]; then
  ENV_NAME="$ENV_OVERRIDE"
else
  ENV_NAME="${CLUSTER_NAME/-cluster/-workshop}"
fi
ok "Environment name: $ENV_NAME"

# Detect registry: check if localhost:9999 responds
REGISTRY_OK=$($SSH 'curl -s -o /dev/null -w "%{http_code}" http://localhost:9999/v2/_catalog 2>/dev/null || echo "000"')
if [[ "$REGISTRY_OK" == "200" ]]; then
  REGISTRY="localhost:9999"
  IMAGE="localhost:9999/otelcol-fingerprint:latest"
  IMAGE_PULL_POLICY="IfNotPresent"
  ok "Registry detected at localhost:9999"
else
  # Fall back to k3d image import
  REGISTRY=""
  IMAGE="otelcol-fingerprint:latest"
  IMAGE_PULL_POLICY="Never"
  ok "No registry — will use k3d image import"
fi

# ── Step 3: SCP repo to EC2 ───────────────────────────────────────────────────
log "Step 3: Packaging and transferring repo to EC2..."

ARCHIVE=$(mktemp /tmp/o11y-repo-XXXX.tar.gz)
tar czf "$ARCHIVE" \
  --exclude='.git' \
  --exclude='data' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.env' \
  --exclude='agents' \
  --exclude='node_modules' \
  --exclude='*.mp4' \
  --exclude='*.pptx' \
  -C "$REPO_DIR" . 2>/dev/null
ARCHIVE_SIZE=$(du -sh "$ARCHIVE" | cut -f1)
ok "Archive: $ARCHIVE_SIZE"

$SCP "$ARCHIVE" "splunk@$EC2_IP:/tmp/o11y-repo.tar.gz"
$SSH "mkdir -p ~/o11y-behaviorbaseline && tar xzf /tmp/o11y-repo.tar.gz -C ~/o11y-behaviorbaseline 2>/dev/null; rm /tmp/o11y-repo.tar.gz"
rm -f "$ARCHIVE"
ok "Repo transferred"

# Write .env on EC2
$SSH "cat > ~/o11y-behaviorbaseline/.env << 'EOF'
SPLUNK_ACCESS_TOKEN=${API_TOKEN}
SPLUNK_INGEST_TOKEN=${INGEST_TOKEN}
SPLUNK_REALM=${REALM}
ENV=${ENV_NAME}
EC2_IP=${EC2_IP}
EC2_PASSWORD=${EC2_PASS}
K3D_CLUSTER=${CLUSTER_NAME}
EOF"
ok ".env written on EC2"

# ── Step 4: Create K8s secrets ────────────────────────────────────────────────
log "Step 4: Creating K8s secrets..."

$SSH "
kubectl create secret generic workshop-secret \
  --from-literal=env=${ENV_NAME} \
  --from-literal=access_token=${INGEST_TOKEN} \
  --from-literal=api_token=${API_TOKEN} \
  --dry-run=client -o yaml | kubectl apply -f -

# splunk-otel-collector secret: MUST use INGEST token (processor uses this for /v2/event calls)
kubectl create secret generic splunk-otel-collector \
  --from-literal=splunk_observability_access_token=${INGEST_TOKEN} \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic splunk-api-token \
  --from-literal=token=${API_TOKEN} \
  --dry-run=client -o yaml | kubectl apply -f -
"
ok "K8s secrets created (ingest token on splunk-otel-collector)"

# ── Step 5: Add helm repos + install Astronomy Shop ──────────────────────────
log "Step 5: Installing Astronomy Shop via Helm..."

$SSH "
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts 2>/dev/null || true
helm repo update >/dev/null 2>&1

if helm list | grep -q '^astronomy-shop'; then
  echo '  astronomy-shop already installed — skipping helm install'
else
  helm install astronomy-shop open-telemetry/opentelemetry-demo \
    --version 0.40.8 \
    -f ~/o11y-behaviorbaseline/otel-processor/k8s/astro-values.yaml \
    --timeout 10m \
    --wait 2>&1 | grep -v 'Warning:' | tail -5
  echo '  helm install complete'
fi
"
ok "Astronomy Shop installed"

# ── Step 6: Build + push/import otelcol-fingerprint image ────────────────────
log "Step 6: Building otelcol-fingerprint image on EC2..."

if [[ -n "$REGISTRY" ]]; then
  $SSH "
cd ~/o11y-behaviorbaseline/otel-processor
docker build --no-cache -t ${IMAGE} . 2>&1 | tail -5
docker push ${IMAGE}
echo 'image pushed to registry'
"
else
  $SSH "
cd ~/o11y-behaviorbaseline/otel-processor
docker build --no-cache -t ${IMAGE} . 2>&1 | tail -5
k3d image import ${IMAGE} -c ${CLUSTER_NAME}
echo 'image imported into k3d'
"
fi
ok "Image ready: $IMAGE"

# ── Step 7: Patch aggregator.yaml + daemonset.yaml for correct image/pull ─────
log "Step 7: Patching k8s manifests for image=$IMAGE pull=$IMAGE_PULL_POLICY..."

$SSH "
# Patch both manifests to use the correct image name + pull policy
for f in ~/o11y-behaviorbaseline/otel-processor/k8s/aggregator.yaml \
          ~/o11y-behaviorbaseline/otel-processor/k8s/daemonset.yaml; do
  # Replace any existing image ref for otelcol-fingerprint
  sed -i 's|image: .*otelcol-fingerprint.*|image: ${IMAGE}|g' \$f
  # Replace pull policy
  sed -i 's|imagePullPolicy: Never|imagePullPolicy: ${IMAGE_PULL_POLICY}|g' \$f
  sed -i 's|imagePullPolicy: IfNotPresent|imagePullPolicy: ${IMAGE_PULL_POLICY}|g' \$f
  sed -i 's|imagePullPolicy: Always|imagePullPolicy: ${IMAGE_PULL_POLICY}|g' \$f
done

# Patch realm-specific URLs in manifests
for f in ~/o11y-behaviorbaseline/otel-processor/k8s/aggregator.yaml \
          ~/o11y-behaviorbaseline/otel-processor/k8s/daemonset.yaml; do
  sed -i 's|https://ingest\.[^\"]*\.signalfx\.com|https://ingest.${REALM}.signalfx.com|g' \$f
  sed -i 's|https://api\.[^\"]*\.signalfx\.com|https://api.${REALM}.signalfx.com|g' \$f
done
echo 'manifests patched'
"
ok "Manifests patched"

# ── Step 8: Seed ConfigMap + deploy aggregator + DaemonSet ───────────────────
log "Step 8: Deploying otelcol-fingerprint stack..."

$SSH "
cd ~/o11y-behaviorbaseline
mkdir -p data
echo '{\"fingerprints\":{}}' > data/baseline.${ENV_NAME}.json
echo '{\"signatures\":{}}' > data/error_baseline.${ENV_NAME}.json

# Seed baseline ConfigMap (empty — aggregator will learn during bootstrap)
kubectl delete configmap behavioral-baseline --ignore-not-found >/dev/null
kubectl create configmap behavioral-baseline \
  --from-file=baseline.json=data/baseline.${ENV_NAME}.json \
  --from-file=error_baseline.json=data/error_baseline.${ENV_NAME}.json

# Sync scripts ConfigMap
kubectl delete configmap baseline-sync-scripts --ignore-not-found >/dev/null
kubectl create configmap baseline-sync-scripts \
  --from-file=baseline-sync-sidecar.py=otel-processor/k8s/baseline-sync-sidecar.py

# ServiceAccount (needed before StatefulSet)
kubectl create serviceaccount otelcol-fingerprint --dry-run=client -o yaml | kubectl apply -f -

# Deploy aggregator FIRST (must be ready before DaemonSet routes to it)
kubectl apply -f otel-processor/k8s/aggregator.yaml
echo '  Waiting for aggregator...'
kubectl rollout status statefulset/otelcol-aggregator --timeout=120s

# Deploy DaemonSet
kubectl apply -f otel-processor/k8s/daemonset.yaml
kubectl rollout restart daemonset/otelcol-fingerprint
kubectl rollout status daemonset/otelcol-fingerprint --timeout=120s

# Inject empty baseline into DaemonSet pods ONLY (NOT aggregator — it needs to learn)
for pod in \$(kubectl get pods -l app=otelcol-fingerprint --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'); do
  kubectl cp data/baseline.${ENV_NAME}.json \$pod:/baseline/baseline.json -c otelcol 2>/dev/null && echo \"  [ds] \$pod: ok\"
done
echo 'stack deployed'
"
ok "Aggregator + DaemonSet deployed"

# ── Step 9: Wait for OTel bootstrap window + pull baseline ────────────────────
log "Step 9: Waiting for OTel bootstrap window (5 min)..."
log "  Aggregator is learning fingerprints from live traffic..."

# Write the merge script to EC2
cat > /tmp/ec2_merge_baseline.py << 'PYEOF'
#!/usr/bin/env python3
import json, os, subprocess, sys, time

ENV = os.environ["BOOTSTRAP_ENV"]
REALM = os.environ.get("BOOTSTRAP_REALM", "us1")
HOME = os.path.expanduser("~")
BASELINE = f"{HOME}/o11y-behaviorbaseline/data/baseline.{ENV}.json"
ERROR_BASELINE = f"{HOME}/o11y-behaviorbaseline/data/error_baseline.{ENV}.json"
os.makedirs(os.path.dirname(BASELINE), exist_ok=True)

# Wait for bootstrap window to complete (poll for log line)
agg_pods = subprocess.check_output(
    ["kubectl", "get", "pods", "-l", "app=otelcol-aggregator",
     "-o", "jsonpath={.items[*].metadata.name}"],
    text=True
).strip().split()

if not agg_pods or agg_pods == ['']:
    print("ERROR: No aggregator pods found", flush=True)
    sys.exit(1)

primary = agg_pods[0]
elapsed = 0
poll = 10
max_wait = 360  # 6 min max

print(f"  Primary pod: {primary}", flush=True)
while elapsed < max_wait:
    try:
        logs = subprocess.check_output(
            ["kubectl", "logs", primary, "-c", "otelcol", "--tail=200"],
            text=True, stderr=subprocess.DEVNULL
        )
        if "bootstrap learning window complete" in logs:
            print(f"  Bootstrap complete after {elapsed}s", flush=True)
            break
        # Show progress every 30s
        if elapsed > 0 and elapsed % 30 == 0:
            spans_raw = subprocess.run(
                ["kubectl", "exec", primary, "-c", "otelcol", "--",
                 "wget", "-qO-", "http://localhost:8888/metrics"],
                capture_output=True, text=True
            ).stdout
            spans = next((l.split()[-1] for l in spans_raw.splitlines()
                          if "receiver_accepted_spans" in l and not l.startswith("#")), "?")
            promoted = logs.count("auto-promoted") + logs.count("newly_promoted")
            print(f"  {elapsed}s — spans: {spans}, fingerprints so far: {promoted}", flush=True)
    except Exception:
        pass
    time.sleep(poll)
    elapsed += poll
    print(f"  {elapsed}s...", end="\r", flush=True)

# Give the processor 3s to finish writing the baseline file after the window closes
time.sleep(3)

# Merge baseline from all aggregator pods
merged = {"fingerprints": {}}
for pod in agg_pods:
    if not pod:
        continue
    try:
        content = subprocess.check_output(
            ["kubectl", "exec", pod, "-c", "otelcol", "--", "cat", "/baseline/baseline.json"],
            text=True, stderr=subprocess.DEVNULL
        ).strip()
        if not content or content == '{"fingerprints":{}}':
            print(f"  {pod}: empty baseline, skipping", flush=True)
            continue
        pod_data = json.loads(content)
        fps = pod_data.get("fingerprints", {})
        for h, fp in fps.items():
            if h not in merged["fingerprints"] or \
               fp.get("occurrences", 0) > merged["fingerprints"][h].get("occurrences", 0):
                merged["fingerprints"][h] = fp
        print(f"  {pod}: {len(fps)} fingerprints", flush=True)
    except Exception as e:
        print(f"  {pod}: error — {e}", flush=True)

total = len(merged["fingerprints"])
print(f"\nTotal merged: {total} fingerprints", flush=True)

if total == 0:
    print("WARNING: 0 fingerprints learned. Is traffic flowing? Check:", flush=True)
    print("  kubectl logs deployment/load-generator --tail=5", flush=True)
    print("  kubectl exec <agg-pod> -c otelcol -- wget -qO- http://localhost:8888/metrics | grep receiver_accepted", flush=True)
    sys.exit(1)

# Promote all: mark auto_promoted + no_missing_service
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
for fp in merged["fingerprints"].values():
    fp["auto_promoted"] = True
    fp["no_missing_service"] = True
    if "promoted_at" not in fp:
        fp["promoted_at"] = now

with open(BASELINE, "w") as f:
    json.dump(merged, f, indent=2)
print(f"Baseline written: {BASELINE}", flush=True)

# Push ConfigMap
subprocess.run(["kubectl", "delete", "configmap", "behavioral-baseline", "--ignore-not-found"],
               capture_output=True)
subprocess.run([
    "kubectl", "create", "configmap", "behavioral-baseline",
    f"--from-file=baseline.json={BASELINE}",
    f"--from-file=error_baseline.json={ERROR_BASELINE}",
], check=True, capture_output=True)
print("ConfigMap updated", flush=True)

# Inject into all running pods
for label in ["app=otelcol-aggregator", "app=otelcol-fingerprint"]:
    pods = subprocess.check_output(
        ["kubectl", "get", "pods", "-l", label,
         "--field-selector=status.phase=Running",
         "-o", "jsonpath={.items[*].metadata.name}"],
        text=True
    ).strip().split()
    for pod in pods:
        if not pod:
            continue
        r = subprocess.run(
            ["kubectl", "cp", BASELINE, f"{pod}:/baseline/baseline.json", "-c", "otelcol"],
            capture_output=True
        )
        tag = "agg" if "aggregator" in pod else "ds"
        print(f"  [{tag}] {pod}: {'ok' if r.returncode == 0 else 'FAILED'}", flush=True)

print(f"\nDone. {total} fingerprints active in all pods.", flush=True)
PYEOF

$SCP /tmp/ec2_merge_baseline.py "splunk@$EC2_IP:/tmp/ec2_merge_baseline.py"
rm -f /tmp/ec2_merge_baseline.py

# Run the bootstrap wait + merge on EC2
$SSH "BOOTSTRAP_ENV=${ENV_NAME} BOOTSTRAP_REALM=${REALM} python3 /tmp/ec2_merge_baseline.py"

FP_COUNT=$($SSH "python3 -c \"import json; d=json.load(open('/root/o11y-behaviorbaseline/data/baseline.${ENV_NAME}.json')); print(len(d.get('fingerprints',{})))\" 2>/dev/null || \
  python3 -c \"import json,os; d=json.load(open(os.path.expanduser('~/o11y-behaviorbaseline/data/baseline.${ENV_NAME}.json'))); print(len(d.get('fingerprints',{})))\"")
ok "Bootstrap complete: $FP_COUNT fingerprints"

# ── Step 10: Pull baseline locally + update .env ─────────────────────────────
log "Step 10: Pulling baseline to local data/ and updating .env..."

mkdir -p "$REPO_DIR/data"
$SCP "splunk@$EC2_IP:~/o11y-behaviorbaseline/data/baseline.${ENV_NAME}.json" \
     "$REPO_DIR/data/baseline.${ENV_NAME}.json"

# Update local .env
ENV_FILE="$REPO_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
  # Update existing fields
  sed -i.bak \
    -e "s|^SPLUNK_ACCESS_TOKEN=.*|SPLUNK_ACCESS_TOKEN=${API_TOKEN}|" \
    -e "s|^SPLUNK_INGEST_TOKEN=.*|SPLUNK_INGEST_TOKEN=${INGEST_TOKEN}|" \
    -e "s|^SPLUNK_REALM=.*|SPLUNK_REALM=${REALM}|" \
    -e "s|^ENV=.*|ENV=${ENV_NAME}|" \
    -e "s|^EC2_IP=.*|EC2_IP=${EC2_IP}|" \
    -e "s|^EC2_PASSWORD=.*|EC2_PASSWORD=${EC2_PASS}|" \
    "$ENV_FILE"
  rm -f "${ENV_FILE}.bak"
else
  cat > "$ENV_FILE" << EOF
SPLUNK_ACCESS_TOKEN=${API_TOKEN}
SPLUNK_INGEST_TOKEN=${INGEST_TOKEN}
SPLUNK_REALM=${REALM}
ENV=${ENV_NAME}
EC2_IP=${EC2_IP}
EC2_PASSWORD=${EC2_PASS}
EOF
fi
ok "Local .env updated (ENV=${ENV_NAME})"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║           ec2-bootstrap.sh complete                  ║"
echo "╠══════════════════════════════════════════════════════╣"
printf "║  EC2          : %-37s║\n" "$EC2_IP:$EC2_PORT"
printf "║  Environment  : %-37s║\n" "$ENV_NAME"
printf "║  Cluster      : %-37s║\n" "$CLUSTER_NAME"
printf "║  Image        : %-37s║\n" "$IMAGE"
printf "║  Baseline     : %-37s║\n" "$FP_COUNT fingerprints"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Start detecting:                                    ║"
echo "║    python3 demo/poll_drift_events.py --triage \\      ║"
printf "║      --environment %-34s║\n" "${ENV_NAME} | python3 agent.py \\"
printf "║      --environment %-33s ║\n" "${ENV_NAME}"
echo "╚══════════════════════════════════════════════════════╝"
