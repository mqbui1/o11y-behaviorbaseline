# New Instance Deployment Runbook

_Use this when spinning up a fresh EC2 instance for a new demo cluster._

---

## Prerequisites

On your local machine:
- `sshpass` + `rsync` installed (`brew install sshpass`)
- `.env` file in repo root with current values
- AWS Bedrock credentials refreshed (`python3 refresh_aws_creds.py`)

---

## Step 1 — Discover cluster config + update `.env`

SSH in and find the `deployment.environment` value set by the cluster:

```bash
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> \
  "kubectl get configmap splunk-otel-collector-otel-agent -o yaml | grep 'deployment.environment' -A1"
# → value: petclinicXXXX-workshop  ← this is your ENV
```

Decode the cluster's ingest and API tokens from `workshop-secret`:

```bash
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> \
  "kubectl get secret workshop-secret -o jsonpath='{.data.access_token}' | base64 -d && echo && \
   kubectl get secret workshop-secret -o jsonpath='{.data.api_token}' | base64 -d && echo"
# access_token → SPLUNK_INGEST_TOKEN
# api_token    → cluster API token (for the splunk-api-token secret below)
```

Edit `.env` with the new values:

```bash
EC2_IP=<new-ip>
EC2_PORT=2222
EC2_PASS=Sp1unkH00di3
ENV=<env-name-from-above>
SPLUNK_INGEST_TOKEN=<access_token from workshop-secret>
SPLUNK_ACCESS_TOKEN=<your personal API token with write perms>
```

> **SPLUNK_ACCESS_TOKEN note:** The workshop cluster's `api_token` is read-only (can query traces).
> For dashboard creation you need a personal token with admin/write permissions.
> If you only have a read token, onboarding will skip dashboard creation but everything else works.

Verify SSH + pod status:

```bash
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> "kubectl get pods"
```

All PetClinic pods should be `Running`.

---

## Step 2 — Build and load OTel processor image

**The cluster does NOT have a pre-populated local registry.** The image must be built on EC2
and imported directly into k3d (no push/pull from ghcr.io needed):

```bash
# Copy source to EC2
rsync -av -e "sshpass -p Sp1unkH00di3 ssh -p 2222 -o StrictHostKeyChecking=no" \
  otel-processor/ splunk@<new-ip>:~/otelcol-fingerprint-src/

# Build on EC2 (takes ~2 min — Go compile)
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> \
  "cd ~/otelcol-fingerprint-src && docker build -t localhost:9999/otelcol-fingerprint:latest ."

# Import directly into all k3d nodes (bypasses registry — use cluster name from `k3d cluster list`)
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> \
  "k3d image import localhost:9999/otelcol-fingerprint:latest -c <cluster-name>"
# cluster name: k3d cluster list → e.g. petclinicXXXX-cluster
```

> **Important:** `daemonset.yaml` uses `imagePullPolicy: IfNotPresent` — this is required for
> k3d image import to work. Do NOT change it to `Always`.

---

## Step 2b — Create the `splunk-api-token` secret

The daemonset needs a secret named `splunk-api-token` (separate from the Helm release secret):

```bash
# Use the cluster's api_token decoded in Step 1
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> \
  "kubectl create secret generic splunk-api-token --from-literal=token=<api_token>"
```

---

## Step 3 — Deploy the DaemonSet

Copy manifests and supporting files to EC2, then apply:

```bash
# Copy daemonset + sync sidecar
sshpass -p "Sp1unkH00di3" scp -P 2222 \
  otel-processor/k8s/daemonset.yaml \
  otel-processor/k8s/baseline-sync-sidecar.py \
  splunk@<new-ip>:/tmp/

# Create empty error baseline placeholder
echo '{"signatures":{}}' > /tmp/empty_error_baseline.json
sshpass -p "Sp1unkH00di3" scp -P 2222 /tmp/empty_error_baseline.json splunk@<new-ip>:/tmp/error_baseline.json

# Create ConfigMaps (use empty baseline.json for now — we'll populate in Step 5)
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> "
  echo '{\"fingerprints\":{}}' > /tmp/baseline.json
  kubectl delete configmap behavioral-baseline --ignore-not-found
  kubectl create configmap behavioral-baseline \
    --from-file=baseline.json=/tmp/baseline.json \
    --from-file=error_baseline.json=/tmp/error_baseline.json
  kubectl delete configmap baseline-sync-scripts --ignore-not-found
  kubectl create configmap baseline-sync-scripts \
    --from-file=baseline-sync-sidecar.py=/tmp/baseline-sync-sidecar.py
  kubectl apply -f /tmp/daemonset.yaml
  kubectl rollout status daemonset/otelcol-fingerprint --timeout=120s
"
```

---

## Step 4 — Route app traces through the fingerprint collector

The OTel Operator Instrumentation CR controls where app pods send traces. The cluster's Helm-managed
CR resets any patches, so use `kubectl set env` directly on each deployment:

```bash
FP="http://otelcol-fingerprint.default.svc.cluster.local:4318"
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> "
  for svc in api-gateway customers-service vets-service visits-service admin-server; do
    kubectl set env deployment/\$svc OTEL_EXPORTER_OTLP_ENDPOINT=\$FP
  done
  kubectl rollout status deployment/api-gateway deployment/customers-service \
    deployment/vets-service deployment/visits-service --timeout=120s
"
```

> **Why not patch the Instrumentation CR?** The Splunk OTel Operator reconciles the CR
> and resets any `kubectl patch` changes. `kubectl set env` writes directly to the Deployment
> spec and survives reconciliation.

---

## Step 5 — Learn and build baseline

Wait at least 5 minutes after pods restart for stable traffic, then learn.
Use `--bootstrap` flag (lowers min-occurrence threshold for fresh clusters):

```bash
python3 core/trace_fingerprint.py --environment $ENV learn --bootstrap --window-minutes 30
python3 core/trace_fingerprint.py --environment $ENV promote
```

Verify the baseline looks sane:

```bash
cat data/baseline.$ENV.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('fingerprints',{})), 'fingerprints')"
```

Expect 10–20 fingerprints for a healthy PetClinic cluster.

---

## Step 6 — Push baselines to cluster

```bash
# Copy baselines
sshpass -p "Sp1unkH00di3" scp -P 2222 data/baseline.$ENV.json splunk@<new-ip>:/tmp/baseline.json
sshpass -p "Sp1unkH00di3" scp -P 2222 data/error_baseline.$ENV.json splunk@<new-ip>:/tmp/error_baseline.json 2>/dev/null || true

# Update ConfigMap — use delete+create, NOT kubectl apply
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> \
  "kubectl delete configmap behavioral-baseline --ignore-not-found && \
   kubectl create configmap behavioral-baseline \
     --from-file=baseline.json=/tmp/baseline.json \
     --from-file=error_baseline.json=/tmp/error_baseline.json"

# Inject directly into running pods (use kubectl cp — no base64 issues)
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> "
  for pod in \$(kubectl get pods -l app=otelcol-fingerprint --field-selector=status.phase=Running \
    -o jsonpath='{.items[*].metadata.name}'); do
    kubectl cp /tmp/baseline.json \$pod:/baseline/baseline.json -c otelcol && echo \"\$pod: ok\"
  done
"
```

> **Use `kubectl cp` not base64 pipe** — avoids line-wrap issues between macOS/Linux.

---

## Step 7 — Learn error baseline

After 10+ minutes of stable traffic, learn the error baseline to capture any
normal startup errors (ConnectException etc.) so they don't alert:

```bash
python3 onboard.py --auto --environment $ENV
```

This runs error baseline learn + pushes to cluster + creates the Splunk O11y dashboard.

> If dashboard creation fails (403), the token lacks write permissions — that's OK,
> error baseline will still be learned and pushed. Create the dashboard manually if needed.

Verify errors are baselined — the error baseline file should have entries:

```bash
cat data/error_baseline.$ENV.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('signatures',{})), 'error signatures')"
```

---

## Step 8 — Verify steady state

Check OTel processor logs for no false alarms (should be silent after ~60s):

```bash
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@$EC2_IP \
  "kubectl logs -l app=otelcol-fingerprint -c otelcol --since=60s --max-log-requests=5 2>&1 \
   | grep -E 'drift|missing|error sig|fingerprint' | tail -10"
# Expected: no output (silent = healthy)
```

Also run check-ready:

```bash
bash demo/check-ready.sh
```

Expected: **8/8 passing**. Do not proceed to demos until this is clean.

---

## Step 9 — Smoke test demos

```bash
# Terminal 1 — topology visualization
python3 demo/topology_server.py --environment $ENV

# Terminal 2 — agent triage pipeline
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

Open `http://localhost:8080`. Click each **Simulate** button to confirm visualization works.

Then run a live cluster trigger to confirm end-to-end:

```bash
# Kill vets-service — should fire in ~10s
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@$EC2_IP \
  "kubectl scale deployment vets-service --replicas=0"

# Restore
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@$EC2_IP \
  "kubectl scale deployment vets-service --replicas=1"
```

---

## Step 10 — Update memory / docs

Update `.env` and `MEMORY.md` with the new cluster details:
- `EC2_IP`, `ENV`, tokens
- Dashboard ID from Step 7 (if created)
- Note previous cluster as decommissioned

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| SSH times out | Confirm security group allows port 2222 from your IP |
| `check-ready.sh` < 8/8 | Check pod status: `kubectl get pods` — wait for all `Running` |
| OTel pods not detecting events | Re-inject baseline, restart daemonset |
| No fingerprints after `learn` | Wait for traffic — all PetClinic pods must be `Running` first |
| `learn` returns 0 fingerprints | Use `--bootstrap` flag to lower min-occurrence threshold |
| Dashboard not created (403) | Token lacks write permission — skip dashboard, everything else still works |
| Traces not reaching fingerprint pods | Check `OTEL_EXPORTER_OTLP_ENDPOINT` in app pod: `kubectl exec <pod> -- env \| grep OTLP` |
| App traces going to splunk-otel-collector instead | Instrumentation CR override not working — use `kubectl set env deployment/<svc> OTEL_EXPORTER_OTLP_ENDPOINT=...` directly |
| `otelcol-fingerprint` pod stuck in ImagePullBackOff | Image not imported — run `k3d image import localhost:9999/otelcol-fingerprint:latest -c <cluster>` |
| ghcr.io pull unauthorized | Image is private — build locally on EC2 with `docker build`, then `k3d image import` |
| `poll_drift_events.py` silent | Pods may have cycled — restart the script to pick up fresh pod names |
| ConfigMap not updating | Use `kubectl delete + create`, never `kubectl apply` |
| False drift events after reset | Run `bash demo/demo-reset.sh` — clears dedup state and error baseline |
| ConnectException errors at startup | Normal — learn error baseline after 10min of stable traffic to suppress them |

---

## Quick Reference

```bash
# SSH into cluster
sshpass -p "Sp1unkH00di3" ssh -p 2222 splunk@$EC2_IP

# Check all pods
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@$EC2_IP "kubectl get pods"

# Tail OTel processor logs
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@$EC2_IP \
  "kubectl logs -f -l app=otelcol-fingerprint -c otelcol --max-log-requests 5"

# Reset demo state between runs
bash demo/demo-reset.sh

# Start topology visualization
python3 demo/topology_server.py --environment $ENV

# Start agent triage pipeline
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV

# Learn + promote baseline
python3 core/trace_fingerprint.py --environment $ENV learn --window-minutes 30
python3 core/trace_fingerprint.py --environment $ENV promote
```
