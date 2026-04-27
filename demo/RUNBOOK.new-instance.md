# New Instance Deployment Runbook

_Use this when spinning up a fresh EC2 instance for a new demo cluster._

---

## Prerequisites

On your local machine:
- `sshpass` installed (`brew install sshpass`)
- `.env` file in repo root with current values
- AWS Bedrock credentials refreshed (`python3 refresh_aws_creds.py`)

---

## Step 1 — Update `.env`

Edit `.env` with the new instance values:

```bash
EC2_IP=<new-ip>
EC2_PORT=2222
EC2_PASS=Sp1unkH00di3
ENV=<new-env-name>          # e.g. mbtest-xxxx-workshop
SPLUNK_INGEST_TOKEN=<token>
SPLUNK_ACCESS_TOKEN=<token>
```

Verify SSH access:

```bash
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> "kubectl get pods"
```

All PetClinic pods should be `Running`.

---

## Step 2 — Pull and push OTel processor image

The cluster uses a local registry at `localhost:9999`. Pull the image on EC2 and push it locally:

```bash
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> \
  "docker pull ghcr.io/mqbui1/otelcol-fingerprint:latest && \
   docker tag ghcr.io/mqbui1/otelcol-fingerprint:latest localhost:9999/otelcol-fingerprint:latest && \
   docker push localhost:9999/otelcol-fingerprint:latest"
```

---

## Step 3 — Learn and build baseline

Let the cluster run for at least 5 minutes to generate traffic, then learn:

```bash
python3 core/trace_fingerprint.py --environment $ENV learn --window-minutes 30
python3 core/trace_fingerprint.py --environment $ENV promote
```

Verify the baseline looks sane:

```bash
cat data/baseline.$ENV.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('fingerprints',{})), 'fingerprints')"
```

Expect 10–20 fingerprints for a healthy PetClinic cluster.

---

## Step 4 — Push baselines to cluster

```bash
# Copy trace baseline
sshpass -p "Sp1unkH00di3" scp -P 2222 data/baseline.$ENV.json splunk@<new-ip>:/tmp/baseline.json

# Copy error baseline (empty is fine on a fresh cluster)
sshpass -p "Sp1unkH00di3" scp -P 2222 data/error_baseline.$ENV.json splunk@<new-ip>:/tmp/error_baseline.json 2>/dev/null || \
  sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> "echo '{}' > /tmp/error_baseline.json"

# Update ConfigMap — use delete+create, NOT kubectl apply (apply silently uses stale annotation)
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> \
  "kubectl delete configmap behavioral-baseline --ignore-not-found && \
   kubectl create configmap behavioral-baseline --from-file=baseline.json=/tmp/baseline.json"

# Inject directly into running pods (bypasses init container — faster than rollout)
B64=$(base64 -i data/baseline.$ENV.json)
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> \
  "for pod in \$(kubectl get pods -l app=otelcol-fingerprint -o jsonpath='{.items[*].metadata.name}'); do
     kubectl exec \$pod -c otelcol -- sh -c \"echo '$B64' | base64 -d > /baseline/baseline.json\"
     echo \"injected into \$pod\"
   done"
```

> **Note:** `base64` flags differ by OS — use `-i` on macOS (local), `-w 0` on Linux (inside SSH).

---

## Step 5 — Restart OTel collector pods

```bash
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> \
  "kubectl rollout restart daemonset/otelcol-fingerprint && \
   kubectl rollout status daemonset/otelcol-fingerprint"
```

Wait ~30 seconds, then verify the processor is receiving spans:

```bash
python3 -u demo/poll_drift_events.py --environment $ENV
# Should show log output from pods with no drift events (steady state)
# Ctrl-C after confirming connectivity
```

---

## Step 6 — Run auto-onboarding

Creates the Splunk O11y dashboard and validates the full setup:

```bash
python3 demo/onboard.py --auto --environment $ENV
```

Expected output:
- Environment discovered ✓
- Baseline fingerprints loaded ✓
- Dashboard created in Splunk O11y ✓

Note the dashboard ID — update MEMORY.md with it.

---

## Step 7 — Verify all checks pass

```bash
bash demo/check-ready.sh
```

Expected: **8/8 passing**. Do not proceed to demos until this is clean.

---

## Step 8 — Smoke test demos

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
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> \
  "kubectl scale deployment vets-service --replicas=0"

# Restore
sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no splunk@<new-ip> \
  "kubectl scale deployment vets-service --replicas=1"
```

---

## Step 9 — Update memory / docs

Update `.env` and `MEMORY.md` with the new cluster details:
- `EC2_IP`, `ENV`, tokens
- Dashboard ID from Step 6
- Note previous cluster as decommissioned

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| SSH times out | Confirm security group allows port 2222 from your IP |
| `check-ready.sh` < 8/8 | Check pod status: `kubectl get pods` — wait for all `Running` |
| OTel pods not detecting events | Re-inject baseline, restart daemonset |
| No fingerprints after `learn` | Wait for traffic — all PetClinic pods must be `Running` first |
| Dashboard not created | Check `SPLUNK_ACCESS_TOKEN` is an API token, not ingest token |
| `poll_drift_events.py` silent | Pods may have cycled — restart the script to pick up fresh pod names |
| ConfigMap not updating | Use `kubectl delete + create`, never `kubectl apply` |
| base64 decode error on cluster | Add `-w 0` flag when running base64 inside SSH/on Linux |
| False drift events after reset | Run `bash demo/demo-reset.sh` — clears dedup state and error baseline |

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
