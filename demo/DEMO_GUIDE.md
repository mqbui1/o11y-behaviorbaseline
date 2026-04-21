# Behavioral Anomaly Framework — Demo Guide

---

## New Cluster Setup (run once per workshop instance)

Use this section when deploying to a brand-new EC2/k3d cluster. Skip to **Prerequisites** if the cluster is already set up.

### What you need
- New EC2 instance running k3d with petclinic + splunk-otel-collector already deployed
- Splunk workshop environment credentials from the `workshop-secret` ConfigMap (on the cluster)

### Step 1 — Extract tokens from the cluster (on EC2)
```bash
# SSH into EC2
ssh -p 2222 splunk@<ec2-ip>  # password: Sp1unkH00di3

# Decode workshop tokens
kubectl get secret workshop-secret -o jsonpath='{.data.access_token}' | base64 -d && echo  # INGEST token
kubectl get secret workshop-secret -o jsonpath='{.data.api_token}'    | base64 -d && echo  # API token
kubectl get secret workshop-secret -o jsonpath='{.data.env}'          | base64 -d && echo  # environment name
```

### Step 2 — Update `.env` (local Mac)
```bash
# Edit .env:
EC2_IP=<new-ec2-ip>
EC2_PASSWORD=Sp1unkH00di3
ENV=<env-name>                      # e.g. mqbtest-f0d4-workshop
SPLUNK_INGEST_TOKEN=<ingest-token>   # from access_token above
SPLUNK_ACCESS_TOKEN=<api-token>      # from api_token above
SPLUNK_REALM=us1

source .env

# SSH alias for cluster commands
alias k='sshpass -p "$EC2_PASSWORD" ssh -p 2222 -o StrictHostKeyChecking=no splunk@$EC2_IP'
```

### Step 3 — Build and push the OTel processor image (on EC2)
```bash
# Copy otel-processor source to EC2
sshpass -p "$EC2_PASSWORD" scp -P 2222 -r otel-processor/ splunk@$EC2_IP:/home/splunk/

# Build and push to local k3d registry
k "cd /home/splunk/otel-processor && \
   docker build -t localhost:9999/otelcol-fingerprint:latest . && \
   docker push localhost:9999/otelcol-fingerprint:latest"
```

### Step 4 — Point app traces directly at otelcol-fingerprint
The OTel Operator's `Instrumentation` CR controls where auto-instrumented app pods send their traces. Patch it to point at `otelcol-fingerprint` so the flow is:

```
app pod → otelcol-fingerprint (fingerprint inline) → Splunk APM
```

No Helm relay patch needed. `deploy.sh` does this automatically in Step 4, but you can also run it manually:

```bash
k "kubectl patch instrumentation splunk-otel-collector --type=merge -p \
  '{\"spec\":{
    \"exporter\":{\"endpoint\":\"http://otelcol-fingerprint.default.svc.cluster.local:4317\"},
    \"java\":{\"env\":[{\"name\":\"OTEL_EXPORTER_OTLP_ENDPOINT\",
      \"value\":\"http://otelcol-fingerprint.default.svc.cluster.local:4318\"}]}
  }}'"
```

After patching, restart app deployments so the mutating webhook re-injects with the new endpoint:
```bash
k "kubectl rollout restart deployment/api-gateway deployment/customers-service \
   deployment/vets-service deployment/visits-service deployment/admin-server"
```

### Step 5 — Learn baseline (local Mac)
Wait **~15 minutes** for petclinic loadgen to generate APM data and for DB query patterns to stabilize, then bootstrap a baseline:
```bash
source .env

# Bootstrap mode: accepts fingerprints seen ≥1 time, then drops seen-once noise.
# Use for fresh clusters where traffic hasn't accumulated enough for the standard min=3 threshold.
# Also merges auto-promoted entries from the OTel ConfigMap automatically.
python3 core/trace_fingerprint.py --environment $ENV learn --bootstrap --window-minutes 30
python3 core/trace_fingerprint.py --environment $ENV promote

# For more established clusters (30+ min of traffic), use standard learn:
# python3 core/trace_fingerprint.py --environment $ENV learn --window-minutes 30
# python3 core/trace_fingerprint.py --environment $ENV promote

# Verify fingerprints were learned
python3 core/trace_fingerprint.py --environment $ENV show
```

> **Expected (bootstrap):** 30–50 fingerprints from 15+ minutes of traffic. The output includes
> a line like `  Merged N OTel-promoted fingerprint(s) from ConfigMap` when the OTel baseline
> already has auto-promoted entries.

> **Bootstrap consolidation:** After the min=1 pass, fingerprints seen exactly once are dropped.
> These are startup transients or stray spans that won't appear again in steady state.

> **If baseline is sparse (<15 fingerprints):** DB query patterns may not have fully varied yet.
> Wait another 5–10 minutes and re-run `learn --bootstrap --window-minutes 30`. The owners list
> endpoint generates varying numbers of `SELECT petclinic` spans depending on data volume, and
> needs a few minutes of warm traffic to produce all variants.

### Step 6 — Seed and deploy the OTel processor (on EC2)
```bash
# Push baseline to EC2
sshpass -p "$EC2_PASSWORD" scp -P 2222 \
  data/baseline.$ENV.json splunk@$EC2_IP:/tmp/baseline.json

# Create required secrets (if not already present)
k "kubectl create secret generic splunk-api-token \
  --from-literal=token=$SPLUNK_ACCESS_TOKEN --dry-run=client -o yaml | kubectl apply -f -"

k "kubectl create secret generic workshop-secret \
  --from-literal=env=$ENV \
  --from-literal=ingest-url=https://ingest.us1.signalfx.com \
  --from-literal=api-url=https://api.us1.signalfx.com \
  --from-literal=access_token=$SPLUNK_INGEST_TOKEN \
  --dry-run=client -o yaml | kubectl apply -f -"

# Create empty error baseline
python3 -c "
import json, pathlib, datetime
e = '$ENV'
pathlib.Path(f'data/error_baseline.{e}.json').write_text(
    json.dumps({'signatures':{},'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'environment':e})
)
print(f'Empty error baseline created: data/error_baseline.{e}.json')
"
sshpass -p "$EC2_PASSWORD" scp -P 2222 \
  data/error_baseline.$ENV.json splunk@$EC2_IP:/tmp/error_baseline.json

# Seed ConfigMap + apply DaemonSet
k "kubectl delete configmap behavioral-baseline --ignore-not-found && \
   kubectl create configmap behavioral-baseline \
     --from-file=baseline.json=/tmp/baseline.json \
     --from-file=error_baseline.json=/tmp/error_baseline.json"

k "kubectl apply -f /home/splunk/otel-processor/k8s/daemonset.yaml"
k "kubectl rollout restart daemonset/otelcol-fingerprint"
k "kubectl rollout status daemonset/otelcol-fingerprint --timeout=120s"

# Inject baseline directly into running pods (active immediately, no 60s wait)
k "B64=\$(base64 -w 0 /tmp/baseline.json); \
   for pod in \$(kubectl get pods -l app=otelcol-fingerprint -o jsonpath='{.items[*].metadata.name}'); do \
     kubectl exec \$pod -c otelcol -- sh -c \"echo '\$B64' | base64 -d > /baseline/baseline.json\"; \
     echo \"  Injected into \$pod\"; \
   done"
```

### Step 7 — Verify (local Mac)
```bash
# Should be silent (no false positives):
python3 -u demo/poll_drift_events.py

# Kill visits-service to confirm Demo 1 fires within ~20s:
k "kubectl scale deployment visits-service --replicas=0"
# Expected: trace.path.drift event appears in poll_drift_events.py within ~20s
# Restore:
k "kubectl scale deployment visits-service --replicas=1"
```

### Re-deploy (subsequent sessions, image already built)
```bash
# Push updated baseline + restart (config-only re-deploy, no build or Instrumentation patch needed)
sshpass -p "$EC2_PASSWORD" scp -P 2222 \
  data/baseline.$ENV.json splunk@$EC2_IP:/tmp/baseline.json
sshpass -p "$EC2_PASSWORD" scp -P 2222 \
  data/error_baseline.$ENV.json splunk@$EC2_IP:/tmp/error_baseline.json
k "kubectl delete configmap behavioral-baseline --ignore-not-found && \
   kubectl create configmap behavioral-baseline \
     --from-file=baseline.json=/tmp/baseline.json \
     --from-file=error_baseline.json=/tmp/error_baseline.json"
k "kubectl rollout restart daemonset/otelcol-fingerprint"
```

---

## Prerequisites

### Terminal setup (run once before demo)
```bash
# All commands in this guide are run from the repo root
cd /Users/mbui/Documents/o11y-behaviorbaseline
source .env
# ENV is set in .env — update before each workshop session

# SSH alias for cluster commands
# EC2_IP and EC2_PASSWORD are set in .env — update before each demo session
alias k='sshpass -p "$EC2_PASSWORD" ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@$EC2_IP'
```

### Refresh AWS credentials (required for Claude/Bedrock triage)
AWS STS tokens expire every few hours. `refresh_aws_creds.py` reads them from the environment — it only works in a terminal that already has AWS credentials set (Claude Code does this automatically).

**Step 1 — In the CLAUDE CODE terminal:**
```bash
cd /Users/mbui/Documents/o11y-behaviorbaseline && python3 refresh_aws_creds.py
# Expected:
#   Credentials verified: arn:aws:sts::387769110234:assumed-role/...
#   .env updated with fresh AWS credentials.
```

**Step 2 — Back in your DEMO terminal:**
```bash
source .env
```

This writes the tokens into `.env` so all scripts pick them up automatically. Do NOT run `refresh_aws_creds.py` in the demo terminal — it will fail with "Missing AWS env vars".

### Splunk O11y URLs
- **APM Service Map**: https://app.us1.signalfx.com/#/apm?environments=$ENV
- **Behavioral Baseline Dashboard**: https://app.us1.signalfx.com/#/dashboard/HERM9jxA1po

### Pre-flight check
```bash
./demo/check-ready.sh
```

This checks all 6 pre-demo conditions in one pass:
1. **AWS credentials** — valid STS token (required for Claude/Bedrock triage)
2. **Cluster pods** — all Running, 3 otelcol-fingerprint pods present
3. **Baseline fingerprints** — ≥10 fingerprints loaded in the OTel processor
4. **Splunk API** — reachable and authenticated
5. **0 trace anomalies** — Python watch returns clean baseline
6. **0 stale OTel events** — no drift events in Splunk in the last 3 minutes

If any check fails, the script prints what to fix and exits 1.

> If `otelcol-fingerprint` pods show `CrashLoopBackOff`, fix before proceeding:
> ```bash
> k "kubectl logs daemonset/otelcol-fingerprint --tail=20"
> # Most common cause: baseline ConfigMap missing. Recreate it:
> ./otel-processor/sync-baseline.sh $ENV
> k "kubectl rollout restart daemonset/otelcol-fingerprint"
> ```

### Reset and verify baselines are clean

**Full reset** (before first demo or after a messy run — ~2-3 minutes):

```bash
# Refresh AWS credentials first (in Claude Code terminal)
python3 refresh_aws_creds.py
# Then back in demo terminal:
source .env

# Run the reset script
./demo/demo-reset.sh
```

`demo-reset.sh` does all of this automatically:
1. Restore all services to `--replicas=1`
2. Wait 30s for DB reconnect
3. Clear `data/alerts.log`
4. Wipe error baseline → push wiped version to ConfigMap + inject into OTel pods
5. Clear dedup state
6. Strip watch-contaminated trace fingerprints
7. Verify 0 Python trace anomalies
8. Verify 0 OTel events in Splunk (last 3m)

> **If step 8 shows OTel events still present:** the previous demo's events haven't aged out of the 3m window yet. Wait 3 minutes and re-run `./demo/demo-reset.sh` — it is idempotent.

**Between-demo reset** (after a demo that killed a service — ~30 seconds with DB, ~5 seconds without):

```bash
./demo/demo-between.sh          # after demos where only a service was killed (no DB)
./demo/demo-between.sh --db     # after demos where DB was killed (adds 30s wait for reconnect)
./demo/demo-between.sh --quick  # local state only, no cluster ops (same as demo-quick-reset.sh)
```

`demo-between.sh` always: clears alerts.log, wipes error baseline + dedup state. By default also restores all services to replicas=1 and wipes OTel error baseline in-memory.

**Quick reset** (between demos, no cluster ops — ~5 seconds):

```bash
./demo/demo-quick-reset.sh
```

Clears alerts.log, wipes error baseline and dedup state locally. No cluster ops. Use between clean demo runs where services were already restored.

> **If trace anomalies persist after reset:** re-learn the baseline:
> ```bash
> python3 core/trace_fingerprint.py --environment $ENV learn --window-minutes 60 --reset
> python3 core/trace_fingerprint.py --environment $ENV promote
> ```

### Open the alert log in a separate terminal
All Python scripts (detection, triage, correlation) run **locally** — only `k "..."` commands go to the EC2 cluster.
```bash
# Run this in a second terminal tab, from the same directory
cd /Users/mbui/Documents/o11y-behaviorbaseline
tail -f data/alerts.log
```

> **Note on scheduling:** In production, `baseline-agent` (Deployment) runs learn/onboard/heal cycles automatically and `triage-agent` (Deployment) polls every 60s for anomalies. During the demo every detection step is run manually to show each layer explicitly.

---

## Hands-Off Demo Mode

Run `demo_watch.py` in one terminal. Kill services in another. Everything else is automatic.

```bash
# Terminal 1 — leave running throughout the demo
python3 demo/demo_watch.py --environment $ENV
```

```bash
# Terminal 2 — trigger scenarios (no other commands needed)
alias k='sshpass -p "$EC2_PASSWORD" ssh -p 2222 -o StrictHostKeyChecking=no splunk@$EC2_IP'
k "kubectl scale deployment vets-service --replicas=0"   # fires in ~15s
# restore
k "kubectl scale deployment vets-service --replicas=1"
```

**What `demo_watch.py` does on each event:**
1. Tails OTel collector logs over SSH — detects drift in ~10–15s, no Splunk wait
2. Pipes events directly to `agent.py` — Claude triage runs immediately
3. Prints elapsed time: `Triage complete in Xs.`
4. Waits 60s for Splunk indexing, then runs `correlate.py` — shows TIER2_TIER3
5. Clears dedup state — ready for next scenario without any manual reset

**Expected output (kill vets-service → watch terminal):**
```
[demo_watch] env=<env> | watching for drift events...
  Kill a service in another terminal to trigger detection.

[22:47:08 UTC] Waiting for drift events from OTel edge processor...
  [22:47:19 UTC] 1 event(s) received — settling for 5s...

[agent] env=<env> | 1 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — The vets-service is unreachable...
    Confidence: HIGH | Affected: vets-service, api-gateway
    Recommended action: PAGE_ONCALL
    [TRIAGE SUMMARY] written to alerts.log

[22:47:34 UTC] Triage complete in 26s.
[22:47:34 UTC] Waiting 60s for Splunk indexing before cross-tier correlation...

[correlate] Fetching anomaly + deployment events in parallel (environment '<env>')...
  Found 4 anomaly events across 2 tier(s)
  [Major] TIER2_TIER3 — api-gateway
    ...

[22:48:38 UTC] Ready for next scenario. Kill a service to trigger again.
```

**Options:**
```bash
# Skip correlate step (faster, triage only)
python3 demo/demo_watch.py --environment $ENV --no-correlate

# Adjust correlate delay (default 60s — Splunk indexing lag)
python3 demo/demo_watch.py --environment $ENV --correlate-delay 90

# Suppress poll/status messages (cleaner output)
python3 demo/demo_watch.py --environment $ENV --quiet
```

> **Tip:** Keep `tail -f data/alerts.log` open in a third terminal — this shows the structured log that `demo_watch.py` writes via `agent.py`, which has cleaner formatting for screen sharing.

---

## Demo 0: Context Setting — Framework in Steady State

**Story:** *"This is what the framework looks like before we break anything. Every component is autonomous — no manual alerting rules, no hardcoded thresholds."*

```bash
# Verify all systems healthy — proves steady state from the OTel processor's perspective
./demo/check-ready.sh
```

**Expected output:**
```
=== Pre-flight check: env=<env> ===
  ✓  AWS credentials valid
  ✓  All pods Running
  ✓  otelcol-fingerprint: 3/3 pods running
  ✓  Local baseline: 52 fingerprints (52 promoted)
  ✓  Cluster ConfigMap baseline: 53 fingerprints loaded
  ✓  Splunk API reachable (HTTP 200)
  ✓  OTel processor: 0 drift events in last 30s — steady state
  ✓  No stale OTel events in Splunk
=== Results: 8 passed, 0 failed ===
    Ready to demo. Start with: demo/demo-reset.sh
```

**Key talking points:**
- *"One command — 8 checks. No alert rules written, no thresholds set. The framework learned call patterns from live traffic and pushed them to every collector node."*
- *"53 fingerprints in the ConfigMap — that's what the OTel processor on each node has loaded. Anything that deviates fires in ~10 seconds."*
- *"0 drift events in the last 30s from the collector pods. 0 stale events in Splunk. The detector is quiet — this is the baseline we'll break in the next demos."*

---

## Demo 1: DB Goes Down — New Error Signatures

**Story:** *"The database goes down. Services start throwing transaction errors and health check failures that have never appeared before. The framework detects brand new error signatures on first occurrence — no threshold, no tuning required."*

### Step 1 — Kill the DB
```bash
k "kubectl scale deployment petclinic-db --replicas=0"
```

### Step 1b — Watch OTel real-time detection (while the countdown runs)
In a third terminal tab, stream drift events directly from the OTel edge processor:
```bash
python3 -u demo/poll_drift_events.py
```

Within **10–15 seconds** of the kill, you'll see `error.signature.drift` events printed — the OTel processor detected new error signatures on the first affected trace.

### Step 3 — Run triage directly from OTel logs (no Splunk wait)
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

Waits for events from the OTel log stream, collects for 5s, then pipes directly to agent.py — no Splunk indexing lag.

**Expected terminal output:**
```
[agent] env=<env> | 4 anomaly(s) from watch
  Reasoning with Claude...

[!] DEGRADED — customers-service is throwing CannotCreateTransactionException on every
    DB call, cascading into 500 errors at the api-gateway on the GET /owners path.
    Root cause: The database is down or unreachable — customers-service cannot open
    a transaction, which propagates as 500s through the api-gateway.
    Confidence: HIGH | Affected: customers-service, api-gateway
    Recommended action: PAGE_ONCALL

    [TRIAGE SUMMARY] written to alerts.log
    [PAGE_ONCALL] event emitted to Splunk
```

> Severity shows `DEGRADED` (not `INCIDENT`) because only the customer/owner path is affected —
> vets-service is still up. Demo 4 (both DB + vets down) produces `INCIDENT`.

**Expected alerts.log:**
```
════════════════════════════════════════════════════════════════════════
[TIMESTAMP UTC]  DETECTION
  anomaly type         : NEW_ERROR_SIGNATURE
  environment          : <env>
  service              : customers-service
  message              : New error signature in customers-service:
                         org.springframework.transaction.CannotCreateTransactionException
                         on OwnerRepository.findAll
────────────────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════════════════
[TIMESTAMP UTC]  DETECTION
  anomaly type         : NEW_ERROR_SIGNATURE
  environment          : <env>
  service              : api-gateway
  message              : New error signature in api-gateway: 500 on GET customers-service
────────────────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════════════════
[TIMESTAMP UTC]  TRIAGE
  severity             : DEGRADED
  confidence           : HIGH
  environment          : <env>
  affected services    : customers-service, api-gateway
  root cause           : customers-service has lost connectivity to its database
  action               : PAGE_ONCALL
────────────────────────────────────────────────────────────────────────
```

**The demo story lands in two acts:**
1. **OTel edge processor fires in ~15s** — structural signal at the collector, no AI needed, no poll interval
2. **Python agent correlates + triages with Claude in seconds** — root cause identified, blast radius mapped

**Key talking points:**
- *"The OTel processor fires in ~10 seconds — it sees the error span on the very first affected trace, before any metric threshold is crossed."*
- *"A DB outage creates brand new error signatures that have never appeared before. The framework fires on first occurrence — no threshold to set."*
- *"The cascade is visible: DB down → CannotCreateTransactionException in customers-service → 500 in api-gateway."*
- *"Claude correctly identifies the shared database as the root cause from the error pattern alone."*

### Step 4 — Restore
```bash
./demo/demo-between.sh --db
```

`--db` restores petclinic-db to replicas=1, waits 30s for services to reconnect, then wipes the error baseline locally and on the cluster so Demo 1 can be repeated cleanly.

> **If the curl verify in demo-between.sh fails:** wait another 30s and re-run `./demo/demo-between.sh --db`. customers-service and visits-service need the DB fully up before accepting requests.

---

## Demo 2: Gap Demo — APM Has No Alert, Framework Fires in 10s

**Story:** *"vets-service is killed. Open the APM Service Map — it shows green. No alert. No incident. APM doesn't know yet. Meanwhile, the OTel edge processor detected the structural absence on the very first affected trace and fired in ~10 seconds. This is the gap the framework fills."*

### Step 1 — Open APM Service Map
Point browser at the Splunk APM Service Map for this environment. Confirm all services green, no incidents.

### Step 2 — Kill vets-service
```bash
k "kubectl scale deployment vets-service --replicas=0"
```

### Step 3 — Watch framework fire in real time
```bash
python3 -u demo/poll_drift_events.py
```

Within **10–15 seconds** you'll see `trace.path.drift` printed here. Refresh APM — still green.

### Step 4 — Run triage
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

**Expected output:**
```
[agent] env=<env> | 1 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — vets-service is absent from traces. Root cause: vets-service is down.
    Confidence: HIGH | Affected: vets-service, api-gateway
    Recommended action: PAGE_ONCALL
```

APM still has no alert at this point.

**Key talking point:** *"APM metrics need time to accumulate before thresholds fire — minutes, not seconds. The OTel edge processor sees structural changes in the first affected trace. That's the gap."*

### Restore
```bash
./demo/demo-between.sh
```

---

## Demo 3: Missing Service — Structural Trace Absence + AI Triage

**Story:** *"vets-service goes down. The framework detects the structural absence from traces and calls Claude (via AWS Bedrock) to reason about it — producing an INCIDENT verdict with root cause and recommended action, written to a log file in under 1 minute."*

### Prerequisites
```bash
./demo/demo-quick-reset.sh
```

### Step 1 — Kill vets-service
```bash
k "kubectl scale deployment vets-service --replicas=0"
```

### Step 1b — Watch OTel real-time detection (while the countdown runs)
In a third terminal tab, stream drift events directly from the OTel edge processor:
```bash
python3 -u demo/poll_drift_events.py
```

Within **10–15 seconds** of the kill, you'll see a `trace.path.drift` event for `api-gateway:GET vets-service` printed to this terminal — the OTel Collector edge processor detected the structural change as the first truncated trace flowed through.

> **Talking point:** *"The OTel processor fires in ~10 seconds — it fingerprints every trace as it flows through the collector, no polling interval. Those events land in Splunk immediately. The next step pulls them from Splunk and calls Claude for triage — no window to wait for."*

### Step 3 — Run triage directly from OTel logs (no Splunk wait)
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

**Expected terminal output:**
```
[agent] env=<env> | 1 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — The vets-service is unreachable, causing api-gateway to return
    sustained errors on all GET vets-service calls.
    Root cause: vets-service is down or network-isolated — the OTel edge processor
    detected the trace path for 'api-gateway:GET vets-service' has changed,
    indicating vets-service is no longer reachable.
    Confidence: HIGH | Affected: vets-service, api-gateway
    Recommended action: PAGE_ONCALL

    [TRIAGE SUMMARY] written to alerts.log
    [PAGE_ONCALL] event emitted to Splunk
```

> The anomaly comes from the OTel edge processor — it detected that the trace fingerprint
> for `api-gateway:GET vets-service` changed (vets-service spans absent). Claude reasons
> from that structural signal to INCIDENT + PAGE_ONCALL.

**Expected alerts.log:**
```
════════════════════════════════════════════════════════════════════════
[2026-04-01 05:47:30 UTC]  DETECTION
  anomaly type         : NEW_FINGERPRINT
  environment          : <env>
  service              : api-gateway
  message              : Trace path drift on 'api-gateway:GET vets-service' (OTel edge detector)
  detail               : Path: api-gateway:GET vets-service
────────────────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════════════════
[2026-04-01 05:47:30 UTC]  TRIAGE
  severity             : INCIDENT
  confidence           : HIGH
  environment          : <env>
  affected services    : vets-service, api-gateway
  root cause           : vets-service is down or network-isolated — trace path drift
                         detected by OTel edge processor on 'api-gateway:GET vets-service'
  action               : PAGE_ONCALL
  narrative            : The OTel collector edge processor detected a structural change
                         in the 'api-gateway:GET vets-service' trace path 10 seconds after
                         vets-service became unreachable. The on-call engineer should
                         immediately check the health and pod status of vets-service.
────────────────────────────────────────────────────────────────────────
```

**Key talking points:**
- *"No alert rules. No thresholds. The OTel processor learned the normal call graph at baseline time — api-gateway always calls vets-service on this path — and detected the deviation as the first affected trace flowed through."*
- *"There's no poll interval. The event fired at the edge, inside the collector, within 10 seconds. We queried Splunk for it 30 seconds later — just to cover indexing lag."*
- *"Claude reads exactly what was detected — one clean anomaly — and reasons about it: INCIDENT, HIGH confidence, PAGE_ONCALL."*
- *"Total time from kill to triage: under 1 minute."*

### Step 4 — Restore
```bash
./demo/demo-between.sh
```

---

## Demo 4: Correlated Anomaly — Two Tiers Fire Simultaneously

**Story:** *"Both vets-service AND the database go down at the same time. The trace tier detects MISSING_SERVICE across multiple paths. The error tier detects new CannotCreateTransactionException signatures. `correlate.py` joins trace + error signals on the same service and emits a `[Major] TIER2_TIER3` correlated event — the framework immediately maps the blast radius across all affected services from a single command."*

### Prerequisites
```bash
./demo/demo-quick-reset.sh

# Verify 0 trace anomalies
python3 core/trace_fingerprint.py --environment $ENV watch --window-minutes 5
# Expected: "All trace paths match baseline"
```

### Step 1 — Kill both vets-service and petclinic-db simultaneously
```bash
k "kubectl scale deployment vets-service --replicas=0 && kubectl scale deployment petclinic-db --replicas=0"
```

### Step 1b — Watch OTel real-time detection (while the countdown runs)
In a third terminal tab, stream drift events directly from the OTel edge processor:
```bash
python3 -u demo/poll_drift_events.py
```

Within **10–15 seconds** you'll see both `trace.path.drift` (vets-service gone) and `error.signature.drift` (DB errors) fire simultaneously.

### Step 3 — Run triage directly from OTel logs (no Splunk wait)
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

**Expected terminal output:**
```
[agent] env=<env> | 7 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — The database backing customers-service is unreachable, causing transaction
    failures, 500 errors at the api-gateway, and complete silence on several trace paths.
    Root cause: Shared database dependency is down — customers-service throws
    CannotCreateTransactionException, cascading into 500s at api-gateway.
    vets-service is also absent from all traces.
    Confidence: HIGH | Affected: api-gateway, customers-service, vets-service
    Recommended action: PAGE_ONCALL

    [TRIAGE SUMMARY] written to alerts.log
    [PAGE_ONCALL] event emitted to Splunk
```

The 7 anomalies:
- `NEW_FINGERPRINT` ×2 on `GET customers-service` — truncated traces (DB call started but never completed)
- `MISSING_SERVICE` — `api-gateway:GET vets-service` — vets-service pod down
- `MISSING_SERVICE` — `api-gateway:GET /api/gateway/owners/{ownerId}` — owner detail path silent
- `MISSING_SERVICE` — `api-gateway:PUT customers-service` — write path silent (can't open DB transaction)
- `NEW_ERROR_SIGNATURE` — `CannotCreateTransactionException` in customers-service
- `NEW_ERROR_SIGNATURE` — `500 on GET customers-service` in api-gateway

### Step 3b — Run correlate.py to see TIER2_TIER3 cross-tier correlation
```bash
python3 core/correlate.py --environment $ENV --window-minutes 20
```

**Expected output:**
```
[correlate] Fetching anomaly + deployment events in parallel (environment '<env>')...
  Found 18 anomaly events across 2 tier(s)
    tier2: 10 event(s)
    tier3: 8 event(s)

  Found 2 correlated anomaly group(s):

  [Major] TIER2_TIER3 — api-gateway
    Tiers:         tier2, tier3
    Anomaly types: MISSING_SERVICE, NEW_ERROR_SIGNATURE, NEW_FINGERPRINT
    Events:        14 over 92s
    - New error signature in api-gateway: 500 on GET customers-service
    - No traces for 'api-gateway:GET vets-service' in window — expected service(s) absent
    - No traces for 'api-gateway:PUT customers-service' in window — expected service(s) absent

  [Major] TIER2_TIER3 — customers-service
    Tiers:         tier2, tier3
    Anomaly types: MISSING_SERVICE, NEW_ERROR_SIGNATURE
    Events:        4 over 88s
    - New error signature in customers-service: org.springframework.transaction.CannotCreateTransactionException on GET /owners

  Event sent for api-gateway (behavioral_baseline.correlated_anomaly)
  Event sent for customers-service (behavioral_baseline.correlated_anomaly)
```

> **Note:** Exact event counts vary. Key indicator: `TIER2_TIER3` on both api-gateway and customers-service, showing trace structural silence AND new error signatures on the same services simultaneously.

**Key talking points:**
- *"Tier 2 alone: could be a canary deploy. Tier 3 alone: could be noise. Both firing on the same service at the same time? That's high-confidence — TIER2_TIER3 escalates to Major immediately."*
- *"correlate.py is the join layer. It groups trace drift + error signals by service and surface blast radius in one pass."*
- *"Without correlation: you'd get separate alerts from separate detectors with no common thread. With it: one correlated event per affected service, full context attached."*
- *"If AutoDetect also fires later, it upgrades automatically to `[Critical] MULTI_TIER`. The framework gets sharper as more evidence accumulates."*

### Step 4 — Restore
```bash
./demo/demo-between.sh --db
```

---

## Demo 5: Deploy-Correlated Severity Downgrade

**Story:** *"A deploy of vets-service is announced via `notify_deployment.py`. The deploy is bad — vets-service crashes immediately on startup. Anomalies fire: trace tier detects MISSING_SERVICE, error tier detects new WebClientRequestException and 503 signatures. On its own, agent.py calls it INCIDENT + PAGE_ONCALL. But `correlate.py` finds the deployment event in its window and downgrades severity from Major → Minor, annotating it as `[deployment-correlated]`. The on-call gets context: this looks like a deploy regression, not a random outage."*

### Prerequisites
```bash
./demo/demo-quick-reset.sh

# Verify 0 anomalies
python3 core/trace_fingerprint.py --environment $ENV watch --window-minutes 5
# Expected: "All trace paths match baseline"
```

### Step 1 — Announce the deployment, then immediately kill vets-service
```bash
# Notify the framework that a deploy is happening
python3 demo/notify_deployment.py --service vets-service --environment $ENV \
  --version v2.1.0 --description "Update vet specialties endpoint"

# Simulate bad deploy (service crashes on startup)
k "kubectl scale deployment vets-service --replicas=0"
```

### Step 2 — Run triage directly from OTel logs (no Splunk wait)
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

This blocks until drift events arrive from the OTel processor (~10-15s after the kill), collects for 5s, then triages immediately.

**Expected terminal output:**
```
[agent] env=<env> | 2 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — The vets-service is completely unreachable, causing 503 errors at the
    api-gateway for all GET vets-service requests.
    Root cause: vets-service is down or unreachable — it is absent from all traces and
    the api-gateway is returning 503s when attempting to call it.
    Confidence: HIGH | Affected: vets-service, api-gateway
    Recommended action: PAGE_ONCALL

    [TRIAGE SUMMARY] written to alerts.log
    [PAGE_ONCALL] event emitted to Splunk
```

### Step 3 — Run correlate.py (sees the deployment event → downgrades severity)
```bash
python3 core/correlate.py --environment $ENV --window-minutes 55
```

**Expected output:**
```
[correlate] Fetching anomaly + deployment events in parallel (environment '<env>')...
  Found 9 anomaly events across 2 tiers
    tier2: 7 event(s)
    tier3: 2 event(s)
  Found 1 deployment event(s) in last 60m:
    vets-service  version=v2.1.0  deployer=n/a

  Found 1 correlated anomaly group(s):

  [Minor] TIER2_TIER3 — api-gateway  [deployment-correlated]
    Tiers:         tier2, tier3
    Anomaly types: MISSING_SERVICE, NEW_ERROR_SIGNATURE
    Events:        9 over 901s
    Deployment:    version=v2.1.0  commit=n/a  deployer=n/a
                   "Update vet specialties endpoint"
    - No traces for 'api-gateway:GET /api/gateway/owners/{ownerId}' in window — expected service(s) absent
    - No traces for 'api-gateway:GET vets-service' in window — expected service(s) absent
    - No traces for 'api-gateway:PUT customers-service' in window — expected service(s) absent

  Event sent for api-gateway (behavioral_baseline.correlated_anomaly)
```

**Key talking points:**
- *"agent.py fires INCIDENT + PAGE_ONCALL because it only sees signals — it doesn't know about the deployment."*
- *"correlate.py is the deployment-aware layer. It queries Splunk for `deployment.started` events emitted by your CI/CD pipeline and matches them against anomaly timing."*
- *"Severity downgrade: Major → Minor. The on-call still gets notified — but at lower urgency with the context 'this is correlated to the v2.1.0 deploy of vets-service'."*
- *"The key insight: you call `notify_deployment.py` from your CI/CD pipeline once. From that point on, every anomaly that fires within 60 minutes of a deploy gets automatically annotated and downgraded. Zero manual work per deployment."*

### Step 4 — Restore
```bash
./demo/demo-between.sh
```

---

## Demo 6: Self-Healing — Live Auto-Promotion

**Story:** *"A deploy of vets-service changes its trace structure. The new call path fires NEW_FINGERPRINT on the first watch run — then again on the second. On the second hit, the framework auto-promotes it: the new path is accepted as baseline with zero human intervention. By the third watch run, silence. The framework learned the new normal entirely on its own."*

### Prerequisites
```bash
./demo/demo-quick-reset.sh

# Simulate a deploy: remove vets-service fingerprints from baseline
# (represents a deployment that changed the call path)
python3 -c "
import json, pathlib, os
e = os.environ['ENV']
p = pathlib.Path(f'data/baseline.{e}.json')
b = json.loads(p.read_text())
fps = b['fingerprints']
removed = [h for h, info in fps.items()
           if info.get('root_op','').startswith('vets-service:')
           or 'vets' in info.get('root_op','').lower()]
for h in removed: del fps[h]
p.write_text(json.dumps(b, indent=2))
print(f'Removed {len(removed)} vets fingerprint(s) — simulating new deploy')
"
```

### Watch run 1 — NEW_FINGERPRINT fires, watch_hits=1
```bash
AUTO_PROMOTE_THRESHOLD=2 python3 core/trace_fingerprint.py --environment $ENV watch --window-minutes 5
```

**Expected output:**
```
  ANOMALY DETECTED
    Type:    NEW_FINGERPRINT
    Message: Unknown execution path for 'api-gateway:GET vets-service'
    Detail:  Path: api-gateway:GET vets-service -> api-gateway:GET -> vets-service:GET /vets -> ...
    TraceID: 480b3c097b6f49d9d2d0cacbc3452f6d
    Event sent (trace.path.drift)

  Checked 27 traces, 173 skipped, 1 anomalies detected
  Per-service breakdown:
    api-gateway                          27 traces checked  [1 anomaly]
  Downstream services seen: customers-service, vets-service, visits-service
```

*Talking point: "The framework sees a path it doesn't know. It alerts — but doesn't immediately accept it. It needs to see this consistently before trusting it."*

### Watch run 2 — auto-promotes (watch_hits=2 ≥ threshold)
```bash
AUTO_PROMOTE_THRESHOLD=2 python3 core/trace_fingerprint.py --environment $ENV watch --window-minutes 5
```

**Expected output:**
```
  ANOMALY DETECTED
    Type:    NEW_FINGERPRINT
    Message: Unknown execution path for 'api-gateway:GET vets-service'
    Detail:  Path: api-gateway:GET vets-service -> api-gateway:GET -> ...
    TraceID: 2e27c87771595231cc4ed1a000d314de
    Event sent (trace.path.drift)

  AUTO-PROMOTED: 31ddc9717bc4e16a... (seen 2 watch runs) root_op=api-gateway:GET vets-service
  Baseline saved -> data/baseline.<env>.json  (19 fingerprints)

  Checked 18 traces, 182 skipped, 1 anomalies detected, 1 auto-promoted
```

*Talking point: "Seen twice consistently — promoted. The new path is now baseline. No human involved."*

### Watch run 3 — completely silent
```bash
AUTO_PROMOTE_THRESHOLD=2 python3 core/trace_fingerprint.py --environment $ENV watch --window-minutes 5
```

**Expected output:**
```
  Checked 24 traces, 176 skipped, 0 anomalies detected
  All trace paths match baseline
```

*Talking point: "Zero anomalies. The framework adapted. No alert fatigue from a known-good deploy."*

**Key talking points:**
- *"No threshold to configure. 2 (or 5 in production) consecutive detections before acceptance — tunable via `AUTO_PROMOTE_THRESHOLD`."*
- *"The framework learned the new normal on its own. After a deployment, new trace paths stop firing within 2 watch cycles. Zero alert fatigue."*
- *"In production, `baseline-agent` runs `baseline_healer.py` every 2 minutes. When anomaly rate spikes then drops to zero (incident resolved), it scores pre-incident windows by error rate + trace diversity and re-learns the cleanest one automatically."*

### Restore
```bash
# Relearn baseline to restore vets fingerprint
python3 core/trace_fingerprint.py --environment $ENV learn --reset --window-minutes 30 --window-offset-minutes 3
python3 core/trace_fingerprint.py --environment $ENV promote
```

---

## Demo 7: Auto-Onboarding a New Environment

**Story:** *"A new environment shows up in Splunk APM — a team just deployed their first instrumented services. `onboard.py --auto` discovers it automatically, builds baselines from live traffic, creates a dashboard, and generates a runbook via Claude. Zero manual configuration. The framework is fully operational for the new environment in one command. In the cluster, `baseline-agent` picks it up on its next 6h onboard cycle."*

> **Why this is last:** `onboard.py --auto` re-learns baselines from the last 120 minutes (which may include outage errors from earlier demos). Running it last means there's no cleanup needed before subsequent demos.

### Prerequisites
```bash
# Back up onboarding state so we can restore after
cp data/onboarding_state.json data/onboarding_state.json.bak

# Remove the environment from onboarding state to simulate a new environment
python3 -c "
import json, os
e = os.environ['ENV']
with open('data/onboarding_state.json') as f:
    state = json.load(f)
del state['environments'][e]
with open('data/onboarding_state.json', 'w') as f:
    json.dump(state, f, indent=2)
print(f'Simulated: {e} removed from known environments')
"
```

### Step 1 — Preview what --auto would do (dry run)
```bash
python3 onboard.py --auto --dry-run
```

**Expected output:**
```
[onboard] Discovering all active environments...
  <env>: 7 services — [api-gateway, customers-service, ...]

[onboard] Diff results:
  New environments:     ['<env>']
  Updated environments: —

[onboard] [DRY RUN] Acting on changes...

  [new] <env>
    $ python3 core/trace_fingerprint.py --environment <env> learn --window-minutes=120
      [dry-run] skipped
    Provisioning dashboard for environment '<env>'...
      [dry-run] Would create dashboard: Behavioral Baseline — <env>
      [dry-run] skipped
    [dry-run] Would add 8 cron job(s) for '<env>'
    [dry-run] Would add 2 global cron job(s)

[onboard] Dry run complete — no changes written.
```

### Step 2 — Run for real
```bash
python3 onboard.py --auto
```

**Expected output:**
```
[onboard] Discovering all active environments...
  <env>: 7 services — ['api-gateway', 'config-server', 'customers-service', 'discovery-server', 'vets-service', 'visits-service']
  unknown: 1 services — ['admin-server']

[onboard] Diff results:
  New environments:     ['<env>']
  Updated environments: —

[onboard] Acting on changes...

  [new] <env>
    $ python3 core/trace_fingerprint.py --environment <env> learn --window-minutes=120
    $ python3 core/error_fingerprint.py --environment <env> learn --window-minutes=120
    Dashboard created: HEwtJd2A0As (group: HD0uRkOA0AE)
    Added 8 cron job(s) for '<env>'
    Added 2 global cron job(s)
    /Users/mbui/Documents/o11y-behaviorbaseline/agents/RUNBOOK.<env>.md already exists. Use --force to regenerate.
    State saved -> data/onboarding_state.json

[onboard] Done.
```

> The runbook line shows "already exists" because it was generated in a prior session. In a truly fresh environment it generates automatically. Use `--force` on `runbook_generator.py` to regenerate.

### Step 3 — Restore
```bash
# Restore onboarding state from backup
cp data/onboarding_state.json.bak data/onboarding_state.json
echo "Onboarding state restored."
```

**What was created in ~60 seconds:**
- Trace fingerprint baseline: structural call path patterns learned from live traffic
- Error signature baseline: known-good error patterns from live traffic
- Dashboard: linked to the Behavioral Baseline dashboard group
- Runbook: `RUNBOOK.<env>.md` generated by Claude with service topology context

> **Note:** Error rate, latency, and request rate detectors are already live via Splunk APM AutoDetect — no provisioning needed. This framework adds the behavioral layer on top.

**Key talking points:**
- *"No YAML. No alert rules. No thresholds to configure. The framework reads the live APM topology, learns what normal looks like, and is ready to detect anomalies — all from a single command."*
- *"Metric-based alerts (error rate, latency, request rate) are already covered by Splunk's built-in APM AutoDetect for every environment with traces flowing. This framework adds a second layer: structural drift, new error signatures, cross-tier correlation."*
- *"`baseline-agent` runs `onboard.py --auto` every 6 hours. If your platform team deploys a new environment on Monday morning, it's onboarded by Monday morning. Zero human intervention."*
- *"The runbook is generated by Claude from the actual service topology — not a generic template. It knows which services call the DB, which are ingress, and what dependencies exist."*

---

## How it works (30-second explanation)

```
LEARN  →  Search each service independently (up to 200 traces each, parallel)
          Build fingerprints: "api-gateway always calls vets-service on GET /vets"
          Build error signatures: "customers-service has no DB errors in healthy state"

          --bootstrap flag: for fresh clusters with <30 min of traffic
            Accepts fingerprints seen ≥1 time (vs default min=3)
            Drops seen-once entries after learning (consolidation pass)
            Merges auto-promoted entries from OTel ConfigMap automatically

WATCH  →  Two paths:

  Fast path (OTel edge, ~10s latency):
          OTel Collector processor fingerprints every trace as it flows through
          DRIFT → emits trace.path.drift / error.signature.drift to its own logs
          demo/poll_drift_events.py --triage tails logs directly → JSON (no Splunk wait)

  Slow path (Python APM polling, ~1-5 min):
          Sample traces from the last N minutes via Splunk APM API
          Trace tier:  known root_op has zero traces → MISSING_SERVICE anomaly
          Error tier:  new error type seen → NEW_ERROR_SIGNATURE anomaly
          Output as JSON

TRIAGE →  Claude reads the JSON anomaly list
          Reasons about severity, root cause, action
          Writes DETECTION + TRIAGE to alerts.log
```

Fast path — triage directly from OTel logs (used in all demos, no Splunk indexing wait):
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV \
  | python3 agent.py --environment $ENV
```

Slow path — Python APM polling (used in Demo 6 auto-promotion only):
```bash
(python3 core/trace_fingerprint.py --environment $ENV watch --window-minutes 5 --json && \
 python3 core/error_fingerprint.py --environment $ENV watch --window-minutes 5 --json) \
  | python3 agent.py --environment $ENV
```

---

## Restore / Reset

**Quick reset between demos** (local state only, ~5 seconds):
```bash
./demo/demo-quick-reset.sh
```
Clears alerts.log, wipes error baseline, clears dedup state. No cluster ops.

**Full reset** (before first demo or after a messy run):
```bash
./demo/demo-reset.sh
```

If you need to also re-learn the trace baseline from scratch (e.g. after a full topology change):

```bash
python3 core/trace_fingerprint.py --environment $ENV learn --reset --window-minutes 60
python3 core/trace_fingerprint.py --environment $ENV promote

# Push updated baseline to cluster
sshpass -p "$EC2_PASSWORD" scp -P 2222 data/baseline.$ENV.json splunk@$EC2_IP:/tmp/baseline.json
k "kubectl delete configmap behavioral-baseline --ignore-not-found && \
   kubectl create configmap behavioral-baseline \
     --from-file=baseline.json=/tmp/baseline.json \
     --from-file=error_baseline.json=/tmp/error_baseline.json && \
   B64=\$(base64 -w 0 /tmp/baseline.json); \
   for pod in \$(kubectl get pods -l app=otelcol-fingerprint -o jsonpath='{.items[*].metadata.name}'); do \
     kubectl exec \$pod -c otelcol -- sh -c \"echo '\$B64' | base64 -d > /baseline/baseline.json\"; \
   done && echo 'Baseline pushed to all pods'"
```

For cold-start re-learn on a fresh cluster:
```bash
python3 core/trace_fingerprint.py --environment $ENV learn --bootstrap --window-minutes 30
python3 core/trace_fingerprint.py --environment $ENV promote
```
