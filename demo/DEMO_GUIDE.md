# Behavioral Anomaly Framework — Demo Guide

---

## Signal Types — What You're Looking At

The framework emits four distinct anomaly signals. Each demo triggers one or more of these.

| Signal | What it means | Demo |
|--------|--------------|------|
| `NEW_FINGERPRINT` | A trace took a call path that has never been seen before — a new service was called, or an existing one was skipped. Fires on the **first occurrence**. | Demo 2 |
| `MISSING_SERVICE` | A root operation that normally involves a specific service produced **zero traces** in the detection window — the service is structurally absent, not just erroring. | Demo 1, 4, 5, 8 |
| `NEW_ERROR_SIGNATURE` | A span produced an exception or error type that has never appeared in this service before. Fires on **first occurrence**, no threshold required. | Demo 3, 4, 5 |
| `AUTODETECT_TIER1` | Splunk APM's built-in AutoDetect fired a metric-based alert (error rate spike, latency spike, request drop). This is the **native APM signal** — the framework correlates it with its own structural signals. | Demo 5 (when AutoDetect catches up) |
| `LATENCY_ANOMALY` | Mean latency for a service/operation exceeded 3 standard deviations above its learned baseline. Fires without any threshold configuration — baseline is learned from the first 30 traces. Baseline adapts per hour-of-day × day-of-week (168 seasonal slots). | Demo 6, 9, 10 |
| `ERROR_RATE_ANOMALY` | The fraction of error spans for a service/operation exceeded 5% over a rolling window. Complements NEW_ERROR_SIGNATURE — fires on sustained rate, not just first occurrence. | Demo 7, 8 |
| `SPAN_COUNT_DROP` | A trace has **far fewer spans** than the learned baseline range — DB calls, downstream hops, or method instrumentation silently absent. Catches silent failures that produce no error signal: connection pool exhaustion short-circuiting retries, pipeline collapse, work items dropped without exception. | Demo 11 |
| `SPAN_COUNT_SPIKE` | A trace has **far more spans** than the learned baseline max — retry storm, fan-out explosion, or loop that shouldn't run. Catches retry patterns that don't change the call graph structure and produce no new error type. | Demo 12 |
| `INFRA_EVENT` | Pod-level Kubernetes warning event (OOMKilling, CrashLoopBackOff, BackOff, Evicted) correlated to a service by pod name. Surfaced in the topology UI alongside trace anomalies. Not a Splunk signal — sourced directly from `kubectl get events`. | Demo 10 (topology UI) |

### Correlation types

When multiple signals fire on the same service within a window, `correlate.py` groups them:

| Correlation | Tiers present | Severity |
|-------------|--------------|---------|
| `TIER2_TIER3` | structural absence + new errors | Major |
| `TIER1_TIER2` | AutoDetect + structural absence | Major |
| `TIER1_TIER3` | AutoDetect + new errors | Major |
| `MULTI_TIER` | all three tiers | Critical |

A `[deployment-correlated]` annotation is added when a `deployment.started` event was emitted within 60 minutes, and severity is downgraded one level (Critical→Major, Major→Minor).

### Detection latency

| Layer | Latency | How |
|-------|---------|-----|
| OTel edge processor | ~10s | Fingerprints every trace inline as it flows through the collector |
| MISSING_SERVICE background checker | ~60s | Periodic check inside the OTel processor for root ops gone silent |

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
app pod → otelcol-fingerprint DaemonSet (forwarder) → otelcol-aggregator StatefulSet (fingerprintprocessor) → Splunk APM
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

### Step 6 — Seed and deploy the OTel processor
`deploy.sh` handles everything: ConfigMap creation (including `baseline-sync-scripts`), DaemonSet apply, Instrumentation CR patch, and baseline injection. Run it on EC2 after SCP-ing the source and baseline files.

**On local Mac — copy files to EC2:**
```bash
# Copy otel-processor source (if not done in Step 3)
sshpass -p "$EC2_PASSWORD" scp -P 2222 -r otel-processor/ splunk@$EC2_IP:/home/splunk/

# Copy baselines
sshpass -p "$EC2_PASSWORD" scp -P 2222 \
  data/baseline.$ENV.json splunk@$EC2_IP:/tmp/baseline.$ENV.json
sshpass -p "$EC2_PASSWORD" scp -P 2222 \
  data/error_baseline.$ENV.json splunk@$EC2_IP:/tmp/error_baseline.$ENV.json
```

**Create required secrets (on EC2, if not already present):**
```bash
k "kubectl create secret generic splunk-api-token \
  --from-literal=token=$SPLUNK_ACCESS_TOKEN --dry-run=client -o yaml | kubectl apply -f -"
```

**Run deploy.sh (on EC2):**
```bash
k "mkdir -p /home/splunk/otel-processor/data && \
   cp /tmp/baseline.$ENV.json /home/splunk/otel-processor/data/baseline.$ENV.json && \
   cp /tmp/error_baseline.$ENV.json /home/splunk/otel-processor/data/error_baseline.$ENV.json && \
   cd /home/splunk/otel-processor && bash deploy.sh $ENV --skip-learn --skip-build"
```

`deploy.sh` runs these steps automatically:
1. Seeds `behavioral-baseline` ConfigMap (baseline + error baseline)
2. Creates `baseline-sync-scripts` ConfigMap from `k8s/baseline-sync-sidecar.py`
3. Patches the OTel Instrumentation CR → otelcol-fingerprint
4. Deploys `aggregator.yaml` (StatefulSet + headless Service + ConfigMap) — must be ready before DaemonSet
5. Applies `daemonset.yaml` (DaemonSet forwarder, config, RBAC, Service)
6. Restarts DaemonSet and waits for rollout
7. Injects baseline directly into running pods — both DaemonSet AND aggregator (immediate — no 60s reload wait)

> **Note:** `aggregator.yaml` includes `missing_service_check_interval: 45s` and `warmup_duration: 2m` in the collector config — no manual patching needed. Detection events come from the aggregator tier; the DaemonSet is a pure forwarder.

### Step 7 — Verify (local Mac)
```bash
# Should be silent (no false positives):
python3 -u demo/poll_drift_events.py

# Kill visits-service to confirm Demo 1 (kill-service) fires within ~20s:
k "kubectl scale deployment visits-service --replicas=0"
# Expected: trace.path.drift event appears in poll_drift_events.py within ~20s
# Restore:
k "kubectl scale deployment visits-service --replicas=1"
```

### Re-deploy (subsequent sessions, image already built)
```bash
# Push updated baselines + re-deploy config (no build or Instrumentation patch needed)
sshpass -p "$EC2_PASSWORD" scp -P 2222 \
  data/baseline.$ENV.json splunk@$EC2_IP:/tmp/baseline.$ENV.json
sshpass -p "$EC2_PASSWORD" scp -P 2222 \
  data/error_baseline.$ENV.json splunk@$EC2_IP:/tmp/error_baseline.$ENV.json
k "mkdir -p /home/splunk/otel-processor/data && \
   cp /tmp/baseline.$ENV.json /home/splunk/otel-processor/data/baseline.$ENV.json && \
   cp /tmp/error_baseline.$ENV.json /home/splunk/otel-processor/data/error_baseline.$ENV.json && \
   cd /home/splunk/otel-processor && bash deploy.sh $ENV --skip-learn --skip-build"
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

This checks all pre-demo conditions in one pass:
1. **AWS credentials** — valid STS token (required for Claude/Bedrock triage)
2. **Cluster pods** — all Running, 3 otelcol-fingerprint (forwarder) + 2 otelcol-aggregator (detector) pods present
3. **Baseline fingerprints** — ≥10 fingerprints loaded in the OTel processor
4. **Splunk API** — reachable and authenticated
5. **0 trace anomalies** — aggregator logs show 0 drift events in last 30s
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
6. Strip watch-contaminated trace fingerprints → push OTel baseline from `/tmp/otel_baseline.json` (preferred) or `/tmp/python_baseline.json` to ConfigMap + inject into pods
7. Verify 0 Python trace anomalies
8. Verify 0 OTel events in Splunk (last 3m)

> **If step 8 shows OTel events still present:** the previous demo's events haven't aged out of the 3m window yet. Wait 3 minutes and re-run `./demo/demo-reset.sh` — it is idempotent.

> **After every `demo-reset.sh` or `demo-between.sh`:** restart `poll_drift_events.py` — the DaemonSet pods are cycled and the script captures pod names at startup. Stale pod streams produce no output.

**Between-demo reset** (after a demo that killed a service — ~30 seconds with DB, ~5 seconds without):

```bash
./demo/demo-between.sh          # after demos where only a service was killed (no DB)
./demo/demo-between.sh --db     # after demos where DB was killed (adds 30s wait for reconnect)
./demo/demo-between.sh --quick  # local state only, no cluster ops (same as demo-quick-reset.sh)
```

`demo-between.sh` always: clears alerts.log, wipes error baseline + dedup state, restores all services to replicas=1, **cycles both DaemonSet and aggregator pods** (clears in-memory `missingEmitted`/`seenCounts` state), re-injects baselines into fresh pods, waits 35s for warmup. Script completes in ~90s with `--db`, ~70s without.

> **After `demo-between.sh`:** pod names change — restart `poll_drift_events.py` before the next demo.

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

## Demo 3: New Error Signature — DB Goes Down

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

`--db` restores petclinic-db to replicas=1, waits 30s for services to reconnect, cycles OTel pods, then wipes baselines and dedup state. Script completes in ~90s — ready to kill services immediately after.

> **If the curl verify in demo-between.sh fails:** wait another 30s and re-run `./demo/demo-between.sh --db`. customers-service and visits-service need the DB fully up before accepting requests.

---

## Demo 1: Kill Service — APM Still Green, Framework Already Paged

**Story:** *"vets-service is killed. The APM Service Map shows green — no alert, no incident. APM metrics need time to accumulate before any threshold fires. Meanwhile, the OTel edge processor detected the structural absence on the very first affected trace and fired in ~10 seconds. Claude reads that signal, names vets-service as the root cause, and calls PAGE_ONCALL — all before APM knows anything happened."*

### Prerequisites
```bash
./demo/demo-between.sh --db```

### Step 1 — Open APM Service Map
Point browser at the Splunk APM Service Map for this environment. Confirm all services green, no incidents.

### Step 2 — Kill vets-service
```bash
k "kubectl scale deployment vets-service --replicas=0"
```

### Step 3 — Watch framework fire in real time
In a second terminal tab, stream drift events directly from the OTel edge processor:
```bash
python3 -u demo/poll_drift_events.py
```

Within **10–15 seconds** you'll see `trace.path.drift` and/or `error.signature.drift` printed here. Refresh APM — still green.

> *"The OTel processor fires in ~10 seconds — it fingerprints every trace as it flows through the collector, no polling interval. No alert rule was written. No threshold was set."*

### Step 4 — Run triage (pipe OTel events directly to Claude)
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

**Expected output:**
```
[agent] env=<env> | 2 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — vets-service is absent from traces, causing api-gateway to return 503
    on all GET vets-service requests.
    Root cause: vets-service is down or unreachable.
    Confidence: HIGH | Affected: vets-service, api-gateway
    Recommended action: PAGE_ONCALL

    [TRIAGE SUMMARY] written to alerts.log
    [PAGE_ONCALL] event emitted to Splunk
```

APM still has no alert at this point.

**Key talking points:**
- *"APM metrics need time to accumulate before thresholds fire — minutes, not seconds. The OTel edge processor sees structural changes in the first affected trace. That's the gap."*
- *"No alert rules. No thresholds. The processor learned the normal call graph at baseline time and detected the deviation on the first affected trace."*
- *"Claude reads exactly what was detected — one structural signal — and reasons about it: INCIDENT, HIGH confidence, PAGE_ONCALL. Total time from kill to triage: under 1 minute."*

### Restore
```bash
./demo/demo-between.sh
```

---

## Demo 4: DB Gone Silent — Correlated Anomaly, Two Tiers

**Story:** *"Both vets-service AND the database go down at the same time. Within 10–15 seconds, the error tier detects new DB exception signatures and Claude triages: mysql:petclinic is down, PAGE_ONCALL. Then ~60 seconds later, the structural absence detector independently fires MISSING_SERVICE for vets-service — no traces at all, not even failed ones. Two detection mechanisms, two latencies, one complete picture."*

### Prerequisites
```bash
bash demo/demo-between.sh --db
```

### Step 1 — Kill both vets-service and petclinic-db simultaneously
```bash
k "kubectl scale deployment vets-service --replicas=0 && kubectl scale deployment petclinic-db --replicas=0"
```

### Step 2 — Watch OTel real-time detection
In a second terminal tab, stream drift events directly from the OTel edge processor:
```bash
python3 -u demo/poll_drift_events.py
```

**What you'll see:**
- **~10–15 seconds:** `error.signature.drift` fires — DB errors hitting customers-service and api-gateway
- **~60 seconds:** `trace.path.drift (MISSING_SERVICE)` fires — OTel background checker notices vets-service has gone completely silent

> *"Two detection mechanisms, two different latencies. The error tier fires on the first affected span — ~10 seconds. The structural absence checker fires after 60 seconds of silence. Together they cover the full failure signature."*

### Step 3 — Run triage (fires in ~15s on error signals)
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

Triage fires ~15s after the kill using the default 5s settle window. The error signatures alone are enough for Claude to identify `mysql:petclinic` as root cause with HIGH confidence.

**Expected output:**
```
[agent] env=<env> | 4+ anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — customers-service is failing on all database operations, cascading 500s through api-gateway.
    Root cause: mysql:petclinic database is likely down — customers-service OwnerRepository.findAll is failing, cascading to api-gateway.
    Confidence: HIGH | Affected: customers-service, api-gateway
    Recommended action: PAGE_ONCALL

    [TRIAGE SUMMARY] written to alerts.log
    [PAGE_ONCALL] event emitted to Splunk
```

> *"Root cause in 15 seconds. The error tier alone is enough to page on-call."*

While triage ran on errors, keep watching the live stream terminal — ~60s after the kill:
```
[10:04:09] trace.path.drift (MISSING_SERVICE)
  root_op=api-gateway:GET vets-service  missing=api-gateway,vets-service
```

> *"And now the structural detector fires — vets-service has gone completely silent. Not just erroring, but absent from traces entirely. The framework caught two independent failure modes."*

### Step 3b — Run correlate.py to see TIER2_TIER3 cross-tier correlation

Wait ~60 seconds after the kill for Splunk to index the events, then:

```bash
python3 core/correlate.py --environment $ENV --window-minutes 20
```

**Expected output:**
```
[correlate] Fetching anomaly + deployment events in parallel (environment '<env>')...
  Found 10+ anomaly events across 2 tier(s)
    tier2: 4+ event(s)   ← MISSING_SERVICE from OTel background checker
    tier3: 6+ event(s)   ← error signatures from customers-service, api-gateway

  Found 2 correlated anomaly group(s):

  [Major] TIER2_TIER3 — api-gateway
    Tiers:         tier2, tier3
    Anomaly types: MISSING_SERVICE, NEW_ERROR_SIGNATURE
    Events:        8+ over 60s
    - New error signature in api-gateway: 500 on GET customers-service
    - No traces for 'api-gateway:GET vets-service' in window — expected service(s) absent
    - No traces for 'api-gateway:PUT customers-service' in window — expected service(s) absent

  [Major] TIER2_TIER3 — customers-service
    Tiers:         tier2, tier3
    Anomaly types: MISSING_SERVICE, NEW_ERROR_SIGNATURE
    Events:        4+ over 60s
    - New error signature in customers-service: CannotCreateTransactionException on GET /owners

  Event sent for api-gateway (behavioral_baseline.correlated_anomaly)
  Event sent for customers-service (behavioral_baseline.correlated_anomaly)
```

> **Note:** Exact event counts vary. Key indicator: `TIER2_TIER3` on both api-gateway and customers-service.

**Key talking points:**
- *"Tier 2 (structural absence) alone: could be a canary deploy. Tier 3 (new errors) alone: could be noise. Both firing on the same service simultaneously? That's high-confidence — TIER2_TIER3 escalates to Major immediately."*
- *"The MISSING_SERVICE signal comes entirely from the OTel edge processor — no Python polling, no APM API call. The background checker fires at the edge in ~15 seconds."*
- *"correlate.py is the join layer. It groups trace drift + error signals by service and surfaces blast radius in one pass."*
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
./demo/demo-between.sh --db```

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
  Found 20+ anomaly events across 2 tier(s)
    tier2: 1 event(s)
    tier3: 19+ event(s)
  Found 1 deployment event(s) in last 60m:
    vets-service  version=v2.1.0  deployer=n/a

  Found 1 correlated anomaly group(s):

  [Minor] TIER2_TIER3 — api-gateway  [deployment-correlated]
    Tiers:         tier2, tier3
    Anomaly types: MISSING_SERVICE, NEW_ERROR_SIGNATURE
    Events:        20+ over 355s
    Deployment:    version=v2.1.0  commit=n/a  deployer=n/a
                   "Update vet specialties endpoint"

  Event sent for api-gateway (behavioral_baseline.correlated_anomaly)
```

> **Note:** The deployment match works because `correlate.py` scans the `missing_services` property of MISSING_SERVICE events to find that `vets-service` is affected, then matches it against the deployment for `vets-service`.

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

## Demo 2: New Call Path — Self-Healing Auto-Promotion

**Story:** *"A deploy of vets-service changes its trace structure. The new call path fires NEW_FINGERPRINT on the first watch run — then again on the second. On the second hit, the framework auto-promotes it: the new path is accepted as baseline with zero human intervention. By the third watch run, silence. The framework learned the new normal entirely on its own."*

### Prerequisites
```bash
./demo/demo-between.sh
# Simulate a deploy: remove vets-service fingerprints from baseline
# (represents a deployment that changed the call path)
export $(grep -v '^#' .env | xargs) && python3 -c "
import json, pathlib, os
e = os.environ['ENV']
p = pathlib.Path(f'data/baseline.{e}.json')
b = json.loads(p.read_text())
fps = b['fingerprints']
# Remove api-gateway-rooted vets paths only — these represent the changed call graph.
# Keep vets-service:GET (config-server startup fetch) — it's a transient that fires
# regardless of the deploy and would confuse the demo story.
removed = [h for h, info in fps.items()
           if 'vets' in info.get('root_op','').lower()
           and not info.get('root_op','').startswith('vets-service:')]
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
    TraceID: ...
    Event sent (trace.path.drift)

  ANOMALY DETECTED
    Type:    NEW_FINGERPRINT
    Message: Unknown execution path for 'api-gateway:GET vets-service'
    Detail:  Path: api-gateway:GET vets-service -> api-gateway:GET -> api-gateway:GET -> vets-service:GET /vets -> ...
    TraceID: ...
    Event sent (trace.path.drift)

  Checked 148+ traces, 52 skipped, 2 anomalies detected
  Per-service breakdown:
    api-gateway                         148 traces checked  [2 anomalys]
  Downstream services seen: customers-service, vets-service, visits-service
```

> Two variants of the vets path fire — petclinic traces have slight structural variation (retry spans).
> Both are unknown; each needs 2 consistent hits before promoting.

*Talking point: "The framework sees paths it doesn't know. It alerts — but doesn't immediately accept them. It needs to see them consistently before trusting them."*

### Watch run 2 — fires again + auto-promotes one variant (watch_hits=2)
```bash
AUTO_PROMOTE_THRESHOLD=2 python3 core/trace_fingerprint.py --environment $ENV watch --window-minutes 5
```

**Expected output:**
```
  ANOMALY DETECTED
    Type:    NEW_FINGERPRINT
    Message: Unknown execution path for 'api-gateway:GET vets-service'
    Detail:  Path: api-gateway:GET vets-service -> api-gateway:GET -> vets-service:GET /vets -> ...
    TraceID: ...
    Event sent (trace.path.drift)

  AUTO-PROMOTED: 31ddc9717bc4e16a... (seen 2 watch runs) root_op=api-gateway:GET vets-service
  Baseline saved -> data/baseline.<env>.json  (21 fingerprints)

  Checked 163+ traces, 37 skipped, 1 anomalies detected, 1 auto-promoted
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

> The second variant may also auto-promote silently on run 3 if it reached threshold.

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

## Demo 0b: Auto-Onboarding a New Environment

**Story:** *"A new environment shows up in Splunk APM — a team just deployed their first instrumented services. `onboard.py --auto` discovers it automatically, builds baselines from live traffic, creates a dashboard, and generates a runbook via Claude. Zero manual configuration. The framework is fully operational for the new environment in one command. In the cluster, `baseline-agent` picks it up on its next 6h onboard cycle."*

> **Why this is run after the main demos:** `onboard.py --auto` re-learns baselines from the last 120 minutes (which may include outage errors from earlier demos). Running it last means there's no cleanup needed before subsequent demos.

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
[onboard] Starting at <timestamp>
[onboard] Discovering all active environments...
  <env>: 7 services — ['admin-server', 'api-gateway', 'config-server', 'customers-service', 'discovery-server', 'vets-service', 'visits-service']
  unknown: 1 services — ['admin-server']

[onboard] Diff results:
  New environments:     ['<env>']
  Updated environments: —

[onboard] Acting on changes...

  [new] <env>
    $ python3 core/trace_fingerprint.py --environment <env> learn --window-minutes=120
    Provisioning dashboard for environment '<env>'...
    $ python3 core/error_fingerprint.py --environment <env> learn --window-minutes=120
[learn] Discovering services for environment '<env>'...
[learn] Discovering services for environment '<env>'...
  Found 7 services
  Sampling last 120m of error traces...
  Found 7 services + 2 inferred nodes
  Sampling last 120m of traces...
  Searching 7 services in parallel...
    Dashboard created: <dashboard-id> (group: <group-id>)
    ...
  Found 1059+ candidate traces (deduplicated)
  Fetching 1059+ traces (20 parallel)...
  ...
  Baseline saved -> data/baseline.<env>.json  (22 fingerprints)
    Cron jobs for '<env>' already present — skipping
[runbook-generator] Generating runbook for '<env>'...
  9 services: admin-server, api-gateway, config-server, customers-service, discovery-server, localhost:8888, mysql:petclinic, vets-service, visits-service
  Calling Claude (Bedrock) to write runbook...
  ✅ Runbook written to agents/RUNBOOK.<env>.md (14000+ chars)
  State saved -> data/onboarding_state.json

[onboard] Done.
```

> **Timing:** the full run takes **2–3 minutes** — trace learn fetches 1000+ traces in parallel, and the Claude runbook generation adds ~30–60s. Plan accordingly when demoing.

> **Cron jobs line:** shows "already present — skipping" because onboarding ran before. In a truly fresh environment it adds 8 cron jobs for the new env + 2 global jobs.

### Step 3 — Restore
```bash
# Restore onboarding state from backup
cp data/onboarding_state.json.bak data/onboarding_state.json
echo "Onboarding state restored."
```

**What was created in ~2-3 minutes:**
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

## Demo 6: Latency Spike — Service Slowdown Detection

**Story:** *"visits-service is running normally. The OTel processor silently learns its latency baseline from the first 30 traces. We then inject 3 seconds of network delay. The processor detects the z-score spike on the very next trace and fires LATENCY_ANOMALY — no threshold configured, no alert rule written. Claude triages: DEGRADED, latency spike on visits-service, investigate immediately."*

### Prerequisites
```bash
./demo/demo-between.sh
# Wait 2 minutes for the learn phase before injecting — pods need ~30 traces to build baseline
```

### Step 1 — Open live stream (second terminal)
```bash
python3 -u demo/poll_drift_events.py
```

### Step 2 — Inject latency and triage
```bash
./demo/demo-latency.sh
```

This injects 3s of network delay into `visits-service` via `tc-netem` (no code change, no redeploy), waits for `LATENCY_ANOMALY` to fire, triages with Claude, then removes the delay automatically.

**Expected output:**
```
=== Demo 7: LATENCY_ANOMALY — env=<env> ===
[4] Injecting 3000ms network delay into visits-service via tc-netem...
    Delay active. visits-service spans will spike from ~3ms baseline to ~753ms.
    Expected: LATENCY_ANOMALY fires within ~10s

[5] Running triage — waiting for LATENCY_ANOMALY events...
  [HH:MM:SS] 1 event(s) received — settling for 5s...

[agent] env=<env> | 1 anomaly(s) from watch
  Reasoning with Claude...

[!] DEGRADED — visits-service is experiencing a severe latency spike (~750ms vs 3ms baseline,
    z-score >8000). Root cause: network-level delay injected on the service or a slow downstream
    dependency. Investigate infrastructure and recent changes to visits-service immediately.
    Confidence: HIGH | Affected: visits-service, api-gateway
    Recommended action: RELEARN_BASELINE

[6] Removing latency injection...
    visits-service back to normal latency.
```

**Options:**
```bash
./demo/demo-latency.sh --inject   # inject only, triage manually
./demo/demo-latency.sh --stop     # remove delay without running triage
```

**Key talking points:**
- *"No threshold was set. The processor learned the normal latency distribution from the first 30 traces — ~2 minutes of live traffic. Everything after that is automatic."*
- *"3ms baseline to 753ms current — z-score of 8496. The processor fires on the very first affected trace, not after minutes of metric accumulation."*
- *"This is injected at the network layer with no code change. In production this could be a slow DB query, a saturated connection pool, or a noisy neighbor on the same node."*

### Restore
```bash
./demo/demo-between.sh
```

---

## Demo 7: Error Rate Anomaly — Sustained Failure Detection

**Story:** *"The database goes down. customers-service starts throwing CannotCreateTransactionException on every DB call. Two signals fire in sequence: NEW_ERROR_SIGNATURE on the very first error span (~10s), then ERROR_RATE_ANOMALY once the error rate crosses 5% over 10+ samples (~30s). Claude receives both signals together and triages: INCIDENT, database connectivity failure, PAGE_ONCALL."*

> **Difference from Demo 3:** Demo 3 shows NEW_ERROR_SIGNATURE (first occurrence, no threshold). Demo 7 shows ERROR_RATE_ANOMALY — the *metric* signal that fires when errors are sustained, even if the error type was seen before. Together they give complete coverage: first occurrence AND ongoing rate.

### Prerequisites
```bash
./demo/demo-between.sh --db
```

### Step 1 — Open live stream (second terminal)
```bash
python3 -u demo/poll_drift_events.py
```

Watch for the two signals arriving in sequence:
- `~10s`: `error.signature.drift` — NEW_ERROR_SIGNATURE
- `~30s`: `service.error.rate.anomaly` — ERROR_RATE_ANOMALY

### Step 2 — Run the demo
```bash
./demo/demo-error-rate.sh
```

Kills the DB, waits 90s for errors to accumulate, restores the DB, then runs triage automatically.

**Expected output:**
```
[3] Killing petclinic-db...
    DB down. customers-service will start throwing DB errors within ~5s.

    Expected signals (in order):
      ~10s  : NEW_ERROR_SIGNATURE  — first CannotCreateTransactionException
      ~30s  : ERROR_RATE_ANOMALY   — error rate > 5% over 10+ error samples

[agent] env=<env> | 15 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — customers-service is experiencing severe latency (~10s) and new 500 errors
    on GET /owners cascading upstream to api-gateway.
    Root cause: customers-service OwnerRepository.findAll is timing out — most likely a
    database connectivity issue or resource exhaustion on the backing data store.
    Confidence: HIGH | Affected: customers-service, api-gateway
    Recommended action: PAGE_ONCALL
```

**Options:**
```bash
./demo/demo-error-rate.sh --keep     # leave DB down, triage manually
./demo/demo-error-rate.sh --restore  # restore DB only
```

**Key talking points:**
- *"Two signals, two different detection mechanisms. NEW_ERROR_SIGNATURE fires on first occurrence — no count needed. ERROR_RATE_ANOMALY fires when the rate is sustained above 5% — catches cases where the error type was seen before but is now happening at scale."*
- *"Together they give complete coverage: you know immediately when a new failure mode appears, and you know when it's not just a blip but an ongoing problem."*
- *"Claude receives both signals in one window and reasons about them together — INCIDENT, HIGH confidence, PAGE_ONCALL. Total time from DB kill to triage: under 2 minutes."*

### Restore
```bash
./demo/demo-between.sh --db
```

---

## Demo 8: Combined Signal — All Three Tiers Simultaneously

**Story:** *"Two things go wrong at once: vets-service is killed and the database goes down. Within 90 seconds, three distinct signal types fire: NEW_ERROR_SIGNATURE from DB exceptions, MISSING_SERVICE from vets-service going structurally absent, and ERROR_RATE_ANOMALY from the sustained DB error rate. Claude receives all three in one triage window and correlates them — naming both mysql:petclinic and vets-service as root causes, INCIDENT, PAGE_ONCALL."*

### Prerequisites
```bash
./demo/demo-between.sh --db
```

### Step 1 — Open live stream (second terminal)
```bash
python3 -u demo/poll_drift_events.py
```

Watch the three signals arrive in order:
- `~10s`: `error.signature.drift` — DB exceptions on customers-service
- `~15s`: `trace.path.drift (MISSING_SERVICE)` — vets-service absent
- `~30s`: `service.error.rate.anomaly` — error rate crosses threshold

### Step 2 — Run the demo
```bash
./demo/demo-combined.sh
```

Kills both services simultaneously, collects all signals for 75s, triages with Claude, then restores.

**Expected output:**
```
[3] Killing vets-service AND petclinic-db simultaneously...

    Both down. Expected timeline:
      ~10s  : NEW_ERROR_SIGNATURE  — DB exceptions on customers-service
      ~15s  : MISSING_SERVICE      — vets-service absent from traces
      ~30s  : ERROR_RATE_ANOMALY   — error rate > 5% on customers-service

[agent] env=<env> | 37 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — Multiple core services are missing from traces and producing new error
    signatures, indicating a cascading outage from a shared infrastructure failure.
    Root cause: mysql:petclinic database is down (customers-service DB errors) and
    vets-service is completely unreachable (absent from all traces).
    Confidence: HIGH | Affected: api-gateway, customers-service, vets-service
    Recommended action: PAGE_ONCALL
```

**Key talking points:**
- *"Three detection mechanisms, one triage. Structural absence, new error signatures, and metric anomaly — all firing independently, all correlated by Claude in a single pass."*
- *"This is the scenario that defeats threshold-based alerting: vets-service going silent produces no metric spike — it just disappears from traces. Only structural detection catches it."*
- *"Claude names both root causes from the combined signal set. This is the full picture that no single detection layer can produce alone."*

### Restore
```bash
./demo/demo-between.sh --db
```

---

## Demo 10: Live Topology UI — Confidence Scoring, User Impact, Infra Correlation

## Demo 9: Slow DB — Correlated Latency Across All Callers

**Story:** *"The database is still up and reachable, but it's overloaded — every service that calls it starts slowing down simultaneously. No structural drift fires (the DB is still in the traces). Instead, mysql:petclinic scores highest in root-cause confidence because it's the shared node whose latency anomaly fired first and whose callers (customers-service, vets-service, visits-service) all show correlated spikes."*

### Prerequisites
```bash
./demo/demo-between.sh
```

### Step 1 — Start the topology server (if not already running)
```bash
python3 demo/topology_server.py --environment $ENV
# Open http://localhost:8080
```

### Step 2 — Inject the slow-db scenario
Click **9 Slow DB** in the topology UI, or run:
```bash
curl -s http://localhost:8080/api/demo/slow-db | jq .
```

**What fires (in sequence, ~500ms apart):**
- `LATENCY_ANOMALY` — mysql:petclinic: 4200ms (baseline 12ms, z=18.4)
- `LATENCY_ANOMALY` — customers-service: 4350ms (baseline 38ms, z=14.2)
- `LATENCY_ANOMALY` — vets-service: 4180ms (baseline 15ms, z=16.9)
- `LATENCY_ANOMALY` — visits-service: 4290ms (baseline 22ms, z=15.7)

**What you see in the topology UI:**
- All four nodes turn amber simultaneously
- Root-cause panel identifies mysql:petclinic with high confidence (fired first, all callers affected)
- No structural drift — the DB is still reachable, just slow

**Key talking points:**
- *"Every service calling the DB slows down in lockstep. No threshold was tuned — each service has its own learned baseline, and each one independently detects a z-score spike."*
- *"The root-cause score uses topology: mysql:petclinic is the shared dependency of all three slow services. Caller fraction = 3/3 = 100%, so it wins the confidence race even without a MISSING_SERVICE signal."*
- *"This is the case that kills threshold alerting — each service's latency looks like a separate problem. The framework sees a shared cause from the topology."*

### Restore
```bash
curl -s http://localhost:8080/api/clear
```

---

**Story:** *"This is the visual layer on top of everything the framework knows. Every signal type, root cause chain, and infra event renders live on the service dependency graph. Five new capabilities surface here that go beyond what APM's topology map shows: probabilistic root cause confidence, user impact estimation, pod-level infra event correlation, topology-aware downstream suppression, and a seasonal latency baseline. Each can be demonstrated independently via the scenario buttons — no cluster changes needed."*

### Start the topology server

```bash
python3 demo/topology_server.py --environment $ENV
# Open http://localhost:8080
```

The server connects to the EC2 cluster over SSH to tail OTel collector logs in real time. The topology is built from the local baseline file (`data/baseline.$ENV.json`) at startup. All 5 new features are visible without any cluster changes — use the scenario buttons to inject synthetic events.

---

### Feature 1: Probabilistic Root Cause Confidence Score

**Scenario to run:** Click **4 DB gone silent** or **5 Cascading failure** in the topology UI, or run `curl -s http://localhost:8080/api/demo/db-incident` / `cascading`

**What you see:** The Causality Chain panel shows the root cause with a green `N% confidence` label next to "ROOT CAUSE ★".

**How the score is computed:**
- **Anomaly type weight** — MISSING_SERVICE (1.0) > ERROR_RATE_ANOMALY (0.85) > NEW_ERROR_SIGNATURE (0.7) > LATENCY_ANOMALY (0.5) > DRIFT (0.3)
- **Caller fraction** — fraction of all affected services that call this node (shared dependency = higher score)
- **Timing bonus** — the service whose anomaly fired earliest gets a small boost (0–10%)

```
Score = (type_weight × 0.5) + (caller_fraction × 0.35) + (timing_bonus × 0.15)
```

**Key talking point:**
> *"Davis AI surfaces confidence scores on every problem. This is how we do it — not a black box, but a transparent formula that weights signal type, topology centrality, and timing. `mysql:petclinic` scores 88% when three services call it and MISSING_SERVICE fires first — the shared dependency pattern is the key signal."*

---

### Feature 2: User Impact Estimation (spans/min)

**Scenario to run:** Click **6 Latency spike** or **7 Error rate** in the topology UI, or run `curl -s http://localhost:8080/api/demo/latency-spike` / `error-rate-spike`

**What you see:** The affected service card shows `~N spans/min affected` in blue below the anomaly message.

**How it works:** The OTel processor tracks a 2-minute sliding window of span counts per service. When `LATENCY_ANOMALY` or `ERROR_RATE_ANOMALY` fires, `spans_per_min` is logged alongside the anomaly and parsed by `poll_drift_events.py`. It represents the throughput of the affected service at the time of detection — a proxy for "how many requests are impacted right now."

**Key talking point:**
> *"Dynatrace shows 'N users affected' via session correlation. We derive impact from span throughput — no session tracking needed. `~47 spans/min` on visits-service means roughly 47 in-flight requests per minute were experiencing 750ms latency instead of 3ms. Real impact, at the edge, without querying any external system."*

---

### Feature 3: Infra Event Correlation (kubectl warning events)

**Scenario to run:** Inject an infra event manually (no cluster needed), then click **6 Latency spike**:
```bash
curl -s -X POST http://localhost:8080/api/inject/infra \
  -H 'Content-Type: application/json' \
  -d '{"service":"visits-service","reason":"OOMKilling",
       "message":"Container visits-service was OOM killed (rss=512Mi limit=256Mi)","count":3}'
# Then click 6 Latency spike in the UI (or: curl -s http://localhost:8080/api/demo/latency-spike)
```

**What you see:** The affected service node turns amber even before any trace anomaly fires. The service card shows `⚙ OOMKilling: Container killed due to OOM (×3)` in the panel. Infra events appear in the live event log as `⚙ INFRA`.

**How it works:** A background task polls `kubectl get events --field-selector type=Warning` every 30 seconds over the existing SSH connection. It strips pod hash suffixes to map pod names to service names (`visits-service-6d8f9c-xkz9p` → `visits-service`), and broadcasts matching events as `infra_events` SSE messages.

**Manual injection for demo (no cluster needed):**
```bash
curl -s -X POST http://localhost:8080/api/inject/infra \
  -H 'Content-Type: application/json' \
  -d '{"service":"visits-service","reason":"OOMKilling",
       "message":"Container visits-service was OOM killed (rss=512Mi limit=256Mi)","count":3}'
```

Then click **6 Latency spike** — you'll see both the infra event (OOM) and the metric anomaly (latency spike) on the same node simultaneously.

**Key talking point:**
> *"Smartscape correlates host-level events into the causality graph automatically. We do the same at the pod layer using kubectl — no agent, no DynatraceAgent CR, no host plugin. If a pod is OOMKilling and latency is spiking, we show both signals on the same node and correlate them in the panel. The root cause score goes up because both signal types are present."*

---

### Feature 4: Topology-Aware Downstream Suppression

**Scenario to run:** Click **5 Cascading failure** in the topology UI, or run `curl -s http://localhost:8080/api/demo/cascading`

**What you see:** After vets-service goes MISSING and api-gateway and customers-service start erroring, the panel shows customers-service at 60% opacity with the note *"secondary effect of vets-service"*. The status badge still shows INCIDENT — the suppression is cosmetic, not a mute.

**How it works:** `_downstream_suppressed()` returns `True` for a service when:
1. It is NOT the root cause
2. It has only DRIFT or LATENCY anomalies (not ERROR/MISSING/ERROR_RATE — those are independent signals)
3. The root cause is reachable downstream from it (it calls the root cause, directly or transitively)

The service is still listed in the panel — it's dimmed, not hidden — with a note identifying it as a secondary effect.

**Key talking point:**
> *"Davis suppresses correlated alerts on downstream services automatically once the root cause is identified. We do the same — if api-gateway is only erroring because vets-service is missing, its anomaly is flagged as a secondary effect rather than a separate incident. The on-call sees one problem, not three."*

---

### Feature 5: Seasonal / Time-of-Day Latency Baseline

**What it is (background):** The OTel processor maintains 168 latency baseline slots (7 days × 24 hours) per (service, operation) pair. Each slot runs its own Welford online accumulator. When the current hour-of-day slot has ≥30 samples, detection uses that slot's mean and stddev instead of the flat all-time baseline.

**Why it matters:** A service that normally responds in 50ms at 2am and 500ms at 9am (peak load) would generate false LATENCY_ANOMALY alerts at 9am against a flat 50ms baseline. The seasonal baseline adapts: it compares current latency against *this hour's* normal, not all-time normal.

**How to see it in action:** The OTel processor logs `"seasonal_baseline": "true"` alongside `latency anomaly detected` lines once the current time slot has been trained. After the cluster has been running for several hours, `poll_drift_events.py` output will show which baseline was used.

**Key talking point:**
> *"Davis baselines every metric per day-of-week and time-of-day out of the box. We implement the same pattern in the OTel processor using 168 Welford accumulators — one per hour-of-day × day-of-week. No configuration, no re-training step. The baseline adapts as traffic naturally varies throughout the week."*

---

### Feature 6: Time-Ordered Causality — Degradation Before Crash

**Scenario to run:** Click **10 DB crash** in the topology UI, or run `curl -s http://localhost:8080/api/demo/oom-crash`

**What fires (in sequence):**
- t=0s: `LATENCY_ANOMALY` — customers-service 3800ms (baseline 38ms, z=12.6) — GC pressure mounting
- t=4s: `MISSING_SERVICE` — customers-service absent from traces — OOM crash
- t=5s: `NEW_ERROR_SIGNATURE` — api-gateway ServiceUnavailableException on GET /owners

**What you see:** The causality chain panel shows the three events time-ordered with a note: *"Latency spike preceded crash by 4s — degradation before failure."* The confidence score for customers-service is boosted by the timing correlation (latency fired first on the same service that later went MISSING).

**Key talking point:**
> *"This is the OOM pattern — GC pressure causes latency to spike before the pod dies. Two separate signal types, one service, 4 seconds apart. The framework correlates them by service and timestamp, surfaces the degradation-before-crash story, and scores it as a single incident rather than two unrelated alerts."*

---

### Topology UI scenario reference

| Button | Scenario key | Anomaly types fired | Features demonstrated |
|--------|-------------|--------------------|-----------------------|
| 1 Kill service | `kill-service` | MISSING_SERVICE | Confidence score, downstream suppression |
| 2 New call path | `new-call-path` | NEW_FINGERPRINT | New node/edge rendering |
| 3 New error sig | `new-error` | NEW_ERROR_SIGNATURE | Error badge, log entry |
| 4 DB gone silent | `db-incident` | MISSING_SERVICE + NEW_ERROR_SIGNATURE × 3 | Confidence score (shared dep), downstream suppression |
| 5 Cascading failure | `cascading` | MISSING_SERVICE → ERROR_SIG → ERROR_SIG (2s apart) | Confidence score, downstream suppression |
| 6 Latency spike | `latency-spike` | LATENCY_ANOMALY | User impact (spans/min), amber node state |
| 7 Error rate | `error-rate-spike` | ERROR_RATE_ANOMALY + NEW_ERROR_SIGNATURE | User impact, red-orange node state, INCIDENT badge |
| 8 Combined | `combined-metric` | MISSING_SERVICE + NEW_ERROR_SIGNATURE + ERROR_RATE_ANOMALY | All features together |
| 9 Slow DB | `slow-db` | LATENCY_ANOMALY × 4 (shared dep) | Root cause confidence (topology-based, no structural drift) |
| 10 OOM crash | `oom-crash` | LATENCY_ANOMALY → MISSING_SERVICE → NEW_ERROR_SIGNATURE | Time-ordered causality, degradation before crash |
| 11 Span drop | `span-count-drop` | SPAN_COUNT_DROP | Silent failure — no errors, no latency change, span count drops 4× below baseline |
| 12 Span spike | `span-count-spike` | SPAN_COUNT_SPIKE | Retry storm — no new error type, span count 4.8× above baseline max |
| — (inject) | `oom-latency` | LATENCY_ANOMALY | Infra event correlation (OOMKill + latency on same node) |

---

### Feature 7: Span Count Distribution Anomaly

**Demo 11 — Span Drop (button `11 Span drop`):** visits-service normally produces 12–18 spans per trace (HTTP handler + DB queries + method instrumentation). A connection pool exhaustion event causes DB calls to short-circuit — each trace completes with only 3 spans. No error is thrown (the pool timeout is silently caught), no latency change (the path exits faster), no MISSING_SERVICE (the service is still reachable). The framework fires `SPAN_COUNT_DROP` because 3 < baseline_min × 0.5.

**Demo 12 — Span Spike (button `12 Span spike`):** customers-service normally produces 8–12 spans per trace. A `ConectTimeout` causes the HTTP client to retry 7 times before succeeding — each trace now contains 58 spans. No new error type (same timeout the baseline has seen), no MISSING_SERVICE. `SPAN_COUNT_SPIKE` fires because 58 > baseline_max × 2.

**Story for both:**
> *"Two failure modes that defeat every other signal. The span drop: DB calls vanish from traces but the service is healthy from APM's perspective — no errors, no latency spike. The span spike: a retry storm that produces no new error signature because the error type was already in the baseline. The only signal is span count — learned from live traffic, no threshold configuration."*

**How the baseline is built:**
- During `learn`, the framework records `span_count_min` and `span_count_max` per fingerprint and aggregates them per root operation.
- DROP fires when `current_span_count < root_op_min × SPAN_COUNT_DROP_THRESHOLD` (default 0.5) — require at least `SPAN_COUNT_DROP_MIN_BASELINE` (default 4) occurrences before trusting the min.
- SPIKE fires when `current_span_count > root_op_max × SPAN_COUNT_SPIKE_MULTIPLIER` (default 2.0).
- Both thresholds adapt automatically via `adaptive_thresholds.py` if false positive rate is high.

**Key talking points:**
- *"This is the silent failure pattern — no error thrown, no timeout logged, no metric threshold crossed. The only observable difference is span count. That requires a distribution baseline, not a point threshold."*
- *"And the retry storm: the error type was already known so NEW_ERROR_SIGNATURE doesn't fire. The only signal is '7 retries per request instead of 1'. Span count catches it."*
- *"Both thresholds adapt. If visits-service legitimately varies between 3 and 18 spans depending on whether a pet has visits, the framework learns that range and doesn't fire on the low end."*

**Inject via CLI** (no topology UI needed):
```bash
# Span count drop — visits-service
curl -s -X POST http://localhost:8080/api/inject \
  -H 'Content-Type: application/json' \
  -d '{
    "anomaly_type": "SPAN_COUNT_DROP",
    "service": "visits-service",
    "root_op": "api-gateway:GET /owners/{ownerId}/pets/{petId}/visits",
    "span_count": 3,
    "span_count_baseline_min": 12,
    "span_count_baseline_max": 18,
    "message": "Span count drop: 3 spans (baseline min 12) — DB calls silently missing"
  }'

# Span count spike — customers-service
curl -s -X POST http://localhost:8080/api/inject \
  -H 'Content-Type: application/json' \
  -d '{
    "anomaly_type": "SPAN_COUNT_SPIKE",
    "service": "customers-service",
    "root_op": "api-gateway:GET /owners",
    "span_count": 58,
    "span_count_baseline_max": 12,
    "message": "Span count spike: 58 spans (baseline max 12, ×4.8) — retry storm"
  }'
```

---

**Inject infra events manually** (no cluster needed — combine with any scenario button):
```bash
# OOMKill on visits-service — then click 6 Latency spike
curl -s -X POST http://localhost:8080/api/inject/infra \
  -H 'Content-Type: application/json' \
  -d '{"service":"visits-service","reason":"OOMKilling","message":"rss=512Mi limit=256Mi","count":3}'

# CrashLoopBackOff on customers-service — then click 10 DB crash
curl -s -X POST http://localhost:8080/api/inject/infra \
  -H 'Content-Type: application/json' \
  -d '{"service":"customers-service","reason":"CrashLoopBackOff","message":"Back-off restarting failed container","count":5}'
```

**Reset the topology UI:**
```bash
curl -s http://localhost:8080/api/clear   # or press C in the browser
```

---



```
LEARN  →  Search each service independently (up to 200 traces each, parallel)
          Build fingerprints: "api-gateway always calls vets-service on GET /vets"
          Build error signatures: "customers-service has no DB errors in healthy state"

          --bootstrap flag: for fresh clusters with <30 min of traffic
            Accepts fingerprints seen ≥1 time (vs default min=3)
            Drops seen-once entries after learning (consolidation pass)
            Merges auto-promoted entries from OTel ConfigMap automatically

WATCH  →  Two paths:

  Detection (OTel edge, ~10s latency):
          OTel Collector processor fingerprints every trace as it flows through
          DRIFT → emits trace.path.drift / error.signature.drift to its own logs
          demo/poll_drift_events.py --triage tails logs directly → JSON (no Splunk wait)

  Lifecycle (Python, learn/promote/heal — not a detection path):
          Sample traces from the last N minutes via Splunk APM API
          Builds and maintains the fingerprint baseline that the OTel processor uses
          Used in Demo 2 (Python watch) and Demo 0b (auto-onboarding) only

TRIAGE →  Claude reads the JSON anomaly list
          Reasons about severity, root cause, action
          Writes DETECTION + TRIAGE to alerts.log
```

Detection path — triage directly from OTel logs (used in Demos 1–8, no Splunk indexing wait):
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV \
  | python3 agent.py --environment $ENV
```

Python watch — baseline lifecycle only (used in Demo 2 auto-promotion):
```bash
AUTO_PROMOTE_THRESHOLD=2 python3 core/trace_fingerprint.py --environment $ENV watch --window-minutes 5
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
# Use /tmp/otel_baseline.json — distinct from /tmp/python_baseline.json (demo-reset.sh uses both)
sshpass -p "$EC2_PASSWORD" scp -P 2222 data/baseline.$ENV.json splunk@$EC2_IP:/tmp/otel_baseline.json
sshpass -p "$EC2_PASSWORD" ssh -p 2222 -o StrictHostKeyChecking=no splunk@$EC2_IP 'bash -s' <<'REMOTE'
kubectl delete configmap behavioral-baseline --ignore-not-found
kubectl create configmap behavioral-baseline \
  --from-file=baseline.json=/tmp/otel_baseline.json \
  --from-file=error_baseline.json=/tmp/error_baseline.json
B64=$(base64 -w 0 /tmp/otel_baseline.json)
for pod in $(kubectl get pods -l app=otelcol-fingerprint -o jsonpath='{.items[*].metadata.name}'); do
  kubectl exec "$pod" -c otelcol -- sh -c "echo '$B64' | base64 -d > /baseline/baseline.json"
done && echo 'Baseline pushed to all pods'
REMOTE
```

For cold-start re-learn on a fresh cluster:
```bash
python3 core/trace_fingerprint.py --environment $ENV learn --bootstrap --window-minutes 30
python3 core/trace_fingerprint.py --environment $ENV promote
```
