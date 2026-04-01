# Behavioral Anomaly Framework — Demo Guide

## Prerequisites

### Terminal setup (run once before demo)
```bash
cd /Users/mbui/Documents/o11y-behaviorbaseline
source .env

# SSH alias for cluster commands
# EC2_IP changes when the instance is restarted — check current IP before demo
# Password is stored in your local .env file as EC2_PASSWORD
alias k='sshpass -p "$EC2_PASSWORD" ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@$EC2_IP'
```

### Refresh AWS credentials (required for Claude/Bedrock triage)
AWS STS tokens from Okta expire every few hours. Run this **from a terminal that has fresh credentials** (e.g. the Claude Code terminal) before starting the demo:
```bash
python3 refresh_aws_creds.py
# Expected:
#   Credentials verified: arn:aws:sts::387769110234:assumed-role/...
#   .env updated with fresh AWS credentials.
```

Then in your **demo terminal**:
```bash
source .env
```

This writes the current tokens into `.env` so all scripts pick them up automatically — no AWS env vars needed in the demo terminal itself.

### Splunk O11y URLs
- **APM Service Map**: https://app.us1.signalfx.com/#/apm?environments=petclinicmbtest
- **Behavioral Baseline Dashboard**: https://app.us1.signalfx.com/#/dashboard/HERM9jxA1po

### Verify cluster is healthy
```bash
k "kubectl get pods --no-headers | awk '{print \$1, \$3}'"
```

**Expected output (all pods Running):**
```
admin-server-586785575f-dr9n9                          Running
api-gateway-765b86f689-5jldp                           Running
config-server-694b6b694c-bfmgz                         Running
customers-service-f688fbb85-xxcpj                      Running
discovery-server-88d47ff57-dzktk                       Running
petclinic-db-758f495756-nx7cn                          Running
petclinic-loadgen-deployment-6954c49d9-qg58j           Running
splunk-otel-collector-agent-m2csz                      Running
splunk-otel-collector-agent-m8jqk                      Running
splunk-otel-collector-agent-zdl5b                      Running
splunk-otel-collector-k8s-cluster-receiver-658b69d995-xp6vj  Running
splunk-otel-collector-operator-67ff5f79b8-zwfj6        Running
vets-service-74885f446b-rgf72                          Running
visits-service-787d65b9c9-q4h6k                        Running
```
> Pod name suffixes will differ — focus on the deployment prefix and `Running` status. If any pod shows `CrashLoopBackOff` or `Pending`, resolve before proceeding.

### Reset and verify baselines are clean

> **Critical order:** restore the cluster to fully healthy BEFORE wiping the baseline.
> If any service is down when you wipe, the first watch run will immediately re-learn
> the active error signatures — defeating the reset.

```bash
# Step 1 — Ensure all services are restored (run after any prior demo)
k "kubectl scale deployment petclinic-db vets-service visits-service customers-service --replicas=1"
k "kubectl rollout status deployment/petclinic-db vets-service visits-service --timeout=90s"

# Step 2 — Wait for services to reconnect to DB (~30s)
sleep 30

# Step 3 — Remove any cron jobs added by Demo 7 (onboard.py --auto)
crontab -l | grep -v "behavioral-baseline-managed" | crontab -

# Step 4 — Clear the alert log
cat /dev/null > data/alerts.log

# Step 5 — Hard-wipe the error baseline (cluster must be healthy before this step)
python3 -c "
import json, pathlib, datetime
pathlib.Path('data/error_baseline.petclinicmbtest.json').write_text(json.dumps({
    'signatures': {},
    'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'environment': 'petclinicmbtest',
}))
print('Error baseline wiped.')
"
python3 core/error_fingerprint.py --environment petclinicmbtest show
# Expected: "Error baseline for environment 'petclinicmbtest' is empty"

# Step 6 — Strip any stale watch-promoted trace fingerprints
python3 -c "
import json, pathlib
p = pathlib.Path('data/baseline.petclinicmbtest.json')
d = json.loads(p.read_text())
before = len(d['fingerprints'])
d['fingerprints'] = {h: fp for h, fp in d['fingerprints'].items()
                     if fp['occurrences'] >= 2 and fp['watch_hits'] == 0}
p.write_text(json.dumps(d, indent=2))
print(f'Trace baseline: {before} -> {len(d[\"fingerprints\"])} fingerprints')
"

# Step 7 — Refresh AWS credentials (tokens expire every few hours)
python3 refresh_aws_creds.py && source .env

# Step 8 — Confirm 0 trace anomalies
python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3
# Expected: "All trace paths match baseline"
```

### Open the alert log in a separate terminal
All Python scripts (detection, triage, correlation) run **locally** — only `k "..."` commands go to the EC2 cluster.
```bash
# Run this in a second terminal tab, from the same directory
cd /Users/mbui/Documents/o11y-behaviorbaseline
tail -f data/alerts.log
```

> **Note on cron jobs:** All cron jobs have been removed for the demo. Every detection step is run manually. The `crontab -l` command in Demo 0 is purely to show the audience that autonomous scheduling exists — the output shown below is what it looks like in a production setup, not what is active during the demo.

---

## Demo 0: Context Setting — Framework in Steady State

**Story:** *"This is what the framework looks like before we break anything. Every component is autonomous — no manual alerting rules, no hardcoded thresholds."*

```bash
# What environments are provisioned and their health
python3 onboard.py --show-state

# 6 known call patterns learned from real traffic
python3 core/trace_fingerprint.py --environment petclinicmbtest show

# Known error signatures
python3 core/error_fingerprint.py --environment petclinicmbtest show

# Show what the autonomous cron schedule looks like in production
# Cron jobs are disabled for this demo — talk through the output below instead
echo "--- In production, these jobs run automatically: ---"
echo "*/5 * * * *  trace_fingerprint watch    # structural drift, every 5m"
echo "*/5 * * * *  error_fingerprint watch    # error signatures, every 5m"
echo "*/5 * * * *  correlate                  # cross-tier correlation, every 5m"
echo "*/5 * * * *  dedup_agent                # flood suppression, every 5m"
echo "0   2 * * *  trace_fingerprint learn    # relearn baseline, daily"
echo "0   2 * * *  error_fingerprint learn    # relearn error baseline, daily"
echo "*/30 * * * * onboard --auto             # discover new environments, every 30m"

# Confirm 0 anomalies right now (1-minute window avoids waiting for outage traces to age out)
python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 1
```

**Expected output (trace show):**
```
Baseline (environment 'petclinicmbtest'): 6 fingerprints
  Services: [api-gateway, customers-service, discovery-server, vets-service, visits-service, ...]

  api-gateway:GET /api/gateway/owners/{ownerId}  (1 pattern)
  api-gateway:GET customers-service              (3 patterns)
  api-gateway:GET vets-service                   (1 pattern)
  api-gateway:PUT customers-service              (1 pattern)
```

**Expected output (trace watch — 0 anomalies):**
```
[watch] Discovering topology + searching traces in parallel (environment 'petclinicmbtest')...
  Topology: 6 services | Traces: 200 candidates
  Fetching 200 traces (20 parallel)...
    40/200 fetched...
    80/200 fetched...
    120/200 fetched...
    160/200 fetched...
    200/200 fetched...

  Checked 21 traces, 179 skipped, 0 anomalies detected
  Per-service breakdown:
    api-gateway                          21 traces checked
  All trace paths match baseline
```

**Key talking points:**
- *"No alert rules written. No thresholds set. The framework learned the normal call graph by sampling live traffic."*
- *"6 structural fingerprints cover every known request path. Anything that deviates fires immediately."*
- *"8 cron jobs per environment run autonomously — trace watch, error watch, correlate, dedup every 5 minutes; relearn daily."*
- *"0 anomalies = the system is healthy. This is the baseline we'll break in the next demos."*

---

## Demo 1: DB Goes Down — New Error Signatures

**Story:** *"The database goes down. Services start throwing transaction errors and health check failures that have never appeared before. The framework detects brand new error signatures on first occurrence — no threshold, no tuning required."*

### Prerequisites
```bash
# Clear alert log and ensure clean error baseline
cat /dev/null > data/alerts.log
python3 -c "
import json, pathlib, datetime
pathlib.Path('data/error_baseline.petclinicmbtest.json').write_text(json.dumps({
    'signatures': {},
    'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'environment': 'petclinicmbtest',
}))
print('Error baseline wiped.')
"
python3 core/error_fingerprint.py --environment petclinicmbtest show
# Expected: 0 signatures (system is healthy)
```

### Step 1 — Kill the DB
```bash
k "kubectl scale deployment petclinic-db --replicas=0"
```

### Step 2 — Wait 3 minutes (countdown for audience)
```bash
for i in $(seq 180 -1 1); do printf "\r  Waiting for failure traces... %02d:%02d remaining" $((i/60)) $((i%60)); sleep 1; done; echo -e "\r  Done — 3 minutes elapsed. Run detection now.          "
```
The loadgen hits owner/pet endpoints every ~5 seconds. After 3 minutes the watch window will contain DB-failure error traces.

### Step 3 — Run detection + triage (one command)
```bash
python3 core/error_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json \
  | python3 agent.py --environment petclinicmbtest
```

**Expected terminal output:**
```
[agent] env=petclinicmbtest | 2 anomaly(s) from watch
  Reasoning with Claude...

[!] DEGRADED — The customers-service cannot create database transactions, causing 500
    errors to propagate back through the api-gateway on the GET /owners endpoint.
    Root cause: The customers-service has lost connectivity to its database —
    org.springframework.transaction.CannotCreateTransactionException on
    OwnerRepository.findAll strongly indicates the database is unreachable or
    refusing connections.
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
[2026-03-31 05:03:46 UTC]  DETECTION
  anomaly type         : NEW_ERROR_SIGNATURE
  environment          : petclinicmbtest
  service              : customers-service
  message              : New error signature in customers-service: org.springframework
                         .transaction.CannotCreateTransactionException on OwnerRepository.findAll, GET /owners
  error type           : org.springframework.transaction.CannotCreateTransactionException
  operation            : OwnerRepository.findAll, GET /owners
  call path            : api-gateway:GET customers-service -> api-gateway:GET
────────────────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════════════════
[2026-03-31 05:03:46 UTC]  DETECTION
  anomaly type         : NEW_ERROR_SIGNATURE
  environment          : petclinicmbtest
  service              : api-gateway
  message              : New error signature in api-gateway: 500 on GET, GET customers-service
  error type           : 500
  operation            : GET, GET customers-service
  call path            : api-gateway:GET customers-service
────────────────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════════════════
[2026-03-31 05:03:46 UTC]  TRIAGE
  severity             : DEGRADED
  confidence           : HIGH
  environment          : petclinicmbtest
  affected services    : customers-service, api-gateway
  root cause           : customers-service has lost connectivity to its database
  action               : PAGE_ONCALL
  narrative            : customers-service is throwing CannotCreateTransactionException
                         when attempting to query the owners table — the backing database
                         is down or unreachable...
────────────────────────────────────────────────────────────────────────
```

**Key talking points:**
- *"A DB outage doesn't just spike existing errors — it creates brand new error signatures that have never appeared before."*
- *"The framework fires on first occurrence. No threshold to set, no baseline rate to exceed."*
- *"The cascade is visible: DB down → CannotCreateTransactionException in customers-service → 500 in api-gateway → 503 health checks across all DB-dependent services."*
- *"Claude correctly identifies the shared database as the root cause from the error pattern alone — no metric thresholds triggered."*

### Step 4 — Restore
```bash
k "kubectl scale deployment petclinic-db --replicas=1"

# Wait for DB to come up and services to reconnect (~30s)
k "kubectl rollout status deployment/petclinic-db --timeout=60s"

# Verify services are responding again
k "kubectl exec deployment/petclinic-loadgen-deployment -- curl -s http://api-gateway:82/api/vet/vets --max-time 8 | head -c 50"
# Expected: JSON list of vets (not 404 or timeout)

# Re-learn clean error baseline after DB recovery
python3 -c "
import json, pathlib, datetime
pathlib.Path('data/error_baseline.petclinicmbtest.json').write_text(json.dumps({
    'signatures': {},
    'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'environment': 'petclinicmbtest',
}))
print('Error baseline wiped.')
"
```

> **Critical:** Services (customers-service, visits-service) take ~30s to reconnect to the DB after it comes back. Don't start the next demo until the curl above returns data. If traces are missing from subsequent learn runs, regenerate traffic and relearn (see Restore/Reset section).

---

## Demo 2: Bad Deploy — New Error Signature on First Occurrence

**Story:** *"A new deploy of visits-service introduces a regression — the pod crashes immediately on startup. The very first request after the deploy hits the dead service and fires a brand new error signature on a code path that was previously clean. No threshold crossed. No baseline rate exceeded. First occurrence fires."*

### Prerequisites
```bash
# Clear alert log and ensure clean error baseline
cat /dev/null > data/alerts.log
python3 -c "
import json, pathlib, datetime
pathlib.Path('data/error_baseline.petclinicmbtest.json').write_text(json.dumps({
    'signatures': {},
    'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'environment': 'petclinicmbtest',
}))
print('Error baseline wiped.')
"
python3 core/error_fingerprint.py --environment petclinicmbtest show
# Expected: 0 signatures (system is healthy)
```

### Step 1 — Simulate bad deploy (visits-service crashes)
```bash
k "kubectl scale deployment visits-service --replicas=0"
```

### Step 2 — Wait 3 minutes (countdown for audience)
```bash
for i in $(seq 180 -1 1); do printf "\r  Waiting for failure traces... %02d:%02d remaining" $((i/60)) $((i%60)); sleep 1; done; echo -e "\r  Done — 3 minutes elapsed. Run detection now.          "
```
The loadgen hits owner detail pages every ~5 seconds, which calls visits-service for pet visit history. After 3 minutes the watch window will contain the new connection errors.

### Step 3 — Run detection + triage (one command)

Both the trace tier and error tier are piped together — Claude sees the full picture from both signals simultaneously.

```bash
(python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json && \
 python3 core/error_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json) \
  | python3 agent.py --environment petclinicmbtest
```

**Expected terminal output:**
```
[agent] env=petclinicmbtest | 1 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — The visits-service is completely absent from traces that normally
    include it when fetching owner details via the api-gateway.
    Root cause: visits-service is down or unreachable, causing it to be dropped
    from the GET /api/gateway/owners/{ownerId} call path.
    As of 05:12 UTC, the visits-service has completely disappeared from traces.
    The api-gateway is successfully routing to customers-service and retrieving
    owner data, but the expected downstream call to visits-service is not
    occurring at all.
    Confidence: HIGH | Affected: visits-service, api-gateway
    Recommended action: PAGE_ONCALL

    [TRIAGE SUMMARY] written to alerts.log
    [PAGE_ONCALL] event emitted to Splunk
```

**Expected alerts.log:**
```
════════════════════════════════════════════════════════════════════════
[2026-03-31 05:13:07 UTC]  DETECTION
  anomaly type         : MISSING_SERVICE
  environment          : petclinicmbtest
  service              : api-gateway
  root op              : api-gateway:GET /api/gateway/owners/{ownerId}
  message              : Expected service(s) absent from 'api-gateway:GET /api/gateway/owners/{ownerId}': ['visits-service']
  missing services     : visits-service
  services in trace    : api-gateway, customers-service
────────────────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════════════════
[2026-03-31 05:13:07 UTC]  TRIAGE
  severity             : INCIDENT
  confidence           : HIGH
  environment          : petclinicmbtest
  affected services    : visits-service, api-gateway
  assessment           : The visits-service is completely absent from traces that
                         normally include it when fetching owner details via the api-gateway.
  root cause           : visits-service is down or unreachable, causing it to be
                         dropped from the GET /api/gateway/owners/{ownerId} call path.
  missing services     : api-gateway:GET /api/gateway/owners/{ownerId} → missing: visits-service
  action               : PAGE_ONCALL
  narrative            : The api-gateway is successfully routing to customers-service
                         and retrieving owner data, but the expected downstream call to
                         visits-service is not occurring at all. Pet visit history is
                         unavailable — page on-call immediately.
────────────────────────────────────────────────────────────────────────
```

**Key talking points:**
- *"No threshold. The baseline had zero error signatures for this service — so the first occurrence fires immediately."*
- *"Running both tiers together gives Claude the full picture: trace tier sees visits-service missing from the call graph, error tier sees the connection exception. Together they unambiguously point to visits-service."*
- *"Notice the triage correctly notes customers-service is healthy — Claude can reason about what's working as well as what's broken."*

### Step 4 — Restore
```bash
k "kubectl scale deployment visits-service --replicas=1"

# Re-learn clean baseline after demo
python3 -c "
import json, pathlib, datetime
pathlib.Path('data/error_baseline.petclinicmbtest.json').write_text(json.dumps({
    'signatures': {},
    'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'environment': 'petclinicmbtest',
}))
print('Error baseline wiped.')
"
```

---

## Demo 3: Missing Service — Structural Trace Absence + AI Triage

**Story:** *"vets-service goes down. The framework detects the structural absence from traces and calls Claude (via AWS Bedrock) to reason about it — producing an INCIDENT verdict with root cause and recommended action, written to a log file in under 3 minutes."*

### Prerequisites
```bash
# Clear alert log and verify 0 trace anomalies
cat /dev/null > data/alerts.log
python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3
# Expected: "All trace paths match baseline"
```

### Step 1 — Kill vets-service
```bash
k "kubectl scale deployment vets-service --replicas=0"
```

### Step 2 — Wait 90 seconds (countdown for audience)
The loadgen hits the vets endpoint every ~5 seconds. 90 seconds is enough to
fill the watch window with failure traces — no need to wait the full 3 minutes.
```bash
for i in $(seq 90 -1 1); do printf "\r  Waiting for failure traces... %02d:%02d remaining" $((i/60)) $((i%60)); sleep 1; done; echo -e "\r  Done — run detection now.                             "
```

### Step 3 — Run detection + triage (one command)
```bash
python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json \
  | python3 agent.py --environment petclinicmbtest
```

**Expected terminal output:**
```
[agent] env=petclinicmbtest | 1 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — The vets-service is completely absent from traces that normally flow
    through api-gateway to vets-service, indicating the service is down or unreachable.
    Root cause: vets-service is down or unreachable — the api-gateway is receiving
    requests for GET vets-service but no spans from vets-service are appearing in traces.
    As of 16:45 UTC, vets-service has completely vanished from distributed traces.
    The api-gateway is routing GET requests intended for vets-service but receiving
    no response spans, consistent with vets-service being crashed, undeployed, or
    network-isolated.
    Confidence: HIGH | Affected: vets-service, api-gateway
    Recommended action: PAGE_ONCALL

    [TRIAGE SUMMARY] written to alerts.log
    [PAGE_ONCALL] event emitted to Splunk
```

**Expected alerts.log:**
```
════════════════════════════════════════════════════════════════════════
[2026-03-31 16:45:10 UTC]  DETECTION
  anomaly type         : MISSING_SERVICE
  environment          : petclinicmbtest
  service              : api-gateway
  message              : Expected service(s) absent from 'api-gateway:GET vets-service': ['vets-service']
  detail               : Path: api-gateway:GET vets-service
  trace id             : 93634beae2b3078c883ca4fde0e6fe29
  root op              : api-gateway:GET vets-service
  missing services     : vets-service
  services in trace    : api-gateway
────────────────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════════════════
[2026-03-31 16:45:10 UTC]  TRIAGE
  severity             : INCIDENT
  confidence           : HIGH
  environment          : petclinicmbtest
  affected services    : vets-service, api-gateway
  assessment           : The vets-service is completely absent from traces that
                         normally flow through api-gateway to vets-service.
  root cause           : vets-service is down or unreachable — the api-gateway is
                         receiving requests for GET vets-service but no spans from
                         vets-service are appearing in traces.
  missing services     : api-gateway:GET vets-service → missing: vets-service
  action               : PAGE_ONCALL
  narrative            : As of 16:45 UTC, vets-service has completely vanished from
                         distributed traces in the petclinicmbtest environment. The
                         api-gateway is routing GET requests intended for vets-service
                         but receiving no response spans — consistent with vets-service
                         being crashed, undeployed, or network-isolated.
────────────────────────────────────────────────────────────────────────
```

**Key talking points:**
- *"No alert rules. No thresholds. The framework learned the normal call graph from traffic — api-gateway always calls vets-service on this path — and detected when that stopped."*
- *"The detection uses structural trace analysis: the span for vets-service is missing from a path where it always appeared."*
- *"Claude reads exactly what was detected — one clean anomaly — and reasons about it: INCIDENT, HIGH confidence, PAGE_ONCALL."*
- *"Total time from kill to triage: 3 minutes."*

### Step 4 — Restore
```bash
k "kubectl scale deployment vets-service --replicas=1"
```

---

## Demo 4: Correlated Anomaly — All Three Tiers Fire Simultaneously

**Story:** *"Both vets-service AND the database go down at the same time. The trace tier sees MISSING_SERVICE across multiple paths. The error tier sees new CannotCreateTransactionException signatures. APM AutoDetect fires on the error rate spike. When all three tiers fire on the same service simultaneously, `correlate.py` emits a `[Critical] MULTI_TIER` correlated event — the highest-confidence signal in the framework."*

### Prerequisites
```bash
# Clear alert log
cat /dev/null > data/alerts.log

# Strip any stale watch-promoted fingerprints (occurrences=1 noise from prior demos)
python3 -c "
import json, pathlib
p = pathlib.Path('data/baseline.petclinicmbtest.json')
d = json.loads(p.read_text())
before = len(d['fingerprints'])
d['fingerprints'] = {h: fp for h, fp in d['fingerprints'].items()
                     if fp['occurrences'] >= 2 and fp['watch_hits'] == 0}
after = len(d['fingerprints'])
p.write_text(json.dumps(d, indent=2))
print(f'Trace baseline: removed {before-after} stale entries, kept {after} clean fingerprints.')
"

# Reset error baseline to 0
python3 -c "
import json, pathlib, datetime
pathlib.Path('data/error_baseline.petclinicmbtest.json').write_text(json.dumps({
    'signatures': {},
    'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'environment': 'petclinicmbtest',
}))
print('Error baseline wiped.')
"
python3 core/error_fingerprint.py --environment petclinicmbtest show
# Expected: 0 signatures

# Verify 0 trace anomalies (cluster must be fully healthy before this check)
python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3
# Expected: "All trace paths match baseline"
```

### Step 1 — Kill both vets-service and petclinic-db simultaneously
```bash
k "kubectl scale deployment vets-service --replicas=0 && kubectl scale deployment petclinic-db --replicas=0"
```

### Step 2 — Wait 3 minutes (countdown for audience)
The watch window is 3 minutes. Pre-kill traces stay in the window for up to 3 minutes — running
detection before the window clears means healthy vets-service traces are still visible and
MISSING_SERVICE will not fire.
```bash
for i in $(seq 180 -1 1); do printf "\r  Waiting for failure traces... %02d:%02d remaining" $((i/60)) $((i%60)); sleep 1; done; echo -e "\r  Done — run detection now.                             "
```
The watch window will contain:
- Trace tier: MISSING_SERVICE for vets-service and owner detail paths (DB down = no traces completing)
- Error tier: CannotCreateTransactionException from customers-service on every DB call

### Step 3 — Run detection + triage (combined tiers)
```bash
(python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json && \
 python3 core/error_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json) \
  | python3 agent.py --environment petclinicmbtest
```

**Expected terminal output:**
```
[agent] env=petclinicmbtest | 6 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — Multiple services are unreachable and the customers-service is failing to
    create database transactions, indicating a database outage affecting the entire petclinic stack.
    Root cause: The database (likely MySQL/PostgreSQL) backing customers-service is down or
    unreachable, causing CannotCreateTransactionException; this also explains why PUT/GET
    operations to customers-service, vets-service, and visits-service have gone silent — all
    depend on DB connectivity to serve requests.
    Confidence: HIGH | Affected: api-gateway, customers-service, visits-service, vets-service
    Recommended action: PAGE_ONCALL

    [TRIAGE SUMMARY] written to alerts.log
    [PAGE_ONCALL] event emitted to Splunk
```

The 6 anomalies:
- `NEW_FINGERPRINT` ×2 on `GET customers-service` — partial/truncated traces (DB call started but never completed)
- `MISSING_SERVICE` — `api-gateway:GET vets-service` — vets-service pod down
- `MISSING_SERVICE` — `api-gateway:GET /api/gateway/owners/{ownerId}` — owner detail path silent (visits-service DB-dependent)
- `MISSING_SERVICE` — `api-gateway:PUT customers-service` — write path silent (can't open DB transaction)
- `NEW_ERROR_SIGNATURE` — `CannotCreateTransactionException` on `GET /owners, OwnerRepository.findAll`

### Step 3b — Wait for AutoDetect to fire (~5 minutes)
AutoDetect needs sustained error rate before it fires. While the audience processes
the triage output, wait for the error rate detectors to trigger on customers-service
and api-gateway.
```bash
for i in $(seq 300 -1 1); do printf "\r  Waiting for AutoDetect to fire... %02d:%02d remaining" $((i/60)) $((i%60)); sleep 1; done; echo -e "\r  Done — run correlate now.                             "
```

> **Tip:** While waiting, show the Splunk APM AutoDetect dashboard to the audience —
> you can watch the error rate climbing on customers-service in real time.

### Step 3c — Run correlate.py to see MULTI_TIER / Critical
With AutoDetect now firing (Tier 1) + trace drift (Tier 2) + error signatures (Tier 3)
all on the same service, correlate.py escalates to `[Critical] MULTI_TIER`.
```bash
python3 core/correlate.py --environment petclinicmbtest --window-minutes 20
```

**Expected output:**
```
[correlate] Fetching anomaly + deployment events in parallel (environment 'petclinicmbtest')...
  Found 20 anomaly events across 3 tier(s)
    tier1: 3 event(s)
    tier2: 14 event(s)
    tier3: 3 event(s)

  Found 2 correlated anomaly group(s):

  [Critical] MULTI_TIER — customers-service
    Tiers:         tier1, tier2, tier3
    Anomaly types: AUTODETECT_TIER1, AUTODETECT_TIER3, MISSING_SERVICE, NEW_ERROR_SIGNATURE
    Events:        14 over 720s
    - AutoDetect [autodetect]: APM - Sudden change in service error rate (severity=Critical)
    - AutoDetect [managed]: [Behavioral Baseline] customers-service error rate spike (severity=Critical)
    - New error signature in customers-service: org.springframework.transaction.CannotCreateTransactionException on GET /owners

  [Critical] MULTI_TIER — api-gateway
    Tiers:         tier1, tier2, tier3
    Anomaly types: AUTODETECT_TIER1, MISSING_SERVICE, NEW_ERROR_SIGNATURE
    Events:        8 over 480s
    - AutoDetect [autodetect]: APM - Sudden change in service error rate (severity=Critical)
    - No traces for 'api-gateway:GET vets-service' in window — expected service(s) absent
    - New error signature in api-gateway: 503 on GET vets-service

  Event sent for customers-service (behavioral_baseline.correlated_anomaly)
  Event sent for api-gateway (behavioral_baseline.correlated_anomaly)
```

> **Note:** Exact event counts and services may vary. The key indicators are `3 tier(s)` in the header
> and `[Critical] MULTI_TIER` in the output. If AutoDetect hasn't fired yet, you'll see `[Major] TIER2_TIER3`
> instead — run correlate again after another 2-3 minutes.

**Key talking points:**
- *"Tier 2 alone: could be a canary deploy. Tier 3 alone: could be noise. But all three tiers firing on the same service simultaneously? That's unambiguous — Critical severity, page oncall immediately."*
- *"AutoDetect sees the error rate spike on metrics. Our framework sees the structural silence in traces AND the new exception type. correlate.py is the join layer that brings all three together."*
- *"Without this correlation layer, you get 3 separate alerts from 3 different systems. With it, you get one [Critical] MULTI_TIER event with full context — tier1 metric anomaly, tier2 trace dropout, tier3 new error signature."*
- *"This is the value of the framework as a layer on top of AutoDetect, not a replacement for it."*

### Step 4 — Restore
```bash
k "kubectl scale deployment vets-service petclinic-db --replicas=1"
k "kubectl rollout status deployment/vets-service deployment/petclinic-db --timeout=90s"

# Wait ~30s for services to reconnect, then relearn
python3 -c "
import json, pathlib, datetime
pathlib.Path('data/error_baseline.petclinicmbtest.json').write_text(json.dumps({
    'signatures': {},
    'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'environment': 'petclinicmbtest',
}))
print('Error baseline wiped.')
"
```

---

## Demo 5: Deploy-Correlated Severity Downgrade

**Story:** *"A deploy of vets-service is announced via `notify_deployment.py`. The deploy is bad — vets-service crashes. Anomalies fire: trace tier detects MISSING_SERVICE, error tier detects 503s. On its own, agent.py calls it INCIDENT + PAGE_ONCALL. But `correlate.py` finds the deployment event in its window and downgrades severity from Major → Minor, annotating it as `[deployment-correlated]`. The on-call gets context: this looks like a deploy regression, not a random outage."*

### Prerequisites
```bash
# Clear alert log and reset error baseline
cat /dev/null > data/alerts.log
python3 -c "
import json, pathlib, datetime
pathlib.Path('data/error_baseline.petclinicmbtest.json').write_text(json.dumps({
    'signatures': {},
    'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'environment': 'petclinicmbtest',
}))
print('Error baseline wiped.')
"

# Verify 0 anomalies
python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3
# Expected: "All trace paths match baseline"
```

### Step 1 — Announce the deployment, then immediately kill vets-service
```bash
# Notify the framework that a deploy is happening
python3 notify_deployment.py --service vets-service --environment petclinicmbtest \
  --version v2.1.0 --description "Update vet specialties endpoint"

# Simulate bad deploy (service crashes on startup)
k "kubectl scale deployment vets-service --replicas=0"
```

### Step 2 — Wait 3 minutes (countdown for audience)
```bash
for i in $(seq 180 -1 1); do printf "\r  Waiting for failure traces... %02d:%02d remaining" $((i/60)) $((i%60)); sleep 1; done; echo -e "\r  Done — 3 minutes elapsed. Run detection now.          "
```

### Step 3 — Run detection + triage (agent sees INCIDENT, doesn't know about deploy)
```bash
(python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json && \
 python3 core/error_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json) \
  | python3 agent.py --environment petclinicmbtest
```

**Expected terminal output:**
```
[agent] env=petclinicmbtest | 2 anomaly(s) from watch
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

### Step 3b — Run correlate.py (sees the deployment event → downgrades severity)
```bash
python3 core/correlate.py --environment petclinicmbtest --window-minutes 15
```

**Expected output:**
```
[correlate] Fetching anomaly + deployment events in parallel (environment 'petclinicmbtest')...
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
k "kubectl scale deployment vets-service --replicas=1"
```

---

## Demo 6: Self-Healing — Auto-Promotion + Baseline Healer

**Story:** *"A deploy of vets-service changes its trace structure. The new call path fires NEW_FINGERPRINT on the first watch run. After 2 consecutive clean runs the framework promotes it automatically — no human intervention, no alert fatigue. In the background, `baseline_healer.py` monitors anomaly event rates; when it detects a spike followed by a drop-to-zero, it scores pre-incident windows, picks the cleanest one, and re-learns the baseline autonomously."*

### Prerequisites
```bash
cat /dev/null > data/alerts.log
python3 -c "
import json, pathlib, datetime
pathlib.Path('data/error_baseline.petclinicmbtest.json').write_text(json.dumps({
    'signatures': {},
    'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'environment': 'petclinicmbtest',
}))
print('Error baseline wiped.')
"

# Simulate a deploy: remove vets-service fingerprint from baseline
# (represents a deployment that changed the call path)
# Also remove the vets-service startup fingerprint (config-server call on pod start)
# — it only appears during restarts, causes MISSING_SERVICE noise during the demo
python3 -c "
import json
with open('data/baseline.petclinicmbtest.json') as f:
    b = json.load(f)
fps = b['fingerprints']
removed = [h for h, info in fps.items() if info.get('root_op','').startswith('vets-service:') or info.get('root_op','').startswith('api-gateway:GET vets')]
for h in removed: del fps[h]
with open('data/baseline.petclinicmbtest.json', 'w') as f:
    json.dump(b, f, indent=2)
print(f'Removed {len(removed)} vets fingerprint(s) — simulating new deploy')
"
```

### Part 1 — Auto-Promotion

#### Watch run 1 — NEW_FINGERPRINT fires, watch_hits=1
```bash
AUTO_PROMOTE_THRESHOLD=2 python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3
```

**Expected output:**
```
  ANOMALY DETECTED
    Type:    NEW_FINGERPRINT
    Message: Unknown execution path for 'api-gateway:GET vets-service'
    Detail:  Path: api-gateway:GET vets-service -> api-gateway:GET -> api-gateway:GET -> vets-service:GET /vets -> vets-service:GET /vets -> vets-service:VetRepository.findAll -> ...
    TraceID: 480b3c097b6f49d9d2d0cacbc3452f6d
    Event sent (trace.path.drift)

  Checked 27 traces, 173 skipped, 1 anomalies detected
  Per-service breakdown:
    api-gateway                          27 traces checked  [1 anomaly]
  Downstream services seen: customers-service, vets-service, visits-service
```

#### Watch run 2 — auto-promotes (watch_hits=2 ≥ threshold)
```bash
AUTO_PROMOTE_THRESHOLD=2 python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3
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
  Baseline saved -> data/baseline.petclinicmbtest.json  (6 fingerprints)

  Checked 18 traces, 182 skipped, 1 anomalies detected, 1 auto-promoted
  Per-service breakdown:
    api-gateway                          18 traces checked  [1 anomaly]
  Downstream services seen: customers-service, vets-service, visits-service
```

#### Watch run 3 — completely silent
```bash
AUTO_PROMOTE_THRESHOLD=2 python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3
```

**Expected output:**
```
  Checked 24 traces, 176 skipped, 0 anomalies detected
  Per-service breakdown:
    api-gateway                          24 traces checked
  Downstream services seen: customers-service, vets-service, visits-service
  All trace paths match baseline
```

### Part 2 — Baseline Healer (scoring demo)

The healer runs autonomously in the background. Show the scoring logic directly:

```bash
python3 -c "
import sys, time, calendar
sys.path.insert(0, 'agents')
from baseline_healer import pick_best_window, heal

# Set incident_start_ms to when the outage began
incident_start = int(time.time() * 1000) - 20 * 60 * 1000   # ~20 min ago
best = pick_best_window(incident_start, 'petclinicmbtest')
if best:
    heal(incident_start, 'petclinicmbtest', best, dry_run=True)
"
```

**Expected output:**
```
  [healer] Scoring 4 candidate windows in parallel...
    Scoring window -30m to -90m...
    Scoring window -60m to -120m...
    Scoring window -120m to -240m...
    Scoring window -240m to -360m...
      17:28-18:28 UTC: 80 traces, error_rate=3.3%, diversity=13, score=0.684
      14:58-16:58 UTC: 80 traces, error_rate=3.3%, diversity=6,  score=0.628
      16:58-17:58 UTC: 80 traces, error_rate=0.0%, diversity=7,  score=0.656
      12:58-14:58 UTC: 80 traces, error_rate=0.0%, diversity=6,  score=0.648

  [healer] Best window: -30m to -90m (score=0.684, error_rate=3.3%, diversity=13)

  [healer] Healing baseline for 'petclinicmbtest' using window -30m to -90m...
    $ python3 core/trace_fingerprint.py --environment petclinicmbtest learn \
        --window-minutes 60 --window-offset-minutes 50 --reset
    $ python3 core/error_fingerprint.py --environment petclinicmbtest learn \
        --window-minutes 60 --window-offset-minutes 50 --reset
    [dry-run] skipped
  [healer] Dry run complete — no changes written.
```

**Key talking points:**
- *"No one configured a threshold for 'how many times to see a new pattern before accepting it'. 2 (or 5 in production) is the default — tunable via `AUTO_PROMOTE_THRESHOLD`."*
- *"The framework learns the new normal on its own. After a deployment, new trace paths stop firing within 25 minutes at the default setting. Zero alert fatigue from known-good deploys."*
- *"The healer scores candidate windows by two metrics: error rate (lower is cleaner) and trace diversity (higher means richer coverage). It picks the window most likely to produce a good baseline — not just the most recent one."*
- *"In production, the healer runs on a 6-hour cron (`0 */6 * * *`). It's stateless — just looks at the last 20 minutes of anomaly events vs the 20 minutes before that. If the rate spiked then dropped, it heals."*

### Restore
```bash
# Relearn baseline to get vets fingerprint back properly
python3 core/trace_fingerprint.py --environment petclinicmbtest learn --reset --window-minutes 10
```

---

## Demo 7: Auto-Onboarding a New Environment

**Story:** *"A new environment shows up in Splunk APM — a team just deployed their first instrumented services. `onboard.py --auto` discovers it automatically, builds baselines from live traffic, creates a dashboard, registers cron jobs, and generates a runbook via Claude. Zero manual configuration. The framework is fully operational for the new environment in one command."*

> **Why this is last:** `onboard.py --auto` re-learns baselines from the last 120 minutes (which includes any outage errors from earlier demos) and adds cron jobs. Running it last means there's no cleanup needed before subsequent demos.

### Prerequisites
```bash
# Back up onboarding state so we can restore after
cp data/onboarding_state.json data/onboarding_state.json.bak

# Remove the environment from onboarding state to simulate a new environment
python3 -c "
import json
with open('data/onboarding_state.json') as f:
    state = json.load(f)
del state['environments']['petclinicmbtest']
with open('data/onboarding_state.json', 'w') as f:
    json.dump(state, f, indent=2)
print('Simulated: petclinicmbtest removed from known environments')
"
```

### Step 1 — Preview what --auto would do (dry run)
```bash
python3 onboard.py --auto --dry-run
```

**Expected output:**
```
[onboard] Discovering all active environments...
  petclinicmbtest: 6 services — [api-gateway, customers-service, ...]

[onboard] Diff results:
  New environments:     ['petclinicmbtest']
  Updated environments: —

[onboard] [DRY RUN] Acting on changes...

  [new] petclinicmbtest
    $ python3 core/trace_fingerprint.py --environment petclinicmbtest learn --window-minutes=120
      [dry-run] skipped
    Provisioning dashboard for environment 'petclinicmbtest'...
      [dry-run] Would create dashboard: Behavioral Baseline — petclinicmbtest
      [dry-run] skipped
    [dry-run] Would add 8 cron job(s) for 'petclinicmbtest'
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
  petclinicmbtest: 6 services — ['api-gateway', 'config-server', 'customers-service', 'discovery-server', 'vets-service', 'visits-service']
  unknown: 1 services — ['admin-server']

[onboard] Diff results:
  New environments:     ['petclinicmbtest']
  Updated environments: —
  Removed environments: ['mbtest-7043-workshop']

[onboard] Acting on changes...

  [new] petclinicmbtest
    $ python3 core/trace_fingerprint.py --environment petclinicmbtest learn --window-minutes=120
    $ python3 core/error_fingerprint.py --environment petclinicmbtest learn --window-minutes=120
    Dashboard created: HEwtJd2A0As (group: HD0uRkOA0AE)
    Added 8 cron job(s) for 'petclinicmbtest'
    Added 2 global cron job(s)
    /Users/mbui/Documents/o11y-behaviorbaseline/agents/RUNBOOK.petclinicmbtest.md already exists. Use --force to regenerate.
    State saved -> data/onboarding_state.json

[onboard] Done.
```

> The runbook line shows "already exists" because it was generated in a prior session. In a truly fresh environment it generates automatically. Use `--force` on `runbook_generator.py` to regenerate.

**What was created in ~60 seconds:**
- Trace fingerprint baseline: 7 structural call path patterns
- Error signature baseline: learned from last 120 minutes of live traffic
- Dashboard: linked to the Behavioral Baseline dashboard group
- Cron jobs: 8 per-environment + 2 global scheduled jobs
- Runbook: `RUNBOOK.petclinicmbtest.md` generated by Claude with service topology context

> **Note:** Error rate, latency, and request rate detectors are already live via Splunk APM AutoDetect — no provisioning needed. This framework adds the behavioral layer on top.

**Key talking points:**
- *"No YAML. No alert rules. No thresholds to configure. The framework reads the live APM topology, learns what normal looks like, and is ready to detect anomalies — all from a single command."*
- *"Metric-based alerts (error rate, latency, request rate) are already covered by Splunk's built-in APM AutoDetect for every environment with traces flowing. This framework adds a second layer: structural drift, new error signatures, cross-tier correlation."*
- *"`--auto` runs every 30 minutes via cron. If your platform team deploys a new environment on Monday morning, it's onboarded by Monday morning. Zero human intervention."*
- *"The runbook is generated by Claude from the actual service topology — not a generic template. It knows which services call the DB, which are ingress, and what dependencies exist."*

---

## How it works (30-second explanation)

```
LEARN  →  Search each service independently (50 traces each, parallel)
          Build fingerprints: "api-gateway always calls vets-service on GET /vets"
          Build error signatures: "customers-service has no DB errors in healthy state"

WATCH  →  Sample traces / error traces from the last 3 minutes
          Trace tier:  known root_op has zero traces → MISSING_SERVICE anomaly
          Error tier:  new error type seen → NEW_ERROR_SIGNATURE anomaly
          Output as JSON

TRIAGE →  Claude reads the JSON anomaly list
          Reasons about severity, root cause, action
          Writes DETECTION + TRIAGE to alerts.log
```

Single tier (trace or error):
```bash
python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json \
  | python3 agent.py --environment petclinicmbtest
```

Both tiers combined (recommended — gives Claude the full picture):
```bash
(python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json && \
 python3 core/error_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json) \
  | python3 agent.py --environment petclinicmbtest
```

---

## Restore / Reset

```bash
# Restore all services
k "kubectl scale deployment vets-service petclinic-db --replicas=1"

# Relearn trace baseline after disruptions
python3 core/trace_fingerprint.py --environment petclinicmbtest learn --reset --window-minutes 15
python3 core/trace_fingerprint.py --environment petclinicmbtest promote

# Relearn error baseline after disruptions (wait for clean window first)
python3 -c "
import json, pathlib, datetime
pathlib.Path('data/error_baseline.petclinicmbtest.json').write_text(json.dumps({
    'signatures': {},
    'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'environment': 'petclinicmbtest',
}))
print('Error baseline wiped.')
"

# Clear alert log
cat /dev/null > data/alerts.log
```
