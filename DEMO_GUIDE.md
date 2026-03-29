# Behavioral Anomaly Framework — Demo Guide

## Prerequisites

### Terminal setup (run once before demo)
```bash
cd /Users/mbui/Documents/o11y-behaviorbaseline
source .env

# AWS credentials for Bedrock (Claude reasoning)
source /tmp/aws_exports.sh

# SSH alias for cluster commands
alias k='sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@18.208.249.178'
```

### Splunk O11y URLs
- **APM Service Map**: https://app.us1.signalfx.com/#/apm?environments=petclinicmbtest
- **Behavioral Baseline Dashboard**: https://app.us1.signalfx.com/#/dashboard/HERM9jxA1po

### Verify cluster is healthy
```bash
k "kubectl get pods --no-headers | awk '{print \$1, \$3}'"
# All pods should show Running
```

### Verify baseline is clean (0 anomalies)
```bash
python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3
# Expected: "All trace paths match baseline"
```

### Open the alert log in a separate terminal
```bash
tail -f data/alerts.log
```

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

# Cron jobs managing everything autonomously
crontab -l | grep behavioral

# Confirm 0 anomalies right now
python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3
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
python3 core/error_fingerprint.py --environment petclinicmbtest learn --reset --window-minutes 2
python3 core/error_fingerprint.py --environment petclinicmbtest show
# Expected: 0 signatures (system is healthy)
```

### Step 1 — Kill the DB
```bash
k "kubectl scale deployment petclinic-db --replicas=0"
```

### Step 2 — Wait 3 minutes
The loadgen hits owner/pet endpoints every ~5 seconds. After 3 minutes the watch window will contain DB-failure error traces.

### Step 3 — Run detection + triage (one command)
```bash
python3 core/error_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json \
  | python3 agent.py --environment petclinicmbtest
```

**Expected terminal output:**
```
[agent] env=petclinicmbtest | 8 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — Multiple services (customers-service, vets-service, visits-service) are
    throwing new error signatures simultaneously, with customers-service unable to create
    database transactions, strongly indicating a shared database is down.
    Root cause: The database is unreachable, causing CannotCreateTransactionException in
    customers-service and 503 health-check failures across vets-service and visits-service.
    ...
    Confidence: HIGH | Affected: customers-service, vets-service, visits-service, api-gateway
    Recommended action: PAGE_ONCALL

    [TRIAGE SUMMARY] written to alerts.log
```

**Expected alerts.log:**
```
════════════════════════════════════════════════════════════════════════
[2026-03-29 05:21:39 UTC]  DETECTION
  anomaly type         : NEW_ERROR_SIGNATURE
  service              : customers-service
  message              : New error signature in customers-service: org.springframework.transaction.CannotCreateTransactionException on OwnerRepository.findAll
  error type           : org.springframework.transaction.CannotCreateTransactionException
  call path            : api-gateway:GET customers-service -> api-gateway:GET
────────────────────────────────────────────────────────────────────────
... (8 DETECTION entries total)

════════════════════════════════════════════════════════════════════════
[2026-03-29 05:21:39 UTC]  TRIAGE
  severity             : INCIDENT
  confidence           : HIGH
  affected services    : customers-service, vets-service, visits-service, api-gateway
  action               : PAGE_ONCALL
  narrative            : ...database is unreachable...
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

# Re-learn clean baseline after demo
python3 core/error_fingerprint.py --environment petclinicmbtest learn --reset --window-minutes 2
```

---

## Demo 2: Bad Deploy — New Error Signature on First Occurrence

**Story:** *"A new deploy of visits-service introduces a regression — the pod crashes immediately on startup. The very first request after the deploy hits the dead service and fires a brand new error signature on a code path that was previously clean. No threshold crossed. No baseline rate exceeded. First occurrence fires."*

### Prerequisites
```bash
# Clear alert log and ensure clean error baseline
cat /dev/null > data/alerts.log
python3 core/error_fingerprint.py --environment petclinicmbtest learn --reset --window-minutes 2
python3 core/error_fingerprint.py --environment petclinicmbtest show
# Expected: 0 signatures (system is healthy)
```

### Step 1 — Simulate bad deploy (visits-service crashes)
```bash
k "kubectl scale deployment visits-service --replicas=0"
```

### Step 2 — Wait 3 minutes
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
    Root cause: visits-service is down or unreachable, causing it to be skipped
    entirely in the GET /api/gateway/owners/{ownerId} call chain.
    ...customers-service is completing successfully, so the issue is isolated to
    visits-service...
    Confidence: HIGH | Affected: visits-service, api-gateway
    Recommended action: PAGE_ONCALL

    [TRIAGE SUMMARY] written to alerts.log
```

**Expected alerts.log:**
```
════════════════════════════════════════════════════════════════════════
[2026-03-29 06:17:53 UTC]  DETECTION
  anomaly type         : MISSING_SERVICE
  service              : api-gateway
  root op              : api-gateway:GET /api/gateway/owners/{ownerId}
  message              : Expected service(s) absent from 'api-gateway:GET /api/gateway/owners/{ownerId}': ['visits-service']
  missing services     : visits-service
  services in trace    : api-gateway, customers-service
────────────────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════════════════
[2026-03-29 06:17:53 UTC]  TRIAGE
  severity             : INCIDENT
  confidence           : HIGH
  affected services    : visits-service, api-gateway
  missing services     : api-gateway:GET /api/gateway/owners/{ownerId} → missing: visits-service
  action               : PAGE_ONCALL
  narrative            : ...visits-service has stopped appearing in traces...
                         customers-service is completing successfully, so the issue
                         is isolated to visits-service...
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
python3 core/error_fingerprint.py --environment petclinicmbtest learn --reset --window-minutes 2
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

### Step 2 — Wait 3 minutes
The loadgen hits the vets endpoint every ~5 seconds. After 3 minutes the watch window will contain only post-failure traces.

### Step 3 — Run detection + triage (one command)
```bash
python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 3 --json \
  | python3 agent.py --environment petclinicmbtest
```

**Expected terminal output:**
```
[watch] Discovering topology + searching traces in parallel (environment 'petclinicmbtest')...
  Topology: 6 services | Traces: 200 candidates
  Fetching 200 traces (20 parallel)...

  ANOMALY DETECTED
    Type:    MISSING_SERVICE
    Message: Expected service(s) absent from 'api-gateway:GET vets-service': ['vets-service']
    Detail:  Path: api-gateway:GET vets-service
    TraceID: 50c692ed3df2d5b6179dc9c3c249bad0
    Event sent (trace.path.drift)

  Checked 29 traces, 171 skipped, 1 anomalies detected

[agent] env=petclinicmbtest | 1 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — The vets-service is completely absent from traces that normally route
    through api-gateway:GET vets-service, indicating it is down or unreachable.
    Root cause: vets-service is likely crashed, unresponsive, or has lost network connectivity.
    ...
    Confidence: HIGH | Affected: vets-service, api-gateway
    Recommended action: PAGE_ONCALL

    [TRIAGE SUMMARY] written to alerts.log
    [PAGE_ONCALL] event emitted to Splunk
```

**Expected alerts.log:**
```
════════════════════════════════════════════════════════════════════════
[2026-03-29 04:27:01 UTC]  DETECTION
  anomaly type         : MISSING_SERVICE
  environment          : petclinicmbtest
  service              : api-gateway
  root op              : api-gateway:GET vets-service
  message              : Expected service(s) absent from 'api-gateway:GET vets-service': ['vets-service']
  trace id             : 50c692ed3df2d5b6179dc9c3c249bad0
  services in trace    : api-gateway
────────────────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════════════════
[2026-03-29 04:27:07 UTC]  TRIAGE
  severity             : INCIDENT
  confidence           : HIGH
  environment          : petclinicmbtest
  affected services    : vets-service, api-gateway
  assessment           : The vets-service is completely absent from traces that
                         normally flow through api-gateway:GET vets-service.
  root cause           : vets-service is not responding or has crashed, causing
                         api-gateway to receive no downstream spans.
  missing services     : api-gateway:GET vets-service → missing: api-gateway
  action               : PAGE_ONCALL
  narrative            : In the last 3 minutes, traces for 'api-gateway:GET vets-service'
                         show only the api-gateway span — vets-service has completely vanished
                         from the call path...
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
python3 core/error_fingerprint.py --environment petclinicmbtest learn --reset --window-minutes 2

# Clear alert log
cat /dev/null > data/alerts.log
```
