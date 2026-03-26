# Behavioral Anomaly Framework — Demo Guide

## Prerequisites

### Terminal setup (run once before demo)
```bash
export SPLUNK_ACCESS_TOKEN=DxSpXOuecLJ-QNbcv1xz5w
export SPLUNK_INGEST_TOKEN=1gMZutcDJFLpeLF_Ku3Nqw
export SPLUNK_REALM=us1
cd /Users/mbui/Documents/o11y-behaviorbaseline

# SSH alias for cluster commands
alias k='sshpass -p "<EC2_PASSWORD>" ssh -p 2222 -o StrictHostKeyChecking=no splunk@18.207.160.194'
```

### Splunk O11y URLs to have open
- **APM Service Map**: https://app.us1.signalfx.com/#/apm?environments=petclinicmbtest
- **Behavioral Baseline Dashboard**: https://app.us1.signalfx.com/#/dashboard/HERM9jxA1po
- **Detectors**: https://app.us1.signalfx.com/#/alerts/detectors

### Verify cluster is healthy before starting
```bash
k "kubectl get pods --no-headers | awk '{print \$1, \$3}'"
# All pods should show Running
```

### Run watch in a dedicated terminal during demo
```bash
# Keep this running — shows detections in real time
tail -f /tmp/bab_petclinicmbtest_trace.log \
        /tmp/bab_petclinicmbtest_error.log \
        /tmp/bab_petclinicmbtest_correlate.log
```

---

## Demo 0: Context Setting — Show the Framework in Steady State

**Talking point:** *"This is what the framework looks like before we break anything.
Every component is autonomous — no manual alerting rules, no hardcoded thresholds."*

```bash
# What's been provisioned
python3 onboard.py --show-state

# 47 known call patterns learned from real traffic
python3 trace_fingerprint.py --environment petclinicmbtest show

# 5 known error signatures
python3 error_fingerprint.py --environment petclinicmbtest show

# Cron jobs managing everything — no manual scheduling
crontab -l | grep behavioral
```

Open the Behavioral Baseline Dashboard — 4 panels live, empty = healthy.

---

## Demo 1: New Error Signatures — DB Goes Down ⭐ Most Reliable

**What fires:** `NEW_ERROR_SIGNATURE` + `SIGNATURE_VANISHED` → `error.signature.drift` events

**Story:** *"The database goes down. Services start throwing transaction errors and
health check 503s that have never appeared before. Simultaneously, the normal
heartbeat errors that were always present disappear — because now everything is
broken, not just intermittent. The framework catches both the new errors AND the
shift in error pattern."*

### Step 1 — Prep: confirm error baseline
```bash
python3 error_fingerprint.py --environment petclinicmbtest show
# Should show 4 java.net.ConnectException signatures, all seen >= 2
```

### Step 2 — Take down the DB
```bash
kubectl scale deployment petclinic-db --replicas=0
kubectl get pods | grep petclinic-db   # confirm gone
```

### Step 3 — Generate traffic to create errors
```bash
for i in $(seq 1 5); do curl -s -o /dev/null --max-time 3 http://localhost:81/api/customer/owners; done
```

### Step 4 — Run detection (or wait for cron)
```bash
python3 error_fingerprint.py --environment petclinicmbtest watch --window-minutes 5
```

**Expected output:**
```
ANOMALY DETECTED
  Type:    NEW_ERROR_SIGNATURE
  Message: New error signature in customers-service: org.springframework.transaction.CannotCreateTransactionException on OwnerRepository.findAll
  Detail:  call_path=api-gateway:GET customers-service -> api-gateway:GET

ANOMALY DETECTED
  Type:    NEW_ERROR_SIGNATURE
  Message: New error signature in customers-service: 503 on GET /actuator/health
  Detail:  call_path=admin-server:GET

ANOMALY DETECTED
  Type:    SIGNATURE_VANISHED
  Message: Dominant error signature disappeared in customers-service: java.net.ConnectException on GET (was 43% of service errors)
  Detail:  baseline_rate=0.75/run  service_share=43%

  Checked N traces, 0 skipped, 8 anomalies detected
```

**Key talking point:** *"A full DB outage doesn't just spike existing errors — it changes
the entire error signature profile. The framework detected brand new error types AND
noticed that the previously dominant patterns vanished, replaced by something worse."*

**Show:** **Error Signature Drift** panel in dashboard updates.

### Step 5 — Restore
```bash
kubectl scale deployment petclinic-db --replicas=1
kubectl rollout status deployment/petclinic-db --timeout=60s
```

### Step 6 — Re-learn to clean baseline after demo
```bash
python3 error_fingerprint.py --environment petclinicmbtest learn --window-minutes 30
```

---

## Demo 2: Brand New Error — Never Seen Before ⭐ Most Reliable

**What fires:** `NEW_ERROR_SIGNATURE` → `error.signature.drift` event

**Story:** *"A bad deploy introduces a 500 error on a new code path that has
never appeared before. The framework fires on first occurrence — no threshold,
no tuning required."*

### Step 1 — Generate a new error type
```bash
# Hit non-existent owner IDs — generates 404/500 with a new operation name
k "for i in \$(seq 1 15); do
  curl -s -o /dev/null http://localhost:81/api/customer/owners/99999
  curl -s -o /dev/null http://localhost:81/api/vet/vets/99999
done"
```

### Step 2 — Run detection
```bash
python3 error_fingerprint.py --environment petclinicmbtest watch --window-minutes 5
```

**Expected output:**
```
ANOMALY DETECTED
  Type:    NEW_ERROR_SIGNATURE
  Message: New error signature in customers-service: 404 on GET /owners/{ownerId}
  Detail:  call_path=api-gateway:GET -> customers-service:GET /owners/{ownerId}
           http_status=404
  Event sent (error.signature.drift)
```

**Key point:** *"First occurrence fires immediately. After 5 consecutive watch
runs it auto-promotes to baseline and goes quiet — because it's now 'expected
bad behavior'. No one has to manually tune anything."*

---

## Demo 3: Missing Service — vets-service Disappears

**What fires:** `MISSING_SERVICE` → `trace.path.drift` event

**Story:** *"vets-service crashes. The trace for the vets endpoint no longer
includes it — the framework detects the structural change in the call graph."*

### Step 0 — Verify baseline includes vets-service
```bash
python3 trace_fingerprint.py --environment petclinicmbtest show | grep -A5 "vets-service"
# Should show: api-gateway:GET vets-service pattern with services=[api-gateway, vets-service]
```

### Step 1 — Scale down vets-service
```bash
k "kubectl scale deployment vets-service --replicas=0"
k "kubectl get pods | grep vets"   # confirm gone (Terminating → no output)
```

### Step 2 — Generate traffic to the vets endpoint
```bash
# Note: /api/vet/vets is the correct route (not /api/gateway/vets)
k "for i in \$(seq 1 10); do curl -s -o /dev/null http://localhost:81/api/vet/vets; sleep 0.5; done"
```

### Step 3 — Run detection
```bash
sleep 10  # allow trace ingestion
python3 trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 5
```

**Expected output:**
```
ANOMALY DETECTED
  Type:    MISSING_SERVICE
  Message: Expected service(s) absent from 'api-gateway:GET vets-service': ['vets-service']
  Detail:  Path: api-gateway:GET vets-service
  Event sent (trace.path.drift)
```

**Key talking point:** *"When vets-service disappears, the gateway trace collapses to a single
span — no child spans, no downstream calls. The framework detects the structural absence:
this root operation normally reaches vets-service, and now it doesn't."*

**Show:** **Trace Path Drift** panel in dashboard.

### Step 4 — Restore
```bash
k "kubectl scale deployment vets-service --replicas=1"
k "kubectl rollout status deployment/vets-service --timeout=60s"
```

---

## Demo 4: Correlated Anomaly — Two Tiers Hit at Once ⭐ Highest Impact

**What fires:** `TIER2_TIER3` → `behavioral_baseline.correlated_anomaly`

**Story:** *"Two independent signals — a missing service AND an error spike —
both hit at the same time. Either alone might be a false positive. Together
they're high-confidence. One consolidated alert instead of two noisy ones."*

### Step 1 — Trigger both simultaneously
```bash
# Missing service (tier 2)
k "kubectl scale deployment vets-service --replicas=0"

# Error spike (tier 3)
k "kubectl scale deployment petclinic-db --replicas=0"

# Generate traffic
k "for i in \$(seq 1 15); do
  curl -s -o /dev/null --max-time 3 http://localhost:81/api/vet/vets
  curl -s -o /dev/null --max-time 3 http://localhost:81/api/customer/owners
  sleep 0.5
done"
```

### Step 2 — Run both watch cycles
```bash
sleep 10  # allow trace ingestion
python3 trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 5
python3 error_fingerprint.py --environment petclinicmbtest watch --window-minutes 5
```

### Step 3 — Correlate
```bash
python3 correlate.py --environment petclinicmbtest --window-minutes 15
```

**Expected output:**
```
Found 1 correlated anomaly group(s):

[Major] TIER2_TIER3 — customers-service
  Tiers:         tier2, tier3
  Anomaly types: MISSING_SERVICE, NEW_ERROR_SIGNATURE
  Events:        4 over 38s
  - Expected service(s) absent from 'api-gateway:GET vets-service': ['vets-service']
  - New error signature in customers-service: org.springframework.transaction.CannotCreateTransactionException on ...

Event sent (behavioral_baseline.correlated_anomaly)
```

**Show:** All three panels update: Trace Drift, Error Drift, Correlated Anomalies.

### Step 4 — Restore
```bash
k "kubectl scale deployment vets-service --replicas=1"
k "kubectl scale deployment petclinic-db --replicas=1"
```

---

## Demo 5: Deploy-Correlated — Severity Downgraded ⭐ Most Differentiated

**What fires:** Same as Demo 4, but annotated and downgraded Major → Minor

**Story:** *"Same exact anomalies. But this time the team called
notify_deployment.py before deploying. The correlator finds the deployment
event, downgrades the severity, and tells you exactly which deploy caused it.
On-call engineer sees: not an incident — it's the 2:34pm deploy by demo-user."*

### Step 1 — Emit deployment event FIRST
```bash
python3 notify_deployment.py \
  --service customers-service vets-service \
  --environment petclinicmbtest \
  --version v2.1.0 \
  --deployer "demo-user" \
  --commit "abc123def" \
  --description "Refactor owner lookup — adds new caching layer"
```

**Show the output:**
```
[sent] deployment.started  service=customers-service  version=v2.1.0
[sent] deployment.started  service=vets-service       version=v2.1.0
[scheduled] baseline re-learn for 'petclinicmbtest' in 5m (background)
```

### Step 2 — Trigger the same disruptions
```bash
k "kubectl scale deployment vets-service --replicas=0"
k "kubectl scale deployment petclinic-db --replicas=0"
k "for i in \$(seq 1 15); do
  curl -s -o /dev/null --max-time 3 http://localhost:81/api/vet/vets
  curl -s -o /dev/null --max-time 3 http://localhost:81/api/customer/owners
  sleep 0.5
done"
```

### Step 3 — Run watch + correlate
```bash
python3 trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 5
python3 error_fingerprint.py --environment petclinicmbtest watch --window-minutes 5
python3 correlate.py --environment petclinicmbtest --window-minutes 15
```

**Expected output — compare with Demo 4:**
```
[Minor] TIER2_TIER3 — customers-service  [deployment-correlated]
  Tiers:         tier2, tier3
  Deployment:    version=v2.1.0  commit=abc123def  deployer=demo-user
                 "Refactor owner lookup — adds new caching layer"
```

**Major → Minor. Context instead of confusion.**

### Step 4 — Restore
```bash
k "kubectl scale deployment vets-service --replicas=1"
k "kubectl scale deployment petclinic-db --replicas=1"
```

---

## Demo 6: Auto-Onboarding a New Environment

**What fires:** `onboard.py --auto` discovers and fully provisions new env

**Story:** *"A new team deploys hipster-shop with OTel instrumentation.
Nobody touches this framework. Within 30 minutes it discovers the new
environment, provisions 11 detectors, builds a baseline, creates a dashboard,
and registers cron jobs. Zero human intervention."*

### Step 1 — Show current state
```bash
python3 onboard.py --show-state
# Only petclinicmbtest
crontab -l | grep behavioral
# Only petclinicmbtest cron jobs
```

### Step 2 — Run auto-discovery
```bash
# If hipstershop-mbtest is deployed:
python3 onboard.py --auto

# If not, show what it would do:
python3 onboard.py --auto --dry-run
```

**Expected output (if new env present):**
```
[onboard] Discovering all active environments...
  petclinicmbtest:    5 services
  hipstershop-mbtest: 9 services  ← NEW

[onboard] Acting on changes...
  [new] hipstershop-mbtest
    Provisioned 11 / 11 detector(s)
    Dashboard created: <id>
    Added 5 cron job(s) for 'hipstershop-mbtest'
```

### Step 3 — Show the result
```bash
python3 onboard.py --show-state      # new env in state with services list
crontab -l | grep behavioral         # new cron jobs registered
```

---

## Demo Quick Reference Card

| # | Demo | Setup | Disrupt | Detect | Signal |
|---|------|-------|---------|--------|--------|
| 1 | Error spike | — | `scale petclinic-db --replicas=0` | `error watch` | `SIGNATURE_SPIKE` |
| 2 | New error | — | `curl /owners/99999` ×15 | `error watch` | `NEW_ERROR_SIGNATURE` |
| 3 | Missing service | re-learn baseline | `scale vets-service --replicas=0` | `trace watch` | `MISSING_SERVICE` |
| 4 | Correlated | — | Demo 3 + Demo 1 together | both watches + correlate | `TIER2_TIER3` |
| 5 | Deploy-correlated | — | `notify_deployment.py` then Demo 4 | both watches + correlate | `TIER2_TIER3` [downgraded] |
| 6 | Auto-onboard | 2nd env deployed | `onboard.py --auto` | state + crontab | new env provisioned |

## Recommended Demo Order

**Short demo (15 min):** Demo 0 → Demo 1 → Demo 5
**Full demo (30 min):** Demo 0 → Demo 1 → Demo 2 → Demo 4 → Demo 5 → Demo 6

## Restore All (Emergency Reset)
```bash
k "kubectl scale deployment vets-service petclinic-db visits-service --replicas=1"
k "kubectl rollout status deployment/vets-service deployment/petclinic-db --timeout=120s"
```
