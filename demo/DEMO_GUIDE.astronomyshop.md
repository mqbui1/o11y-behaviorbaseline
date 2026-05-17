# Behavioral Anomaly Framework — Demo Guide (Astronomy Shop)

This guide covers the **OpenTelemetry Demo (Astronomy Shop)** cluster.
For the PetClinic cluster, see `DEMO_GUIDE.md`.

---

## Signal Types — What You're Looking At

| Signal | What it means | Demo |
|--------|--------------|------|
| `NEW_FINGERPRINT` | A trace took a call path that has never been seen before — a new service was called, or an existing one was skipped. Fires on the **first occurrence**. | Demo 2 |
| `MISSING_SERVICE` | A root operation that normally involves a specific service produced **zero traces** in the detection window — the service is structurally absent, not just erroring. | Demo 1, 4, 5, 8 |
| `NEW_ERROR_SIGNATURE` | A span produced an exception or error type that has never appeared in this service before. Fires on **first occurrence**, no threshold required. | Demo 3, 4, 5 |
| `LATENCY_ANOMALY` | Mean latency for a service/operation exceeded 3 standard deviations above its learned baseline. Fires without any threshold configuration — baseline is learned from the first 30 traces. | Demo 6, 9, 10 |
| `ERROR_RATE_ANOMALY` | The fraction of error spans for a service/operation exceeded 5% over a rolling window. Complements NEW_ERROR_SIGNATURE — fires on sustained rate, not just first occurrence. | Demo 7, 8 |
| `SPAN_COUNT_DROP` | A trace has **far fewer spans** than the learned baseline range — downstream hops or instrumented calls silently absent. Catches silent failures that produce no error signal. | Demo 11 |
| `SPAN_COUNT_SPIKE` | A trace has **far more spans** than the learned baseline max — retry storm, fan-out explosion, or loop that shouldn't run. | Demo 12 |
| `INFRA_EVENT` | Pod-level Kubernetes warning event (OOMKilling, CrashLoopBackOff, BackOff) correlated to a service by pod name. Surfaced in the topology UI alongside trace anomalies. | Demo 10 |

---

## Astronomy Shop Architecture

22 services. Load generator at ~10 users / ~2 RPS drives the following main flows:

```
load-generator
  ├── user_browse_product  → frontend → product-catalog → recommendation
  ├── user_add_to_cart     → frontend → cart ──→ valkey-cart (Redis, untraced)
  ├── user_view_cart       → frontend → cart
  └── user_checkout_single → frontend → checkout ──→ payment
                                                  └→ cart
                                                  └→ email
                                                  └→ shipping → currency
                                                  └→ product-catalog
                                                  └→ currency
```

**Key shared dependencies:**
- `cart` — all checkout paths go through cart; backed by `valkey-cart` (Redis, not OTel-instrumented)
- `checkout` — orchestrates the full order flow: calls payment, cart, email, shipping, product-catalog, currency
- `product-catalog` — called by recommendation, cart, checkout, frontend

**Bidirectional orchestrator pattern:** `checkout ↔ frontend` both call each other (checkout reads cart state from frontend, frontend initiates checkout). This is normal and expected in the topology.

---

## New Cluster Setup (run once per workshop instance)

### What you need
- EC2 instance with k3d + Astronomy Shop + splunk-otel-collector already deployed
- Splunk workshop environment credentials from the `workshop-secret` ConfigMap

### Step 1 — Extract tokens from the cluster (on EC2)
```bash
ssh -p 2222 splunk@<ec2-ip>  # password: Sp1unkH00di3

kubectl get secret workshop-secret -o jsonpath='{.data.access_token}' | base64 -d && echo  # INGEST token
kubectl get secret workshop-secret -o jsonpath='{.data.api_token}'    | base64 -d && echo  # API token
kubectl get secret workshop-secret -o jsonpath='{.data.env}'          | base64 -d && echo  # environment name
```

### Step 2 — Update `.env` (local Mac)
```bash
EC2_IP=<new-ec2-ip>
EC2_PASSWORD=Sp1unkH00di3
ENV=<env-name>                       # e.g. astronomyshop-84f5-workshop
SPLUNK_INGEST_TOKEN=<ingest-token>   # from access_token above
SPLUNK_ACCESS_TOKEN=<api-token>      # from api_token above
SPLUNK_REALM=us1

source .env
alias k='sshpass -p "$EC2_PASSWORD" ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@$EC2_IP'
```

### Step 3 — Copy source to EC2 and build image
```bash
# Copy otel-processor source to EC2
sshpass -p "$EC2_PASSWORD" scp -P 2222 -r otel-processor/ splunk@$EC2_IP:/home/splunk/

# On EC2: build image (NO registry — k3d uses direct import)
k "cd /home/splunk/otel-processor && docker build --no-cache -t otelcol-fingerprint:latest ."
```

> **k3d clusters do NOT have a local registry on port 9999.** Build the image without a
> registry prefix and import directly into k3d. `deploy.sh` handles this automatically
> when `K3D_CLUSTER` is set.

### Step 4 — Deploy the OTel processor (fast path — ~10 min total)

The **fastest path** for Astronomy Shop is `--otel-bootstrap`, which skips APM API calls entirely
and learns fingerprints directly from live traffic in a 5-minute OTel bootstrap window:

```bash
# Get the k3d cluster name (on EC2)
k "k3d cluster list"
# Output: astronomyshop-84f5-cluster (or similar)

# Full deploy from scratch — builds image, wires all 16 app deployments, learns baseline
k "cd /home/splunk/o11y-behaviorbaseline && \
   K3D_CLUSTER=astronomyshop-84f5-cluster \
   ./otel-processor/deploy.sh $ENV --app astronomy-shop --otel-bootstrap"
```

**What `--otel-bootstrap` does end-to-end:**
1. Seeds empty baseline (skips APM API learn step)
2. Builds image + imports into k3d via `k3d image import` (no registry needed)
3. Sets `OTEL_EXPORTER_OTLP_ENDPOINT` on all 16 app deployments → otelcol-fingerprint
4. Waits for all rollouts, deploys aggregator StatefulSet + DaemonSet
5. Waits 5 minutes for aggregator bootstrap window to complete
6. Pulls merged baseline from both aggregator pods, promotes all fingerprints
7. Pushes promoted baseline to ConfigMap + injects into all pods

> **Astronomy Shop uses built-in OTel SDK** — no OTel Operator Instrumentation CR needed.
> `deploy.sh` sets `OTEL_EXPORTER_OTLP_ENDPOINT` directly on each deployment.

### Step 5 — Verify (local Mac)
```bash
source .env
./demo/check-ready.sh
# Expected: 8/8 checks passing
# Local baseline: ~124 fingerprints (22 services × 5–8 paths each)
```

### Re-deploy (subsequent sessions, image already built)
```bash
# Push updated baselines + re-deploy config (no build, no app rewiring needed)
sshpass -p "$EC2_PASSWORD" scp -P 2222 \
  data/baseline.$ENV.json splunk@$EC2_IP:/tmp/baseline.$ENV.json
sshpass -p "$EC2_PASSWORD" scp -P 2222 \
  data/error_baseline.$ENV.json splunk@$EC2_IP:/tmp/error_baseline.$ENV.json

k "mkdir -p /home/splunk/o11y-behaviorbaseline/data && \
   cp /tmp/baseline.$ENV.json /home/splunk/o11y-behaviorbaseline/data/baseline.$ENV.json && \
   cp /tmp/error_baseline.$ENV.json /home/splunk/o11y-behaviorbaseline/data/error_baseline.$ENV.json && \
   cd /home/splunk/o11y-behaviorbaseline && \
   K3D_CLUSTER=astronomyshop-84f5-cluster \
   ./otel-processor/deploy.sh $ENV --skip-learn --skip-build"
```

---

## Prerequisites

### Terminal setup
```bash
cd /Users/mbui/Documents/o11y-behaviorbaseline
source .env
alias k='sshpass -p "$EC2_PASSWORD" ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@$EC2_IP'
```

### Refresh AWS credentials (required for Claude/Bedrock triage)

**Step 1 — In the CLAUDE CODE terminal:**
```bash
cd /Users/mbui/Documents/o11y-behaviorbaseline && python3 refresh_aws_creds.py
```

**Step 2 — Back in demo terminal:**
```bash
source .env
```

### Splunk O11y URLs
- **APM Service Map**: https://app.us1.signalfx.com/#/apm?environments=$ENV
- **Behavioral Baseline Dashboard**: https://app.us1.signalfx.com/#/dashboard/HERM9jxA1po

### Pre-flight check
```bash
./demo/check-ready.sh
```

Checks: AWS credentials, cluster pods (3 DaemonSet forwarders + 2 aggregator detectors), baseline fingerprints, Splunk API, 0 drift events in last 30s, 0 stale OTel events in Splunk.

### Reset before demo session

**Full reset** (before first demo — ~2-3 minutes):
```bash
python3 refresh_aws_creds.py  # in Claude Code terminal
source .env                   # back in demo terminal
./demo/demo-reset.sh
```

`demo-reset.sh` does: restore all services → wipe error baseline → clear dedup state → push clean trace baseline → cycle OTel pods → verify 0 anomalies.

**Between demos** (~70s without cache restore, ~100s with):
```bash
./demo/demo-between.sh           # after demos where only a service was killed
./demo/demo-between.sh --cache   # after demos where valkey-cart/Redis was killed
./demo/demo-between.sh --quick   # local state only, no cluster ops
```

> **After every `demo-between.sh`:** restart `poll_drift_events.py` — pod names change when pods cycle.

### Open the live event stream
```bash
# Terminal 2 — leave running throughout the demo
python3 -u demo/poll_drift_events.py
```

---

## Demo 0: Steady State — Framework Is Running

**Story:** *"Before we break anything — this is what the framework looks like in steady state.
22 services, ~2 RPS from the load generator, 124 fingerprints loaded in every collector node.
No alert rules written, no thresholds configured."*

```bash
./demo/check-ready.sh
```

**Key talking points:**
- *"One command — 8 checks. The framework learned call patterns from live Astronomy Shop traffic and pushed them to every collector node in the DaemonSet."*
- *"124 fingerprints — every variant of every trace path across 22 services. Any deviation fires in ~10 seconds."*
- *"0 drift events in the last 30s. The detector is quiet. This is the baseline we're about to break."*

---

## Demo 1: Kill Service — APM Still Green, Framework Already Paged

**Story:** *"checkout is killed. The APM Service Map shows green — no alert, no incident. Metrics haven't accumulated yet. Meanwhile the OTel edge processor detected the structural absence on the very first affected trace and fired in ~10 seconds. Claude reads that signal and pages on-call before APM knows anything happened."*

### Prerequisites
```bash
./demo/demo-between.sh
```

### Step 1 — Open APM Service Map
Point browser at the Splunk APM Service Map for this environment. Confirm all services green.

### Step 2 — Kill checkout
```bash
k "kubectl scale deployment checkout --replicas=0"
```

### Step 3 — Watch framework fire in real time
In terminal 2 (poll_drift_events.py running):

Within **10–15 seconds** you'll see `trace.path.drift (MISSING_SERVICE)` for `checkout`. Refresh APM — still green.

> *"The OTel processor fingerprints every trace as it flows through the collector — no polling interval, no metric accumulation. checkout disappeared from the first affected trace, and that's enough."*

### Step 4 — Run triage
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

**Expected output:**
```
[agent] env=<env> | 1 anomaly(s) from watch
  Reasoning with Claude...

[!!] INCIDENT — checkout is absent from all checkout flow traces.
    Root cause: checkout service is down or unreachable.
    Confidence: HIGH | Affected: checkout, frontend
    Recommended action: PAGE_ONCALL
```

**Key talking points:**
- *"APM metrics need minutes to accumulate before a threshold fires. The OTel processor fires on the first affected trace — that's the gap."*
- *"No alert rule was written. The processor learned what 'normal' looks like at baseline time."*

### Restore
```bash
k "kubectl scale deployment checkout --replicas=1"
./demo/demo-between.sh
```

---

## Demo 2: New Call Path — Structural Drift

**Story:** *"A code change makes product-catalog call recommendation for every product lookup — a dependency that never existed before. The framework detects the new edge on the first trace that contains it, surfaces it as a new node in the topology, and fires NEW_FINGERPRINT. No error, no latency change — purely structural."*

### Prerequisites
```bash
./demo/demo-between.sh
```

### Step 1 — Trigger new call path (topology simulation)
Open the Topology UI and click **2 New Call Path**.

Or via API:
```bash
curl -X GET "http://localhost:8080/api/demo/new-call-path"
```

### Step 2 — Observe in topology
- A new node `recommendation` appears connected to `product-catalog` with a discovered (dashed) edge
- The panel shows `NEW_FINGERPRINT` on product-catalog
- The new edge is highlighted in the causality chain

**Key talking points:**
- *"A new service dependency appeared in production. No deployment was announced, no feature flag was toggled — the framework just noticed it."*
- *"First occurrence — no threshold. One trace with the new edge is enough to fire."*

### Restore
```bash
./demo/demo-between.sh --quick
```

---

## Demo 3: New Error Signature — First Occurrence

**Story:** *"product-catalog starts returning errors that have never appeared before — a DataAccessException on GetProduct. The framework fires on the very first occurrence. No error rate threshold, no minimum sample count."*

### Step 1 — Kill product-catalog (or inject via topology UI)
To trigger real signals from the cluster:
```bash
k "kubectl scale deployment product-catalog --replicas=0"
```

Or use the topology simulation button **3 New Error Sig**.

### Step 2 — Watch OTel stream
Within **~10 seconds:**
```
[HH:MM:SS] error.signature.drift
  service=product-catalog  error_type=DataAccessException  op=GetProduct
```

### Step 3 — Triage
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

**Key talking points:**
- *"First occurrence fires. This is the signal you can't get from error rate alerting — you need to see at least N errors before a rate threshold fires. We saw one."*

### Restore
```bash
k "kubectl scale deployment product-catalog --replicas=1"
./demo/demo-between.sh
```

---

## Demo 4: Cache Incident — Structural + Error, Two Tiers

**Story:** *"valkey-cart (the Redis cache backing cart) goes down. Within ~10 seconds, cart and checkout throw RedisConnectionException — new error signatures, never seen before. At ~60 seconds, the MISSING_SERVICE checker fires: cart traces show no valkey-cart anywhere. Two detection mechanisms, two latencies, one root cause."*

### Prerequisites
```bash
./demo/demo-between.sh --cache
```

### Step 1 — Kill valkey-cart
```bash
k "kubectl scale deployment valkey-cart --replicas=0"
```

Or use the topology simulation button **4 Cache Incident**.

### Step 2 — Watch OTel stream
- **~10 seconds:** `error.signature.drift` — `RedisConnectionException` on cart:AddItem and checkout:PlaceOrder
- **~60 seconds:** `trace.path.drift (MISSING_SERVICE)` — valkey-cart absent from all cart/checkout traces

### Step 3 — Triage (fires on error signals, ~15s)
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

**Expected output:**
```
[!!] INCIDENT — cart is failing on all cache operations, cascading errors through checkout.
    Root cause: valkey-cart (Redis cache) is down — RedisConnectionException on AddItem/PlaceOrder.
    Confidence: HIGH | Affected: cart, checkout
    Recommended action: PAGE_ONCALL
```

**Key talking points:**
- *"The error tier fires in ~10 seconds on the first failed Redis call. The structural tier fires at ~60 seconds confirming complete absence. Two layers of signal, one incident."*
- *"valkey-cart isn't even OTel-instrumented — it's a plain Redis pod. The framework detects its failure through the absence of its spans in the services that call it."*

### Step 4 — Cross-tier correlation
```bash
python3 core/correlate.py --environment $ENV --window-minutes 20
```

### Restore
```bash
k "kubectl scale deployment valkey-cart --replicas=1"
./demo/demo-between.sh --cache
```

---

## Demo 5: Cascading Failure — Root Cause in a Chain

**Story:** *"checkout is killed. frontend starts throwing ServiceUnavailableException on every checkout request. cart starts timing out. Three services affected, three anomaly signals — but the framework identifies checkout as the root cause because it's structurally absent, not just erroring."*

### Step 1 — Kill checkout
```bash
k "kubectl scale deployment checkout --replicas=0"
```

Or use the topology simulation button **5 Cascading Failure**.

### Step 2 — Watch propagation unfold
- **t=0:** `MISSING_SERVICE` — checkout absent from traces
- **t=2s:** `NEW_ERROR_SIGNATURE` — frontend: ServiceUnavailableException on POST /api/checkout
- **t=2s:** `NEW_ERROR_SIGNATURE` — cart: TimeoutException on AddItem

### Step 3 — Triage
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

**Expected output:**
```
[!!] INCIDENT — checkout is absent from traces, causing cascading failures in frontend and cart.
    Root cause: checkout is down.
    Confidence: HIGH | Affected: checkout, frontend, cart
    Causality chain: checkout → frontend → cart
    Recommended action: PAGE_ONCALL
```

**Key talking points:**
- *"Three services with anomalies — the framework doesn't just list them. It identifies the structural root: checkout is completely absent, so everything that calls it is secondary."*
- *"The causality chain shows propagation order. The on-call engineer goes straight to checkout."*

### Restore
```bash
k "kubectl scale deployment checkout --replicas=1"
./demo/demo-between.sh
```

---

## Demo 6: Latency Spike — tc-netem Network Delay

**Story:** *"product-catalog starts responding slowly — 892ms instead of 4ms. The OTel processor has a learned latency baseline for this service. A z-score of 7340σ fires immediately on the first affected trace. Claude identifies the degradation and recommends investigation."*

### Prerequisites
```bash
./demo/demo-between.sh
# Confirm OTel pods have been running ≥2 min (latency baseline requires ~30 traces)
k "kubectl get pods -l app=otelcol-aggregator"
```

### Step 1 — Inject network delay
```bash
./demo/demo-latency.astronomyshop.sh --inject
```

This uses `tc-netem` via `nsenter` on the k3d node to add 3s of network latency to `product-catalog`.

### Step 2 — Watch LATENCY_ANOMALY fire
Within **~10 seconds:**
```
[HH:MM:SS] latency anomaly detected
  service=product-catalog  op=GetProduct  current=892ms  baseline=4ms  z=7340
```

### Step 3 — Triage
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

### Step 4 — Remove delay
```bash
./demo/demo-latency.astronomyshop.sh --stop
```

**Key talking points:**
- *"No threshold was set. The baseline was learned from live traffic — first 30 traces. z=7340σ fires on the first affected trace after the delay was injected."*
- *"Latency anomalies are per-service, per-operation. product-catalog slowing down doesn't trigger false alerts on cart or checkout."*

### Restore
```bash
./demo/demo-between.sh
```

---

## Demo 7: Error Rate Spike — Sustained Failure

**Story:** *"payment starts rejecting every charge — 100% error rate. Two signals fire together: NEW_ERROR_SIGNATURE on the first bad span, then ERROR_RATE_ANOMALY once 10+ error spans have accumulated. The rate signal confirms it's not a one-off."*

### Step 1 — Kill payment or inject errors
```bash
./demo/demo-error-rate.astronomyshop.sh
```

Or use the topology simulation button **7 Error Rate**.

### Step 2 — Watch signals (in order)
- **~10s:** `NEW_ERROR_SIGNATURE` — PaymentServiceException on Charge (first occurrence)
- **~30s:** `ERROR_RATE_ANOMALY` — payment 100% error rate over 38 spans

### Step 3 — Triage
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

**Key talking points:**
- *"Two complementary signals: structural (first occurrence, no threshold) and metric (sustained rate, confirms it's not transient). The first fires in 10 seconds; the second confirms pattern."*

### Restore
```bash
./demo/demo-error-rate.astronomyshop.sh --restore
./demo/demo-between.sh
```

---

## Demo 8: Combined Signal — Structural + Metric

**Story:** *"checkout disappears from traces (MISSING_SERVICE) and payment simultaneously starts throwing PaymentServiceException at 97% error rate. Both happen because checkout orchestrates payment — when checkout fails, payment calls pile up and fail. The framework identifies checkout as the root cause because it's structurally absent; payment's errors are a downstream effect."*

### Step 1 — Trigger combined scenario (topology simulation)
Open the Topology UI and click **8 Combined**.

Or via API:
```bash
curl -X GET "http://localhost:8080/api/demo/combined-metric"
```

### Step 2 — Observe in topology
- checkout: `MISSING_SERVICE` → `ROOT CAUSE ★`
- payment: `ERROR_RATE_ANOMALY` + `NEW_ERROR_SIGNATURE` → downstream effect (suppressed)
- Causality chain: `checkout → payment`

### Step 3 — Triage
Click **Triage** in the topology UI or run:
```bash
python3 demo/poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV
```

**Key talking points:**
- *"Structural absence wins over metric anomaly in root cause scoring. checkout is gone — payment is suffering the consequences. The framework doesn't just list affected services; it ranks them by causal order."*

### Restore
```bash
./demo/demo-between.sh --quick
```

---

## Demo 9: Slow Shared Cache — Correlated Latency

**Story:** *"valkey-cart (the Redis cache) is overloaded but still responding — no MISSING_SERVICE, no errors. cart, checkout, and frontend all slow down simultaneously because they all depend on cache reads. The framework identifies cart as the root cause because it's the shared dependency that's directly overloaded; checkout and frontend are secondary callers."*

### Step 1 — Trigger slow-db scenario (topology simulation)
Open the Topology UI and click **9 Slow Cache**.

Or via API:
```bash
curl -X GET "http://localhost:8080/api/demo/slow-db"
```

### Step 2 — Observe in topology
- cart: `LATENCY_ANOMALY` 3950ms (baseline 32ms) → `ROOT CAUSE ★`
- checkout: `LATENCY_ANOMALY` 4100ms → downstream (suppressed)
- frontend: `LATENCY_ANOMALY` 4250ms → downstream (suppressed)
- Causality chain: `cart → checkout → frontend`

**Key talking points:**
- *"No error signal, no structural change. Pure latency, but correlated across three services simultaneously. The shared dependency — cart's Redis backend — is the root cause."*
- *"valkey-cart isn't even traced. The framework infers the cache problem from the services that depend on it."*

### Restore
```bash
./demo/demo-between.sh --quick
```

---

## Demo 10: OOM Crash — Latency Then Missing

**Story:** *"cart starts slowing down (GC pressure from memory leak). Then 4 seconds later it crashes entirely and disappears from traces. Two signals, time-ordered: LATENCY_ANOMALY first, then MISSING_SERVICE. Claude reads both and identifies a memory-pressure-induced crash."*

### Step 1 — Trigger OOM scenario (topology simulation)
Open the Topology UI and click **10 OOM Crash**.

### Step 2 — Watch signals unfold
- **t=0:** `LATENCY_ANOMALY` — cart 3600ms (baseline 32ms, z=11.8) — GC pressure
- **t=4s:** `MISSING_SERVICE` — cart absent from traces
- **t=1s:** `NEW_ERROR_SIGNATURE` — frontend: ServiceUnavailableException on POST /api/cart

**Key talking points:**
- *"The latency signal is the warning — the system is struggling before it dies. The MISSING_SERVICE is the crash. Together they tell the OOM story."*

### Restore
```bash
./demo/demo-between.sh --quick
```

---

## Demo 11: Span Count Drop — Silent Failure

**Story:** *"product-catalog normally produces 9–14 spans per trace (HTTP layer + catalog DB reads + recommendation fanout). After a config change, it produces only 2 spans — the DB calls are silently missing. No error, no latency change, no MISSING_SERVICE. SPAN_COUNT_DROP catches it."*

### Step 1 — Trigger span-count-drop (topology simulation)
Open the Topology UI and click **11 Span Drop**.

### Step 2 — Observe
- product-catalog: `SPAN_COUNT_DROP` — 2 spans (baseline min 9)
- Panel shows: *"DB calls silently missing"*

**Key talking points:**
- *"No error. No latency. No service disappeared. The instrumentation is just... less. A misconfigured connection pool, a silent code path skip — SPAN_COUNT_DROP is the only signal that catches this class of failure."*

### Restore
```bash
./demo/demo-between.sh --quick
```

---

## Demo 12: Span Count Spike — Retry Storm

**Story:** *"cart starts seeing 64 spans per trace instead of the normal 8–10. A Redis connection timeout is triggering 6× retries on every AddItem call. The same error type (TimeoutException) was already in the baseline — so NEW_ERROR_SIGNATURE won't fire. SPAN_COUNT_SPIKE is the only signal."*

### Step 1 — Trigger span-count-spike (topology simulation)
Open the Topology UI and click **12 Span Spike**.

### Step 2 — Observe
- cart: `SPAN_COUNT_SPIKE` — 64 spans (baseline max 10, ×6.4)
- Panel shows: *"retry storm"*

**Key talking points:**
- *"The error type is known — it's been in the baseline since before the storm. ERROR_RATE doesn't fire because retries eventually succeed. SPAN_COUNT_SPIKE is the only window into this failure mode."*
- *"6.4× the normal span count. Every retry adds spans. This is what a retry storm looks like in OTel data."*

### Restore
```bash
./demo/demo-between.sh --quick
```

---

## Full Demo Reset

Run before the first demo of a session, or if something went wrong:

```bash
source .env
python3 refresh_aws_creds.py   # in Claude Code terminal first
source .env                    # back in demo terminal

./demo/demo-reset.sh
```

Expected:
```
=== demo-reset.sh: env=astronomyshop-84f5-workshop ===
[1/8] Restoring all services...
[2/8] Waiting 30s for cache reconnect...
[3/8] Clearing alert log...
[4/8] Wiping error baseline...
[5/8] Clearing dedup state...
[6/8] Cleaning trace baseline (removing watch-contaminated entries)...
[7/8] Verifying 0 trace anomalies (Python watch)...
  0 trace anomalies
[8/8] Verifying 0 OTel events in Splunk (last 3m)...
  0 OTel events
=== Reset complete. Ready for demo. ===
```

---

## Topology UI Simulation

The topology UI (`http://localhost:8080`) supports all 12 demo scenarios via the simulation
buttons on the right panel. These inject synthetic anomaly events without touching the cluster —
useful for standalone topology demos or when the cluster is unavailable.

| Button | Scenario | Signals |
|--------|----------|---------|
| 1 Kill Service | checkout disappears | `MISSING_SERVICE` |
| 2 New Call Path | product-catalog → recommendation (new edge) | `NEW_FINGERPRINT` |
| 3 New Error Sig | product-catalog DataAccessException | `NEW_ERROR_SIGNATURE` |
| 4 Cache Incident | valkey-cart down → cart + checkout errors | `MISSING_SERVICE` + `NEW_ERROR_SIGNATURE` |
| 5 Cascading Failure | checkout down → frontend + cart cascade | `MISSING_SERVICE` + `NEW_ERROR_SIGNATURE` |
| 6 Latency Spike | product-catalog 892ms (baseline 4ms) | `LATENCY_ANOMALY` |
| 7 Error Rate | payment 100% error rate | `ERROR_RATE_ANOMALY` + `NEW_ERROR_SIGNATURE` |
| 8 Combined | checkout missing + payment error rate | `MISSING_SERVICE` + `ERROR_RATE_ANOMALY` |
| 9 Slow Cache | cart→checkout→frontend correlated latency | `LATENCY_ANOMALY` ×3 |
| 10 OOM Crash | cart latency spike → cart disappears | `LATENCY_ANOMALY` + `MISSING_SERVICE` |
| 11 Span Drop | product-catalog DB calls silently absent | `SPAN_COUNT_DROP` |
| 12 Span Spike | cart retry storm 64 spans (baseline 10) | `SPAN_COUNT_SPIKE` |

To start the topology server:
```bash
source .env
python3 demo/topology_server.py --environment $ENV
# Open: http://localhost:8080
```
