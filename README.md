# Behavioral Baseline — Anomaly Detection for Splunk Observability

Detects **structural and behavioral changes** in distributed systems instrumented with Splunk Observability APM. Goes beyond metric thresholds to catch things that standard alerting misses:

- A service that has never called your database suddenly does
- A known DB caller goes completely silent
- A request now flows through a new service it never touched before
- An error type that has never appeared before fires for the first time

Fully generic — no hardcoded service names. Everything is auto-discovered from the live APM topology.

---

## Detection Tiers

| Tier | Script | What it detects | How |
|------|--------|----------------|-----|
| 1b | `provision_detectors.py` | Request rate spike on ingress services | APM AutoDetectCustomization (no MetricSets required) |
| 2  | `trace_fingerprint.py`  | New/changed execution paths, missing services | SHA-256 of ordered parent→child span edge sequence |
| 3  | `error_fingerprint.py`  | New error signatures, rate spikes, vanished signatures | SHA-256 of service + error_type + operation + call_path |
| 3  | `provision_detectors.py` | Error rate spike per service | APM AutoDetectCustomization (no MetricSets required) |
| 4  | `provision_detectors.py` | p99 latency drift per service | APM AutoDetectCustomization (no MetricSets required) |
| C  | `correlate.py`          | 2+ tiers firing on same service simultaneously | Joins Tier 2/3 custom events by service within a time window |

**Tiers 1, 4** run as persistent Splunk detectors (always-on SignalFlow).
**Tiers 2, 3, and C** run as scheduled scripts on cron.

---

## Requirements

- Python 3.10+
- Splunk Observability Cloud account with APM enabled
- Services instrumented with OpenTelemetry (traces flowing)
- `SPLUNK_ACCESS_TOKEN` — an API token with read+write access
- `SPLUNK_INGEST_TOKEN` — an ingest token for writing custom events (if omitted, falls back to `SPLUNK_ACCESS_TOKEN`)
- `SPLUNK_REALM` — your realm (e.g. `us1`, `eu0`)

No third-party Python packages required. All scripts use the standard library only.

---

## Setup

```bash
git clone https://github.com/mqbui1/o11y-behaviorbaseline.git
cd o11y-behaviorbaseline

export SPLUNK_ACCESS_TOKEN=your_token_here
export SPLUNK_REALM=us1
```

---

## Usage

### One-time onboarding (new environment)

```bash
# 1. Preview what will be created
python onboard.py --environment petclinicmbtest --dry-run

# 2. Provision detectors + build baselines
python onboard.py --environment petclinicmbtest
```

This runs all three steps in sequence:
1. `provision_detectors.py` — creates Tier 1a/1b/1c/3/4 SignalFlow detectors
2. `trace_fingerprint.py learn` — builds Tier 2 trace path baseline
3. `error_fingerprint.py learn` — builds Tier 3 error signature baseline

### Automatic multi-environment mode

```bash
# Discover all active environments and provision any new/changed ones
python onboard.py --auto
```

`onboard.py` manages all cron jobs automatically. After onboarding an environment, the following entries are added to crontab (tagged `# behavioral-baseline-managed`):

```
# Per-environment (added once per environment)
*/5 * * * *   trace_fingerprint.py --environment <env> watch
*/5 * * * *   error_fingerprint.py --environment <env> watch
*/5 * * * *   correlate.py --environment <env>
0   2 * * *   trace_fingerprint.py --environment <env> learn --window-minutes 120
0   2 * * *   error_fingerprint.py --environment <env> learn --window-minutes 120

# Global (added once)
*/30 * * * *  onboard.py --auto   ← discovers new environments every 30 min
```

Teardown (`onboard.py --teardown --environment <env>`) removes the per-environment entries. No manual crontab editing required.

### Individual scripts

```bash
# Discover what's in your environment
python trace_fingerprint.py --environment petclinicmbtest discover
python error_fingerprint.py --environment petclinicmbtest discover

# Build / rebuild baselines
python trace_fingerprint.py --environment petclinicmbtest learn --window-minutes 120
python error_fingerprint.py --environment petclinicmbtest learn --window-minutes 120

# Inspect current baselines
python trace_fingerprint.py --environment petclinicmbtest show
python error_fingerprint.py --environment petclinicmbtest show

# Promote fingerprints/signatures after intentional changes (see below)
python trace_fingerprint.py --environment petclinicmbtest promote
python error_fingerprint.py --environment petclinicmbtest promote

# Provision / teardown SignalFlow detectors
python provision_detectors.py --environment petclinicmbtest --dry-run
python provision_detectors.py --environment petclinicmbtest
python provision_detectors.py --environment petclinicmbtest --teardown
```

---

## Deployment-aware correlation

When anomalies fire shortly after a deployment, they are likely caused by the intentional change rather than an incident. `correlate.py` detects this automatically when you instrument your CI/CD pipeline with `notify_deployment.py`.

**Emit a deployment event from CI/CD:**

```bash
# Minimal
python notify_deployment.py --service api-gateway --environment production

# Full context (recommended)
python notify_deployment.py \
    --service api-gateway customers-service \
    --environment production \
    --version v2.4.1 \
    --deployer github-actions \
    --commit $GIT_SHA \
    --description "Add new payment service integration"
```

**What happens when correlate.py runs:**
1. Fetches `deployment.started` events from the last `DEPLOYMENT_CORRELATION_WINDOW_MINUTES` (default: 60)
2. If a correlated anomaly's service matches a recent deployment, the severity is **downgraded by one level** (Critical→Major, Major→Minor)
3. The correlated event is annotated with `deployment_version`, `deployment_commit`, `deployment_deployer`, and `deployment_correlated=true`
4. The console output shows `[deployment-correlated]` next to the service name

This preserves full observability of what changed while preventing high-severity pages for expected behavior.

**Post-deploy baseline re-learn:**

`notify_deployment.py` also schedules a background re-learn that runs automatically after a configurable delay (default: 5 minutes). This allows new-version traces to start flowing before the baseline is rebuilt, so the new call patterns are learned rather than permanently alerted on.

```bash
# Default: re-learn fires 5 minutes after the deploy event
python notify_deployment.py --service api-gateway --environment production --version v2.4.1

# Custom delay
python notify_deployment.py --service api-gateway --environment production --relearn-delay 10

# Disable post-deploy re-learn entirely
python notify_deployment.py --service api-gateway --environment production --relearn-delay 0
```

The re-learn uses a 30-minute window to capture the new trace patterns. Logs are written to `/tmp/bab_relearn_deploy.log`.

---

## Baseline auto-promotion

After an intentional change (new deployment, feature rollout, service rename), Tiers 2 and 3 will alert on the new patterns until the baseline is updated. Auto-promotion handles this without manual intervention.

**How it works:**

When `watch` detects a new trace path or error signature, it records the pattern as *pending* in the baseline with a `watch_hits` counter. Each subsequent watch run that sees the same pattern increments the counter. Once the counter reaches `AUTO_PROMOTE_THRESHOLD` (default: 5), the pattern is automatically promoted — it becomes part of the baseline and stops generating alerts.

At the default 5-minute cron interval, a new pattern is silenced after ~25 minutes of consistent observation.

**Manual promotion** — use this immediately after a known deployment to skip the waiting period:

```bash
# Promote all pending patterns (seen at least once but not yet auto-promoted)
python trace_fingerprint.py --environment petclinicmbtest promote
python error_fingerprint.py --environment petclinicmbtest promote

# Promote specific hashes (copy from watch output or show)
python trace_fingerprint.py --environment petclinicmbtest promote abc123def456...
python error_fingerprint.py --environment petclinicmbtest promote abc123def456... 789xyz...
```

**Configuration:**

| Env var | Default | Description |
|---------|---------|-------------|
| `AUTO_PROMOTE_THRESHOLD` | `5` | Watch runs before a new pattern is auto-promoted. Set to `0` to disable. |

**When to re-run `learn` instead:** If you make a large structural change (many services added/removed, major refactor), a full `learn` rebuild is faster than waiting for auto-promotion to accumulate on dozens of new patterns.

**Baseline pruning:** Each `learn` run also removes fingerprints and error signatures that were *not* observed in the current window (auto-promoted entries are always retained). This prevents stale patterns from accumulating over time — for example, startup-era errors that no longer occur will be removed on the next daily re-learn.

---

## Baseline files

Each environment gets its own isolated baseline files:

| File | Content |
|------|---------|
| `baseline.<env>.json` | Tier 2 trace path fingerprints |
| `error_baseline.<env>.json` | Tier 3 error signature fingerprints |
| `onboarding_state.json` | Record of provisioned environments and last run |

Override paths via env vars:
```bash
export BASELINE_PATH=/opt/baselines/baseline.json
export ERROR_BASELINE_PATH=/opt/baselines/error_baseline.json
export ONBOARDING_STATE_PATH=/opt/baselines/onboarding_state.json
```

For production deployments where scripts run on multiple machines or containers, store baseline files on a shared volume or in object storage and sync them before/after each run.

---

## Alerts emitted

Tiers 1a/1b/1c/3/4 fire as native Splunk detector alerts (visible in Alerts & Detectors UI).

Tiers 2 and 3 emit **Splunk custom events** queryable via `search_events`:

| Event type | Tier | Dimensions |
|------------|------|-----------|
| `trace.path.drift` | 2 | `anomaly_type`, `root_operation`, `fp_hash`, `environment` |
| `topology.new_service` | 1 | `new_service`, `environment` |
| `error.signature.drift` | 3 | `anomaly_type`, `service`, `error_type`, `sig_hash`, `environment` |
| `behavioral_baseline.correlated_anomaly` | C | `service`, `corr_type`, `severity`, `tiers`, `environment` |
| `deployment.started` | input | `service`, `environment` — emitted by `notify_deployment.py` |
| `behavioral_baseline.onboarded` | audit | `environment`, `action`, `provision_ok`, `baseline_ok` |

---

## Environment variables reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLUNK_ACCESS_TOKEN` | required | API token (read/write) |
| `SPLUNK_INGEST_TOKEN` | falls back to `SPLUNK_ACCESS_TOKEN` | Ingest token for writing custom events |
| `SPLUNK_REALM` | `us0` | Splunk realm |
| `BASELINE_PATH` | `./baseline.json` | Trace fingerprint baseline location |
| `ERROR_BASELINE_PATH` | `./error_baseline.json` | Error signature baseline location |
| `ONBOARDING_STATE_PATH` | `./onboarding_state.json` | Onboarding state file location |
| `TOPOLOGY_LOOKBACK_HOURS` | `48` | How far back topology queries look |
| `AUTO_PROMOTE_THRESHOLD` | `5` | Watch runs before a new pattern is auto-promoted (0 = disabled) |
| `DEPLOYMENT_CORRELATION_WINDOW_MINUTES` | `60` | How far back to look for deployment events when correlating anomalies |
| `RELEARN_DELAY_MINUTES` | `5` | Minutes after a deploy event before background re-learn fires (0 = disabled) |
| `MISSING_SERVICE_DOMINANCE_THRESHOLD` | `0.6` | Fraction of baseline patterns a service must appear in to trigger `MISSING_SERVICE` |
| `WATCH_SAMPLE_LIMIT` | `50` | Max traces fetched per watch run |
| `MAX_WORKERS` | `20` | Parallel threads for trace detail fetching |

---

## Architecture

```
onboard.py                     ← orchestration controller
├── provision_detectors.py     ← Tiers 1a, 1b, 1c, 4 (SignalFlow, seasonality-aware)
├── trace_fingerprint.py       ← Tier 2 (trace path drift, cron script)
├── error_fingerprint.py       ← Tier 3 (error signatures + spikes, cron script)
├── correlate.py               ← Tier C (cross-tier correlation + deployment context)
└── notify_deployment.py       ← CI/CD hook (emits deployment.started events)

Splunk Observability
├── APM topology API           ← service discovery (all scripts)
├── APM trace search API       ← trace sampling (fingerprint scripts)
├── SignalFlow detector API    ← detector CRUD (provision_detectors.py)
└── Custom events API          ← anomaly alerting + deployment events
```

---

## Fingerprinting & Baselining Architecture

### Data flow

```
Splunk APM
  ├── search_traces()        → all traces (by service + environment)
  └── search_error_traces()  → error traces only (traces with error spans)
          │
          ▼
  FINGERPRINTING
  ┌─────────────────────────────────┬──────────────────────────────────────┐
  │  build_fingerprint(trace)       │  build_error_signatures(trace)       │
  │  • root_op = svc:operation      │  • error_type (exception class or    │
  │  • edges = parent→child spans   │    HTTP status code)                 │
  │  • services = set of svc names  │  • operation (span op name)          │
  │  • path = edge chain string     │  • call_path (root→error hop)        │
  │  • hash = SHA256(path)[:16]     │  • hash = SHA256(sig_key)[:16]       │
  │  • requires MIN_SPANS=2         │  • skips spans without error tags    │
  │    (or known root op in watch)  │                                      │
  └─────────────────────────────────┴──────────────────────────────────────┘
```

### Learn command

```
learn [--window-minutes N] [--window-offset-minutes M] [--reset]

  For each trace/error in the window:
  ┌──────────────────────────────────────────────────────┐
  │  STAGING (in-memory, per learn run)                  │
  │                                                      │
  │  fingerprint seen → staged[hash].occurrences++       │
  │                                                      │
  │  occurrences < MIN_BASELINE_OCCURRENCES (2)?         │
  │      └─► EXCLUDED — never written to baseline        │
  │                                                      │
  │  occurrences ≥ MIN_BASELINE_OCCURRENCES?             │
  │      └─► GRADUATE → baseline[hash]                   │
  └──────────────────────────────────────────────────────┘

  Prune stale: entries in baseline NOT seen in window → deleted
               (except auto_promoted=true, which are always kept)

  --window-offset-minutes M  shifts the window back M minutes
                             (re-baseline after an incident without
                              waiting for bad traces to age out)
  --reset                    wipes the existing baseline before
                             learning (clean-slate re-baseline)
```

### Watch command — anomaly classification

```
watch [--window-minutes N] (default: 10)

  For each TRACE fingerprint fp:
  ┌────────────────────────────────────────────────────────────────────────┐
  │  classify_anomaly(fp, baseline)                                        │
  │                                                                        │
  │  1. MISSING_SERVICE (early)  ─── new hash, but known root_op has      │
  │                                  fewer services than baseline dominant  │
  │                                  (catches collapsed 1-span traces when  │
  │                                   downstream service is completely gone)│
  │                                                                        │
  │  2. NEW_FINGERPRINT          ─── hash not in baseline, or             │
  │                                  occurrences < MIN_BASELINE_OCC       │
  │                                                                        │
  │  3. NEW_SERVICE              ─── services in trace not seen in any    │
  │                                  baseline pattern for this root_op     │
  │                                                                        │
  │  4. SPAN_COUNT_SPIKE         ─── span_count > 2× baseline max        │
  │                                                                        │
  │  5. MISSING_SERVICE (estab.) ─── dominant service (≥60% of baseline  │
  │                                  patterns for root_op) absent from    │
  │                                  current trace                         │
  └────────────────────────────────────────────────────────────────────────┘

  For each ERROR signature sig:
  ┌────────────────────────────────────────────────────────────────────────┐
  │  NEW_ERROR_SIGNATURE   ─── hash not in baseline                       │
  │  SIGNATURE_SPIKE       ─── rate > 3× baseline rate                   │
  │                            (requires occurrences ≥ 5 in baseline)     │
  │  SIGNATURE_VANISHED    ─── dominant sig (≥20% of service errors)      │
  │                            absent from watch window                    │
  └────────────────────────────────────────────────────────────────────────┘

  AUTO-PROMOTION: NEW_FINGERPRINT seen in N consecutive watch runs
      └─► hash.auto_promoted = true  (silenced permanently)
          (N = AUTO_PROMOTE_THRESHOLD, default 5 → ~25 min at 5m cron)
```

### State transitions

```
  TRACE FINGERPRINT                      ERROR SIGNATURE
  ─────────────────                      ───────────────
  [unseen]                               [unseen]
      │ seen ≥2x in learn window             │ seen ≥2x in learn window
      ▼                                      ▼
  [established]  ◄── re-learn           [established]  ◄── re-learn
      │ not seen in learn window             │ not seen in learn window
      ▼                                      ▼
  [pruned]                               [pruned]
      │
  [established]                          [established]
      │ in watch: services mismatch          │ in watch: rate > 3× baseline
      ▼                                      ▼
  MISSING_SERVICE fired              SIGNATURE_SPIKE fired

  [established / new hash]               [established]
      │ in watch: hash unknown               │ in watch: dominant + absent
      ▼                                      ▼
  NEW_FINGERPRINT fired              SIGNATURE_VANISHED fired
      │ seen N consec. watch runs
      ▼
  [auto_promoted]  ◄── promote cmd
      (silent forever)                   [any]  ◄── promote cmd
                                             ▼
                                         [auto_promoted]
                                             (silent forever)
```

### Baseline file schema

```
baseline.<env>.json                    error_baseline.<env>.json
───────────────────                    ─────────────────────────
{                                      {
  "created_at": "...",                   "created_at": "...",
  "topology": { services, inferred },    "signatures": {
  "fingerprints": {                        "<hash>": {
    "<hash>": {                              "hash", "service",
      "hash", "root_op",                     "error_type", "operation",
      "path", "services",                    "call_path", "occurrences",
      "span_count", "occurrences",           "auto_promoted",
      "auto_promoted", "watch_hits",         "last_seen"
      "last_seen"                          }
    }                                    }
  },                                   }
  "learn_runs": N
}
```

---

## AI Agents

A layer of autonomous agents built on top of the detection framework. Each agent addresses a specific operational gap — from suppressing noise floods to generating incident runbooks. All agents are integrated into `onboard.py` and run automatically via cron.

### Cron schedule (managed automatically by `onboard.py`)

```
# Per-environment (every 5 min)
*/5 * * * *   dedup_agent.py --environment <env>

# Per-environment (daily maintenance)
0   2 * * *   trace_fingerprint.py learn  (re-baseline)
0   2 * * *   error_fingerprint.py learn  (re-baseline)
30  2 * * *   noise_learner.py --apply    (after re-learn)
0 */6 * * *   baseline_healer.py          (post-incident check)

# Global (every 30 min)
*/30 * * * *  multi_env_correlator.py

# On new environment onboarded (one-time)
              runbook_generator.py        → RUNBOOK.<env>.md
```

---

### #1 — Self-Healing Baseline (`baseline_healer.py`)

**Problem:** After an incident, the baseline is contaminated with incident-era error signatures and degraded trace paths. The next re-learn will encode the bad state as "normal."

**What it does:** Monitors the anomaly event rate for an environment. When a spike is detected and then subsides (incident resolved), it automatically selects the best pre-incident window, scores it for quality (low error rate + high path diversity), and re-runs `trace_fingerprint learn` and `error_fingerprint learn` on that clean window — without human intervention.

```bash
python baseline_healer.py --environment petclinicmbtest
python baseline_healer.py --environment petclinicmbtest --dry-run
```

Emits `baseline.healed` to Splunk when a re-learn fires.

---

### #2 — Anomaly Triage Agent (`triage_agent.py`)

**Problem:** Correlated anomaly events tell you *what* fired, not *why* or *what to do*.

**What it does:** Fetches recent correlated anomaly events, retrieves representative traces from Splunk APM, and calls Claude (via AWS Bedrock) to produce a plain-English incident summary with a severity assessment and suggested next steps. Optionally polls continuously and routes critical summaries to a webhook (PagerDuty, Slack, etc.).

```bash
python triage_agent.py --environment petclinicmbtest --window-minutes 60
python triage_agent.py --environment petclinicmbtest --mode poll
python triage_agent.py --environment petclinicmbtest --dry-run  # no API call
```

Requires ambient AWS credentials (same IAM role as your deployment environment).

---

### #3 — Adaptive Thresholds (`adaptive_thresholds.py`)

**Problem:** Detection thresholds are static defaults. High-churn services generate false positives; quiet services miss real incidents.

**What it does:** Observes anomaly events over a rolling window and classifies each as a True Positive (TP) or False Positive (FP) based on whether a correlated anomaly followed within 10 minutes. Adjusts per-service thresholds in `thresholds.json`: tightens when FP rate is high, loosens when TP rate is low. Changes are picked up by `trace_fingerprint.py` and `error_fingerprint.py` on the next run with no restart required.

```bash
python adaptive_thresholds.py --environment petclinicmbtest
python adaptive_thresholds.py --environment petclinicmbtest --observation-days 7
```

---

### #4 — Root Cause Hypothesis Engine (`hypothesis_engine.py`)

**Problem:** The triage agent has anomaly data but no topology context — it cannot reason about which dependency is the most likely root cause.

**What it does:** Walks the APM dependency graph (BFS in both directions) from the affected service, gathers per-node anomaly signals, and generates ranked hypotheses before the Claude call. Injected directly into the triage agent's prompt so Claude reasons about the actual dependency graph.

Hypothesis types: `SHARED_DEPENDENCY`, `DOWNSTREAM_FAILURE`, `UPSTREAM_CHANGE`, `SELF_CHANGE`, `CASCADING_FAILURE`.

---

### #5 — Onboarding Advisor (`onboarding_advisor.py`)

**Problem:** Default thresholds work for average environments. High-traffic environments need tighter config; quiet environments get flooded with false positives.

**What it does:** When `onboard.py --advise` onboards a new environment, the advisor samples live traffic and topology to classify the environment (traffic tier, error tier, complexity), then generates concrete config recommendations: watch interval, learn window, which anomaly types to enable, and per-service threshold overrides. Writes recommendations to `thresholds.json`.

```bash
python onboarding_advisor.py --environment petclinicmbtest --apply
python onboard.py --environment petclinicmbtest --advise  # runs automatically on new envs
```

---

### #6 — Baseline Quality Monitor (`baseline_monitor.py`)

**Problem:** A stale or contaminated baseline silently degrades detection quality. You do not know the baseline is bad until incidents are missed or false alarms flood.

**What it does:** Runs health checks against baseline files: detects empty baselines, stale entries, low-confidence fingerprints, incident artifacts in error signatures, near-duplicate fingerprints (Jaccard similarity > 0.85), and persistent noise patterns. Correlates findings against detected incident windows. Exits with code 1 if any CRITICAL issues are found — usable as a CI/CD gate.

```bash
python baseline_monitor.py --environment petclinicmbtest
python baseline_monitor.py --environment petclinicmbtest --fix  # auto-remove LOW_CONFIDENCE entries
```

---

### #7 — Anomaly Deduplication Agent (`dedup_agent.py`)

**Problem:** A single incident generates dozens of identical events per watch cycle. After 30 minutes: 30+ duplicates. `correlate.py` fires every cycle. The dashboard is unreadable.

**What it does:** Groups anomaly events by `(service, anomaly_type, fingerprint_key)`, forwards only the first occurrence, suppresses duplicates, detects escalations (new anomaly type for same service), and emits `incident.resolved` when a group goes quiet for 15 minutes.

```bash
python dedup_agent.py --environment petclinicmbtest --window-minutes 5
python dedup_agent.py --environment petclinicmbtest --show  # inspect incident state
```

In testing: 2577 raw events → 51 unique incidents (84% noise reduction).

Emits: `behavioral_baseline.incident.opened`, `.escalated`, `.resolved`.

---

### #8 — Deployment Risk Scorer (`deployment_risk_scorer.py`)

**Problem:** You deploy without knowing whether the behavioral baseline is in a state that will cause immediate false alarms.

**What it does:** Computes a 0–100 risk score across four dimensions: baseline stability, error baseline health, blast radius, and recent anomaly rate. Exits with code 1 if score ≥ `BLOCK_THRESHOLD` (default 75) for CI/CD gating.

```bash
python deployment_risk_scorer.py --service api-gateway --environment petclinicmbtest
python deployment_risk_scorer.py --service $SERVICE --environment $ENV || exit 1  # CI/CD gate
```

Grades: `LOW` (0–34) / `MEDIUM` (35–54) / `HIGH` (55–74) / `CRITICAL` (75+).

---

### #9 — Drift Explainer (`drift_explainer.py`)

**Problem:** `trace_fingerprint.py` tells you *that* a path changed, but not *what edge changed or why*.

**What it does:** Diffs baseline fingerprints against live traces edge-by-edge, classifies changes (drifted / new / vanished), and calls Claude (Bedrock) to generate plain-English explanations with root cause hypotheses. Emits `behavioral_baseline.drift.explained` to Splunk.

```bash
python drift_explainer.py --service api-gateway --environment petclinicmbtest
python drift_explainer.py --service api-gateway --environment petclinicmbtest --diff-only
python drift_explainer.py --environment petclinicmbtest  # explain all drifted services
```

Example output:
> *"api-gateway:GET now routes through discovery-server before reaching vets-service. This edge did not exist in baseline. Likely a Eureka re-registration triggered by a restart."*

---

### #10 — Multi-Environment Propagation Detector (`multi_env_correlator.py`)

**Problem:** The same bad change propagating dev → staging → prod is invisible until it hits production.

**What it does:** Watches for the same anomaly pattern appearing across environments in pipeline order within a configurable window (default: 60 min). Pipeline order is auto-detected from environment name conventions (`dev < test/staging < preprod < prod`). Fires `behavioral_baseline.propagation.detected` before production is fully impacted.

```bash
python multi_env_correlator.py
python multi_env_correlator.py --pipeline dev staging prod --lookback-hours 4
```

---

### #11 — Baseline Coverage Auditor (`coverage_auditor.py`)

**Problem:** You do not know if your baseline actually covers normal traffic patterns.

**What it does:** Samples live traces, fingerprints them, and computes per-root-op coverage. Reports which services need a longer learn window.

```bash
python coverage_auditor.py --environment petclinicmbtest
python coverage_auditor.py --environment petclinicmbtest --window-minutes 60 --threshold 70
```

Example output:
```
api-gateway
  ✅ GET /api/gateway/owners/{ownerId}    100%  (51/51 traces)
  ⚠️  PUT customers-service               31%   → re-run learn --window-minutes 240
```

---

### #12 — SLO Impact Estimator (`slo_impact_estimator.py`)

**Problem:** During an incident, you know there is elevated error rate — but not how long until your SLO burns out.

**What it does:** Queries error rate and p99 latency from Splunk APM metrics, computes error budget burn rate against configurable SLO targets, and estimates time to exhaustion. Injected into the triage agent summary.

```bash
python slo_impact_estimator.py --service api-gateway --environment petclinicmbtest
```

SLO targets can be set per-service in `thresholds.json`:
```json
{ "services": { "api-gateway": { "availability_slo": 0.999, "p99_latency_ms": 500 } } }
```

---

### #13 — Runbook Generator (`runbook_generator.py`)

**Problem:** Every new environment needs a hand-written incident runbook. Nobody writes them.

**What it does:** Reads the APM topology, baseline fingerprints, error signatures, and per-service thresholds, then calls Claude (Bedrock) to write a tailored Markdown runbook: service map, triage checklist ordered by blast radius, per-service reference, copy-paste commands, and a quick-reference card. Generated automatically for every new environment onboarded.

```bash
python runbook_generator.py --environment petclinicmbtest
python runbook_generator.py --environment petclinicmbtest --force  # regenerate
```

Output: `RUNBOOK.<env>.md` alongside the baseline files.

---

### #14 — Noise Pattern Learner (`noise_learner.py`)

**Problem:** `NOISE_PATTERNS` is a hardcoded list of universal patterns. Application-specific noise (custom health endpoints, internal heartbeats) slips through and pollutes the baseline.

**What it does:** Analyzes the baseline for auto-promoted fingerprints and high-`watch_hits` entries, extracts candidate noise pattern substrings, and suggests additions to the noise filter. With `--apply`, writes patterns to `noise_patterns.json`. With `--patch`, injects them into `trace_fingerprint.py`.

```bash
python noise_learner.py --environment petclinicmbtest
python noise_learner.py --environment petclinicmbtest --apply --patch
```

Runs automatically at 2:30am daily after the nightly re-learn.

---

### Agent events reference

| Event type | Emitted by | Description |
|------------|-----------|-------------|
| `behavioral_baseline.incident.opened` | `dedup_agent.py` | First occurrence of a unique incident group |
| `behavioral_baseline.incident.escalated` | `dedup_agent.py` | Incident gained a new anomaly type |
| `behavioral_baseline.incident.resolved` | `dedup_agent.py` | Incident silent for 15+ minutes |
| `behavioral_baseline.drift.explained` | `drift_explainer.py` | Claude explanation of an edge-level path change |
| `behavioral_baseline.propagation.detected` | `multi_env_correlator.py` | Same anomaly spreading across pipeline environments |
| `baseline.healed` | `baseline_healer.py` | Autonomous post-incident re-learn completed |


---

## Limitations

- **Auto-promotion lag**: New patterns after a deployment will alert for up to `AUTO_PROMOTE_THRESHOLD × cron_interval` minutes before being silenced. Use `promote` immediately after a known deployment to skip the wait, or run `learn` for large-scale topology changes.
- **AutoDetect parent detectors must exist**: Tiers 1b, 3, and 4 create `AutoDetectCustomization` children scoped to specific services. The org-wide AutoDetect parent detectors (`GmlOPziA4AA`, `GmlOMziA4AA`, `GmlOLziA4AA`) must exist in your organization — they are created automatically by Splunk Observability and are present in all orgs with APM enabled. No MetricSets configuration required.
- **First 5 minutes after provisioning**: AutoDetect-based detectors (Tiers 1b, 3, 4) may take a few minutes to begin evaluating after creation as Splunk initializes the customization.
