# Behavioral Baseline — Anomaly Detection for Splunk Observability

Detects **structural and behavioral changes** in distributed systems instrumented with Splunk Observability APM. Goes beyond metric thresholds to catch things that standard alerting misses:

- A service that has never called your database suddenly does
- A known DB caller goes completely silent
- A request now flows through a new service it never touched before
- An error type that has never appeared before fires for the first time

Fully generic — no hardcoded service names. Everything is auto-discovered from the live APM topology.

---

## Repo structure

```
o11y-behaviorbaseline/
├── agent.py              ← unified agent (primary entry point)
├── collect.py            ← all data fetching (topology, anomalies, SLO, deployments)
├── baseline.py           ← baseline data layer (load, summarize, health, learn, promote)
├── onboard.py            ← provisioning + cron management
├── notify_deployment.py  ← CI/CD hook (emits deployment.started events)
│
├── core/                 ← detection engine (called by agent + onboard)
│   ├── trace_fingerprint.py    ← Tier 2: trace path drift
│   ├── error_fingerprint.py    ← Tier 3: error signature drift
│   ├── correlate.py            ← Tier C: cross-tier correlation
│   └── provision_detectors.py  ← Tiers 1b/3/4: SignalFlow detectors
│
├── agents/               ← standalone agents (superseded by agent.py)
│   └── triage_agent.py, baseline_healer.py, drift_explainer.py, ...
│
└── data/                 ← runtime state (gitignored)
    ├── baseline.<env>.json
    ├── error_baseline.<env>.json
    ├── dedup_state.<env>.json
    └── thresholds.json
```

---

## Requirements

- Python 3.10+
- Splunk Observability Cloud account with APM enabled
- Services instrumented with OpenTelemetry (traces flowing)
- `SPLUNK_ACCESS_TOKEN` — an API token with read+write access
- `SPLUNK_INGEST_TOKEN` — an ingest token for writing custom events (falls back to `SPLUNK_ACCESS_TOKEN`)
- `SPLUNK_REALM` — your realm (e.g. `us1`, `eu0`)
- `boto3` — for the unified agent's Claude calls (`pip install boto3`)

---

## Quick start

```bash
git clone https://github.com/mqbui1/o11y-behaviorbaseline.git
cd o11y-behaviorbaseline

export SPLUNK_ACCESS_TOKEN=your_token_here
export SPLUNK_REALM=us1

# Onboard an environment: provisions detectors + builds baselines + sets up cron
python onboard.py --environment your-env

# Run the unified agent (single cycle)
python agent.py --environment your-env

# Run continuously, every 5 minutes
python agent.py --environment your-env --poll 5
```

---

## The unified agent

`agent.py` is the primary entry point. It runs a perception-action loop every cycle:

1. **Perceive** — fetches anomaly events, topology, deployments, SLO status, baseline health, open incidents
2. **Reason** — one Claude call (AWS Bedrock) synthesizes everything into a structured assessment
3. **Act** — executes Claude's action plan

```bash
python agent.py --environment petclinicmbtest              # single cycle
python agent.py --environment petclinicmbtest --poll 5     # every 5 minutes
python agent.py --environment petclinicmbtest --dry-run    # perceive + reason, no actions
python agent.py --environment petclinicmbtest --json       # print Claude's raw plan
```

Example output when an incident is detected:

```json
{
  "assessment": "vets-service is missing from traces after the 14:03 deploy",
  "severity": "INCIDENT",
  "root_cause": "Deployment of vets-service v2.1 introduced a startup crash",
  "affected_services": ["vets-service", "api-gateway"],
  "confidence": "HIGH",
  "actions": [
    { "type": "PAGE_ONCALL",       "service": "vets-service", "reason": "service missing from all traces" },
    { "type": "SUPPRESS_ANOMALY",  "service": "api-gateway",  "reason": "downstream effect of vets-service failure" }
  ],
  "narrative": "vets-service stopped appearing in traces at 14:03, immediately after a deployment..."
}
```

Action types: `NO_ACTION`, `SUPPRESS_ANOMALY`, `RELEARN_BASELINE`, `EMIT_EVENT`, `PAGE_ONCALL`, `UPDATE_THRESHOLD`.

---

## Detection tiers

The `core/` scripts handle detection. They run on cron (managed by `onboard.py`) and emit custom events to Splunk.

| Tier | Script | What it detects | How |
|------|--------|----------------|-----|
| 1b | `core/provision_detectors.py` | Request rate spike on ingress services | APM AutoDetectCustomization |
| 2  | `core/trace_fingerprint.py`  | New/changed execution paths, missing services | SHA-256 of ordered parent→child span edge sequence |
| 3  | `core/error_fingerprint.py`  | New error signatures, rate spikes, vanished signatures | SHA-256 of service + error_type + operation + call_path |
| 3  | `core/provision_detectors.py` | Error rate spike per service | APM AutoDetectCustomization |
| 4  | `core/provision_detectors.py` | p99 latency drift per service | APM AutoDetectCustomization |
| C  | `core/correlate.py`          | 2+ tiers firing on same service simultaneously | Joins Tier 2/3 events by service within a time window |

**Tiers 1b, 3, 4** run as persistent Splunk detectors (always-on SignalFlow).
**Tiers 2, 3, and C** run as scheduled scripts on cron.

---

## Onboarding

```bash
# Preview what will be created
python onboard.py --environment petclinicmbtest --dry-run

# Provision detectors + build baselines + install cron jobs
python onboard.py --environment petclinicmbtest

# Discover all active environments and onboard any new ones
python onboard.py --auto
```

`onboard.py` installs the following cron jobs automatically (tagged `# behavioral-baseline-managed`):

```
# Per-environment (every 5 min)
*/5 * * * *   core/trace_fingerprint.py --environment <env> watch
*/5 * * * *   core/error_fingerprint.py --environment <env> watch
*/5 * * * *   core/correlate.py --environment <env>
*/5 * * * *   agents/dedup_agent.py --environment <env>

# Per-environment (daily)
0   2 * * *   core/trace_fingerprint.py --environment <env> learn
0   2 * * *   core/error_fingerprint.py --environment <env> learn
30  2 * * *   agents/noise_learner.py --environment <env> --apply
0 */6 * * *   agents/baseline_healer.py --environment <env>

# Global (every 30 min)
*/30 * * * *  agents/multi_env_correlator.py
*/30 * * * *  onboard.py --auto
```

Teardown removes all per-environment entries:

```bash
python onboard.py --teardown --environment petclinicmbtest
```

---

## Deployment-aware correlation

Instrument your CI/CD pipeline with `notify_deployment.py` so anomalies that fire shortly after a deploy are automatically annotated and downgraded in severity:

```bash
python notify_deployment.py \
    --service api-gateway \
    --environment production \
    --version v2.4.1 \
    --commit $GIT_SHA
```

`correlate.py` will annotate the correlated event with `deployment_correlated=true` and downgrade severity (Critical→Major). A background re-learn fires automatically 5 minutes after the deploy to absorb new trace patterns.

---

## Baseline management

```bash
# Build / rebuild
python core/trace_fingerprint.py --environment petclinicmbtest learn --window-minutes 120
python core/error_fingerprint.py --environment petclinicmbtest learn --window-minutes 120

# Inspect
python core/trace_fingerprint.py --environment petclinicmbtest show
python core/error_fingerprint.py --environment petclinicmbtest show

# Promote after a known deployment (skips auto-promotion wait)
python core/trace_fingerprint.py --environment petclinicmbtest promote
python core/error_fingerprint.py --environment petclinicmbtest promote
```

**Auto-promotion:** A new fingerprint seen in `AUTO_PROMOTE_THRESHOLD` consecutive watch runs (default: 5, ~25 min at 5m cron) is automatically promoted and stops alerting.

Baseline files live in `data/` and are gitignored. Override locations via env vars:

```bash
export BASELINE_PATH=/opt/baselines/baseline.json
export ERROR_BASELINE_PATH=/opt/baselines/error_baseline.json
```

---

## Alerts emitted

Tiers 1b/3/4 fire as native Splunk detector alerts (visible in Alerts & Detectors UI).

Tiers 2, 3, and C emit **custom events** queryable via SignalFlow:

| Event type | Tier | Key dimensions |
|------------|------|----------------|
| `trace.path.drift` | 2 | `anomaly_type`, `root_operation`, `fp_hash`, `sf_environment` |
| `error.signature.drift` | 3 | `anomaly_type`, `service`, `error_type`, `sig_hash`, `sf_environment` |
| `behavioral_baseline.correlated_anomaly` | C | `service`, `corr_type`, `severity`, `tiers`, `sf_environment` |
| `deployment.started` | input | `service`, `sf_environment` |
| `behavioral_baseline.agent.action` | agent | `service`, `action`, `reason`, `severity` |
| `behavioral_baseline.oncall.page` | agent | `service`, `severity`, `root_cause` |

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLUNK_ACCESS_TOKEN` | required | API token (read/write) |
| `SPLUNK_INGEST_TOKEN` | falls back to `SPLUNK_ACCESS_TOKEN` | Ingest token for writing custom events |
| `SPLUNK_REALM` | `us0` | Splunk realm |
| `BASELINE_PATH` | `data/baseline.json` | Trace fingerprint baseline location |
| `ERROR_BASELINE_PATH` | `data/error_baseline.json` | Error signature baseline location |
| `THRESHOLDS_PATH` | `data/thresholds.json` | Per-service threshold overrides |
| `TOPOLOGY_LOOKBACK_HOURS` | `48` | How far back topology queries look |
| `AUTO_PROMOTE_THRESHOLD` | `5` | Watch runs before a new pattern is auto-promoted (0 = disabled) |
| `DEPLOYMENT_CORRELATION_WINDOW_MINUTES` | `60` | How far back to look for deployment events |
| `RELEARN_DELAY_MINUTES` | `5` | Minutes after a deploy before background re-learn fires |
| `MISSING_SERVICE_DOMINANCE_THRESHOLD` | `0.6` | Fraction of baseline patterns a service must appear in to trigger `MISSING_SERVICE` |
| `WATCH_SAMPLE_LIMIT` | `50` | Max traces fetched per watch run |
| `AGENT_WINDOW_MINUTES` | `30` | Anomaly lookback window for `agent.py` |
| `AWS_REGION` | `us-west-2` | AWS region for Bedrock (Claude) calls |

---

## How fingerprinting works

A **trace fingerprint** is the ordered parent→child service:operation edge list of a trace, hashed to a stable 16-char ID. Immune to timing variation — only structural changes trigger alerts.

```
learn:  sample traces → build edge sets → hash → store in data/baseline.<env>.json
watch:  sample traces → hash → compare to baseline → emit event on mismatch
```

Anomaly types detected by `core/trace_fingerprint.py`:

| Anomaly | Trigger |
|---------|---------|
| `NEW_FINGERPRINT` | Hash not in baseline |
| `NEW_SERVICE` | Service in trace not seen in any baseline pattern for this root op |
| `SPAN_COUNT_SPIKE` | Span count > 2× baseline max |
| `MISSING_SERVICE` | Dominant service (≥60% of baseline patterns) absent from current trace |

Anomaly types detected by `core/error_fingerprint.py`:

| Anomaly | Trigger |
|---------|---------|
| `NEW_ERROR_SIGNATURE` | Error hash not in baseline |
| `SIGNATURE_SPIKE` | Rate > 3× baseline rate |
| `SIGNATURE_VANISHED` | Dominant signature absent from watch window |

---

## Standalone agents (`agents/`)

The `agents/` directory contains 14 single-purpose scripts built before `agent.py`. They remain available for targeted use:

| Script | Purpose |
|--------|---------|
| `triage_agent.py` | Claude summary of correlated anomalies + traces |
| `baseline_healer.py` | Auto re-learns baseline after incident resolves |
| `adaptive_thresholds.py` | Tunes per-service thresholds based on TP/FP history |
| `hypothesis_engine.py` | BFS dependency walk + ranked root cause hypotheses |
| `dedup_agent.py` | Deduplicates anomaly floods, tracks incident lifecycle |
| `deployment_risk_scorer.py` | 0–100 pre-deploy risk score, CI/CD gate |
| `drift_explainer.py` | Edge-by-edge trace diff with Claude explanation |
| `multi_env_correlator.py` | Detects anomaly propagation across pipeline environments |
| `coverage_auditor.py` | Per-root-op baseline coverage measurement |
| `slo_impact_estimator.py` | Error budget burn rate + time-to-breach |
| `runbook_generator.py` | Generates `RUNBOOK.<env>.md` via Claude |
| `noise_learner.py` | Learns app-specific noise patterns from auto-promoted fingerprints |
| `baseline_monitor.py` | Health checks on baseline files (stale, contaminated, near-dupes) |
| `onboarding_advisor.py` | Classifies env traffic, writes config recommendations |

`agent.py` subsumes all of the above in a single perception-action loop. Use the standalone agents when you need targeted, per-concern observability or are debugging a specific dimension.

---

---

## Demos

Live demos tested against the `petclinicmbtest` environment (Spring PetClinic on k3d + Splunk OTel).

### Prerequisites (run once before any demo)
```bash
cd /Users/mbui/Documents/o11y-behaviorbaseline
source .env

# AWS credentials for Bedrock (required for Demo 7 — AI triage)
source /tmp/aws_exports.sh

# SSH alias for cluster commands
alias k='sshpass -p "Sp1unkH00di3" ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password splunk@18.208.249.178'
```

### Splunk O11y URLs
- **APM Service Map**: https://app.us1.signalfx.com/#/apm?environments=petclinicmbtest
- **Behavioral Baseline Dashboard**: https://app.us1.signalfx.com/#/dashboard/HERM9jxA1po

---

### Demo 0: Context Setting — Framework in Steady State

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

## Limitations

- **Auto-promotion lag**: New patterns after a deployment will alert for up to `AUTO_PROMOTE_THRESHOLD × cron_interval` minutes. Use `promote` immediately after a known deployment to skip the wait.
- **Trace search cap**: The Splunk APM trace search API returns at most 200 traces per query, regardless of `WATCH_SAMPLE_LIMIT`. Low-frequency paths may need multiple learn windows to achieve full coverage.
- **AutoDetect parent detectors**: Tiers 1b, 3, and 4 create `AutoDetectCustomization` children. The org-wide parent detectors must exist in your org — they are created automatically by Splunk Observability in all orgs with APM enabled.
- **Bedrock credentials**: `agent.py` and the Claude-calling standalone agents require ambient AWS credentials with Bedrock access.
