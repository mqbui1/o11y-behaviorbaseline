# Behavioral Baseline — Anomaly Detection for Splunk Observability

**Augments Splunk APM AutoDetect** with structural and behavioral detection that metric thresholds cannot catch. Splunk's built-in AutoDetect already covers error rate, latency, and request rate anomalies for every APM-enabled service. This framework adds a second layer on top:

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

| Tier | Source | What it detects | How |
|------|--------|----------------|-----|
| 1b | Splunk APM AutoDetect _(native)_ | Request rate spike on ingress services | Built-in — fires for all APM environments automatically |
| 3  | Splunk APM AutoDetect _(native)_ | Error rate spike per service | Built-in — fires for all APM environments automatically |
| 4  | Splunk APM AutoDetect _(native)_ | p99 latency drift per service | Built-in — fires for all APM environments automatically |
| 2  | `core/trace_fingerprint.py`  | New/changed execution paths, missing services | SHA-256 of ordered parent→child span edge sequence |
| 3+ | `core/error_fingerprint.py`  | New error signatures, rate spikes, vanished signatures | SHA-256 of service + error_type + operation + call_path |
| C  | `core/correlate.py`          | 2+ tiers firing on same service simultaneously | Joins Tier 2/3 events by service within a time window |

**Tiers 1b, 3, and 4** are native Splunk APM AutoDetect — no provisioning required; they fire automatically for every APM-enabled environment.

**Tiers 2, 3+, and C** are this framework's behavioral layer — structural drift detection that AutoDetect cannot provide. They run as scheduled scripts on cron.

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

### What onboarding produces

For each new environment, `onboard.py` creates:

> **Note:** Error rate, latency, and request rate alerts are already covered by Splunk APM AutoDetect for every APM-enabled environment. No detector provisioning is required.

| Output | Location | Description |
|--------|----------|-------------|
| Trace baseline | `data/baseline.<env>.json` | Structural call path fingerprints from live traffic |
| Error baseline | `data/error_baseline.<env>.json` | Known error signatures from live traffic |
| Dashboard | Splunk Dashboards | Behavioral Baseline dashboard linked to env |
| Cron jobs | Local crontab | Watch every 5m, learn daily, correlate every 5m |
| Runbook | `agents/RUNBOOK.<env>.md` | Claude-generated incident runbook (see below) |

### Auto-generated runbook

When a new environment is onboarded, `runbook_generator.py` calls Claude (AWS Bedrock) with the live APM topology and produces a tailored incident runbook at `agents/RUNBOOK.<env>.md`. It includes:

- **Service map** — ASCII dependency graph drawn from actual trace data
- **Blast radius ranking** — shared dependencies sorted by number of callers
- **First 10 minutes triage checklist** — top-down investigation order (ingress → shared deps → domain services)
- **Per-service reference** — role, upstream/downstream callers, known error types, investigation commands
- **Common failure scenarios** — DB down, discovery down, bad deploy patterns specific to this topology
- **Copy-paste commands** — ready-to-run triage commands for each service

Example for a 6-service Spring PetClinic stack:

```
## 2. First 10 Minutes: Triage Checklist

### Step 1 — Run Global Triage (0:00–1:00)
python3 triage_agent.py --environment petclinicmbtest --window-minutes 60

### Step 2 — Check api-gateway (1:00–2:00)
api-gateway is the single ingress. If it is erroring, all users are affected.

### Step 3 — Check Shared Dependencies (2:00–5:00)
If multiple domain services are failing simultaneously, check shared deps first:
  discovery-server (4 callers — highest blast radius)
  mysql:petclinic  (3 callers — DB outage pattern)

### Step 4 — Check Domain Services (5:00–8:00)
python3 triage_agent.py --environment petclinicmbtest --service customers-service
python3 triage_agent.py --environment petclinicmbtest --service vets-service
```

Regenerate after topology changes:

```bash
python3 agents/runbook_generator.py --environment petclinicmbtest --force
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

## OTel Collector edge processor (real-time detection)

The default cron-based watch cycle detects anomalies with ~1–5 minute latency. For near-real-time detection (~10 seconds), deploy the custom OTel Collector processor in `otel-processor/`.

### How it works

```
App emits spans
      │
      ▼
otelcol-fingerprint (DaemonSet)
      │
      ├── fingerprintprocessor (custom Go processor)
      │     ├── buffers spans per traceId (10s tail window)
      │     ├── on flush: compute trace fingerprint + error signatures
      │     ├── compare against baseline (ConfigMap-mounted JSON)
      │     ├── MATCH  → silent, pass through
      │     └── DRIFT  → emit event to Splunk ingest immediately (~10s latency)
      │
      └── forward all spans to Splunk APM unchanged
```

Detection latency: **~10 seconds** vs ~5 minutes with cron.

Events emitted:
- `behavioral_baseline.trace.drift` — new/unknown trace structure
- `behavioral_baseline.error.drift` — new error signature never seen in baseline

### Directory layout

```
otel-processor/
├── fingerprintprocessor/     ← Go processor (OTel Collector component)
│   ├── processor.go          ← trace buffering + detection logic
│   ├── fingerprint.go        ← fingerprinting + error sig extraction (mirrors Python)
│   ├── baseline.go           ← thread-safe baseline store, reloads every 60s
│   ├── emitter.go            ← POST events to Splunk ingest
│   ├── factory.go            ← OTel Collector registration
│   ├── config.go             ← config schema
│   └── go.mod
├── collector-builder/
│   └── manifest.yaml         ← ocb manifest (compiles custom collector binary)
├── k8s/
│   ├── daemonset.yaml        ← DaemonSet + ConfigMap + Service + ServiceAccount
│   ├── baseline-sync.yaml    ← CronJob: pushes baseline JSON into ConfigMap every 5m
│   └── otelcol-config.yaml   ← collector pipeline config (reference)
├── Dockerfile                ← multi-stage: ocb build + alpine runtime
└── sync-baseline.sh          ← helper: push baseline files into ConfigMap
```

### Deploy

**Prerequisites:** Docker, kubectl, a k8s cluster with a local or remote registry.

**Step 1 — Build and push the image**

```bash
docker build -t localhost:9999/otelcol-fingerprint:latest otel-processor/
docker push localhost:9999/otelcol-fingerprint:latest
```

**Step 2 — Learn baseline and seed the ConfigMap**

```bash
python3 core/trace_fingerprint.py --environment <env> learn
python3 core/error_fingerprint.py --environment <env> learn

./otel-processor/sync-baseline.sh <env>
```

**Step 3 — Deploy**

```bash
# Update image reference in daemonset.yaml if not using localhost:9999
kubectl apply -f otel-processor/k8s/daemonset.yaml
```

**Step 4 — Redirect app spans through the processor**

```bash
for svc in api-gateway customers-service vets-service visits-service; do
  kubectl set env deployment/$svc \
    OTEL_EXPORTER_OTLP_ENDPOINT=http://otelcol-fingerprint.default.svc.cluster.local:4317
done
```

### Keeping the baseline in sync

The processor reloads baseline files from the `behavioral-baseline` ConfigMap every 60 seconds. After each Python learn or promote cycle, push updated files:

```bash
./otel-processor/sync-baseline.sh <env>
# Pods pick up the new baseline within ~60 seconds
```

The `baseline-sync` CronJob in `k8s/baseline-sync.yaml` can automate this if baseline files are on a shared PVC.

### Processor configuration

All settings are in the `otelcol-fingerprint-config` ConfigMap under `fingerprintprocessor:`:

| Setting | Default | Description |
|---------|---------|-------------|
| `trace_buffer_timeout` | `10s` | How long to buffer spans per traceId before flushing |
| `min_spans` | `2` | Minimum spans required to fingerprint a trace |
| `min_baseline_occurrences` | `2` | Min baseline hits for a pattern to be considered established |
| `baseline_reload_interval` | `60s` | How often baseline JSON is re-read from disk |
| `baseline_path` | `/baseline/baseline.json` | Mounted trace baseline file path |
| `error_baseline_path` | `/baseline/error_baseline.json` | Mounted error baseline file path |

---

## Limitations

- **Auto-promotion lag**: New patterns after a deployment will alert for up to `AUTO_PROMOTE_THRESHOLD × cron_interval` minutes. Use `promote` immediately after a known deployment to skip the wait.
- **Trace search cap**: The Splunk APM trace search API returns at most 200 traces per query, regardless of `WATCH_SAMPLE_LIMIT`. Low-frequency paths may need multiple learn windows to achieve full coverage.
- **AutoDetect parent detectors**: Tiers 1b, 3, and 4 create `AutoDetectCustomization` children. The org-wide parent detectors must exist in your org — they are created automatically by Splunk Observability in all orgs with APM enabled.
- **Bedrock credentials**: `agent.py` and the Claude-calling standalone agents require ambient AWS credentials with Bedrock access.
- **Edge processor baseline sync**: The OTel Collector processor detects against a static baseline snapshot. It does not auto-promote fingerprints — run `sync-baseline.sh` after each Python learn/promote cycle to keep the processor's view current.
