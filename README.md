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
| 1a | `provision_detectors.py` | New caller of a database node | SignalFlow detector on `spans.count` grouped by `sf_initiating_service` |
| 1b | `provision_detectors.py` | Call volume spike on ingress services | SignalFlow: 5m mean > 10× 1h mean |
| 1c | `provision_detectors.py` | Known DB caller goes silent | SignalFlow: 30m mean == 0 after non-zero 6h mean |
| 2  | `trace_fingerprint.py`  | New or changed execution paths | SHA-256 of ordered parent→child span edge sequence |
| 3  | `error_fingerprint.py`  | New error signatures, rate spikes, vanished signatures | SHA-256 of service + error_type + operation + call_path |
| 4  | `provision_detectors.py` | p99 latency drift | SignalFlow: 15m mean > 2× 1h mean |
| C  | `correlate.py`          | 2+ tiers firing on same service simultaneously | Joins Tier 1/2/3 custom events by service within a time window |

**Tiers 1, 4** run as persistent Splunk detectors (always-on SignalFlow).
**Tiers 2, 3, and C** run as scheduled scripts on cron.

---

## Requirements

- Python 3.10+
- Splunk Observability Cloud account with APM enabled
- Services instrumented with OpenTelemetry (traces flowing)
- `SPLUNK_ACCESS_TOKEN` — an API token with read+write access
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

### Automatic multi-environment mode (cron)

```bash
# Discover all active environments and provision any new/changed ones
python onboard.py --auto

# Daily cron
0 6 * * * cd /opt/behavioral-baseline && python onboard.py --auto >> onboard.log 2>&1
```

### Continuous watch (cron every 5 minutes)

```bash
# Tier 2 — trace path drift
*/5 * * * * python trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 5

# Tier 3 — new error signatures, rate spikes, vanished signatures
*/5 * * * * python error_fingerprint.py --environment petclinicmbtest watch --window-minutes 5

# Correlation — joins Tier 1/2/3 events, fires combined alert when 2+ tiers hit same service
*/5 * * * * python correlate.py --environment petclinicmbtest --window-minutes 15
```

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

# Provision / teardown SignalFlow detectors
python provision_detectors.py --environment petclinicmbtest --dry-run
python provision_detectors.py --environment petclinicmbtest
python provision_detectors.py --environment petclinicmbtest --teardown
```

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
| `behavioral_baseline.onboarded` | audit | `environment`, `action`, `provision_ok`, `baseline_ok` |

---

## Environment variables reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLUNK_ACCESS_TOKEN` | required | API token |
| `SPLUNK_REALM` | `us0` | Splunk realm |
| `BASELINE_PATH` | `./baseline.json` | Trace fingerprint baseline location |
| `ERROR_BASELINE_PATH` | `./error_baseline.json` | Error signature baseline location |
| `ONBOARDING_STATE_PATH` | `./onboarding_state.json` | Onboarding state file location |
| `TOPOLOGY_LOOKBACK_HOURS` | `48` | How far back topology queries look |

---

## Architecture

```
onboard.py                     ← orchestration controller
├── provision_detectors.py     ← Tiers 1a, 1b, 1c, 4 (SignalFlow)
├── trace_fingerprint.py       ← Tier 2 (trace path drift, cron script)
├── error_fingerprint.py       ← Tier 3 (error signatures + spikes, cron script)
└── correlate.py               ← Tier C (cross-tier correlation, cron script)

Splunk Observability
├── APM topology API           ← service discovery (all scripts)
├── APM trace search API       ← trace sampling (fingerprint scripts)
├── SignalFlow detector API    ← detector CRUD (provision_detectors.py)
└── Custom events API          ← anomaly alerting (fingerprint scripts)
```

---

## Limitations

- **MetricSets required for Tiers 1/4**: SignalFlow detectors read `spans.count` and `service.request.duration.ns.p99` which are derived metrics. Enable APM MetricSets in Splunk Observability settings for your services.
- **Static baselines**: `trace_fingerprint.py` and `error_fingerprint.py` baselines are point-in-time snapshots. Re-run `learn` after intentional topology changes (new feature deployments, service renames) to prevent false positives.
- **No seasonality awareness**: The SignalFlow detectors compare rolling windows (5m vs 1h) which does not account for traffic patterns that legitimately vary by time of day or day of week.
