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
| 1b | `provision_detectors.py` | Call volume spike on ingress services | SignalFlow: 5m window > 10× same 5m window 1 week ago (`timeshift('1w')`) |
| 1c | `provision_detectors.py` | Known DB caller goes silent | SignalFlow: 30m mean == 0 after non-zero 6h mean |
| 2  | `trace_fingerprint.py`  | New or changed execution paths | SHA-256 of ordered parent→child span edge sequence |
| 3  | `error_fingerprint.py`  | New error signatures, rate spikes, vanished signatures | SHA-256 of service + error_type + operation + call_path |
| 4  | `provision_detectors.py` | p99 latency drift | SignalFlow: 15m window > 2× same 15m window 1 week ago (`timeshift('1w')`) |
| C  | `correlate.py`          | 2+ tiers firing on same service simultaneously | Joins Tier 1/2/3 custom events by service within a time window |

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

## Limitations

- **MetricSets required for Tiers 1/4**: SignalFlow detectors read `spans.count` and `service.request.duration.ns.p99` which are derived metrics. Enable APM MetricSets in Splunk Observability settings for your services.
- **Auto-promotion lag**: New patterns after a deployment will alert for up to `AUTO_PROMOTE_THRESHOLD × cron_interval` minutes before being silenced. Use `promote` immediately after a known deployment to skip the wait, or run `learn` for large-scale topology changes.
- **Seasonality requires 1 week of history**: Tiers 1b and 4 use `timeshift('1w')` for seasonality-aware comparison. The first week after provisioning will fall back to a flat baseline (no prior week data exists yet). This is expected behavior.
