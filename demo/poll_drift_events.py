#!/usr/bin/env python3
"""Tail OTel collector logs on the cluster for real-time drift event detection.

Default mode: human-readable live stream (Ctrl+C to stop).
  python3 poll_drift_events.py

Triage mode: wait for events, collect for a settle window, emit agent.py JSON, exit.
  python3 poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV

  --settle-seconds N   Collect for N more seconds after first event (default: 5)
  --timeout-seconds N  Give up if no events arrive within N seconds (default: 120)
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).parent.parent  # demo/ -> repo root

# Load .env
_env = _REPO / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

EC2_IP   = os.environ.get("EC2_IP", "")
EC2_PORT = os.environ.get("EC2_PORT", "2222")
EC2_PASS = os.environ.get("EC2_PASS", os.environ.get("EC2_PASSWORD", ""))

if not EC2_IP or not EC2_PASS:
    print("ERROR: EC2_IP and EC2_PASS (or EC2_PASSWORD) must be set in .env")
    sys.exit(1)

# In the two-tier topology, the DaemonSet is a pure forwarder — detection events
# (drift, error signatures, MISSING_SERVICE, latency anomaly) come from the aggregator.
DAEMONSET_LABEL = os.environ.get("OTEL_POD_LABEL", "app=otelcol-aggregator")
OTEL_CONTAINER  = os.environ.get("OTEL_CONTAINER", "otelcol")
_DATA_DIR       = _REPO / "data"

def _make_ssh_cmd(since: str = "5s") -> str:
    return (
        "exec bash -c '"
        "for p in $(kubectl get pods -l " + DAEMONSET_LABEL + " -o jsonpath=\"{.items[*].metadata.name}\");"
        f" do kubectl logs -f --since={since} $p -c " + OTEL_CONTAINER + " 2>/dev/null & done;"
        " tail -f /dev/null'"
    )

def _make_proc(since: str = "5s"):
    return subprocess.Popen(
        ["sshpass", f"-p{EC2_PASS}",
         "ssh", "-T", "-p", EC2_PORT,
         "-o", "StrictHostKeyChecking=no",
         "-o", "RequestTTY=no",
         f"splunk@{EC2_IP}",
         _make_ssh_cmd(since)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

def _dedup_path(env: str) -> Path:
    return _DATA_DIR / f"otel_dedup_state.{env}.json"

def _load_dedup(env: str) -> dict:
    p = _dedup_path(env)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}

def _save_dedup(env: str, state: dict) -> None:
    _dedup_path(env).write_text(json.dumps(state))

drift_re    = re.compile(r'(trace drift detected|new trace fingerprint \(unknown root op\)|new error signature detected|missing service detected|latency anomaly detected|error rate anomaly detected|slow db query detected|new db query plan detected)')
hash_re     = re.compile(r'"hash": "([^"]+)"')
op_re       = re.compile(r'"root_op": "([^"]+)"')
svc_re      = re.compile(r'"service": "([^"]+)"')
path_re     = re.compile(r'"path": "([^"]+)"')
tid_re      = re.compile(r'"trace_id": "([^"]+)"')
env_re      = re.compile(r'"environment": "([^"]+)"')
etype_re    = re.compile(r'"error_type": "([^"]+)"')
op2_re      = re.compile(r'"operation": "([^"]+)"')
missing_re  = re.compile(r'"missing_services": \[([^\]]*)\]')
cur_ms_re   = re.compile(r'"current_mean_ms": "([^"]+)"')
base_ms_re  = re.compile(r'"baseline_mean_ms": "([^"]+)"')
zscore_re   = re.compile(r'"z_score": "([^"]+)"')
erate_re    = re.compile(r'"error_pct": "([^"]+)"')
ecnt_re     = re.compile(r'"error_count": (\d+)')
tcnt_re     = re.compile(r'"total_count": (\d+)')
dbsys_re    = re.compile(r'"db_system": "([^"]+)"')
tmpl_re     = re.compile(r'"template": "([^"]+)"')

DEDUP_TTL = 90
# Events within this many seconds of the first event are grouped into one incident
INCIDENT_WINDOW_SECONDS = 30


def _group_into_incidents(events: list[dict]) -> list[dict]:
    """
    Group co-occurring anomalies into incidents.

    Events that fire within INCIDENT_WINDOW_SECONDS of the first event in a
    cluster are assigned a shared incident_id and an incident_group label that
    summarises the involved signal types. This gives agent.py richer context
    for root-cause reasoning and suppresses duplicate pages for the same
    underlying outage.

    A new incident group starts whenever a gap > INCIDENT_WINDOW_SECONDS
    occurs between consecutive events.
    """
    if not events:
        return events

    # Sort by timestamp_ms so clusters are contiguous
    sorted_events = sorted(events, key=lambda e: e.get("timestamp_ms", 0))

    groups: list[list[dict]] = []
    current_group: list[dict] = [sorted_events[0]]

    for evt in sorted_events[1:]:
        gap_s = (evt.get("timestamp_ms", 0) - current_group[-1].get("timestamp_ms", 0)) / 1000
        if gap_s <= INCIDENT_WINDOW_SECONDS:
            current_group.append(evt)
        else:
            groups.append(current_group)
            current_group = [evt]
    groups.append(current_group)

    result: list[dict] = []
    for group in groups:
        # Stable incident_id: hash of sorted anomaly types + services
        sig = "|".join(sorted(
            f"{e.get('anomaly_type')}:{e.get('service','')}"
            for e in group
        ))
        incident_id = "INC-" + hashlib.sha1(sig.encode()).hexdigest()[:8].upper()

        # Human-readable group label: unique signal types
        types_seen = sorted({e.get("anomaly_type", "UNKNOWN") for e in group})
        services_seen = sorted({e.get("service", "") for e in group if e.get("service")})
        group_label = (
            f"{'+'.join(types_seen)} on {','.join(services_seen)}"
            if services_seen else "+".join(types_seen)
        )

        for evt in group:
            annotated = dict(evt)
            annotated["incident_id"]    = incident_id
            annotated["incident_group"] = group_label
            annotated["incident_size"]  = len(group)
            result.append(annotated)

    return result


def _parse_event(line: str) -> dict | None:
    """Parse a drift log line into an anomaly dict (agent.py schema)."""
    if not drift_re.search(line):
        return None
    is_error      = "error signature" in line
    is_missing    = "missing service" in line
    is_latency    = "latency anomaly" in line
    is_error_rate = "error rate anomaly" in line
    is_slow_query = "slow db query" in line
    is_new_query  = "new db query plan" in line
    h    = hash_re.search(line)
    op   = op_re.search(line)
    svc  = svc_re.search(line)
    tid  = tid_re.search(line)
    path = path_re.search(line)
    et   = etype_re.search(line)
    op2  = op2_re.search(line)
    miss = missing_re.search(line)

    h_val   = h.group(1)   if h   else ""
    op_val  = op.group(1)  if op  else ""
    svc_val = svc.group(1) if svc else (op_val.split(":")[0] if ":" in op_val else op_val)

    if is_latency:
        cur_ms  = cur_ms_re.search(line)
        base_ms = base_ms_re.search(line)
        zs      = zscore_re.search(line)
        op2_val = op2.group(1) if op2 else ""
        cur_val  = cur_ms.group(1)  if cur_ms  else "?"
        base_val = base_ms.group(1) if base_ms else "?"
        zs_val   = zs.group(1)      if zs      else "?"
        return {
            "anomaly_type":      "LATENCY_ANOMALY",
            "service":           svc_val,
            "operation":         op2_val,
            "current_mean_ms":   cur_val,
            "baseline_mean_ms":  base_val,
            "z_score":           zs_val,
            "message":           f"Latency spike on {svc_val} {op2_val}: {cur_val}ms (baseline {base_val}ms, z={zs_val})",
            "hash":              f"latency:{svc_val}:{op2_val}",
            "source":            "otel-edge",
            "timestamp_ms":      int(time.time() * 1000),
        }
    elif is_error_rate:
        er      = erate_re.search(line)
        ec      = ecnt_re.search(line)
        tc      = tcnt_re.search(line)
        op2_val  = op2.group(1) if op2 else ""
        er_val   = er.group(1)  if er  else "?"
        ec_val   = ec.group(1)  if ec  else "0"
        tc_val   = tc.group(1)  if tc  else "0"
        return {
            "anomaly_type": "ERROR_RATE_ANOMALY",
            "service":      svc_val,
            "operation":    op2_val,
            "error_pct":    er_val,
            "error_count":  ec_val,
            "total_count":  tc_val,
            "message":      f"Error rate spike on {svc_val} {op2_val}: {er_val} ({ec_val}/{tc_val} spans)",
            "hash":         f"errrate:{svc_val}:{op2_val}",
            "source":       "otel-edge",
            "timestamp_ms": int(time.time() * 1000),
        }
    elif is_slow_query:
        db_sys  = dbsys_re.search(line)
        tmpl    = tmpl_re.search(line)
        cur_ms  = cur_ms_re.search(line)
        base_ms = base_ms_re.search(line)
        zs      = zscore_re.search(line)
        db_sys_val  = db_sys.group(1)  if db_sys  else "?"
        tmpl_val    = tmpl.group(1)    if tmpl    else ""
        cur_val     = cur_ms.group(1)  if cur_ms  else "?"
        base_val    = base_ms.group(1) if base_ms else "?"
        zs_val      = zs.group(1)      if zs      else "?"
        h_val_local = h.group(1)       if h       else f"slowq:{svc_val}:{db_sys_val}"
        return {
            "anomaly_type":      "SLOW_QUERY",
            "service":           svc_val,
            "db_system":         db_sys_val,
            "template":          tmpl_val[:120] + ("..." if len(tmpl_val) > 120 else ""),
            "current_mean_ms":   cur_val,
            "baseline_mean_ms":  base_val,
            "z_score":           zs_val,
            "message":           f"Slow DB query on {svc_val} ({db_sys_val}): {cur_val}ms (baseline {base_val}ms, z={zs_val})",
            "hash":              h_val_local,
            "source":            "otel-edge",
            "timestamp_ms":      int(time.time() * 1000),
        }
    elif is_new_query:
        db_sys  = dbsys_re.search(line)
        tmpl    = tmpl_re.search(line)
        db_sys_val = db_sys.group(1) if db_sys else "?"
        tmpl_val   = tmpl.group(1)   if tmpl   else ""
        h_val_local = h.group(1)     if h      else f"newq:{svc_val}:{db_sys_val}"
        return {
            "anomaly_type": "NEW_QUERY_PLAN",
            "service":      svc_val,
            "db_system":    db_sys_val,
            "template":     tmpl_val[:120] + ("..." if len(tmpl_val) > 120 else ""),
            "message":      f"New DB query plan on {svc_val} ({db_sys_val}): {tmpl_val[:80]}",
            "hash":         h_val_local,
            "source":       "otel-edge",
            "timestamp_ms": int(time.time() * 1000),
        }
    elif is_missing:
        # Parse missing_services list from JSON-ish log field: ["svc1", "svc2"]
        missing_svcs: list[str] = []
        if miss:
            missing_svcs = [s.strip().strip('"') for s in miss.group(1).split(",") if s.strip().strip('"')]
        # Use the most specific missing service (not the root/gateway, prefer leaf)
        leaf_svc = missing_svcs[-1] if missing_svcs else svc_val
        return {
            "anomaly_type":     "MISSING_SERVICE",
            "service":          leaf_svc,
            "root_op":          op_val,
            "missing_services": missing_svcs,
            "message":          f"MISSING_SERVICE: {', '.join(missing_svcs)} absent from traces for root_op '{op_val}'",
            "hash":             h_val or f"missing:{op_val}",
            "source":           "otel-edge",
            "timestamp_ms":     int(time.time() * 1000),
        }
    elif is_error:
        et_val  = et.group(1)  if et  else ""
        op2_val = op2.group(1) if op2 else ""
        return {
            "anomaly_type": "NEW_ERROR_SIGNATURE",
            "service":      svc_val,
            "message":      f"New error signature in {svc_val}: {et_val} on {op2_val}",
            "error_type":   et_val,
            "operation":    op2_val,
            "trace_id":     tid.group(1) if tid else "",
            "hash":         h_val,
            "source":       "otel-edge",
            "timestamp_ms": int(time.time() * 1000),
        }
    else:
        path_val = path.group(1) if path else ""
        return {
            "anomaly_type": "NEW_FINGERPRINT",
            "service":      svc_val,
            "root_op":      op_val,
            "message":      f"Trace path drift on '{op_val}' (OTel edge detector)",
            "detail":       f"Path: {path_val}" if path_val else "",
            "trace_id":     tid.group(1) if tid else "",
            "hash":         h_val,
            "source":       "otel-edge",
            "timestamp_ms": int(time.time() * 1000),
        }


def _load_baseline_root_services(env: str) -> set[str]:
    """
    Load the set of root service names from the Python baseline for the given
    environment. These are the services that appear as trace initiators in
    steady-state traffic (e.g. the ingress/gateway layer).

    OTel NEW_FINGERPRINT events whose root service is NOT in this set are
    direct service-to-service calls being auto-promoted by the OTel processor —
    not user-facing anomalies. Suppressing them prevents steady-state noise
    without hardcoding any service names.

    Falls back to an empty set (suppress nothing) if the baseline is missing.
    """
    baseline_path = _DATA_DIR / f"baseline.{env}.json"
    if not baseline_path.exists():
        return set()
    try:
        data = json.loads(baseline_path.read_text())
        return {
            info["root_op"].split(":")[0]
            for info in data.get("fingerprints", {}).values()
            if ":" in info.get("root_op", "")
        }
    except Exception:
        return set()


def _is_noise_fingerprint(event: dict, baseline_root_services: set[str]) -> bool:
    """
    Return True if this NEW_FINGERPRINT event is OTel auto-promotion noise.

    A NEW_FINGERPRINT is noise when its root service is not among the services
    that initiate traces in steady-state traffic (as known from the Python
    baseline). These are direct service-to-service calls that the OTel processor
    fires continuously until it auto-promotes them after 10 detections.
    Error signatures are never suppressed.
    """
    if event.get("anomaly_type") != "NEW_FINGERPRINT":
        return False
    if not baseline_root_services:
        return False  # no baseline loaded — keep everything
    root_op = event.get("root_op", "")
    root_svc = root_op.split(":")[0] if ":" in root_op else root_op
    return root_svc not in baseline_root_services


def _run_watch(triage: bool, environment: str, settle: int, timeout: int,
               min_collect: int = 0, dedup_ttl: int = DEDUP_TTL) -> None:
    """Live stream mode (triage=False) or triage mode (triage=True).

    Triage mode shares the same dedup state file as watch_otel_events.py so that
    hashes already suppressed there are also suppressed here, preventing steady-state
    OTel auto-promotion events from triggering spurious triage runs.
    """
    # In triage mode: use --since=30s to catch events that fired before we connected,
    # while relying on the shared dedup state to suppress already-seen steady-state hashes.
    # The dedup state is cleared by demo-reset.sh before each demo, so only events from
    # the current demo scenario will appear.
    since = "30s" if triage else "5s"
    dedup_state: dict = _load_dedup(environment) if triage else {}
    new_dedup:   dict = dict(dedup_state)
    baseline_roots: set[str] = _load_baseline_root_services(environment) if triage else set()

    hash_last_seen: dict = {}  # in-memory dedup for live stream mode
    collected: list[dict] = []
    missing_svc_seen: set[str] = set()  # dedup MISSING_SERVICE by leaf service name
    first_event_time: float | None = None
    last_event_time:  float | None = None

    proc = _make_proc(since)
    deadline = time.time() + timeout

    try:
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip()

            # In triage mode: exit once we've had `settle` seconds of silence
            # after the last event AND min_collect seconds have elapsed since
            # the first event. min_collect ensures MISSING_SERVICE events (~60s
            # after error signatures) are captured in the same triage window.
            if triage and last_event_time is not None:
                elapsed_since_first = time.time() - first_event_time if first_event_time else 0
                if (time.time() - last_event_time >= settle
                        and elapsed_since_first >= min_collect):
                    break

            if not triage and not drift_re.search(line):
                continue

            event = _parse_event(line)
            if event is None:
                continue

            h_val = event.get("hash", "")
            now = time.time()

            if triage:
                # Skip direct-service NEW_FINGERPRINT events (OTel auto-promotion noise).
                # Uses the Python baseline's root services as the reference — no
                # hardcoded service names.
                if _is_noise_fingerprint(event, baseline_roots):
                    continue

                # For MISSING_SERVICE: deduplicate by leaf service name so that multiple
                # root_ops going silent for the same downed service emit only one event.
                if event.get("anomaly_type") == "MISSING_SERVICE":
                    leaf = event.get("service", "")
                    if leaf in missing_svc_seen:
                        continue
                    missing_svc_seen.add(leaf)

                # Use shared dedup state (same file watch_otel_events.py writes)
                # For MISSING_SERVICE: key on leaf service (no hash in log); for others: use hash.
                if event.get("anomaly_type") == "MISSING_SERVICE":
                    dedup_key = f"MISSING_SERVICE:{event.get('service', event.get('root_op', ''))}"
                else:
                    dedup_key = h_val if h_val else (
                        f"{event.get('anomaly_type')}:{event.get('service')}:{event.get('root_op') or event.get('error_type')}"
                    )
                last_seen_ms = dedup_state.get(dedup_key, 0)
                if now * 1000 - last_seen_ms < dedup_ttl * 1000:
                    continue
                new_dedup[dedup_key] = int(now * 1000)

                collected.append(event)
                if first_event_time is None:
                    first_event_time = now
                    print(f"  [{time.strftime('%H:%M:%S')}] {len(collected)} event(s) received — settling for {settle}s...",
                          file=sys.stderr)
                last_event_time = now
                if now >= deadline:
                    break
            else:
                # Live stream: in-memory dedup by hash (errors/fingerprints) or
                # by leaf service name (MISSING_SERVICE — no stable hash in logs).
                atype = event.get("anomaly_type", "")
                if atype == "MISSING_SERVICE":
                    dedup_key_live = f"MISSING_SERVICE:{event.get('service', '')}"
                else:
                    dedup_key_live = h_val
                if dedup_key_live:
                    if now - hash_last_seen.get(dedup_key_live, 0) < dedup_ttl:
                        continue
                    hash_last_seen[dedup_key_live] = now

                ts = time.strftime("%H:%M:%S")
                if atype == "NEW_ERROR_SIGNATURE":
                    etype = "error.signature.drift"
                elif atype == "MISSING_SERVICE":
                    etype = "trace.path.drift (MISSING_SERVICE)"
                elif atype == "LATENCY_ANOMALY":
                    etype = "service.latency.anomaly"
                elif atype == "ERROR_RATE_ANOMALY":
                    etype = "service.error.rate.anomaly"
                elif atype == "SLOW_QUERY":
                    etype = "db.query.slow"
                elif atype == "NEW_QUERY_PLAN":
                    etype = "db.query.new_plan"
                else:
                    etype = "trace.path.drift"
                print(f"[{ts}] {etype}")
                print(f"  root_op={event.get('root_op') or event.get('service')}  hash={h_val or '?'}")
                if event.get("missing_services"):
                    print(f"  missing={','.join(event['missing_services'])}")
                if atype == "LATENCY_ANOMALY":
                    print(f"  current={event.get('current_mean_ms')}ms  baseline={event.get('baseline_mean_ms')}ms  z={event.get('z_score')}")
                if atype == "ERROR_RATE_ANOMALY":
                    print(f"  error_pct={event.get('error_pct')}  ({event.get('error_count')}/{event.get('total_count')} spans)")
                if atype in ("SLOW_QUERY", "NEW_QUERY_PLAN"):
                    print(f"  db={event.get('db_system')}  template={event.get('template','')[:80]}")
                if atype == "SLOW_QUERY":
                    print(f"  current={event.get('current_mean_ms')}ms  baseline={event.get('baseline_mean_ms')}ms  z={event.get('z_score')}")
                if event.get("trace_id"):
                    print(f"  trace_id={event['trace_id']}")
                print()

    except KeyboardInterrupt:
        pass
    finally:
        try:
            proc.terminate()
        except Exception:
            pass

    if triage:
        if not collected:
            print("  No drift events received within timeout.", file=sys.stderr)
            sys.exit(1)
        _save_dedup(environment, new_dedup)
        grouped = _group_into_incidents(collected)
        # Summarise incident grouping for operator visibility
        incident_ids = sorted({e["incident_id"] for e in grouped})
        if len(incident_ids) > 1:
            print(f"  [{time.strftime('%H:%M:%S')}] Grouped {len(collected)} events into "
                  f"{len(incident_ids)} incident(s): {', '.join(incident_ids)}", file=sys.stderr)
        elif incident_ids:
            print(f"  [{time.strftime('%H:%M:%S')}] Incident {incident_ids[0]}: "
                  f"{grouped[0].get('incident_group', '')} ({len(collected)} signal(s))", file=sys.stderr)
        result = {
            "environment":    environment,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "window_minutes": 0,
            "source":         "otel-edge-direct",
            "checked":        len(grouped),
            "anomalies":      grouped,
        }
        print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--triage", action="store_true",
                        help="Collect events and emit agent.py JSON instead of live stream")
    parser.add_argument("--environment", default=os.environ.get("ENV", ""),
                        help="Environment name (for JSON output)")
    parser.add_argument("--settle-seconds", type=int, default=5,
                        help="Seconds of silence after last event before triaging (default: 5)")
    parser.add_argument("--min-collect-seconds", type=int, default=0,
                        help="Minimum seconds to collect after first event before triaging (default: 0)")
    parser.add_argument("--timeout-seconds", type=int, default=120,
                        help="Give up if no events arrive within this many seconds (default: 120)")
    args = parser.parse_args()

    if not args.triage:
        print("Watching OTel collector for real-time drift events...")
        print("Press Ctrl+C to stop.\n")

    _run_watch(
        triage=args.triage,
        environment=args.environment,
        settle=args.settle_seconds,
        timeout=args.timeout_seconds,
        min_collect=args.min_collect_seconds,
    )


if __name__ == "__main__":
    main()
