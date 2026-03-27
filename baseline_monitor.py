#!/usr/bin/env python3
"""
Behavioral Baseline — Quality Monitor
======================================
Proactively detects baseline health problems before they surface as
false positives or missed detections during watch cycles.

Today: you discover a dirty baseline during a demo and fix it manually.

This script runs automatically (daily cron or pre-watch hook) and flags:

  STALE_ENTRIES      — fingerprints/signatures whose first_seen timestamp
                        falls inside a known incident window (high anomaly
                        event density) — these are incident artifacts,
                        not normal baseline behavior.

  LOW_CONFIDENCE     — entries seen fewer than MIN_BASELINE_OCCURRENCES times.
                        They pass the staging threshold but are statistically
                        weak — one unusual trace/error entered the baseline.

  PERSISTENT_NOISE   — entries with high watch_hits but no promotion. The
                        watch cycle keeps firing on them — they're either
                        real anomalies that should be promoted, or noise
                        that should be removed.

  NEAR_DUPLICATES    — fingerprints with the same root_op and very similar
                        edge paths (Jaccard similarity > 0.85). Bloat the
                        baseline and dilute dominance thresholds.

  INCIDENT_ARTIFACTS — error signatures that look like incident-era errors:
                        503 Service Unavailable, ConnectException,
                        CannotCreateTransactionException, etc.
                        Should not be in a healthy baseline.

  STALE_BASELINE     — the baseline's updated_at is more than N days old
                        while the environment is actively producing traces.
                        Baseline has drifted from reality.

  EMPTY_BASELINE     — zero entries. Fingerprint scripts will fire on every
                        trace — extremely noisy. Needs a learn run.

Output:
  Prints a per-environment health report with severity (CRITICAL/WARNING/INFO)
  and a concrete remediation command for each issue.

Usage:
  python baseline_monitor.py                           # check all envs
  python baseline_monitor.py --environment petclinicmbtest
  python baseline_monitor.py --environment petclinicmbtest --verbose
  python baseline_monitor.py --auto-fix --dry-run      # show what --auto-fix would do
  python baseline_monitor.py --auto-fix                # apply safe fixes (remove LOW_CONFIDENCE entries)

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

# ── Config ─────────────────────────────────────────────────────────────────────

_ENV_FILE = Path(__file__).parent / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN")
REALM        = os.environ.get("SPLUNK_REALM", "us0")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
    sys.exit(1)

STREAM_URL = f"https://stream.{REALM}.signalfx.com"

# Baseline files are env-scoped: baseline.<env>.json
BASELINE_GLOB      = "./baseline.*.json"
ERR_BASELINE_GLOB  = "./error_baseline.*.json"

# Health thresholds
MIN_OCCURRENCES        = 2     # below this = LOW_CONFIDENCE
HIGH_WATCH_HITS        = 8     # above this = PERSISTENT_NOISE
STALE_DAYS             = 3     # baseline older than this = STALE_BASELINE
NEAR_DUPE_THRESHOLD    = 0.85  # Jaccard similarity = NEAR_DUPLICATES
INCIDENT_WINDOW_BUFFER = 5     # minutes buffer around detected incident spike

# Error types that indicate incident-era contamination
INCIDENT_ERROR_TYPES = {
    "503", "502", "504",
    "java.net.ConnectException",
    "java.net.SocketTimeoutException",
    "CannotCreateTransactionException",
    "org.springframework.transaction.CannotCreateTransactionException",
    "Connection refused",
    "connection refused",
    "ECONNREFUSED",
}

# How far back to look for anomaly event spikes (to detect incident windows)
INCIDENT_DETECTION_WINDOW_HOURS = 72  # 3 days back


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _signalflow_events(event_type: str, start_ms: int, end_ms: int,
                       timeout: float = 15.0) -> list[dict]:
    program = f'events(eventType="{event_type}").publish()'
    url = (f"{STREAM_URL}/v2/signalflow/execute"
           f"?start={start_ms}&stop={end_ms}&immediate=true")
    req = urllib.request.Request(
        url, data=program.encode(),
        headers={"X-SF-Token": ACCESS_TOKEN, "Content-Type": "text/plain"},
        method="POST",
    )
    results = []
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data_lines: list[str] = []
            for raw_line in resp:
                line     = raw_line.decode()
                stripped = line.strip()
                if stripped.startswith("data:"):
                    data_lines.append(stripped[5:].strip())
                elif stripped == "" and data_lines:
                    payload    = "".join(data_lines)
                    data_lines = []
                    try:
                        msg = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    if "properties" in msg and "metadata" in msg:
                        results.append(msg)
                    if msg.get("event") in ("STREAM_STOP", "END_OF_CHANNEL"):
                        break
    except Exception as e:
        print(f"  [warn] SignalFlow {event_type}: {e}", file=sys.stderr)
    return results


# ── Incident window detection ──────────────────────────────────────────────────

def detect_incident_windows(environment: str | None,
                             lookback_hours: int = INCIDENT_DETECTION_WINDOW_HOURS
                             ) -> list[tuple[datetime, datetime]]:
    """
    Query anomaly event history and find time windows where event density
    spiked (≥3 events in a 10-min bucket). Returns list of (start, end) windows.
    """
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - lookback_hours * 3600 * 1000

    # Collect all anomaly event timestamps
    all_ts: list[int] = []
    for et in ["trace.path.drift", "error.signature.drift"]:
        for msg in _signalflow_events(et, start_ms, now_ms):
            dims      = msg.get("metadata", {})
            event_env = dims.get("environment") or msg.get("properties", {}).get("environment", "all")
            if environment and event_env not in (environment, "all"):
                continue
            ts = msg.get("timestampMs", 0)
            if ts:
                all_ts.append(ts)

    if not all_ts:
        return []

    # Bucket into 10-min slots, find slots with ≥3 events
    BUCKET_MS = 10 * 60 * 1000
    bucket_counts: dict[int, int] = defaultdict(int)
    for ts in all_ts:
        bucket = (ts // BUCKET_MS) * BUCKET_MS
        bucket_counts[bucket] += 1

    spike_buckets = sorted(b for b, c in bucket_counts.items() if c >= 3)
    if not spike_buckets:
        return []

    # Merge adjacent spike buckets into incident windows
    windows: list[tuple[datetime, datetime]] = []
    window_start = spike_buckets[0]
    window_end   = spike_buckets[0] + BUCKET_MS

    for bucket in spike_buckets[1:]:
        if bucket <= window_end + BUCKET_MS:  # adjacent or overlapping
            window_end = bucket + BUCKET_MS
        else:
            buf = INCIDENT_WINDOW_BUFFER * 60 * 1000
            windows.append((
                datetime.fromtimestamp((window_start - buf) / 1000, tz=timezone.utc),
                datetime.fromtimestamp((window_end   + buf) / 1000, tz=timezone.utc),
            ))
            window_start = bucket
            window_end   = bucket + BUCKET_MS

    buf = INCIDENT_WINDOW_BUFFER * 60 * 1000
    windows.append((
        datetime.fromtimestamp((window_start - buf) / 1000, tz=timezone.utc),
        datetime.fromtimestamp((window_end   + buf) / 1000, tz=timezone.utc),
    ))

    return windows


def _in_incident_window(ts_str: str | None,
                         windows: list[tuple[datetime, datetime]]) -> tuple[datetime, datetime] | None:
    """Return the incident window that contains ts_str, or None."""
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None
    for start, end in windows:
        if start <= dt <= end:
            return (start, end)
    return None


# ── Similarity ────────────────────────────────────────────────────────────────

def _edge_tokens(path: str) -> set[str]:
    """Extract edge tokens from a fingerprint path string for similarity."""
    return set(path.split(" -> "))


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


# ── Baseline loading ──────────────────────────────────────────────────────────

def _extract_env(filename: str) -> str | None:
    """Extract environment name from baseline.<env>.json filename."""
    stem = Path(filename).stem  # e.g. "baseline.petclinicmbtest"
    parts = stem.split(".", 1)
    return parts[1] if len(parts) == 2 else None


def load_baseline_files(target_env: str | None) -> list[dict]:
    """
    Load all trace and error baseline files.
    Returns list of {env, type, path, data, fingerprints_or_sigs}.
    """
    script_dir = Path(__file__).parent
    files = []

    for pattern, btype in [(BASELINE_GLOB, "trace"), (ERR_BASELINE_GLOB, "error")]:
        for fp in sorted(script_dir.glob(pattern.lstrip("./"))):
            env = _extract_env(fp.name)
            if target_env and env != target_env:
                continue
            try:
                data    = json.loads(fp.read_text())
                entries = data.get("fingerprints", data.get("signatures", {}))
                files.append({
                    "env":     env,
                    "type":    btype,
                    "path":    fp,
                    "data":    data,
                    "entries": entries,
                })
            except Exception as e:
                print(f"  [warn] Could not read {fp}: {e}", file=sys.stderr)

    return files


# ── Health checks ──────────────────────────────────────────────────────────────

def check_empty(baseline: dict) -> list[dict]:
    issues = []
    if len(baseline["entries"]) == 0:
        updated = baseline["data"].get("updated_at", "unknown")
        issues.append({
            "severity": "CRITICAL",
            "check":    "EMPTY_BASELINE",
            "message":  (f"{baseline['type']} baseline for '{baseline['env']}' "
                         f"has 0 entries (last updated: {updated[:19]})."),
            "fix":      (f"python3 {'trace_fingerprint' if baseline['type']=='trace' else 'error_fingerprint'}.py "
                         f"--environment {baseline['env']} learn --window-minutes 120"),
        })
    return issues


def check_stale_baseline(baseline: dict) -> list[dict]:
    issues = []
    updated_str = baseline["data"].get("updated_at")
    if not updated_str or len(baseline["entries"]) == 0:
        return []
    try:
        updated = datetime.fromisoformat(updated_str.replace("Z", "+00:00"))
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - updated).days
        if age_days >= STALE_DAYS:
            issues.append({
                "severity": "WARNING",
                "check":    "STALE_BASELINE",
                "message":  (f"{baseline['type']} baseline for '{baseline['env']}' "
                             f"last updated {age_days} days ago."),
                "fix":      (f"python3 {'trace_fingerprint' if baseline['type']=='trace' else 'error_fingerprint'}.py "
                             f"--environment {baseline['env']} learn --window-minutes 120"),
            })
    except Exception:
        pass
    return issues


def check_stale_entries(baseline: dict,
                         incident_windows: list[tuple[datetime, datetime]]) -> list[dict]:
    """Find entries whose first_seen falls inside an incident window."""
    if not incident_windows:
        return []
    issues = []
    stale_entries = []
    for h, entry in baseline["entries"].items():
        window = _in_incident_window(entry.get("first_seen"), incident_windows)
        if window:
            stale_entries.append((h, entry, window))

    if stale_entries:
        # Compute offset: how far back (in minutes) is the latest incident window end
        now = datetime.now(timezone.utc)
        worst_window_end   = max(w[1] for w in [x[2] for x in stale_entries])
        offset_minutes     = int((now - worst_window_end).total_seconds() / 60) + 60

        entry_desc = []
        for h, entry, window in stale_entries[:5]:
            if baseline["type"] == "trace":
                desc = entry.get("root_op", h[:8])
            else:
                desc = f"{entry.get('service','?')}:{entry.get('error_type','?')}"
            entry_desc.append(desc)

        issues.append({
            "severity": "CRITICAL",
            "check":    "STALE_ENTRIES",
            "message":  (
                f"{baseline['type']} baseline for '{baseline['env']}' has "
                f"{len(stale_entries)} entry(ies) first seen during an incident window "
                f"({stale_entries[0][2][0].strftime('%m-%d %H:%M')}–"
                f"{stale_entries[0][2][1].strftime('%H:%M UTC')}): "
                f"{', '.join(entry_desc)}"
                f"{'...' if len(stale_entries) > 5 else ''}"
            ),
            "fix":      (
                f"python3 {'trace_fingerprint' if baseline['type']=='trace' else 'error_fingerprint'}.py "
                f"--environment {baseline['env']} learn "
                f"--window-minutes 120 --window-offset-minutes {offset_minutes} --reset"
            ),
        })
    return issues


def check_low_confidence(baseline: dict) -> list[dict]:
    """Find entries with very low occurrence counts."""
    weak = [
        (h, e) for h, e in baseline["entries"].items()
        if e.get("occurrences", 0) < MIN_OCCURRENCES
        and not e.get("auto_promoted")
    ]
    if not weak:
        return []
    return [{
        "severity": "WARNING",
        "check":    "LOW_CONFIDENCE",
        "message":  (
            f"{baseline['type']} baseline for '{baseline['env']}' has "
            f"{len(weak)} entry(ies) with occurrences < {MIN_OCCURRENCES} "
            f"(weak evidence — likely one-off traces admitted to baseline)."
        ),
        "fix":      (
            f"python3 {'trace_fingerprint' if baseline['type']=='trace' else 'error_fingerprint'}.py "
            f"--environment {baseline['env']} learn --window-minutes 120 --reset"
        ),
        "entries":  [(h, e) for h, e in weak],
    }]


def check_persistent_noise(baseline: dict) -> list[dict]:
    """Find entries with many watch hits but not auto-promoted."""
    noisy = [
        (h, e) for h, e in baseline["entries"].items()
        if e.get("watch_hits", 0) >= HIGH_WATCH_HITS
        and not e.get("auto_promoted")
    ]
    if not noisy:
        return []
    issues = []
    for h, e in noisy:
        if baseline["type"] == "trace":
            desc = e.get("root_op", h[:8])
        else:
            desc = f"{e.get('service','?')}:{e.get('error_type','?')}"
        issues.append({
            "severity": "WARNING",
            "check":    "PERSISTENT_NOISE",
            "message":  (
                f"'{desc}' in {baseline['type']} baseline for "
                f"'{baseline['env']}' has fired {e['watch_hits']} times "
                f"without promotion — possible persistent anomaly or noisy entry."
            ),
            "fix":      (
                f"Investigate '{desc}': if expected, promote it:  "
                f"python3 {'trace_fingerprint' if baseline['type']=='trace' else 'error_fingerprint'}.py "
                f"--environment {baseline['env']} promote {h[:8]}"
            ),
        })
    return issues


def check_near_duplicates(baseline: dict) -> list[dict]:
    """Find near-duplicate fingerprints (same root_op, high path similarity)."""
    if baseline["type"] != "trace":
        return []
    # Group by root_op
    by_root: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for h, e in baseline["entries"].items():
        by_root[e.get("root_op", "")].append((h, e))

    issues = []
    for root_op, entries in by_root.items():
        if len(entries) < 2:
            continue
        # Pairwise similarity
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                h1, e1 = entries[i]
                h2, e2 = entries[j]
                tokens1 = _edge_tokens(e1.get("path", ""))
                tokens2 = _edge_tokens(e2.get("path", ""))
                sim = _jaccard(tokens1, tokens2)
                if sim >= NEAR_DUPE_THRESHOLD:
                    issues.append({
                        "severity": "INFO",
                        "check":    "NEAR_DUPLICATES",
                        "message":  (
                            f"Near-duplicate fingerprints in '{baseline['env']}' "
                            f"for '{root_op}': {h1[:8]} ↔ {h2[:8]} "
                            f"(Jaccard={sim:.2f}). "
                            f"Dilutes MISSING_SERVICE dominance calculation."
                        ),
                        "fix":      (
                            f"Review with:  python3 trace_fingerprint.py "
                            f"--environment {baseline['env']} show  "
                            f"— then re-learn with --reset if needed."
                        ),
                    })
    return issues


def check_incident_artifacts(baseline: dict) -> list[dict]:
    """Find error signatures that look like incident-era errors."""
    if baseline["type"] != "error":
        return []
    artifacts = []
    for h, e in baseline["entries"].items():
        error_type = e.get("error_type", "")
        if any(art.lower() in error_type.lower() for art in INCIDENT_ERROR_TYPES):
            artifacts.append((h, e))

    if not artifacts:
        return []

    now = datetime.now(timezone.utc)
    descs = []
    for h, e in artifacts:
        age_str = ""
        fs = e.get("first_seen")
        if fs:
            try:
                dt    = datetime.fromisoformat(fs.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age_h = int((now - dt).total_seconds() / 3600)
                age_str = f" (first seen {age_h}h ago)"
            except Exception:
                pass
        descs.append(
            f"{e.get('service','?')}:{e.get('error_type','?')} "
            f"on {e.get('operation','?')}{age_str}"
        )

    # Suggest a window offset based on the oldest artifact's first_seen
    oldest_fs  = min(
        (e.get("first_seen") for _, e in artifacts if e.get("first_seen")),
        default=None
    )
    offset_min = 0
    if oldest_fs:
        try:
            dt = datetime.fromisoformat(oldest_fs.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            offset_min = int((now - dt).total_seconds() / 60) + 60
        except Exception:
            pass

    return [{
        "severity": "CRITICAL",
        "check":    "INCIDENT_ARTIFACTS",
        "message":  (
            f"Error baseline for '{baseline['env']}' contains "
            f"{len(artifacts)} incident-era signature(s): {'; '.join(descs)}"
        ),
        "fix":      (
            f"python3 error_fingerprint.py --environment {baseline['env']} "
            f"learn --window-minutes 120 --window-offset-minutes {offset_min} --reset"
        ),
    }]


# ── Full health check ─────────────────────────────────────────────────────────

def run_health_check(target_env: str | None = None,
                     verbose: bool = False) -> dict[str, list[dict]]:
    """
    Run all health checks across all baseline files.
    Returns {env: [issue, ...]} grouped by environment.
    """
    baselines = load_baseline_files(target_env)
    if not baselines:
        envs = [target_env] if target_env else []
        print(f"  No baseline files found for {envs or 'any environment'}.")
        return {}

    # Detect incident windows once (covers all environments if no target)
    print(f"  Detecting incident windows (last {INCIDENT_DETECTION_WINDOW_HOURS}h)...")
    all_issues: dict[str, list[dict]] = defaultdict(list)

    # Collect unique environments to query
    envs_to_check = sorted({b["env"] for b in baselines if b["env"]})
    incident_windows_by_env: dict[str | None, list] = {}
    for env in envs_to_check:
        windows = detect_incident_windows(env)
        incident_windows_by_env[env] = windows
        if windows:
            print(f"    {env}: {len(windows)} incident window(s) detected")

    print(f"  Running health checks on {len(baselines)} baseline file(s)...")
    for baseline in baselines:
        env     = baseline["env"]
        windows = incident_windows_by_env.get(env, [])

        issues = []
        issues += check_empty(baseline)
        issues += check_stale_baseline(baseline)
        issues += check_stale_entries(baseline, windows)
        issues += check_low_confidence(baseline)
        issues += check_persistent_noise(baseline)
        issues += check_near_duplicates(baseline)
        issues += check_incident_artifacts(baseline)

        if issues:
            all_issues[env or "unknown"].extend(issues)
        elif verbose:
            print(f"    ✓ {baseline['type']} baseline for '{env}': healthy "
                  f"({len(baseline['entries'])} entries)")

    return dict(all_issues)


# ── Report ─────────────────────────────────────────────────────────────────────

_SEV_ICON = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵"}
_SEV_ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}


def print_health_report(all_issues: dict[str, list[dict]],
                         verbose: bool = False) -> int:
    """Print the health report. Returns total critical issue count."""
    if not all_issues:
        print("\n  ✅ All baselines are healthy.")
        return 0

    total_critical = 0
    print()
    for env in sorted(all_issues.keys()):
        issues = sorted(all_issues[env],
                        key=lambda x: _SEV_ORDER.get(x["severity"], 9))
        critical = sum(1 for i in issues if i["severity"] == "CRITICAL")
        warnings = sum(1 for i in issues if i["severity"] == "WARNING")
        total_critical += critical

        print(f"{'─'*65}")
        print(f"  {env}  [{critical} critical, {warnings} warning(s)]")
        print(f"{'─'*65}")
        for issue in issues:
            icon = _SEV_ICON.get(issue["severity"], "•")
            print(f"\n  {icon} [{issue['severity']}] {issue['check']}")
            print(f"     {issue['message']}")
            print(f"     Fix: {issue['fix']}")

    print()
    return total_critical


# ── Auto-fix ──────────────────────────────────────────────────────────────────

def auto_fix(all_issues: dict[str, list[dict]], dry_run: bool = True) -> None:
    """
    Apply safe automatic fixes:
      - LOW_CONFIDENCE: remove weak entries directly from baseline file
        (safe — just removes unreliable data, doesn't change structure)
    Other issues require human review and are left for manual action.
    """
    import subprocess
    script_dir = Path(__file__).parent

    for env, issues in all_issues.items():
        for issue in issues:
            if issue["check"] != "LOW_CONFIDENCE":
                continue
            entries_to_remove = issue.get("entries", [])
            if not entries_to_remove:
                continue

            # Find the baseline file for this env
            for btype, glob in [("trace", f"baseline.{env}.json"),
                                 ("error", f"error_baseline.{env}.json")]:
                fp = script_dir / glob
                if not fp.exists():
                    continue
                try:
                    data    = json.loads(fp.read_text())
                    entries = data.get("fingerprints", data.get("signatures", {}))
                    hashes_to_remove = {h for h, _ in entries_to_remove
                                        if h in entries}
                    if not hashes_to_remove:
                        continue

                    if dry_run:
                        print(f"  [dry-run] Would remove {len(hashes_to_remove)} "
                              f"LOW_CONFIDENCE entries from {fp.name}")
                        for h in hashes_to_remove:
                            e = entries[h]
                            desc = (e.get("root_op") or
                                    f"{e.get('service','?')}:{e.get('error_type','?')}")
                            print(f"    - {h[:8]} {desc} (occurrences={e.get('occurrences',0)})")
                    else:
                        for h in hashes_to_remove:
                            entries.pop(h, None)
                        data["updated_at"] = datetime.now(timezone.utc).isoformat()
                        fp.write_text(json.dumps(data, indent=2))
                        print(f"  Removed {len(hashes_to_remove)} LOW_CONFIDENCE "
                              f"entries from {fp.name}")
                except Exception as e:
                    print(f"  [warn] auto-fix failed for {fp}: {e}", file=sys.stderr)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Baseline Quality Monitor — proactive health checks for behavioral baselines"
    )
    parser.add_argument("--environment", default=None,
                        help="Check only this environment (default: all)")
    parser.add_argument("--verbose", action="store_true",
                        help="Show healthy baselines too")
    parser.add_argument("--auto-fix", action="store_true",
                        help="Apply safe automatic fixes (removes LOW_CONFIDENCE entries)")
    parser.add_argument("--dry-run", action="store_true",
                        help="With --auto-fix: show what would be removed without writing")
    args = parser.parse_args()

    print(f"[baseline-monitor] Checking baselines "
          f"({'all environments' if not args.environment else args.environment})...")

    all_issues = run_health_check(args.environment, verbose=args.verbose)
    critical   = print_health_report(all_issues, verbose=args.verbose)

    if args.auto_fix:
        if all_issues:
            print(f"[baseline-monitor] Running auto-fix "
                  f"({'dry-run' if args.dry_run else 'live'})...")
            auto_fix(all_issues, dry_run=args.dry_run)
        else:
            print("[baseline-monitor] Nothing to auto-fix.")

    sys.exit(1 if critical > 0 else 0)


if __name__ == "__main__":
    main()
