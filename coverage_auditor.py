#!/usr/bin/env python3
"""
Behavioral Baseline — Baseline Coverage Auditor (#11)
=======================================================
Answers: "Does your baseline actually cover normal traffic?"

Today you don't know if your baseline fingerprints represent a good sample of
production traffic. This agent samples live traces, matches them against the
stored baseline, and computes per-root-op coverage:

  api-gateway:GET vets-service      94%  ✅  (31/33 live traces match)
  visits-service:PUT                31%  ⚠️  (5/16 live traces match — needs longer learn)
  customers-service:GET /owners     0%   ❌  (0/8 live traces match — new endpoint or baseline stale)

Action recommendations:
  - < 50% coverage → re-run learn with a longer window
  - > 0 unmatched, service active → flag for baseline update
  - Root op in baseline but 0 live traces → potential dead endpoint

Usage:
  python coverage_auditor.py --environment petclinicmbtest
  python coverage_auditor.py --environment petclinicmbtest --window-minutes 60
  python coverage_auditor.py --environment petclinicmbtest --service api-gateway
  python coverage_auditor.py --environment petclinicmbtest --threshold 70  # warn below 70%

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
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

DEFAULT_WINDOW_MINUTES  = 30
DEFAULT_WARN_THRESHOLD  = 50   # % coverage below which we warn
DEFAULT_SAMPLE_LIMIT    = 200

# ── Import from trace_fingerprint ─────────────────────────────────────────────

_TF_DIR = Path(__file__).parent
sys.path.insert(0, str(_TF_DIR))
try:
    from trace_fingerprint import (
        build_fingerprint,
        discover_topology,
        search_traces,
        get_trace_full,
        _is_noise_trace,
    )
    _TF_AVAILABLE = True
except ImportError as e:
    print(f"  [warn] trace_fingerprint import failed: {e}", file=sys.stderr)
    _TF_AVAILABLE = False


# ── Baseline loading ──────────────────────────────────────────────────────────

def _load_baseline(environment: str | None) -> dict:
    script_dir = Path(__file__).parent
    for pattern in [f"baseline.{environment}.json", "baseline.json"]:
        fp = script_dir / pattern
        if fp.exists():
            try:
                return json.loads(fp.read_text())
            except Exception:
                pass
    return {"fingerprints": {}}


# ── Coverage computation ──────────────────────────────────────────────────────

def _root_op_service(root_op: str) -> str:
    return root_op.split(":")[0] if ":" in root_op else root_op


def compute_coverage(environment: str | None,
                     service_filter: str | None,
                     window_minutes: int,
                     sample_limit: int) -> list[dict]:
    """
    Sample live traces, fingerprint them, and compute per-root-op coverage.
    Returns list of coverage dicts sorted by coverage % ascending.
    """
    if not _TF_AVAILABLE:
        print("  [error] trace_fingerprint module not available", file=sys.stderr)
        return []

    baseline     = _load_baseline(environment)
    baseline_fps = baseline.get("fingerprints", {})

    # Build lookup: root_op → set of known hashes
    baseline_by_root: dict[str, set[str]] = defaultdict(set)
    for h, v in baseline_fps.items():
        baseline_by_root[v.get("root_op", "")].add(h)

    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    # Discover services to sample
    topo = discover_topology(lookback_hours=2, environment=environment)
    all_services = topo.get("services", [])
    if service_filter:
        services = [s for s in all_services if s == service_filter] or [service_filter]
    else:
        services = all_services

    print(f"  Sampling {len(services)} service(s) over last {window_minutes}m...")

    # Sample traces for each service
    live_by_root: dict[str, list[str]] = defaultdict(list)   # root_op → [hash, ...]
    total_traces = 0

    for svc in services:
        raw = search_traces([svc], start_ms, now_ms, limit=sample_limit // max(1, len(services)))
        for t in raw:
            trace_id = t.get("traceId") or t.get("id")
            if not trace_id:
                continue
            full = get_trace_full(trace_id)
            if not full:
                continue
            fp = build_fingerprint(full)
            if not fp:
                continue
            live_by_root[fp["root_op"]].append(fp["hash"])
            total_traces += 1

    print(f"  {total_traces} live traces sampled across {len(live_by_root)} root op(s)")

    # Compute coverage per root_op
    results: list[dict] = []

    # Root ops seen in live traffic
    all_root_ops = set(baseline_by_root.keys()) | set(live_by_root.keys())
    for root_op in sorted(all_root_ops):
        svc = _root_op_service(root_op)
        if service_filter and svc != service_filter:
            continue

        live_hashes   = live_by_root.get(root_op, [])
        known_hashes  = baseline_by_root.get(root_op, set())
        live_total    = len(live_hashes)
        matched       = sum(1 for h in live_hashes if h in known_hashes)
        unmatched     = live_total - matched
        in_baseline   = len(known_hashes)

        if live_total == 0:
            coverage_pct = None  # can't compute — no live traffic
            status = "NO_TRAFFIC"
        else:
            coverage_pct = round(100 * matched / live_total, 1)
            if coverage_pct >= 80:
                status = "GOOD"
            elif coverage_pct >= 50:
                status = "WARN"
            else:
                status = "LOW"

        results.append({
            "root_op":       root_op,
            "service":       svc,
            "coverage_pct":  coverage_pct,
            "status":        status,
            "live_total":    live_total,
            "matched":       matched,
            "unmatched":     unmatched,
            "baseline_fps":  in_baseline,
        })

    # Sort: NO_TRAFFIC and LOW first, then WARN, then GOOD
    order = {"LOW": 0, "WARN": 1, "NO_TRAFFIC": 2, "GOOD": 3}
    results.sort(key=lambda r: (order.get(r["status"], 4),
                                (r["coverage_pct"] or 101)))
    return results


# ── Recommendation generation ─────────────────────────────────────────────────

def _recommend(r: dict) -> str:
    if r["status"] == "NO_TRAFFIC":
        if r["baseline_fps"] > 0:
            return (f"In baseline ({r['baseline_fps']} fp) but no live traffic in window — "
                    "possible dead endpoint or low-traffic path. Extend window to verify.")
        return "Not in baseline and no live traffic — skip."
    pct = r["coverage_pct"]
    if pct == 0:
        return (f"0% match ({r['unmatched']} live traces) — baseline likely stale or "
                "this endpoint changed. Re-run: python trace_fingerprint.py learn --reset")
    elif pct < 50:
        return (f"Only {pct}% covered ({r['matched']}/{r['live_total']} traces). "
                "Run learn with a longer window: trace_fingerprint.py learn --window-minutes 240")
    elif pct < 80:
        return (f"{pct}% covered — some edge cases missing. "
                "Consider: trace_fingerprint.py learn --window-minutes 120")
    return f"{pct}% — good coverage."


# ── Report ────────────────────────────────────────────────────────────────────

def print_report(results: list[dict], warn_threshold: int) -> int:
    """Returns exit code: 1 if any LOW coverage, else 0."""
    status_icon = {"GOOD": "✅", "WARN": "⚠️ ", "LOW": "❌", "NO_TRAFFIC": "⬜"}
    has_low = False

    print(f"\n{'='*70}")
    print(f"BASELINE COVERAGE AUDIT")
    print(f"{'='*70}")

    by_service: dict[str, list] = defaultdict(list)
    for r in results:
        by_service[r["service"]].append(r)

    for svc, rows in sorted(by_service.items()):
        print(f"\n  {svc}")
        for r in rows:
            icon = status_icon.get(r["status"], "•")
            pct_str = f"{r['coverage_pct']:.0f}%" if r["coverage_pct"] is not None else "n/a"
            live_str = f"({r['matched']}/{r['live_total']} traces)" if r["live_total"] else "(no live traffic)"
            root_op_short = r["root_op"][len(svc)+1:] if r["root_op"].startswith(svc) else r["root_op"]
            print(f"    {icon} {root_op_short:<40} {pct_str:>6}  {live_str}")
            if r["status"] in ("LOW", "WARN", "NO_TRAFFIC") and r["live_total"] > 0:
                print(f"       → {_recommend(r)}")
            if r["status"] == "LOW":
                has_low = True

    total = len([r for r in results if r["live_total"] > 0])
    good  = len([r for r in results if r["status"] == "GOOD"])
    warn  = len([r for r in results if r["status"] == "WARN"])
    low   = len([r for r in results if r["status"] == "LOW"])

    print(f"\n  Summary: {total} root ops with live traffic — "
          f"{good} GOOD, {warn} WARN, {low} LOW")
    print()
    return 1 if has_low else 0


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Baseline Coverage Auditor — measures how much live traffic your baseline covers"
    )
    parser.add_argument("--environment",    default=None)
    parser.add_argument("--service",        default=None, help="Audit a specific service only")
    parser.add_argument("--window-minutes", type=int, default=DEFAULT_WINDOW_MINUTES)
    parser.add_argument("--threshold",      type=int, default=DEFAULT_WARN_THRESHOLD,
                        help=f"Coverage pct below which to warn (default: {DEFAULT_WARN_THRESHOLD})")
    parser.add_argument("--sample-limit",   type=int, default=DEFAULT_SAMPLE_LIMIT)
    parser.add_argument("--json",           action="store_true")
    args = parser.parse_args()

    print(f"[coverage-auditor] env={args.environment or 'all'}, "
          f"window={args.window_minutes}m, warn-threshold={args.threshold}%")

    results = compute_coverage(
        args.environment, args.service,
        args.window_minutes, args.sample_limit,
    )

    if args.json:
        print(json.dumps(results, indent=2))
        sys.exit(0)

    exit_code = print_report(results, args.threshold)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
