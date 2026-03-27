#!/usr/bin/env python3
"""
Behavioral Baseline — Noise Pattern Learner (#14)
==================================================
Today: NOISE_PATTERNS in trace_fingerprint.py is a hardcoded list of
universal health-check and registry URL substrings.

Problem: your application may have additional high-frequency, always-normal
paths that are constantly auto-promoted (fire → auto-promoted → fire again
next learn cycle). These pollute the baseline and generate alert noise.

This agent:
  1. Reads the baseline and finds fingerprints that have been auto-promoted
     OR have very high watch_hits without ever firing a real alert
  2. Identifies patterns in their root operations (common prefixes, substrings)
  3. Shows which patterns would suppress the most noise if added
  4. With --apply: writes suggested patterns to noise_patterns.json and
     optionally patches trace_fingerprint.py directly (--patch)

Usage:
  python noise_learner.py --environment petclinicmbtest
  python noise_learner.py --environment petclinicmbtest --apply
  python noise_learner.py --environment petclinicmbtest --apply --patch

  # Also useful before re-learning to clean up noise first:
  python noise_learner.py --environment petclinicmbtest --apply --patch
  python trace_fingerprint.py --environment petclinicmbtest learn --reset

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

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

# Minimum watch_hits to be considered a noise candidate
MIN_WATCH_HITS = 3
# Minimum number of fingerprints sharing a pattern to suggest it
MIN_PATTERN_SUPPORT = 1

NOISE_PATTERNS_PATH = Path(os.environ.get("NOISE_PATTERNS_PATH", "./noise_patterns.json"))
TF_PATH             = Path(__file__).parent / "trace_fingerprint.py"


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


def _load_existing_noise_patterns() -> list[str]:
    """Load previously saved custom noise patterns."""
    if NOISE_PATTERNS_PATH.exists():
        try:
            data = json.loads(NOISE_PATTERNS_PATH.read_text())
            return data.get("patterns", [])
        except Exception:
            pass
    return []


def _load_builtin_noise_patterns() -> list[str]:
    """Read the hardcoded NOISE_PATTERNS from trace_fingerprint.py."""
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        from trace_fingerprint import NOISE_PATTERNS
        return list(NOISE_PATTERNS)
    except ImportError:
        return []


# ── Pattern extraction ────────────────────────────────────────────────────────

def _extract_op_path(root_op: str) -> str:
    """Extract the operation part from 'service:operation'."""
    return root_op.split(":", 1)[1] if ":" in root_op else root_op


def _candidate_substrings(op: str) -> list[str]:
    """
    Generate candidate noise pattern substrings from an operation string.
    We try:
      - URL path segments (if op looks like a URL path)
      - The full operation (for non-URL ops like 'HealthCheck', 'Ping')
      - First two path segments
    """
    candidates = []

    # URL-style paths
    if "/" in op:
        parts = [p for p in op.split("/") if p]
        # First segment as /<segment>/
        if parts:
            candidates.append(f"/{parts[0]}/")
        # First two segments as /<a>/<b>
        if len(parts) >= 2:
            candidates.append(f"/{parts[0]}/{parts[1]}")
        # Full path up to first param (strip /{id} and similar)
        clean = re.sub(r"/\{[^}]+\}", "/{*}", op)
        clean = re.sub(r"/[0-9]+", "/{*}", clean)
        if clean != op and len(clean) > 3:
            candidates.append(clean)
    else:
        # Non-URL op — use lowercased op as pattern
        lo = op.lower()
        for kw in ["health", "ping", "ready", "live", "heartbeat", "status",
                   "register", "registry", "eureka", "consul", "discover"]:
            if kw in lo:
                candidates.append(kw)
        if not candidates and len(op) > 3:
            candidates.append(op)

    return candidates


def find_noise_candidates(baseline: dict) -> list[dict]:
    """
    Identify fingerprints that look like noise:
    - auto_promoted = True (repeatedly fired, always promoted)
    - OR watch_hits >= MIN_WATCH_HITS (high frequency, never alerted)
    """
    fps = baseline.get("fingerprints", {})
    candidates = []

    for h, v in fps.items():
        root_op   = v.get("root_op", "")
        hits      = v.get("watch_hits", 0)
        promoted  = v.get("auto_promoted", False)
        path      = v.get("path", "")
        services  = v.get("services", [])

        is_noise = promoted or hits >= MIN_WATCH_HITS
        if not is_noise:
            continue

        op = _extract_op_path(root_op)
        candidates.append({
            "hash":        h,
            "root_op":     root_op,
            "op":          op,
            "watch_hits":  hits,
            "auto_promoted": promoted,
            "services":    services,
            "path_snippet": path[:120],
        })

    return sorted(candidates, key=lambda c: (-c["watch_hits"], c["root_op"]))


def compute_pattern_suggestions(candidates: list[dict],
                                 builtin_patterns: list[str],
                                 existing_custom: list[str]) -> list[dict]:
    """
    For each candidate, extract substrings that would suppress it.
    Group by pattern, count how many candidates each covers.
    Return ranked suggestions.
    """
    all_known = set(builtin_patterns) | set(existing_custom)
    pattern_covers: dict[str, list[dict]] = defaultdict(list)

    for cand in candidates:
        subs = _candidate_substrings(cand["op"])
        for sub in subs:
            sub_lo = sub.lower()
            # Skip if already in builtin or existing custom patterns
            if any(sub_lo in p.lower() or p.lower() in sub_lo for p in all_known):
                continue
            pattern_covers[sub].append(cand)

    suggestions = []
    seen_roots: set[str] = set()
    for pattern, covered in sorted(pattern_covers.items(),
                                    key=lambda x: -len(x[1])):
        # De-duplicate: skip if a shorter pattern already covers same candidates
        root_set = frozenset(c["root_op"] for c in covered)
        if root_set in seen_roots:
            continue
        seen_roots.add(root_set)

        total_hits = sum(c["watch_hits"] for c in covered)
        suggestions.append({
            "pattern":     pattern,
            "covers":      len(covered),
            "total_hits":  total_hits,
            "examples":    [c["root_op"] for c in covered[:3]],
            "auto_promoted_count": sum(1 for c in covered if c["auto_promoted"]),
        })

    return sorted(suggestions, key=lambda s: (-s["covers"], -s["total_hits"]))


# ── Apply ─────────────────────────────────────────────────────────────────────

def save_noise_patterns(patterns: list[str]) -> None:
    existing = _load_existing_noise_patterns()
    merged   = sorted(set(existing) | set(patterns))
    data = {
        "patterns": merged,
        "description": (
            "Application-specific noise patterns learned by noise_learner.py. "
            "These are loaded by trace_fingerprint.py at startup to supplement "
            "the built-in NOISE_PATTERNS list."
        ),
    }
    NOISE_PATTERNS_PATH.write_text(json.dumps(data, indent=2))
    print(f"  → Saved {len(merged)} patterns to {NOISE_PATTERNS_PATH}")


def patch_trace_fingerprint(new_patterns: list[str]) -> bool:
    """
    Inject new patterns into trace_fingerprint.py's NOISE_PATTERNS section.
    Inserts a comment + new patterns at the end of HEALTHCHECK_PATTERNS.
    """
    if not TF_PATH.exists():
        print(f"  [warn] trace_fingerprint.py not found at {TF_PATH}", file=sys.stderr)
        return False

    content = TF_PATH.read_text()
    marker  = "NOISE_PATTERNS: list[str] = REGISTRY_PATTERNS + HEALTHCHECK_PATTERNS"

    if marker not in content:
        print(f"  [warn] Could not find insertion point in trace_fingerprint.py",
              file=sys.stderr)
        return False

    # Check which patterns are already present
    truly_new = [p for p in new_patterns if f'"{p}"' not in content]
    if not truly_new:
        print("  trace_fingerprint.py already contains all suggested patterns.")
        return True

    # Build insertion: add to HEALTHCHECK_PATTERNS before the NOISE_PATTERNS line
    insert_before = marker
    lines_to_add  = "\n".join(f'    "{p}",  # learned by noise_learner.py'
                               for p in truly_new)
    injection     = f"\n# App-specific learned patterns:\nAPP_NOISE_PATTERNS: list[str] = [\n{lines_to_add}\n]\n\n"

    new_marker = "NOISE_PATTERNS: list[str] = REGISTRY_PATTERNS + HEALTHCHECK_PATTERNS + APP_NOISE_PATTERNS"

    if "APP_NOISE_PATTERNS" not in content:
        content = content.replace(
            marker,
            injection + new_marker,
        )
    else:
        # Already patched — just add to APP_NOISE_PATTERNS block
        # Find the closing ] of APP_NOISE_PATTERNS
        ap_start = content.index("APP_NOISE_PATTERNS: list[str] = [")
        ap_end   = content.index("]", ap_start)
        new_lines = "\n".join(f'    "{p}",  # learned by noise_learner.py'
                               for p in truly_new)
        content = content[:ap_end] + f"\n{new_lines}\n" + content[ap_end:]

    TF_PATH.write_text(content)
    print(f"  → Patched trace_fingerprint.py with {len(truly_new)} new pattern(s)")
    return True


# ── Report ────────────────────────────────────────────────────────────────────

def print_report(candidates: list[dict], suggestions: list[dict],
                  existing_custom: list[str]) -> None:
    print(f"\n{'='*65}")
    print(f"NOISE PATTERN ANALYSIS")
    print(f"{'='*65}")

    if not candidates:
        print("\n  No noise candidates found — baseline looks clean.")
        return

    print(f"\n  Noise candidates ({len(candidates)} fingerprints):")
    for c in candidates:
        reason = "auto-promoted" if c["auto_promoted"] else f"watch_hits={c['watch_hits']}"
        print(f"    [{reason:>16}]  {c['root_op']}")

    if existing_custom:
        print(f"\n  Existing custom patterns ({len(existing_custom)}): "
              f"{', '.join(existing_custom[:5])}" +
              (f" ..." if len(existing_custom) > 5 else ""))

    if not suggestions:
        print("\n  No new pattern suggestions — all noise already covered.")
        return

    print(f"\n  Suggested noise patterns ({len(suggestions)}):")
    for i, s in enumerate(suggestions, 1):
        print(f"\n  {i}. \"{s['pattern']}\"")
        print(f"     Covers {s['covers']} fingerprint(s), "
              f"{s['total_hits']} total watch_hits, "
              f"{s['auto_promoted_count']} auto-promoted")
        for ex in s["examples"]:
            print(f"     e.g. {ex}")

    print(f"\n  To apply:  python noise_learner.py --environment <env> --apply")
    print(f"  To patch trace_fingerprint.py:  add --patch")
    print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Noise Pattern Learner — discovers app-specific noise from auto-promoted fingerprints"
    )
    parser.add_argument("--environment", default=None)
    parser.add_argument("--apply",  action="store_true",
                        help="Write suggested patterns to noise_patterns.json")
    parser.add_argument("--patch",  action="store_true",
                        help="Also patch trace_fingerprint.py directly (requires --apply)")
    parser.add_argument("--json",   action="store_true")
    args = parser.parse_args()

    print(f"[noise-learner] env={args.environment or 'all'}")

    baseline         = _load_baseline(args.environment)
    builtin_patterns = _load_builtin_noise_patterns()
    existing_custom  = _load_existing_noise_patterns()

    candidates  = find_noise_candidates(baseline)
    suggestions = compute_pattern_suggestions(candidates, builtin_patterns, existing_custom)

    if args.json:
        print(json.dumps({
            "candidates":  candidates,
            "suggestions": suggestions,
        }, indent=2))
        sys.exit(0)

    print_report(candidates, suggestions, existing_custom)

    if args.apply and suggestions:
        new_patterns = [s["pattern"] for s in suggestions]
        save_noise_patterns(new_patterns)
        if args.patch:
            patch_trace_fingerprint(new_patterns)
        print(f"  Done. Re-run learn to rebuild baseline without these patterns.")
    elif args.apply:
        print("  Nothing to apply.")


if __name__ == "__main__":
    main()
