#!/usr/bin/env python3
"""
baseline.py — Baseline store for the unified agent.

Wraps trace + error baseline files with a clean API:
  - load / save
  - summarize (for Claude context — small, no raw hashes)
  - health check (stale? contaminated? empty?)
  - learn (re-learn from live traces)
  - promote (pending → confirmed)

No Splunk API calls here except what's needed for learn().
Imports from trace_fingerprint and error_fingerprint for the heavy lifting.
"""

import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Paths ─────────────────────────────────────────────────────────────────────

_SCRIPT_DIR  = Path(__file__).parent
_CORE_DIR    = _SCRIPT_DIR / "core"
_DATA_DIR    = _SCRIPT_DIR / "data"

_INCIDENT_ERROR_TYPES = {
    "503", "502", "504", "java.net.ConnectException",
    "java.net.SocketTimeoutException", "CannotCreateTransactionException",
    "Connection refused", "ECONNREFUSED",
}

STALE_DAYS = 7   # baseline older than this is flagged stale


# ── BaselineStore ─────────────────────────────────────────────────────────────

class BaselineStore:
    """
    Unified access to trace + error baselines for one environment.

    Usage:
        bs = BaselineStore("petclinicmbtest")
        summary = bs.summarize()   # small dict safe to pass to Claude
        health  = bs.health()      # list of health issues
    """

    def __init__(self, environment: str | None):
        self.environment = environment
        self._trace_path = self._find_path("baseline")
        self._error_path = self._find_path("error_baseline")
        self._trace: dict = {}
        self._error: dict = {}
        self._load()

    def _find_path(self, prefix: str) -> Path:
        if self.environment:
            p = _DATA_DIR / f"{prefix}.{self.environment}.json"
            if p.exists():
                return p
        p = _DATA_DIR / f"{prefix}.json"
        return p

    def _load(self) -> None:
        self._trace = self._read(self._trace_path)
        self._error = self._read(self._error_path)

    def reload(self) -> None:
        self._load()

    @staticmethod
    def _read(path: Path) -> dict:
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                pass
        return {}

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def trace_fingerprints(self) -> dict:
        return self._trace.get("fingerprints", {})

    @property
    def error_signatures(self) -> dict:
        return self._error.get("signatures", {})

    def summarize(self) -> dict:
        """
        Return a compact summary safe to include in a Claude prompt.
        No raw hashes — just counts, service names, health indicators.
        """
        fps = self.trace_fingerprints
        sigs = self.error_signatures

        # Per-service fingerprint counts
        by_service: dict[str, int] = defaultdict(int)
        for fp in fps.values():
            svc = fp.get("root_op", "").split(":")[0] if ":" in fp.get("root_op", "") else ""
            if svc:
                by_service[svc] += 1

        # Per-service error signature counts
        err_by_service: dict[str, int] = defaultdict(int)
        contaminated: list[str] = []
        for sig in sigs.values():
            svc = sig.get("service", "")
            err_by_service[svc] += 1
            if any(art.lower() in sig.get("error_type", "").lower()
                   for art in _INCIDENT_ERROR_TYPES):
                contaminated.append(svc)

        # Staleness
        learned_at = self._trace.get("learned_at") or self._trace.get("updated_at")
        stale = False
        age_days = None
        if learned_at:
            try:
                dt = datetime.fromisoformat(learned_at)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - dt).days
                stale = age_days > STALE_DAYS
            except Exception:
                pass

        # Pending promotions
        pending = [h for h, fp in fps.items() if not fp.get("promoted", True)]

        return {
            "trace_fingerprints_total": len(fps),
            "by_service":               dict(by_service),
            "error_signatures_total":   len(sigs),
            "error_by_service":         dict(err_by_service),
            "contaminated_services":    list(set(contaminated)),
            "pending_promotions":       len(pending),
            "learned_at":               learned_at,
            "age_days":                 age_days,
            "stale":                    stale,
        }

    def health(self) -> list[dict]:
        """
        Return a list of health issues. Empty list = healthy.
        Each issue: {"severity": "warn|critical", "issue": "...", "service": "..."}
        """
        issues = []
        summary = self.summarize()

        if summary["stale"]:
            issues.append({
                "severity": "warn",
                "issue":    f"Trace baseline is {summary['age_days']} days old (>{STALE_DAYS}d)",
                "service":  None,
            })

        if summary["trace_fingerprints_total"] == 0:
            issues.append({
                "severity": "critical",
                "issue":    "Trace baseline is empty — no fingerprints learned yet",
                "service":  None,
            })

        for svc in summary["contaminated_services"]:
            issues.append({
                "severity": "critical",
                "issue":    f"Error baseline contaminated with incident artifacts",
                "service":  svc,
            })

        if summary["pending_promotions"] > 5:
            issues.append({
                "severity": "warn",
                "issue":    f"{summary['pending_promotions']} fingerprints pending promotion",
                "service":  None,
            })

        return issues

    def learn(self, service: str | None = None,
              window_minutes: int = 240, reset: bool = False) -> bool:
        """
        Re-learn the trace baseline by delegating to trace_fingerprint.py.
        Returns True on success.
        """
        import subprocess
        import sys
        cmd = [
            sys.executable, str(_CORE_DIR / "trace_fingerprint.py"),
            "learn", f"--window-minutes={window_minutes}",
        ]
        if self.environment:
            cmd += ["--environment", self.environment]
        if reset:
            cmd.append("--reset")
        if service:
            cmd += ["--service", service]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                self.reload()
                return True
            return False
        except Exception:
            return False

    def promote(self, hashes: list[str] | None = None) -> int:
        """
        Promote pending fingerprints. Returns count promoted.
        Delegates to trace_fingerprint.py promote.
        """
        import subprocess
        import sys
        cmd = [sys.executable, str(_CORE_DIR / "trace_fingerprint.py"), "promote"]
        if self.environment:
            cmd += ["--environment", self.environment]
        if hashes:
            cmd += hashes
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            self.reload()
            # Count promoted from stdout
            for line in result.stdout.splitlines():
                if "promoted" in line.lower():
                    parts = [p for p in line.split() if p.isdigit()]
                    if parts:
                        return int(parts[0])
            return 0
        except Exception:
            return 0
