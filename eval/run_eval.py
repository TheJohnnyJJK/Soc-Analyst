"""Grades soc.triage.triage() against alerts/golden_alerts.json.

Requires ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY to actually resolve
the IP/domain/hash cases for real (NVD needs no key). Without them, the
IP/domain/hash cases will error out rather than silently pass - this
run is meant to prove the real pipeline works end to end, not to fake
a green result offline. See README for how to get free keys.

    python -m eval.run_eval

Writes eval/results.json (per-case), same "commit the honest number,
don't leave a placeholder" convention as every other eval harness in
this portfolio.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from alerts.schema import load_golden_alerts
from soc.triage import triage

_RESULTS_PATH = Path(__file__).resolve().parent / "results.json"


def run() -> dict:
    """Runs every golden case through triage() (correlate=False, so
    this never touches the audit store - see soc/triage.py) and
    returns the same summary dict that gets written to results.json."""
    cases = load_golden_alerts()
    records: list[dict[str, Any]] = []
    for case in cases:
        started = time.perf_counter()
        try:
            result = triage(case.alert)
            error = None
            passed = result.verdict == case.expected_verdict
        except Exception as exc:  # noqa: BLE001 - a hard failure is its own finding, not a crash
            result = None
            error = str(exc)
            passed = False
        records.append(
            {
                "alert_id": case.alert.alert_id,
                "expected": case.expected_verdict,
                "got": result.verdict if result else None,
                "passed": passed,
                "confidence": result.confidence if result else None,
                "scorer": result.scorer if result else None,
                "error": error,
                "latency_ms": (time.perf_counter() - started) * 1000,
            }
        )

    passed_count = sum(bool(r["passed"]) for r in records)
    total_latency = sum(float(r["latency_ms"]) for r in records)
    summary = {
        "total": len(records),
        "passed": passed_count,
        "accuracy": passed_count / len(records) if records else 0.0,
        "avg_latency_ms": total_latency / len(records) if records else 0.0,
        "cases": records,
    }
    _RESULTS_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    """CLI entry point - runs the eval, prints the score, and lists
    every miss with what was expected vs. what actually came back."""
    summary = run()
    print(f"{summary['passed']}/{summary['total']} correct ({summary['accuracy']:.1%})")
    print(f"avg latency: {summary['avg_latency_ms']:.0f}ms")
    for r in summary["cases"]:
        if not r["passed"]:
            print(
                f"  MISS [{r['alert_id']}] expected={r['expected']} "
                f"got={r['got']} error={r['error']}"
            )


if __name__ == "__main__":
    main()
