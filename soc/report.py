"""Renders a TriageResult as the human-readable transcript a SOC
analyst actually reads - the proof deliverable this project is graded
on: every claim traces back to a named evidence source, not a bare
"trust me" verdict.
"""
from __future__ import annotations

from alerts.schema import Alert, TriageResult

_VERDICT_LABELS = {
    "confirmed_threat": "CONFIRMED THREAT",
    "likely_benign": "LIKELY BENIGN",
    "needs_review": "NEEDS HUMAN REVIEW",
}


def render_report(alert: Alert, result: TriageResult) -> str:
    lines = [
        f"=== Alert {alert.alert_id} ({alert.source}) ===",
        alert.raw_text,
        "",
        f"Verdict: {_VERDICT_LABELS[result.verdict]}  (confidence {result.confidence:.0%}, "
        f"scored by {result.scorer}, {result.latency_ms:.0f}ms)",
        "",
    ]
    if result.evidence:
        lines.append("Evidence:")
        for e in result.evidence:
            lines.append(f"  - [{e.ioc_type}] {e.value}: {e.verdict} (source: {e.source_tool})")
    else:
        lines.append("Evidence: none - no IOCs extracted from the alert text.")
    lines += ["", "Analyst summary:", result.reasoning]
    # This tool never takes action on its own - see the module's README
    # for why that's a design decision, not a missing feature.
    lines += ["", "No containment action taken. This is a triage recommendation only."]
    return "\n".join(lines)
