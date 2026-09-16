from __future__ import annotations

from alerts.schema import Alert, Evidence, TriageResult
from soc.report import render_report


def test_render_report_includes_verdict_evidence_and_no_action_disclaimer():
    alert = Alert(alert_id="alert-01", source="IDS", raw_text="brute force from 1.2.3.4")
    result = TriageResult(
        alert_id="alert-01",
        verdict="confirmed_threat",
        confidence=0.9,
        reasoning="Verdict: confirmed_threat. ip 1.2.3.4: malicious per abuseipdb.",
        evidence=[
            Evidence(ioc_type="ip", value="1.2.3.4", verdict="malicious", source_tool="abuseipdb")
        ],
        scorer="heuristic",
        latency_ms=12.3,
    )
    report = render_report(alert, result)
    assert "CONFIRMED THREAT" in report
    assert "1.2.3.4" in report
    assert "malicious" in report
    assert "No containment action taken" in report


def test_render_report_with_no_evidence_says_so():
    alert = Alert(alert_id="alert-08", source="SOC-note", raw_text="something felt off")
    result = TriageResult(
        alert_id="alert-08",
        verdict="needs_review",
        confidence=0.3,
        reasoning="No indicators of compromise could be extracted.",
        evidence=[],
        scorer="heuristic",
        latency_ms=0.5,
    )
    report = render_report(alert, result)
    assert "no IOCs extracted" in report
