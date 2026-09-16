from __future__ import annotations

from alerts.schema import Alert, Evidence
from soc import triage


def _ev(ioc_type, value, verdict, **detail) -> Evidence:
    return Evidence(
        ioc_type=ioc_type, value=value, verdict=verdict, source_tool="test", detail=detail
    )


def test_classify_no_evidence_needs_review():
    verdict, confidence = triage.classify([])
    assert verdict == "needs_review"
    assert confidence < 0.5


def test_classify_any_malicious_is_confirmed_threat():
    evidence = [_ev("ip", "1.2.3.4", "clean"), _ev("domain", "x.example", "malicious")]
    verdict, confidence = triage.classify(evidence)
    assert verdict == "confirmed_threat"
    assert confidence >= 0.7


def test_classify_more_malicious_signals_raise_confidence():
    one = triage.classify([_ev("ip", "1.2.3.4", "malicious")])
    two = triage.classify(
        [_ev("ip", "1.2.3.4", "malicious"), _ev("domain", "x.example", "malicious")]
    )
    assert two[1] > one[1]


def test_classify_no_data_without_malicious_needs_review():
    verdict, _ = triage.classify([_ev("domain", "x.example", "no_data")])
    assert verdict == "needs_review"


def test_classify_suspicious_without_malicious_or_no_data_needs_review():
    verdict, _ = triage.classify([_ev("cve", "CVE-2024-0000", "suspicious")])
    assert verdict == "needs_review"


def test_classify_all_clean_is_likely_benign():
    evidence = [_ev("ip", "8.8.8.8", "clean"), _ev("domain", "wikipedia.org", "clean")]
    verdict, confidence = triage.classify(evidence)
    assert verdict == "likely_benign"
    assert confidence > 0.5


def test_malicious_takes_precedence_over_no_data_and_suspicious():
    evidence = [
        _ev("ip", "1.2.3.4", "malicious"),
        _ev("domain", "x.example", "no_data"),
        _ev("cve", "CVE-2024-0000", "suspicious"),
    ]
    verdict, _ = triage.classify(evidence)
    assert verdict == "confirmed_threat"


def test_template_reasoning_cites_every_evidence_entry():
    evidence = [_ev("ip", "1.2.3.4", "malicious")]
    text = triage.template_reasoning(_alert(), evidence, "confirmed_threat")
    assert "1.2.3.4" in text
    assert "malicious" in text


def test_template_reasoning_with_no_evidence_says_so():
    text = triage.template_reasoning(_alert(), [], "needs_review")
    assert "no indicators of compromise" in text.lower()


def test_triage_falls_back_to_heuristic_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(triage, "gather_evidence", lambda iocs: [_ev("ip", "1.2.3.4", "malicious")])
    result = triage.triage(_alert(raw_text="contacted 1.2.3.4"))
    assert result.scorer == "heuristic"
    assert result.verdict == "confirmed_threat"


def test_triage_with_no_iocs_never_calls_gather_evidence(monkeypatch):
    def boom(iocs):
        raise AssertionError("should not be called when there are no IOCs")

    monkeypatch.setattr(triage, "gather_evidence", boom)
    result = triage.triage(_alert(raw_text="something felt off, no details"))
    assert result.verdict == "needs_review"
    assert result.evidence == []


def test_triage_falls_back_to_heuristic_when_llm_call_fails(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "secret")
    monkeypatch.setattr(triage, "gather_evidence", lambda iocs: [_ev("ip", "1.2.3.4", "malicious")])

    def boom(alert, evidence, verdict):
        raise RuntimeError("api unreachable")

    monkeypatch.setattr(triage, "llm_reasoning", boom)
    result = triage.triage(_alert(raw_text="contacted 1.2.3.4"))
    assert result.scorer == "heuristic"
    assert result.verdict == "confirmed_threat"


def _alert(raw_text: str = "contacted 1.2.3.4") -> Alert:
    return Alert(alert_id="t-01", source="test", raw_text=raw_text)
