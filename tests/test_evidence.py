from __future__ import annotations

import httpx
import pytest

from soc import evidence


def test_ip_evidence_uses_abuseipdb_verdict(monkeypatch):
    monkeypatch.setattr(
        evidence,
        "check_ip_reputation",
        lambda ip: {"ip": ip, "abuse_confidence_score": 100, "verdict": "malicious"},
    )
    result = evidence.gather_evidence({"ip": ["1.2.3.4"], "domain": [], "hash": [], "cve": []})
    assert len(result) == 1
    assert result[0].ioc_type == "ip"
    assert result[0].verdict == "malicious"
    assert result[0].source_tool == "abuseipdb"


def test_domain_evidence_uses_virustotal_verdict(monkeypatch):
    monkeypatch.setattr(
        evidence,
        "check_domain_reputation",
        lambda domain: {"domain": domain, "malicious": 5, "verdict": "malicious"},
    )
    result = evidence.gather_evidence({"ip": [], "domain": ["evil.example"], "hash": [], "cve": []})
    assert result[0].verdict == "malicious"
    assert result[0].source_tool == "virustotal"


def test_domain_not_found_becomes_no_data(monkeypatch):
    def raise_404(domain):
        request = httpx.Request("GET", "https://virustotal.example")
        response = httpx.Response(404, request=request)
        raise httpx.HTTPStatusError("not found", request=request, response=response)

    monkeypatch.setattr(evidence, "check_domain_reputation", raise_404)
    result = evidence.gather_evidence(
        {"ip": [], "domain": ["never-seen.example"], "hash": [], "cve": []}
    )
    assert result[0].verdict == "no_data"


def test_domain_other_http_errors_are_not_swallowed(monkeypatch):
    def raise_500(domain):
        request = httpx.Request("GET", "https://virustotal.example")
        response = httpx.Response(500, request=request)
        raise httpx.HTTPStatusError("server error", request=request, response=response)

    monkeypatch.setattr(evidence, "check_domain_reputation", raise_500)
    with pytest.raises(httpx.HTTPStatusError):
        evidence.gather_evidence({"ip": [], "domain": ["x.example"], "hash": [], "cve": []})


def test_hash_not_found_becomes_no_data(monkeypatch):
    def raise_404(file_hash):
        request = httpx.Request("GET", "https://virustotal.example")
        response = httpx.Response(404, request=request)
        raise httpx.HTTPStatusError("not found", request=request, response=response)

    monkeypatch.setattr(evidence, "check_file_hash", raise_404)
    result = evidence.gather_evidence({"ip": [], "domain": [], "hash": ["deadbeef"], "cve": []})
    assert result[0].verdict == "no_data"


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("CRITICAL", "malicious"), ("HIGH", "malicious"), ("MEDIUM", "suspicious"), ("LOW", "clean")],
)
def test_cve_severity_maps_to_a_verdict(monkeypatch, severity, expected):
    monkeypatch.setattr(
        evidence,
        "get_cve",
        lambda cve_id: {"id": cve_id, "base_severity": severity, "base_score": 5.0},
    )
    result = evidence.gather_evidence(
        {"ip": [], "domain": [], "hash": [], "cve": ["CVE-2024-0000"]}
    )
    assert result[0].verdict == expected


def test_cve_not_found_becomes_no_data(monkeypatch):
    monkeypatch.setattr(evidence, "get_cve", lambda cve_id: None)
    result = evidence.gather_evidence(
        {"ip": [], "domain": [], "hash": [], "cve": ["CVE-0000-0000"]}
    )
    assert result[0].verdict == "no_data"


def test_gathers_evidence_for_multiple_iocs_in_order(monkeypatch):
    monkeypatch.setattr(evidence, "check_ip_reputation", lambda ip: {"verdict": "clean"})
    monkeypatch.setattr(evidence, "check_domain_reputation", lambda d: {"verdict": "malicious"})
    result = evidence.gather_evidence(
        {"ip": ["1.2.3.4"], "domain": ["evil.example"], "hash": [], "cve": []}
    )
    assert [e.ioc_type for e in result] == ["ip", "domain"]
