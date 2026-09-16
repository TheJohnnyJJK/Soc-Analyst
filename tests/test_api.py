"""FastAPI TestClient hitting the real routes - offline, gather_evidence
mocked so no real network call happens. Mirrors Lead Router's
tests/test_api.py conventions (temp-file DB per test, auth off by default)."""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from mcp_threat_intel.server import MissingApiKeyError

from alerts.schema import Evidence


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test_soc.db"
    monkeypatch.delenv("SOC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    from soc import store
    store.DB_PATH = str(db_path)

    from soc import triage as triage_module

    def fake_gather_evidence(iocs):
        if not iocs.get("ip"):
            return []
        return [Evidence(ioc_type="ip", value="1.2.3.4", verdict="malicious", source_tool="test")]

    monkeypatch.setattr(triage_module, "gather_evidence", fake_gather_evidence)

    from soc.api import app
    with TestClient(app) as test_client:
        yield test_client


def _post_alert(client, alert_id=None, raw_text="connection from 1.2.3.4", source="IDS"):
    body = {"source": source, "raw_text": raw_text}
    if alert_id:
        body["alert_id"] = alert_id
    return client.post("/alerts", json=body)


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_create_alert_returns_a_stored_record(client):
    resp = client.post(
        "/alerts", json={"source": "IDS", "raw_text": "connection from 1.2.3.4"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["verdict"] == "confirmed_threat"
    assert body["status"] == "open"
    assert "id" in body
    assert body["alert"]["alert_id"]  # auto-generated since none was supplied


def test_create_alert_honors_a_supplied_alert_id(client):
    resp = _post_alert(client, alert_id="custom-01")
    assert resp.json()["alert"]["alert_id"] == "custom-01"


def test_get_alert_by_id(client):
    created = _post_alert(client).json()
    resp = client.get(f"/alerts/{created['id']}")
    assert resp.status_code == 200
    assert resp.json()["id"] == created["id"]


def test_get_alert_missing_id_is_404(client):
    resp = client.get("/alerts/99999")
    assert resp.status_code == 404


def test_list_alerts_most_recent_first(client):
    _post_alert(client, alert_id="a-01")
    _post_alert(client, alert_id="a-02", raw_text="no iocs here")
    resp = client.get("/alerts")
    assert resp.status_code == 200
    ids = [r["alert"]["alert_id"] for r in resp.json()]
    assert ids == ["a-02", "a-01"]


def test_list_alerts_filters_by_verdict(client):
    _post_alert(client, alert_id="a-01")
    _post_alert(client, alert_id="a-02", raw_text="no iocs here")
    resp = client.get("/alerts", params={"verdict": "confirmed_threat"})
    ids = [r["alert"]["alert_id"] for r in resp.json()]
    assert ids == ["a-01"]


def test_action_alert_approves_a_record(client):
    created = _post_alert(client).json()
    resp = client.post(
        f"/alerts/{created['id']}/action",
        json={"status": "approved", "actioned_by": "analyst1", "note": "confirmed real"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "approved"
    assert body["actioned_by"] == "analyst1"
    assert body["actioned_note"] == "confirmed real"


def test_action_alert_missing_id_is_404(client):
    body = {"status": "approved", "actioned_by": "analyst1"}
    resp = client.post("/alerts/99999/action", json=body)
    assert resp.status_code == 404


def test_repeat_sighting_escalates_via_the_real_http_flow(client, monkeypatch):
    """End-to-end proof of the correlation feature: the same suspicious
    IOC arriving in a second, unrelated alert gets escalated - exercised
    through the actual API, not just the unit-tested _correlate()."""
    from soc import triage as triage_module

    def suspicious_ip_evidence(iocs):
        if not iocs.get("ip"):
            return []
        return [Evidence(ioc_type="ip", value="5.6.7.8", verdict="suspicious", source_tool="test")]

    monkeypatch.setattr(triage_module, "gather_evidence", suspicious_ip_evidence)

    first = _post_alert(client, alert_id="s-01", raw_text="connection from 5.6.7.8").json()
    assert first["result"]["verdict"] == "needs_review"

    second = _post_alert(client, alert_id="s-02", raw_text="connection from 5.6.7.8").json()
    assert second["result"]["verdict"] == "confirmed_threat"
    assert "s-01" in second["result"]["correlation"]


def test_create_alert_returns_503_when_a_threat_intel_key_is_missing(client, monkeypatch):
    from soc import triage as triage_module

    def boom(iocs):
        raise MissingApiKeyError("ABUSEIPDB_API_KEY is not set - see .env.example")

    monkeypatch.setattr(triage_module, "gather_evidence", boom)
    resp = _post_alert(client)
    assert resp.status_code == 503
    assert "ABUSEIPDB_API_KEY" in resp.json()["detail"]


def test_create_alert_returns_502_on_a_threat_intel_http_error(client, monkeypatch):
    from soc import triage as triage_module

    def boom(iocs):
        request = httpx.Request("GET", "https://example.com")
        raise httpx.ConnectTimeout("timed out", request=request)

    monkeypatch.setattr(triage_module, "gather_evidence", boom)
    resp = _post_alert(client)
    assert resp.status_code == 502


def test_auth_required_when_soc_api_key_is_set(client, monkeypatch):
    monkeypatch.setenv("SOC_API_KEY", "secret")
    resp = client.post("/alerts", json={"source": "IDS", "raw_text": "connection from 1.2.3.4"})
    assert resp.status_code == 401

    resp = client.post(
        "/alerts",
        json={"source": "IDS", "raw_text": "connection from 1.2.3.4"},
        headers={"X-API-Key": "secret"},
    )
    assert resp.status_code == 200
