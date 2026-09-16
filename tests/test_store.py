from __future__ import annotations

import pytest

from alerts.schema import Alert, Evidence, TriageResult
from soc import store


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "test_soc.db"))
    store.init_db()


def _alert(alert_id: str = "a-01") -> Alert:
    return Alert(alert_id=alert_id, source="test", raw_text="contacted 1.2.3.4")


def _result(alert_id: str = "a-01", verdict: str = "confirmed_threat") -> TriageResult:
    return TriageResult(
        alert_id=alert_id,
        verdict=verdict,
        confidence=0.9,
        reasoning="test reasoning",
        evidence=[
            Evidence(ioc_type="ip", value="1.2.3.4", verdict="malicious", source_tool="test")
        ],
        scorer="heuristic",
        latency_ms=1.0,
    )


def test_insert_and_get_round_trips_every_field():
    record_id = store.insert_triage(_alert(), _result())
    record = store.get_record(record_id)
    assert record is not None
    assert record.alert.alert_id == "a-01"
    assert record.result.verdict == "confirmed_threat"
    assert record.result.evidence[0].value == "1.2.3.4"
    assert record.status == "open"
    assert record.actioned_by is None


def test_get_record_returns_none_for_a_missing_id():
    assert store.get_record(999) is None


def test_list_records_most_recent_first():
    store.insert_triage(_alert("a-01"), _result("a-01"))
    store.insert_triage(_alert("a-02"), _result("a-02"))
    records = store.list_records()
    assert [r.alert.alert_id for r in records] == ["a-02", "a-01"]


def test_list_records_filters_by_verdict_and_status():
    store.insert_triage(_alert("a-01"), _result("a-01", verdict="confirmed_threat"))
    store.insert_triage(_alert("a-02"), _result("a-02", verdict="likely_benign"))
    threats = store.list_records(verdict="confirmed_threat")
    assert [r.alert.alert_id for r in threats] == ["a-01"]

    record_id = store.insert_triage(_alert("a-03"), _result("a-03"))
    store.record_action(record_id, status="approved", actioned_by="analyst1")
    approved = store.list_records(status="approved")
    assert [r.alert.alert_id for r in approved] == ["a-03"]


def test_record_action_sets_actioned_fields():
    record_id = store.insert_triage(_alert(), _result())
    updated = store.record_action(
        record_id, status="dismissed", actioned_by="analyst1", note="false positive"
    )
    assert updated is not None
    assert updated.status == "dismissed"
    assert updated.actioned_by == "analyst1"
    assert updated.actioned_note == "false positive"
    assert updated.actioned_at is not None


def test_record_action_on_a_missing_id_returns_none():
    assert store.record_action(999, status="approved", actioned_by="analyst1") is None


def test_recent_sightings_finds_the_same_ioc_from_a_different_alert():
    store.insert_triage(_alert("a-01"), _result("a-01"))
    hits = store.recent_sightings("ip", "1.2.3.4", within_hours=24, exclude_alert_id="a-02")
    assert len(hits) == 1
    assert hits[0]["alert_id"] == "a-01"
    assert hits[0]["verdict"] == "malicious"


def test_recent_sightings_excludes_the_same_alert_id():
    store.insert_triage(_alert("a-01"), _result("a-01"))
    hits = store.recent_sightings("ip", "1.2.3.4", within_hours=24, exclude_alert_id="a-01")
    assert hits == []


def test_recent_sightings_finds_nothing_for_an_unrelated_ioc():
    store.insert_triage(_alert("a-01"), _result("a-01"))
    hits = store.recent_sightings("ip", "9.9.9.9", within_hours=24, exclude_alert_id="a-02")
    assert hits == []


def test_recent_sightings_respects_the_time_window():
    store.insert_triage(_alert("a-01"), _result("a-01"))
    hits = store.recent_sightings("ip", "1.2.3.4", within_hours=0, exclude_alert_id="a-02")
    assert hits == []


def test_insert_triage_is_idempotent_on_alert_id():
    first_id = store.insert_triage(_alert("a-01"), _result("a-01"))
    second_id = store.insert_triage(_alert("a-01"), _result("a-01"))
    assert first_id == second_id
    assert len(store.list_records()) == 1


def test_get_record_by_alert_id():
    store.insert_triage(_alert("a-01"), _result("a-01"))
    record = store.get_record_by_alert_id("a-01")
    assert record is not None
    assert record.alert.alert_id == "a-01"


def test_get_record_by_alert_id_returns_none_when_missing():
    assert store.get_record_by_alert_id("no-such-alert") is None


def test_reset_db_clears_all_records(monkeypatch, tmp_path):
    store.insert_triage(_alert(), _result())
    assert store.list_records() != []
    store.reset_db()
    assert store.list_records() == []
