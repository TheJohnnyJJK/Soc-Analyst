from __future__ import annotations

from alerts.schema import load_golden_alerts


def test_golden_alert_set_loads_and_has_ten_cases():
    cases = load_golden_alerts()
    assert len(cases) == 10
    assert len({c.alert.alert_id for c in cases}) == 10, "alert_ids must be unique"


def test_all_three_verdicts_are_represented():
    cases = load_golden_alerts()
    verdicts = {c.expected_verdict for c in cases}
    assert verdicts == {"confirmed_threat", "likely_benign", "needs_review"}
