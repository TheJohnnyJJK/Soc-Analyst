"""Data contracts for one security alert, the evidence gathered about it,
and the triage verdict a scorer reaches - same "declare it once, validate
it with Pydantic" convention as every other project in this portfolio.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

IOCType = Literal["ip", "domain", "hash", "cve"]
# What a single piece of threat intel says about one IOC - "no_data" is
# its own state, not folded into "clean", because "nobody has ever seen
# this before" and "many sources have looked and it's fine" call for
# different levels of trust.
EvidenceVerdict = Literal["malicious", "suspicious", "clean", "no_data"]
# needs_review is a first-class outcome, not a fallback for "we're not
# sure" - it's the correct answer when the evidence genuinely doesn't
# support a confident call either way (no IOCs to check, or IOCs no
# threat-intel source has ever seen).
Verdict = Literal["confirmed_threat", "likely_benign", "needs_review"]
# What a human reviewer has done with a stored triage record - "open"
# until someone acts on it. A record can only ever leave "open" once,
# through soc/store.py::record_action() - see that module for why this
# is the actual audit trail, not TriageResult itself.
ActionStatus = Literal["open", "approved", "dismissed"]


class Alert(BaseModel):
    """One inbound security alert - the analog of Lead Router's LeadIn.

    raw_text is the only field the agent actually reasons over; the rest
    is bookkeeping a real SIEM/EDR would attach.
    """

    # Uniquely identifies this alert - soc/store.py enforces this at the
    # database level too, so posting the same alert_id twice (e.g. a
    # webhook retry) is idempotent rather than creating a duplicate row.
    alert_id: str = Field(min_length=1, max_length=40)
    # Which system reported this (e.g. "IDS", "EDR", "vuln-scanner") -
    # free text, not validated against a fixed list, since a real
    # deployment's source names aren't known in advance.
    source: str = Field(min_length=1, max_length=100)
    # The only field soc/iocs.py::extract_iocs() and the LLM narration
    # actually read - everything else here is metadata.
    raw_text: str = Field(min_length=1, max_length=5_000)
    reported_at: str | None = None


class Evidence(BaseModel):
    """One piece of threat intel gathered about one extracted IOC -
    the output of soc/evidence.py::gather_evidence() for a single
    IP/domain/hash/CVE."""

    ioc_type: IOCType
    # The IOC itself, e.g. "1.2.3.4" or "CVE-2024-3094".
    value: str
    verdict: EvidenceVerdict
    # Which external service produced this verdict, e.g. "abuseipdb",
    # "virustotal", "nvd" - lets a reader trace a claim back to its source.
    source_tool: str
    # The raw, unmodified response fields from that source (e.g.
    # AbuseIPDB's abuse_confidence_score, VirusTotal's malicious count) -
    # kept around so soc/triage.py::_evidence_line() can quote the exact
    # numbers in the report instead of just repeating the verdict word.
    detail: dict = Field(default_factory=dict)


class TriageResult(BaseModel):
    """What the agent decided about one alert, and why - the return
    value of soc/triage.py::triage()."""

    alert_id: str
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    # The human-readable explanation - either Claude's prose
    # (llm_reasoning()) or the deterministic fallback (template_reasoning()).
    reasoning: str = Field(max_length=2_000)
    evidence: list[Evidence]
    # Which of the two reasoning paths above actually produced `reasoning`.
    scorer: Literal["llm", "heuristic"]
    # How long triage() took, end to end, in milliseconds - this is
    # what the eval harness averages into eval/results.json's
    # avg_latency_ms.
    latency_ms: float
    # Set only when triage(alert, correlate=True) finds a prior sighting
    # of one of this alert's IOCs in a *different* alert - see
    # soc/triage.py::_correlate. None (not "") means "correlation wasn't
    # checked or found nothing", distinct from an empty string, which
    # would wrongly imply it was checked and came back with literally
    # nothing to say.
    correlation: str | None = None


class StoredTriageRecord(BaseModel):
    """A TriageResult as persisted in the audit store, plus the alert it
    came from and whatever a human has since done about it. This is the
    actual compliance artifact this project produces - see soc/store.py.
    soc/api.py returns this shape from every /alerts route."""

    # Auto-incrementing database row id (soc/store.py's PRIMARY KEY) -
    # distinct from alert_id, which is caller-chosen and only unique,
    # not necessarily numeric or sequential.
    id: int
    alert: Alert
    result: TriageResult
    # "open" until a human calls POST /alerts/{id}/action.
    status: ActionStatus
    # The following three are all None until record_action() sets them,
    # and all set together, exactly once, at that point.
    actioned_by: str | None = None
    actioned_at: str | None = None
    actioned_note: str | None = None
    # The identity resolved from the caller's X-Source-Key (see
    # soc/security.py::identify_source), or None when SOC_SOURCE_KEYS
    # isn't configured or the caller didn't authenticate as a source.
    # Distinct from `alert.source`, which is free text the caller
    # chooses - this is only ever set by verifying a shared secret, which
    # is what makes it safe for soc/triage.py::_correlate to trust as
    # "an independent reporter", not just "a different string".
    authenticated_source: str | None = None
    created_at: str


class GoldenAlertCase(BaseModel):
    """One golden-set entry: a real alert plus the ground-truth verdict
    it should produce, graded deterministically the same way every other
    golden set in this portfolio is."""

    alert: Alert
    expected_verdict: Verdict
    notes: str = Field(min_length=1, max_length=800)


_CASES_PATH = Path(__file__).resolve().parent / "golden_alerts.json"


def load_golden_alerts(path: Path | None = None) -> list[GoldenAlertCase]:
    """Loads and validates golden_alerts.json (or `path`, for a test
    that wants to feed in a fixture instead). Every entry is checked
    against GoldenAlertCase on the way in, so a malformed row fails
    loudly here rather than surfacing as a confusing error later."""
    raw = json.loads((path or _CASES_PATH).read_text(encoding="utf-8"))
    return [GoldenAlertCase(**entry) for entry in raw]
