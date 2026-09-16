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


class Alert(BaseModel):
    """One inbound security alert - the analog of Lead Router's LeadIn.

    raw_text is the only field the agent actually reasons over; the rest
    is bookkeeping a real SIEM/EDR would attach.
    """

    alert_id: str = Field(min_length=1, max_length=40)
    source: str = Field(min_length=1, max_length=100)
    raw_text: str = Field(min_length=1, max_length=5_000)
    reported_at: str | None = None


class Evidence(BaseModel):
    """One piece of threat intel gathered about one extracted IOC."""

    ioc_type: IOCType
    value: str
    verdict: EvidenceVerdict
    source_tool: str
    detail: dict = Field(default_factory=dict)


class TriageResult(BaseModel):
    """What the agent decided about one alert, and why."""

    alert_id: str
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    reasoning: str = Field(max_length=2_000)
    evidence: list[Evidence]
    scorer: Literal["llm", "heuristic"]
    latency_ms: float


class GoldenAlertCase(BaseModel):
    """One golden-set entry: a real alert plus the ground-truth verdict
    it should produce, graded deterministically the same way every other
    golden set in this portfolio is."""

    alert: Alert
    expected_verdict: Verdict
    notes: str = Field(min_length=1, max_length=800)


_CASES_PATH = Path(__file__).resolve().parent / "golden_alerts.json"


def load_golden_alerts(path: Path | None = None) -> list[GoldenAlertCase]:
    raw = json.loads((path or _CASES_PATH).read_text(encoding="utf-8"))
    return [GoldenAlertCase(**entry) for entry in raw]
