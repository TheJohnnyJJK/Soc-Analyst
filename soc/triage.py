"""Turns one Alert into a TriageResult.

The verdict is always decided by classify() - deterministic rules over
gathered Evidence, never by the LLM. That's a deliberate departure from
Lead Router (where the LLM picks the tier): a security verdict has to
be reproducible enough that the golden-set eval score means something
run to run, and auditable enough that a human reviewer can see exactly
which evidence forced which outcome. The LLM's only job, when available,
is to narrate that already-decided outcome in prose - see llm_reasoning().

classify()'s precedence, checked in order:
  1. no IOCs extracted at all           -> needs_review (nothing to check)
  2. any evidence is "malicious"        -> confirmed_threat
  3. any evidence is "no_data"          -> needs_review (absence of a bad
                                           reputation isn't the same as a
                                           good one - see soc/evidence.py)
  4. any evidence is "suspicious"       -> needs_review
  5. every piece of evidence is "clean" -> likely_benign
"""
from __future__ import annotations

import os
import time

from alerts.schema import Alert, Evidence, TriageResult, Verdict

from .evidence import gather_evidence
from .iocs import extract_iocs


def classify(evidence: list[Evidence]) -> tuple[Verdict, float]:
    if not evidence:
        return "needs_review", 0.3
    verdicts = [e.verdict for e in evidence]
    malicious = verdicts.count("malicious")
    if malicious:
        # More independent malicious signals = higher confidence a
        # correlated pattern is real, not a single source's false positive.
        confidence = min(0.7 + 0.1 * (malicious - 1), 0.95)
        return "confirmed_threat", confidence
    if "no_data" in verdicts:
        return "needs_review", 0.4
    if "suspicious" in verdicts:
        return "needs_review", 0.5
    return "likely_benign", 0.8


def template_reasoning(alert: Alert, evidence: list[Evidence], verdict: Verdict) -> str:
    """Deterministic, no-LLM-required reasoning string - every sentence
    traces back to one Evidence entry, so this reads the same whether
    or not ANTHROPIC_API_KEY is set."""
    if not evidence:
        return (
            "No indicators of compromise (IP, domain, hash, or CVE ID) could be "
            "extracted from the alert text - nothing to check against threat intel."
        )
    lines = [_evidence_line(e) for e in evidence]
    return f"Verdict: {verdict}. " + " ".join(lines)


def _evidence_line(e: Evidence) -> str:
    if e.verdict == "no_data":
        return f"{e.ioc_type} {e.value}: no data from {e.source_tool}."
    if e.ioc_type == "cve":
        severity = e.detail.get("base_severity", "unknown")
        return f"{e.value}: CVSS {e.detail.get('base_score')} ({severity}) per NVD."
    return f"{e.ioc_type} {e.value}: {e.verdict} per {e.source_tool}."


def llm_reasoning(alert: Alert, evidence: list[Evidence], verdict: Verdict) -> str:
    import anthropic  # imported lazily so the module loads without the package during tests

    facts = "\n".join(_evidence_line(e) for e in evidence) or "No IOCs were extracted."
    prompt = f"""A security alert was triaged with verdict "{verdict}". Write 2-3 sentences a
human SOC analyst can read in five seconds, explaining why, using ONLY the facts below -
do not introduce any claim that isn't listed here, and do not suggest a different verdict.

Alert ({alert.source}): {alert.raw_text}

Evidence:
{facts}"""
    client = anthropic.Anthropic()
    response = client.messages.create(
        model=os.environ.get("ANTHROPIC_MODEL", "claude-opus-5"),
        max_tokens=300,
        messages=[{"role": "user", "content": prompt}],
    )
    block = response.content[0]
    if not isinstance(block, anthropic.types.TextBlock):
        raise ValueError(f"expected a text block, got {type(block).__name__}")
    return block.text


def triage(alert: Alert) -> TriageResult:
    started = time.perf_counter()
    iocs = extract_iocs(alert.raw_text)
    evidence = gather_evidence(iocs) if any(iocs.values()) else []
    verdict, confidence = classify(evidence)

    use_llm = bool(os.environ.get("ANTHROPIC_API_KEY"))
    try:
        reasoning = llm_reasoning(alert, evidence, verdict) if use_llm else None
        scorer = "llm"
    except Exception:  # noqa: BLE001 - any LLM failure falls back, same as Lead Router's score_lead
        reasoning = None
        scorer = "heuristic"
    if reasoning is None:
        reasoning = template_reasoning(alert, evidence, verdict)
        scorer = "heuristic"

    return TriageResult(
        alert_id=alert.alert_id,
        verdict=verdict,
        confidence=confidence,
        reasoning=reasoning,
        evidence=evidence,
        scorer=scorer,
        latency_ms=(time.perf_counter() - started) * 1000,
    )
