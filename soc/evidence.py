"""Turns extracted IOCs into Evidence records by calling out to the
portfolio's own MCP servers - literally the same functions Claude
Desktop/Cursor would invoke over MCP, just called in-process here
instead of over the stdio wire. That's the entire point of building
mcp-threat-intel and mcp-cve-feed as real importable Python packages
rather than one-off scripts: this project gets IP/domain/hash/CVE
lookups for free instead of a third reimplementation of the same
HTTP-calling code.
"""
from __future__ import annotations

import httpx
from mcp_cve_feed.server import get_cve
from mcp_threat_intel.server import (
    check_domain_reputation,
    check_file_hash,
    check_ip_reputation,
)

from alerts.schema import Evidence, IOCType

# CVE severity doesn't map onto "is this IOC bad" the same way a
# reputation verdict does, but a CRITICAL/HIGH CVE genuinely under
# active exploitation deserves the same escalation weight as a
# malicious IP - see the module docstring in soc/triage.py for how
# these verdicts get aggregated into a final tier.
_CVE_SEVERITY_TO_VERDICT = {
    "CRITICAL": "malicious",
    "HIGH": "malicious",
    "MEDIUM": "suspicious",
    "LOW": "clean",
}


def gather_evidence(iocs: dict[IOCType, list[str]]) -> list[Evidence]:
    """Looks up every extracted IOC and returns one Evidence per IOC.
    A source that has never seen an indicator (VirusTotal 404s on an
    unknown domain/hash) becomes verdict="no_data", not a crash and not
    a silent "clean" - see _NOT_FOUND handling below."""
    evidence: list[Evidence] = []
    for ip in iocs.get("ip", []):
        evidence.append(_ip_evidence(ip))
    for domain in iocs.get("domain", []):
        evidence.append(_domain_evidence(domain))
    for file_hash in iocs.get("hash", []):
        evidence.append(_hash_evidence(file_hash))
    for cve_id in iocs.get("cve", []):
        evidence.append(_cve_evidence(cve_id))
    return evidence


def _ip_evidence(ip: str) -> Evidence:
    result = check_ip_reputation(ip)
    return Evidence(
        ioc_type="ip", value=ip, verdict=result["verdict"], source_tool="abuseipdb", detail=result
    )


def _domain_evidence(domain: str) -> Evidence:
    try:
        result = check_domain_reputation(domain)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return _no_data("domain", domain, "virustotal")
        raise
    return Evidence(
        ioc_type="domain",
        value=domain,
        verdict=result["verdict"],
        source_tool="virustotal",
        detail=result,
    )


def _hash_evidence(file_hash: str) -> Evidence:
    try:
        result = check_file_hash(file_hash)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return _no_data("hash", file_hash, "virustotal")
        raise
    return Evidence(
        ioc_type="hash",
        value=file_hash,
        verdict=result["verdict"],
        source_tool="virustotal",
        detail=result,
    )


def _cve_evidence(cve_id: str) -> Evidence:
    result = get_cve(cve_id)
    if result is None:
        return _no_data("cve", cve_id, "nvd")
    verdict = _CVE_SEVERITY_TO_VERDICT.get(result["base_severity"] or "", "no_data")
    return Evidence(ioc_type="cve", value=cve_id, verdict=verdict, source_tool="nvd", detail=result)


def _no_data(ioc_type: IOCType, value: str, source_tool: str) -> Evidence:
    return Evidence(
        ioc_type=ioc_type,
        value=value,
        verdict="no_data",
        source_tool=source_tool,
        detail={"note": f"{source_tool} has no record of this {ioc_type}"},
    )
