"""Regex-based IOC extraction from free-text alert bodies.

Deliberately simple pattern matching, not NLP - a SOC alert's IOCs
(an IP, a domain, a hash, a CVE ID) have a fixed enough shape that regex
is the right tool, and it's the same "deterministic where possible"
instinct as the rest of this portfolio: extraction shouldn't need a
model call any more than grading does.

The domain pattern requires an alphabetic final label ("wikipedia.org",
not "159.203.184.15") specifically so it never double-counts an IPv4
address as a domain - the two patterns are mutually exclusive by
construction, not by one excluding the other's matches after the fact.
"""
from __future__ import annotations

import ipaddress
import re

from alerts.schema import IOCType

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_HASH = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def extract_iocs(text: str) -> dict[IOCType, list[str]]:
    """Returns each IOC type's matches, de-duplicated but order-preserving.
    An empty list for a type means none were found - callers shouldn't
    treat a missing key specially since every key is always present."""
    # Private/loopback/link-local addresses (10.x, 192.168.x, 127.x, ...)
    # are never meaningfully scoreable by an external reputation source -
    # skip them here rather than burning a free-tier API call to learn
    # that AbuseIPDB has never heard of your own LAN.
    ips = _dedupe(ip for ip in _IPV4.findall(text) if not _is_internal(ip))
    hashes = _dedupe(_HASH.findall(text))
    cves = _dedupe(m.upper() for m in _CVE.findall(text))
    # Domains are extracted last and filtered against the other three -
    # an IPv4 octet run never matches _DOMAIN (its final label is
    # numeric), but a hash or CVE ID never contains a literal "." so
    # there's nothing to overlap there either; the filter exists mainly
    # so a domain-shaped substring inside a longer already-classified
    # token (unlikely given the patterns above, but not impossible)
    # can't sneak into both lists.
    already_matched = set(ips) | set(hashes) | set(cves)
    domains = _dedupe(m for m in _DOMAIN.findall(text) if m not in already_matched)
    return {"ip": ips, "domain": domains, "hash": hashes, "cve": cves}


def _is_internal(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def _dedupe(items) -> list[str]:
    seen: set[str] = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
