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

A red-team pass on this project (see README's Honesty notes) found
this extractor was blind to *defanged* notation - "159[.]203[.]184[.]15",
"hxxp://amaamn[.]com" - which isn't even an attack, it's the standard
way analysts write IOCs in prose specifically so they don't
accidentally become clickable/pingable. _refang() undoes that before
any pattern runs, so this tool sees the same indicator a human would.
"""
from __future__ import annotations

import ipaddress
import re

from alerts.schema import IOCType

# How many indicators of ONE type this project will actually look up
# for a single alert. Uncapped, one 5,000-char alert (the max raw_text
# length) could contain hundreds of distinct fake IOCs and turn one
# inbound POST into hundreds of live third-party API calls - a
# red-team pass confirmed this by firing 10 real lookups from one
# request with no cap in place. This bounds the worst case regardless
# of how creative the input gets.
_MAX_IOCS_PER_TYPE = 15

_ZERO_WIDTH = re.compile("[​‌‍﻿]")
# Common defanging conventions, checked before any IOC pattern runs.
# Not exhaustive (decimal/hex-encoded IPs are a much deeper rabbit hole
# and are rare outside crafted URLs, which the domain pattern already
# catches once refanged) - this covers the conventions actually used in
# ordinary SOC/threat-intel writing: bracketed dots, hxxp(s), [at].
_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\[\.\]|\(\.\)|\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[at\]|\(at\)", re.IGNORECASE), "@"),
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
]

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_HASH = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# A domain-shaped token whose final label is actually a common file
# extension is almost always a filename mentioned in passing
# ("invoice.pdf", "setup.exe"), not a domain - a red-team pass found
# this misfiring on ordinary, non-malicious alert prose and burning a
# real VirusTotal lookup on every one. Not perfect (a handful of
# ccTLDs collide with extensions, e.g. .md/.sh) but it removes the
# common, high-volume false positives.
_FILE_EXTENSIONS = {
    "pdf", "exe", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "rar", "7z", "dll", "bat", "py", "js", "ps1", "csv", "json",
    "xml", "log", "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4",
    "avi", "ini", "conf", "yml", "yaml", "rtf", "msi", "bin", "dat",
    "tmp", "bak", "sql", "db",
}


def _refang(text: str) -> str:
    text = _ZERO_WIDTH.sub("", text)
    for pattern, replacement in _REFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


def extract_iocs(text: str) -> dict[IOCType, list[str]]:
    """Returns each IOC type's matches, de-duplicated but order-preserving
    and capped at _MAX_IOCS_PER_TYPE. An empty list for a type means none
    were found - callers shouldn't treat a missing key specially since
    every key is always present."""
    text = _refang(text)
    # Private/loopback/link-local addresses (10.x, 192.168.x, 127.x, ...)
    # are never meaningfully scoreable by an external reputation source -
    # skip them here rather than burning a free-tier API call to learn
    # that AbuseIPDB has never heard of your own LAN.
    ips = _cap(_dedupe(ip for ip in _IPV4.findall(text) if not _is_internal(ip)))
    hashes = _cap(_dedupe(_HASH.findall(text)))
    cves = _cap(_dedupe(m.upper() for m in _CVE.findall(text)))
    # Domains are extracted last and filtered against the other three -
    # an IPv4 octet run never matches _DOMAIN (its final label is
    # numeric), but a hash or CVE ID never contains a literal "." so
    # there's nothing to overlap there either; the filter exists mainly
    # so a domain-shaped substring inside a longer already-classified
    # token (unlikely given the patterns above, but not impossible)
    # can't sneak into both lists.
    already_matched = set(ips) | set(hashes) | set(cves)
    domains = _cap(
        _dedupe(
            m for m in _DOMAIN.findall(text)
            if m not in already_matched and m.rsplit(".", 1)[-1].lower() not in _FILE_EXTENSIONS
        )
    )
    return {"ip": ips, "domain": domains, "hash": hashes, "cve": cves}


def _is_internal(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def _cap(items: list[str]) -> list[str]:
    return items[:_MAX_IOCS_PER_TYPE]


def _dedupe(items) -> list[str]:
    seen: set[str] = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
