from __future__ import annotations

from soc.iocs import extract_iocs


def test_extracts_an_ipv4_address():
    result = extract_iocs("connection from 159.203.184.15 on port 22")
    assert result["ip"] == ["159.203.184.15"]


def test_extracts_a_domain_but_not_an_ip():
    result = extract_iocs("beaconed out to amaamn.com and to 8.8.8.8")
    assert result["domain"] == ["amaamn.com"]
    assert result["ip"] == ["8.8.8.8"]


def test_version_number_is_not_mistaken_for_an_ip_or_domain():
    result = extract_iocs("xz-utils 5.6.1 flagged as vulnerable")
    assert result["ip"] == []
    assert result["domain"] == []


def test_extracts_a_sha256_hash():
    file_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    result = extract_iocs(f"quarantined file matching {file_hash}")
    assert result["hash"] == [file_hash]


def test_extracts_and_uppercases_a_cve_id():
    result = extract_iocs("flagged as vulnerable to cve-2024-3094 in the base image")
    assert result["cve"] == ["CVE-2024-3094"]


def test_no_iocs_returns_empty_lists_for_every_type():
    result = extract_iocs("something felt off, no other details")
    assert result == {"ip": [], "domain": [], "hash": [], "cve": []}


def test_duplicate_iocs_are_deduplicated():
    result = extract_iocs("159.203.184.15 hit us twice: 159.203.184.15 again")
    assert result["ip"] == ["159.203.184.15"]


def test_private_and_loopback_ips_are_not_extracted():
    result = extract_iocs("internal host 10.0.0.5 talked to 127.0.0.1 then to 8.8.8.8")
    assert result["ip"] == ["8.8.8.8"]


def test_extracts_multiple_iocs_of_different_types_together():
    result = extract_iocs(
        "host contacted 149.54.9.42 then amaamn.com, related to CVE-2024-3094"
    )
    assert result["ip"] == ["149.54.9.42"]
    assert result["domain"] == ["amaamn.com"]
    assert result["cve"] == ["CVE-2024-3094"]


def test_extracts_a_bracket_defanged_ip():
    result = extract_iocs("connection from 159[.]203[.]184[.]15")
    assert result["ip"] == ["159.203.184.15"]


def test_extracts_an_hxxp_defanged_domain():
    result = extract_iocs("beaconed to hxxp://amaamn[.]com/payload")
    assert result["domain"] == ["amaamn.com"]


def test_extracts_a_domain_split_by_zero_width_characters():
    result = extract_iocs("beaconed to amaamn​.com")
    assert result["domain"] == ["amaamn.com"]


def test_common_file_extensions_are_not_mistaken_for_domains():
    result = extract_iocs("attached invoice.pdf, setup.exe, and readme.txt")
    assert result["domain"] == []


def test_iocs_of_one_type_are_capped_per_alert():
    text = " ".join(f"1.2.3.{i}" for i in range(1, 50))
    result = extract_iocs(text)
    assert len(result["ip"]) == 15
