"""Minimal shared-secret guard for soc/api.py - same shape and same
reasoning as Lead Router's agent/security.py: opt-in via an unset-by-
default env var, so local dev and the test suite get an open API, and
setting SOC_API_KEY the moment this deploys anywhere reachable beyond
localhost closes it.
"""
from __future__ import annotations

import json
import os
import secrets

from fastapi import Header, HTTPException


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """FastAPI dependency - raises 401 if SOC_API_KEY is set and the
    caller's X-API-Key header doesn't match it. Reads the env var fresh
    on every call rather than once at import time, so a test can
    monkeypatch it per-test and see the effect immediately."""
    expected = os.environ.get("SOC_API_KEY")
    if not expected:
        return  # auth disabled - the documented local-dev default
    # secrets.compare_digest(), not `==`, so the comparison runs in
    # constant time regardless of how many leading characters of the
    # key were correct - the standard way to check a secret without
    # leaking timing information about it.
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="missing or invalid X-API-Key")


def identify_source(x_source_key: str | None = Header(default=None)) -> str | None:
    """FastAPI dependency resolving *which* upstream integration is
    posting an alert - separate from require_api_key's single shared
    secret, which only answers "is this caller allowed to use the API
    at all," not "which caller is this."

    This closes a real gap a red-team pass found and documented, not
    fixed at the time, in soc/triage.py::_correlate: escalating a lone
    "suspicious" signal to confirmed_threat on a repeat sighting only
    means something if the repeat came from an independent reporter -
    without this, one caller could post the same IOC under several
    self-chosen alert_ids and manufacture that corroboration on demand.

    SOC_SOURCE_KEYS is a JSON object mapping each upstream integration's
    own secret to a name, e.g. {"<key-a>": "edr-vendor", "<key-b>":
    "siem-vendor"} - one entry per source that should be able to
    corroborate the others. Same opt-in shape as SOC_API_KEY: unset (the
    local-dev default), this returns None and soc/triage.py::_correlate
    falls back to the original, documented alert_id-only trust model.
    Configured, every request must present a valid X-Source-Key (401 if
    missing or unrecognized), and the matching name is what gets stored
    and compared for correlation - a value nothing but this function
    ever sets, so it can't be spoofed via the request body.
    """
    raw = os.environ.get("SOC_SOURCE_KEYS")
    if not raw:
        return None  # feature not opted into - see docstring above
    keys: dict[str, str] = json.loads(raw)
    if x_source_key:
        for key, name in keys.items():
            if secrets.compare_digest(x_source_key, key):
                return name
    raise HTTPException(status_code=401, detail="missing or invalid X-Source-Key")
