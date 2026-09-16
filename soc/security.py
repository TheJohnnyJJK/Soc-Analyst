"""Minimal shared-secret guard for soc/api.py - same shape and same
reasoning as Lead Router's agent/security.py: opt-in via an unset-by-
default env var, so local dev and the test suite get an open API, and
setting SOC_API_KEY the moment this deploys anywhere reachable beyond
localhost closes it.
"""
from __future__ import annotations

import os
import secrets

from fastapi import Header, HTTPException


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    expected = os.environ.get("SOC_API_KEY")
    if not expected:
        return
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="missing or invalid X-API-Key")
