"""FastAPI service - the real ingestion path a SIEM's outbound webhook,
a cron job, or a curl from a log-watcher can point at, instead of the
golden set being the only way alerts ever reach this project.

POST /alerts               triage one inbound alert, persist it, return the audit record
GET  /alerts               recent audit records, optionally filtered by verdict/status
GET  /alerts/{record_id}   one audit record
POST /alerts/{record_id}/action   record a human decision (approve/dismiss) on one record
GET  /health               liveness check, deliberately unauthenticated
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import Annotated, Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query
from mcp_threat_intel.server import MissingApiKeyError
from pydantic import BaseModel, Field

from alerts.schema import Alert, StoredTriageRecord, Verdict

from . import store
from .security import require_api_key
from .triage import triage

Authed = Annotated[None, Depends(require_api_key)]


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db()
    yield


app = FastAPI(title="SOC Analyst", version="0.1.0", lifespan=lifespan)


class AlertIn(BaseModel):
    # Optional: a real SIEM webhook may not supply a stable id of its own,
    # so one is generated (see create_alert()) rather than rejecting the
    # request.
    alert_id: str | None = Field(default=None, min_length=1, max_length=40)
    source: str = Field(min_length=1, max_length=100)
    raw_text: str = Field(min_length=1, max_length=5_000)
    reported_at: str | None = None


class ActionIn(BaseModel):
    status: Literal["approved", "dismissed"]
    actioned_by: str = Field(min_length=1, max_length=100)
    note: str | None = Field(default=None, max_length=1_000)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/alerts", response_model=StoredTriageRecord)
def create_alert(payload: AlertIn, _auth: Authed) -> StoredTriageRecord:
    """Runs the real pipeline (extract -> gather evidence -> classify ->
    correlate against the audit store -> narrate) and persists the
    result - this is the one place correlate=True is ever passed, since
    it's also the one place that follows through and actually writes the
    result the correlation check just read against."""
    alert = Alert(
        alert_id=payload.alert_id or uuid.uuid4().hex[:12],
        source=payload.source,
        raw_text=payload.raw_text,
        reported_at=payload.reported_at,
    )
    try:
        result = triage(alert, correlate=True)
    except MissingApiKeyError as exc:
        raise HTTPException(status_code=503, detail=f"threat-intel not configured: {exc}") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"threat-intel lookup failed: {exc}") from exc
    record_id = store.insert_triage(alert, result)
    record = store.get_record(record_id)
    if record is None:  # pragma: no cover - insert_triage() just created this row
        raise HTTPException(status_code=500, detail="failed to read back the record just written")
    return record


@app.get("/alerts", response_model=list[StoredTriageRecord])
def list_alerts(
    _auth: Authed,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    verdict: Verdict | None = None,
    status: Literal["open", "approved", "dismissed"] | None = None,
) -> list[StoredTriageRecord]:
    return store.list_records(limit=limit, verdict=verdict, status=status)


@app.get("/alerts/{record_id}", response_model=StoredTriageRecord)
def get_alert(record_id: int, _auth: Authed) -> StoredTriageRecord:
    record = store.get_record(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"no record with id {record_id}")
    return record


@app.post("/alerts/{record_id}/action", response_model=StoredTriageRecord)
def action_alert(record_id: int, payload: ActionIn, _auth: Authed) -> StoredTriageRecord:
    if store.get_record(record_id) is None:
        raise HTTPException(status_code=404, detail=f"no record with id {record_id}")
    record = store.record_action(
        record_id, status=payload.status, actioned_by=payload.actioned_by, note=payload.note
    )
    if record is None:  # pragma: no cover - just confirmed the row exists, immediately above
        raise HTTPException(status_code=500, detail="record disappeared mid-request")
    return record
