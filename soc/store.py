"""SQLite audit trail - the actual product this project's research
identified as what regulated buyers pay for. Every triage() call that
passes a store_path gets one row here: the alert, the evidence, the
verdict, and later, what a human did about it. Nothing is ever deleted
or overwritten except the action fields (see record_action()) - a
compliance examiner reading this table sees the same thing the system
saw at decision time.

Security note: every query uses `?` placeholders with values passed as
a separate tuple, never string-formatted into the SQL - same rule and
same reasoning as Lead Router's agent/store.py.
"""
from __future__ import annotations

import datetime
import json
import os
import sqlite3
from contextlib import contextmanager

from alerts.schema import Alert, Evidence, StoredTriageRecord, TriageResult

_DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "soc_analyst.db")
DB_PATH = os.environ.get("SOC_STORE_DB", _DEFAULT_DB_PATH)

# ioc_sightings is a separate table, not a JSON LIKE-query against
# triage_records, specifically so recent_sightings() below is an exact,
# indexed match on (ioc_type, value) - matching against serialized JSON
# text risks a false hit from formatting/escaping, or a false miss from
# the same.
SCHEMA = """
CREATE TABLE IF NOT EXISTS triage_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    source TEXT NOT NULL,
    raw_text TEXT NOT NULL,
    reported_at TEXT,
    verdict TEXT NOT NULL,
    confidence REAL NOT NULL,
    reasoning TEXT NOT NULL,
    correlation TEXT,
    evidence_json TEXT NOT NULL,
    scorer TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    actioned_by TEXT,
    actioned_at TEXT,
    actioned_note TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_triage_created_at ON triage_records(created_at);
CREATE INDEX IF NOT EXISTS idx_triage_status ON triage_records(status);

CREATE TABLE IF NOT EXISTS ioc_sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id INTEGER NOT NULL REFERENCES triage_records(id),
    alert_id TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    verdict TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sightings_lookup ON ioc_sightings(ioc_type, value, created_at);
"""


@contextmanager
def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with _conn() as conn:
        conn.executescript(SCHEMA)


def reset_db() -> None:
    """Deletes the database file and recreates empty tables - used by
    tests, each of which points DB_PATH at its own temp file first."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


def insert_triage(alert: Alert, result: TriageResult) -> int:
    """Records one triage() call and its evidence, returns the new row's
    id. Called from soc/api.py after triage() returns - never called
    directly by the eval harness, which stays a pure in-memory grading
    run with no persistence side effect."""
    created_at = datetime.datetime.utcnow().isoformat()
    with _conn() as conn:
        cur = conn.execute(
            """INSERT INTO triage_records
               (alert_id, source, raw_text, reported_at, verdict, confidence,
                reasoning, correlation, evidence_json, scorer, latency_ms,
                status, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,'open',?)""",
            (
                alert.alert_id, alert.source, alert.raw_text, alert.reported_at,
                result.verdict, result.confidence, result.reasoning, result.correlation,
                json.dumps([e.model_dump() for e in result.evidence]),
                result.scorer, result.latency_ms, created_at,
            ),
        )
        record_id = cur.lastrowid
        for e in result.evidence:
            conn.execute(
                """INSERT INTO ioc_sightings
                   (record_id, alert_id, ioc_type, value, verdict, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (record_id, alert.alert_id, e.ioc_type, e.value, e.verdict, created_at),
            )
    return record_id


def recent_sightings(
    ioc_type: str, value: str, within_hours: float, exclude_alert_id: str
) -> list[dict]:
    """Every prior sighting of this exact (ioc_type, value) pair, from a
    *different* alert, within the last `within_hours`. Excluding the
    current alert_id matters because a single alert can legitimately
    mention the same IOC more than once - that's not a cross-alert
    pattern, it's the same sighting."""
    cutoff = (
        datetime.datetime.utcnow() - datetime.timedelta(hours=within_hours)
    ).isoformat()
    with _conn() as conn:
        rows = conn.execute(
            """SELECT DISTINCT alert_id, verdict, created_at FROM ioc_sightings
               WHERE ioc_type = ? AND value = ? AND alert_id != ? AND created_at >= ?
               ORDER BY created_at DESC""",
            (ioc_type, value, exclude_alert_id, cutoff),
        ).fetchall()
    return [dict(r) for r in rows]


def get_record(record_id: int) -> StoredTriageRecord | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM triage_records WHERE id = ?", (record_id,)
        ).fetchone()
    return _row_to_record(row) if row else None


def list_records(
    limit: int = 50, verdict: str | None = None, status: str | None = None
) -> list[StoredTriageRecord]:
    """Most recent first, optionally filtered by verdict and/or status.
    `limit` is honored as given - the API layer (soc/api.py) is what
    bounds it, the same division of responsibility as Lead Router's
    store.get_leads()/agent/main.py."""
    clauses, params = [], []
    if verdict:
        clauses.append("verdict = ?")
        params.append(verdict)
    if status:
        clauses.append("status = ?")
        params.append(status)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM triage_records {where} ORDER BY id DESC LIMIT ?",  # noqa: S608
            (*params, limit),
        ).fetchall()
    return [_row_to_record(r) for r in rows]


def record_action(
    record_id: int, status: str, actioned_by: str, note: str | None = None
) -> StoredTriageRecord | None:
    """Records what a human did about one open record. A record's
    action fields, once set, are never cleared by this function again -
    re-actioning an already-actioned record overwrites them, which is a
    deliberate choice left to the API layer to allow or reject (see
    soc/api.py) rather than enforced here."""
    actioned_at = datetime.datetime.utcnow().isoformat()
    with _conn() as conn:
        conn.execute(
            """UPDATE triage_records SET status = ?, actioned_by = ?,
               actioned_at = ?, actioned_note = ? WHERE id = ?""",
            (status, actioned_by, actioned_at, note, record_id),
        )
    return get_record(record_id)


def _row_to_record(row: sqlite3.Row) -> StoredTriageRecord:
    evidence = [Evidence(**e) for e in json.loads(row["evidence_json"])]
    alert = Alert(
        alert_id=row["alert_id"], source=row["source"],
        raw_text=row["raw_text"], reported_at=row["reported_at"],
    )
    result = TriageResult(
        alert_id=row["alert_id"], verdict=row["verdict"], confidence=row["confidence"],
        reasoning=row["reasoning"], correlation=row["correlation"], evidence=evidence,
        scorer=row["scorer"], latency_ms=row["latency_ms"],
    )
    return StoredTriageRecord(
        id=row["id"], alert=alert, result=result, status=row["status"],
        actioned_by=row["actioned_by"], actioned_at=row["actioned_at"],
        actioned_note=row["actioned_note"], created_at=row["created_at"],
    )
