from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from triage.config import ROOT

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    verdict TEXT NOT NULL,
    priority TEXT NOT NULL,
    confidence REAL NOT NULL,
    route TEXT NOT NULL,
    needs_human INTEGER NOT NULL,
    probabilities TEXT NOT NULL,
    evidence TEXT NOT NULL,
    remediation TEXT NOT NULL,
    expected_label TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    action TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    edited_verdict TEXT,
    edited_priority TEXT,
    created_at TEXT NOT NULL,
    idempotency_key TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reviews_idempotency
    ON reviews(idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS explanations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    explanation TEXT NOT NULL,
    evidence_ids TEXT NOT NULL,
    uncertainty TEXT NOT NULL,
    next_step TEXT NOT NULL,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    latency_ms REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_explanations_cache ON explanations(cache_key);
CREATE INDEX IF NOT EXISTS idx_explanations_incident ON explanations(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_reviews_incident ON reviews(incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_events(incident_id);
"""

POSTGRES_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        verdict TEXT NOT NULL,
        priority TEXT NOT NULL,
        confidence DOUBLE PRECISION NOT NULL,
        route TEXT NOT NULL,
        needs_human BOOLEAN NOT NULL,
        probabilities JSONB NOT NULL,
        evidence JSONB NOT NULL,
        remediation JSONB NOT NULL,
        expected_label TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS reviews (
        id BIGSERIAL PRIMARY KEY,
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
        reviewer TEXT NOT NULL,
        action TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        edited_verdict TEXT,
        edited_priority TEXT,
        created_at TEXT NOT NULL,
        idempotency_key TEXT
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_reviews_idempotency "
    "ON reviews(idempotency_key) WHERE idempotency_key IS NOT NULL",
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        id BIGSERIAL PRIMARY KEY,
        incident_id TEXT,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        details JSONB NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS explanations (
        id BIGSERIAL PRIMARY KEY,
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
        cache_key TEXT NOT NULL,
        model TEXT NOT NULL,
        prompt_version TEXT NOT NULL,
        explanation TEXT NOT NULL,
        evidence_ids JSONB NOT NULL,
        uncertainty TEXT NOT NULL,
        next_step TEXT NOT NULL,
        prompt_tokens INTEGER NOT NULL DEFAULT 0,
        completion_tokens INTEGER NOT NULL DEFAULT 0,
        latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_explanations_cache ON explanations(cache_key)",
    "CREATE INDEX IF NOT EXISTS idx_explanations_incident ON explanations(incident_id)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)",
    "CREATE INDEX IF NOT EXISTS idx_reviews_incident ON reviews(incident_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_events(incident_id)",
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def default_database_url() -> str:
    return os.environ.get("DATABASE_URL", f"sqlite:///{ROOT / 'data' / 'triage.db'}")


class Database:
    """Small SQL layer that works with SQLite locally and Postgres in deployment."""

    def __init__(self, url: str | None = None) -> None:
        self.url = url or default_database_url()
        self.is_postgres = self.url.startswith(("postgres://", "postgresql://"))

    @property
    def backend(self) -> str:
        return "postgres" if self.is_postgres else "sqlite"

    @contextmanager
    def connect(self) -> Iterator[Any]:
        if self.is_postgres:
            import psycopg
            from psycopg.rows import dict_row

            # Neon's pooled endpoint runs PgBouncer in transaction mode, where
            # server-side prepared statements do not survive between requests.
            connection = psycopg.connect(
                self.url, row_factory=dict_row, prepare_threshold=None
            )
        else:
            path = self.url.removeprefix("sqlite:///")
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(path, check_same_thread=False)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _sql(self, statement: str) -> str:
        return statement.replace("?", "%s") if self.is_postgres else statement

    def init_schema(self) -> None:
        with self.connect() as connection:
            if self.is_postgres:
                for statement in POSTGRES_SCHEMA:
                    connection.execute(statement)
            else:
                connection.executescript(SQLITE_SCHEMA)

    def fetch_all(self, statement: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(self._sql(statement), params).fetchall()
        return [dict(row) for row in rows]

    def fetch_one(self, statement: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(self._sql(statement), params).fetchone()
        return dict(row) if row else None

    def execute(self, statement: str, params: Sequence[Any] = ()) -> int | None:
        with self.connect() as connection:
            cursor = connection.execute(self._sql(statement), params)
            if self.is_postgres:
                return cursor.rowcount
            return int(cursor.lastrowid) if cursor.lastrowid is not None else None

    def execute_returning(
        self, statement: str, params: Sequence[Any] = ()
    ) -> dict[str, Any] | None:
        if not self.is_postgres:
            raise RuntimeError("execute_returning is only for Postgres")
        with self.connect() as connection:
            row = connection.execute(statement, params).fetchone()
        return dict(row) if row else None


def json_load(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return json.loads(value)
    return value


def incident_row(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["needs_human"] = bool(result["needs_human"])
    for key in ("probabilities", "evidence", "remediation"):
        result[key] = json_load(result.get(key))
    return result
