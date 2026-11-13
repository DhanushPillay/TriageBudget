from __future__ import annotations

import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from triage.config import ROOT
from triage.web.db import Database, incident_row, utc_now

LOGGER = logging.getLogger("triage.web")
PUBLIC_DIR = ROOT / "public"
VERDICTS = ("true_positive", "benign_positive", "false_positive", "undetermined")
PRIORITIES = ("critical", "high", "medium", "low")
ACTIONS = ("approve", "edit", "reject")
STATUS_BY_ACTION = {"approve": "approved", "edit": "edited", "reject": "rejected"}
PRIORITY_ORDER = (
    "CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
    "WHEN 'medium' THEN 2 ELSE 3 END"
)


class ReviewRequest(BaseModel):
    action: Literal["approve", "edit", "reject"]
    reviewer: str = Field(min_length=1, max_length=80)
    note: str = Field(default="", max_length=2000)
    edited_verdict: Literal[
        "true_positive", "benign_positive", "false_positive", "undetermined"
    ] | None = None
    edited_priority: Literal["critical", "high", "medium", "low"] | None = None


def _json_value(value: Any, postgres: bool) -> Any:
    if not postgres:
        return json.dumps(value)
    from psycopg.types.json import Jsonb

    return Jsonb(value)


def _review_token() -> str:
    return os.environ.get("TRIAGE_REVIEW_TOKEN", "demo-review-token")


def _demo_mode() -> bool:
    return os.environ.get("TRIAGE_DEMO_MODE", "1").lower() not in {"0", "false", "no"}


def require_review_token(x_review_token: str | None = Header(default=None)) -> None:
    expected = _review_token()
    if not _demo_mode() and not os.environ.get("TRIAGE_REVIEW_TOKEN"):
        raise HTTPException(status_code=503, detail="Review token is not configured")
    if not x_review_token or not secrets.compare_digest(x_review_token, expected):
        raise HTTPException(status_code=401, detail="Invalid review token")


def create_app(database: Database | None = None) -> FastAPI:
    db = database or Database()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        db.init_schema()
        yield

    app = FastAPI(
        title="TriageBudget review API",
        version="w5_demo_v1",
        description="Review queue for frozen GUIDE demo decisions. Not a production SOC.",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def request_log(request: Request, call_next):
        started = time.perf_counter()
        request_id = request.headers.get("x-request-id") or secrets.token_hex(8)
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        LOGGER.info(
            json.dumps(
                {
                    "event": "http_request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                }
            )
        )
        return response

    @app.exception_handler(Exception)
    async def unhandled_exception(_: Request, exc: Exception) -> JSONResponse:
        LOGGER.exception("unhandled_error", exc_info=exc)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    @app.get("/health")
    def health() -> dict[str, Any]:
        db.fetch_one("SELECT 1 AS ok")
        return {
            "status": "ok",
            "version": "w5_demo_v1",
            "database": db.backend,
            "demo_mode": _demo_mode(),
        }

    @app.get("/api/incidents")
    def list_incidents(
        status: str | None = Query(default=None, max_length=20),
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        where = ""
        params: list[Any] = []
        if status:
            if status not in {"pending", "approved", "edited", "rejected"}:
                raise HTTPException(status_code=422, detail="Unknown status filter")
            where = "WHERE status = ?"
            params.append(status)
        rows = db.fetch_all(
            f"""
            SELECT incident_id, case_id, title, verdict, priority, confidence,
                   route, needs_human, status, updated_at
            FROM incidents
            {where}
            ORDER BY {PRIORITY_ORDER}, confidence DESC, incident_id ASC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        )
        total = db.fetch_one(
            f"SELECT COUNT(*) AS count FROM incidents {where}", params
        )
        return {
            "items": [{**row, "needs_human": bool(row["needs_human"])} for row in rows],
            "total": int(total["count"]) if total else 0,
            "limit": limit,
            "offset": offset,
        }

    @app.get("/api/incidents/{incident_id}")
    def get_incident(incident_id: str) -> dict[str, Any]:
        row = db.fetch_one("SELECT * FROM incidents WHERE incident_id = ?", [incident_id])
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        reviews = db.fetch_all(
            "SELECT * FROM reviews WHERE incident_id = ? ORDER BY id ASC", [incident_id]
        )
        audit = db.fetch_all(
            "SELECT * FROM audit_events WHERE incident_id = ? ORDER BY id ASC",
            [incident_id],
        )
        return {
            "incident": incident_row(row),
            "reviews": reviews,
            "audit": audit,
        }

    @app.get("/api/decisions")
    def list_decisions(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        rows = db.fetch_all(
            f"""
            SELECT incident_id, title, verdict, priority, confidence, route,
                   needs_human, status, updated_at
            FROM incidents
            ORDER BY {PRIORITY_ORDER}, confidence DESC, incident_id ASC
            LIMIT ? OFFSET ?
            """,
            [limit, offset],
        )
        return {
            "items": [{**row, "needs_human": bool(row["needs_human"])} for row in rows]
        }

    @app.post("/api/incidents/{incident_id}/review")
    def review_incident(
        incident_id: str,
        payload: ReviewRequest,
        _: None = Depends(require_review_token),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        if payload.action == "edit" and not (
            payload.edited_verdict or payload.edited_priority
        ):
            raise HTTPException(status_code=422, detail="Edit requires a changed field")
        if payload.action != "edit" and (
            payload.edited_verdict or payload.edited_priority
        ):
            raise HTTPException(status_code=422, detail="Only edit may change fields")
        if idempotency_key and len(idempotency_key) > 120:
            raise HTTPException(status_code=422, detail="Idempotency key is too long")

        with db.connect() as connection:
            row = connection.execute(
                db._sql("SELECT * FROM incidents WHERE incident_id = ?"), [incident_id]
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Incident not found")
            current = dict(row)
            if idempotency_key:
                existing = connection.execute(
                    db._sql("SELECT * FROM reviews WHERE idempotency_key = ?"),
                    [idempotency_key],
                ).fetchone()
                if existing:
                    return {"review": dict(existing), "duplicate": True}

            now = utc_now()
            insert_sql = db._sql(
                """
                INSERT INTO reviews (
                    incident_id, reviewer, action, note, edited_verdict,
                    edited_priority, created_at, idempotency_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """
            )
            params = [
                incident_id,
                payload.reviewer.strip(),
                payload.action,
                payload.note.strip(),
                payload.edited_verdict,
                payload.edited_priority,
                now,
                idempotency_key,
            ]
            if db.is_postgres:
                inserted = connection.execute(
                    insert_sql + " RETURNING *", params
                ).fetchone()
                review = dict(inserted)
            else:
                cursor = connection.execute(insert_sql, params)
                review = {
                    "id": cursor.lastrowid,
                    "incident_id": incident_id,
                    "reviewer": payload.reviewer.strip(),
                    "action": payload.action,
                    "note": payload.note.strip(),
                    "edited_verdict": payload.edited_verdict,
                    "edited_priority": payload.edited_priority,
                    "created_at": now,
                    "idempotency_key": idempotency_key,
                }

            status = STATUS_BY_ACTION[payload.action]
            verdict = payload.edited_verdict or current["verdict"]
            priority = payload.edited_priority or current["priority"]
            connection.execute(
                db._sql(
                    """
                    UPDATE incidents
                    SET status = ?, verdict = ?, priority = ?, updated_at = ?
                    WHERE incident_id = ?
                    """
                ),
                [status, verdict, priority, now, incident_id],
            )
            details = _json_value(
                {
                    "review_id": review["id"],
                    "action": payload.action,
                    "reviewer": payload.reviewer.strip(),
                    "note": payload.note.strip(),
                    "edited_verdict": payload.edited_verdict,
                    "edited_priority": payload.edited_priority,
                },
                db.is_postgres,
            )
            connection.execute(
                db._sql(
                    """
                    INSERT INTO audit_events (incident_id, actor, action, details, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """
                ),
                [
                    incident_id,
                    payload.reviewer.strip(),
                    f"review.{payload.action}",
                    details,
                    now,
                ],
            )
        return {"review": review, "status": status, "duplicate": False}

    @app.get("/api/audit")
    def audit(
        incident_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, Any]:
        if incident_id:
            rows = db.fetch_all(
                "SELECT * FROM audit_events WHERE incident_id = ? ORDER BY id DESC LIMIT ?",
                [incident_id, limit],
            )
        else:
            rows = db.fetch_all(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", [limit]
            )
        return {"items": rows}

    @app.get("/api/metrics")
    def metrics() -> dict[str, Any]:
        status_rows = db.fetch_all(
            "SELECT status, COUNT(*) AS count FROM incidents GROUP BY status"
        )
        verdict_rows = db.fetch_all(
            "SELECT verdict, COUNT(*) AS count FROM incidents GROUP BY verdict"
        )
        review_count = db.fetch_one("SELECT COUNT(*) AS count FROM reviews")
        return {
            "incidents": sum(int(row["count"]) for row in status_rows),
            "reviews": int(review_count["count"]) if review_count else 0,
            "by_status": {row["status"]: int(row["count"]) for row in status_rows},
            "by_verdict": {row["verdict"]: int(row["count"]) for row in verdict_rows},
            "demo": True,
            "note": "Demo decisions are precomputed from reports/w3_traces.json.",
        }

    if PUBLIC_DIR.exists():
        app.mount("/", StaticFiles(directory=PUBLIC_DIR, html=True), name="ui")

    return app


app = create_app()
