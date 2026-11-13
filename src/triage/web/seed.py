from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from triage.config import ROOT
from triage.web.db import Database, default_database_url, utc_now

DEFAULT_TRACES = ROOT / "reports" / "w3_traces.json"


def _json_value(value: Any, postgres: bool) -> Any:
    if not postgres:
        return json.dumps(value)
    from psycopg.types.json import Jsonb

    return Jsonb(value)


def _incident_from_trace(trace: dict[str, Any]) -> dict[str, Any]:
    decision = trace["decision"]
    evidence = decision.get("evidence", [])
    summary = ""
    if evidence:
        summary = str(evidence[0].get("quote") or "")
    title = summary[:96].strip() or str(trace.get("case_id") or trace["incident_id"])
    probabilities = trace.get("probabilities") or {}
    now = utc_now()
    return {
        "incident_id": str(trace["incident_id"]),
        "case_id": str(trace.get("case_id") or trace["incident_id"]),
        "title": title,
        "summary": summary,
        "verdict": str(decision["verdict"]),
        "priority": str(decision["priority"]),
        "confidence": float(decision["confidence"]),
        "route": str(decision["route"]),
        "needs_human": bool(decision.get("needs_human")),
        "probabilities": probabilities,
        "evidence": evidence,
        "remediation": decision.get("remediation", []),
        "expected_label": trace.get("expected_label"),
        "status": "pending",
        "created_at": now,
        "updated_at": now,
    }


def seed_database(
    db: Database,
    traces_path: Path = DEFAULT_TRACES,
    reset: bool = False,
    if_empty: bool = False,
) -> int:
    db.init_schema()
    existing = db.fetch_one("SELECT COUNT(*) AS count FROM incidents")
    count = int(existing["count"]) if existing else 0
    if if_empty and count:
        return 0
    if reset:
        db.execute("DELETE FROM audit_events")
        db.execute("DELETE FROM reviews")
        db.execute("DELETE FROM incidents")
        count = 0
    traces = json.loads(Path(traces_path).read_text(encoding="utf-8"))
    inserted = 0
    for trace in traces:
        incident = _incident_from_trace(trace)
        params = [
            incident["incident_id"],
            incident["case_id"],
            incident["title"],
            incident["summary"],
            incident["verdict"],
            incident["priority"],
            incident["confidence"],
            incident["route"],
            incident["needs_human"],
            _json_value(incident["probabilities"], db.is_postgres),
            _json_value(incident["evidence"], db.is_postgres),
            _json_value(incident["remediation"], db.is_postgres),
            incident["expected_label"],
            incident["status"],
            incident["created_at"],
            incident["updated_at"],
        ]
        if db.is_postgres:
            db.execute(
                """
                INSERT INTO incidents (
                    incident_id, case_id, title, summary, verdict, priority,
                    confidence, route, needs_human, probabilities, evidence,
                    remediation, expected_label, status, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (incident_id) DO NOTHING
                """,
                params,
            )
        else:
            db.execute(
                """
                INSERT INTO incidents (
                    incident_id, case_id, title, summary, verdict, priority,
                    confidence, route, needs_human, probabilities, evidence,
                    remediation, expected_label, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO NOTHING
                """,
                params,
            )
        inserted += 1
    return inserted if not if_empty else len(traces) - count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed the TriageBudget demo database.")
    parser.add_argument("--db", default=default_database_url())
    parser.add_argument("--traces", default=str(DEFAULT_TRACES))
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--if-empty", action="store_true")
    args = parser.parse_args(argv)
    db = Database(args.db)
    inserted = seed_database(
        db,
        Path(args.traces),
        reset=args.reset,
        if_empty=args.if_empty,
    )
    print(json.dumps({"backend": db.backend, "inserted": inserted}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
