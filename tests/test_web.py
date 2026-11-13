from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from triage.web.app import create_app
from triage.web.db import Database
from triage.web.seed import seed_database

TOKEN = {"X-Review-Token": "demo-review-token"}


@pytest.fixture()
def client(tmp_path: Path):
    db = Database(f"sqlite:///{tmp_path / 'review.db'}")
    seed_database(db, reset=True)
    app = create_app(db)
    with TestClient(app) as test_client:
        yield test_client


def test_health_and_queue(client: TestClient) -> None:
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["demo_mode"] is True

    queue = client.get("/api/incidents?limit=200")
    assert queue.status_code == 200
    body = queue.json()
    assert body["total"] == 20
    assert len(body["items"]) == 20
    assert {"incident_id", "verdict", "priority", "confidence"} <= set(body["items"][0])


def test_detail_includes_evidence_and_history(client: TestClient) -> None:
    response = client.get("/api/incidents/0:809")
    assert response.status_code == 200
    body = response.json()
    assert body["incident"]["incident_id"] == "0:809"
    assert len(body["incident"]["evidence"]) >= 1
    assert body["reviews"] == []
    assert body["audit"] == []


def test_review_requires_token(client: TestClient) -> None:
    response = client.post(
        "/api/incidents/0:809/review",
        json={"action": "approve", "reviewer": "analyst"},
    )
    assert response.status_code == 401


def test_review_is_idempotent_and_audited(client: TestClient) -> None:
    payload = {
        "action": "approve",
        "reviewer": "analyst",
        "note": "Confirmed with evidence.",
    }
    headers = {**TOKEN, "Idempotency-Key": "case-809-approve"}
    first = client.post("/api/incidents/0:809/review", json=payload, headers=headers)
    assert first.status_code == 200
    assert first.json()["duplicate"] is False
    assert first.json()["status"] == "approved"

    second = client.post("/api/incidents/0:809/review", json=payload, headers=headers)
    assert second.status_code == 200
    assert second.json()["duplicate"] is True

    detail = client.get("/api/incidents/0:809").json()
    assert detail["incident"]["status"] == "approved"
    assert len(detail["reviews"]) == 1
    assert detail["audit"][0]["action"] == "review.approve"

    audit = client.get("/api/audit?incident_id=0:809").json()
    assert len(audit["items"]) == 1


def test_edit_updates_verdict_and_priority(client: TestClient) -> None:
    response = client.post(
        "/api/incidents/0:809/review",
        json={
            "action": "edit",
            "reviewer": "analyst",
            "edited_verdict": "benign_positive",
            "edited_priority": "low",
        },
        headers=TOKEN,
    )
    assert response.status_code == 200
    detail = client.get("/api/incidents/0:809").json()
    assert detail["incident"]["verdict"] == "benign_positive"
    assert detail["incident"]["priority"] == "low"
    assert detail["incident"]["status"] == "edited"


def test_review_validation(client: TestClient) -> None:
    assert (
        client.post(
            "/api/incidents/0:809/review",
            json={"action": "edit", "reviewer": "analyst"},
            headers=TOKEN,
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/incidents/0:809/review",
            json={
                "action": "approve",
                "reviewer": "analyst",
                "edited_verdict": "false_positive",
            },
            headers=TOKEN,
        ).status_code
        == 422
    )
    assert client.get("/api/incidents?status=unknown").status_code == 422
    assert client.get("/api/incidents/missing").status_code == 404


def test_static_console_is_served(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "TriageBudget" in response.text
    assert "Review queue" in response.text


def test_metrics_counts_reviews(client: TestClient) -> None:
    client.post(
        "/api/incidents/0:809/review",
        json={"action": "reject", "reviewer": "analyst"},
        headers=TOKEN,
    )
    body = client.get("/api/metrics").json()
    assert body["incidents"] == 20
    assert body["reviews"] == 1
    assert body["by_status"]["rejected"] == 1
