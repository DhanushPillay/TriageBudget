from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from triage.web import ai
from triage.web.app import create_app
from triage.web.db import Database
from triage.web.seed import seed_database

TOKEN = {"X-Review-Token": "demo-review-token"}
INCIDENT = "0:809"


def _reply(payload: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        json={
            "choices": [{"message": {"content": json.dumps(payload)}}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 60},
        },
    )


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    db = Database(f"sqlite:///{tmp_path / 'explain.db'}")
    seed_database(db, reset=True)
    with TestClient(create_app(db)) as test_client:
        yield test_client


def _mock(monkeypatch: pytest.MonkeyPatch, handler) -> list[httpx.Request]:
    calls: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)

    transport = httpx.MockTransport(record)
    monkeypatch.setattr(ai, "http_client", lambda: httpx.Client(transport=transport))
    return calls


def _good_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    prompt = body["messages"][1]["content"]
    incident = json.loads(prompt.split("<incident>")[1].split("</incident>")[0])
    cited = incident["evidence"][0]["evidence_id"]
    return _reply(
        {
            "explanation": "The classifier matched known credential access activity.",
            "evidence_ids": [cited],
            "uncertainty": "medium",
            "next_step": "Confirm the account owner with the identity team.",
        }
    )


def test_explain_caches_per_source(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _mock(monkeypatch, _good_handler)

    detail = client.get(f"/api/incidents/{INCIDENT}").json()
    assert detail["explanation"] is None

    response = client.post(f"/api/incidents/{INCIDENT}/explain", headers=TOKEN)
    assert response.status_code == 200
    body = response.json()
    assert body["cached"] is False
    assert body["explanation"]["uncertainty"] == "medium"
    assert body["explanation"]["model"] == "openai/gpt-oss-120b"
    assert body["explanation"]["prompt_version"] == ai.PROMPT_VERSION
    assert body["explanation"]["evidence_ids"]
    assert len(calls) == 1

    again = client.post(f"/api/incidents/{INCIDENT}/explain", headers=TOKEN)
    assert again.status_code == 200
    assert again.json()["cached"] is True
    assert len(calls) == 1

    detail = client.get(f"/api/incidents/{INCIDENT}").json()
    assert detail["explanation"]["explanation"] == body["explanation"]["explanation"]


def test_explain_requires_token(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _mock(monkeypatch, _good_handler)
    response = client.post(f"/api/incidents/{INCIDENT}/explain")
    assert response.status_code == 401
    assert calls == []


def test_explain_without_key_returns_503(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    response = client.post(f"/api/incidents/{INCIDENT}/explain", headers=TOKEN)
    assert response.status_code == 503


def test_unknown_evidence_id_is_rejected(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _reply(
            {
                "explanation": "Something plausible.",
                "evidence_ids": ["invented-1"],
                "uncertainty": "low",
                "next_step": "Check the host.",
            }
        )

    _mock(monkeypatch, handler)
    response = client.post(f"/api/incidents/{INCIDENT}/explain", headers=TOKEN)
    assert response.status_code == 502
    assert "not retrieved" in response.json()["detail"]


def test_upstream_failure_retries_then_fails(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _mock(monkeypatch, lambda request: httpx.Response(500))
    response = client.post(f"/api/incidents/{INCIDENT}/explain", headers=TOKEN)
    assert response.status_code == 502
    assert len(calls) == 2


def test_health_reports_ai_configuration(client: TestClient) -> None:
    assert client.get("/health").json()["ai_configured"] is True
