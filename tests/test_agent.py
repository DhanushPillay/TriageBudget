from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
import pytest

from triage.agent import (
    EvidenceCitation,
    OfflineAgent,
    Remediation,
    ToolBudgetExceeded,
    ToolContext,
    TriageDecision,
    _policy,
    _propose_actions,
    _summarize,
    render_report,
)
from triage.config import ROOT
from triage.retrieval import SearchHit


def _public(incident_id: str = "dev:1", **overrides: Any) -> dict[str, Any]:
    payload = {
        "incident_id": incident_id,
        "title": "Impossible travel",
        "alert_title": "Cloud login",
        "summary": "CredentialAccess T1078 impossible travel cloud login",
        "created_at": "2026-01-01 00:00:00",
        "org_hash": "abc123",
        "alert_count": 10,
        "evidence_count": 20,
        "detector_count": 2,
        "entity_type_count": 2,
        "category_count": 1,
        "has_mitre": 1,
        "suspicious_count": 2,
        "verdict_count": 1,
        "malicious_count": 0,
        "sha256_count": 0,
        "ip_count": 1,
        "url_count": 0,
        "account_count": 1,
        "device_count": 1,
        "registry_count": 0,
        "file_count": 0,
        "email_count": 0,
        "categories": ["CredentialAccess"],
        "mitre": ["T1078"],
        "threat_families": [],
        "suspicion_levels": [],
        "last_verdicts": [],
    }
    payload.update(overrides)
    return payload


class FakeStore:
    def __init__(self, public: dict[str, Any] | None = None) -> None:
        self.payload = public or _public()

    def public(self, incident_id: str) -> dict[str, Any]:
        return self.payload

    def inference_frame(self, incident_id: str) -> pd.DataFrame:
        return pd.DataFrame([{"incident_id": incident_id}])


class FakeClassifier:
    model_version = "fake_classifier_v1"

    def __init__(self, probabilities: list[float]) -> None:
        self.probabilities = np.asarray(probabilities)

    def predict_frame(self, frame: pd.DataFrame) -> np.ndarray:
        return self.probabilities.reshape(1, -1)


class FakeIndex:
    def search(self, *args: Any, **kwargs: Any) -> list[SearchHit]:
        source = kwargs.get("source")
        if source == "playbook":
            return [
                SearchHit(
                    doc_id="playbook:credential:containment",
                    source="playbook",
                    source_id="playbook:credential:containment",
                    title="Credential playbook / Containment",
                    text="Reset credentials and revoke sessions.",
                    score=0.5,
                    categories=["CredentialAccess"],
                    metadata={"heading": "Containment"},
                )
            ]
        return [
            SearchHit(
                doc_id="incident:train1",
                source="incident",
                source_id="train1",
                title="Past credential incident",
                text="CredentialAccess T1078 impossible travel",
                score=0.8,
                label="true_positive",
                categories=["CredentialAccess"],
                mitre=["T1078"],
                metadata={},
            )
        ]


def test_decision_validation_rejects_uncited_true_positive():
    decision = TriageDecision(
        incident_id="dev:1",
        verdict="true_positive",
        priority="high",
        remediation=[],
        evidence=[],
        confidence=0.8,
        needs_human=False,
        route="auto_escalate",
        classifier_version="v1",
        prompt_version="p1",
        tool_calls=1,
        latency_ms=1,
        cost_usd=0.0,
    )
    assert "true_positive requires at least one citation" in decision.validate()


def test_decision_validation_rejects_containment_on_benign():
    decision = TriageDecision(
        incident_id="dev:1",
        verdict="benign_positive",
        priority="medium",
        remediation=[
            Remediation(
                action="contain_host",
                target="affected_host",
                rationale="Evidence incident:dev:1 supports containment.",
            )
        ],
        evidence=[
            EvidenceCitation(
                evidence_id="incident:dev:1",
                quote="summary",
                source="incident",
            )
        ],
        confidence=0.8,
        needs_human=False,
        route="agent",
        classifier_version="v1",
        prompt_version="p1",
        tool_calls=1,
        latency_ms=1,
        cost_usd=0.0,
    )
    problems = decision.validate()
    assert any("incompatible with benign_positive" in problem for problem in problems)


def test_propose_actions_uses_only_citations_and_taxonomy():
    proposals = _propose_actions(
        "true_positive",
        ["CredentialAccess"],
        {"device_count": 1, "account_count": 1, "ip_count": 1},
        ["train_incident:1"],
    )
    assert {item["action"] for item in proposals} == {
        "contain_host",
        "disable_account",
        "block_indicator",
        "escalate_to_incident_response",
    }
    assert all("train_incident:1" in item["rationale"] for item in proposals)


def test_policy_abstains_on_malicious_verdict_false_positive():
    verdict, priority, route, needs_human, confidence = _policy(
        _public(malicious_count=813),
        np.asarray([0.35, 0.05, 0.60]),
        [],
    )
    assert verdict == "undetermined"
    assert route == "human"
    assert needs_human is True
    assert priority == "medium"
    assert confidence == pytest.approx(0.60)


def test_tool_context_enforces_cap():
    context = ToolContext({"echo": lambda value: value}, max_calls=1)
    assert context.call("echo", value="one") == "one"
    with pytest.raises(ToolBudgetExceeded):
        context.call("echo", value="two")


def test_offline_agent_produces_valid_trace():
    agent = OfflineAgent(
        FakeClassifier([0.8, 0.1, 0.1]),
        FakeIndex(),
        FakeStore(),
        ROOT / "prompts",
    )
    trace = agent.run({"case_id": "case_01", "incident_id": "dev:1"}, "true_positive")
    assert trace.schema_valid is True
    assert trace.decision.verdict == "true_positive"
    assert trace.decision.route == "auto_escalate"
    assert trace.decision.evidence[0].source == "incident"
    assert all(call.ok for call in trace.tool_calls)
    assert len(trace.tool_calls) == 5
    assert trace.prompt_sha256
    assert trace.expected_label == "true_positive"


def test_summarize_and_report_include_gates():
    trace = {
        "case_id": "case_01",
        "incident_id": "dev:1",
        "expected_label": "true_positive",
        "decision": {
            "incident_id": "dev:1",
            "verdict": "true_positive",
            "priority": "high",
            "remediation": [],
            "evidence": [
                {
                    "evidence_id": "incident:dev:1",
                    "quote": "summary",
                    "source": "incident",
                }
            ],
            "confidence": 0.8,
            "needs_human": False,
            "route": "auto_escalate",
            "classifier_version": "v1",
            "prompt_version": "p1",
            "tool_calls": 5,
            "latency_ms": 10,
            "cost_usd": 0.0,
        },
        "probabilities": {"true_positive": 0.8},
        "top_label": "true_positive",
        "tool_calls": [{"name": "get_incident", "args": {}, "ok": True,
                        "latency_ms": 1, "result_size": 1, "preview": "",
                        "error": None}],
        "revision_count": 0,
        "prompt_version": "p1",
        "prompt_sha256": "abc",
        "prompt_chars": 10,
        "llm_backend": "offline_policy",
        "schema_valid": True,
        "violations": [],
        "latency_ms": 10,
        "cost_usd": 0.0,
        "notes": [],
    }
    metrics = _summarize([trace], "fixture")
    assert metrics["schema_valid"] == 1
    assert metrics["gates"]["zero_hard_constraint_violations"] is True
    report = render_report(metrics, [trace])
    assert "Week 3 agent report" in report
    assert "case_01" in report
