from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
import pytest

from triage import selective
from triage.retrieval import SearchHit


def _frame() -> pd.DataFrame:
    rows = [
        ("a", "true_positive", "true_positive", 0.90),
        ("b", "true_positive", "true_positive", 0.80),
        ("c", "true_positive", "false_positive", 0.70),
        ("d", "true_positive", "false_positive", 0.60),
        ("e", "true_positive", "benign_positive", 0.95),
        ("f", "benign_positive", "benign_positive", 0.90),
        ("g", "benign_positive", "benign_positive", 0.80),
        ("h", "benign_positive", "false_positive", 0.70),
        ("i", "false_positive", "false_positive", 0.90),
        ("j", "false_positive", "false_positive", 0.80),
    ]
    return pd.DataFrame(
        rows,
        columns=["incident_id", "expected_label", "predicted_label", "confidence"],
    )


def test_curve_point_counts_coverage_and_tp_misses() -> None:
    point = selective.curve_point(_frame(), 0.65)
    assert point["total"] == 10
    assert point["covered"] == 6
    assert point["coverage"] == pytest.approx(0.6)
    assert point["tp_total"] == 5
    assert point["tp_miss"] == 1
    assert point["tp_miss_rate"] == pytest.approx(0.2)
    assert point["selective_errors"] == 2
    assert point["selective_risk"] == pytest.approx(1 / 3)
    assert point["review_minutes_per_100_incidents"] == pytest.approx(400.0)


def test_curve_coverage_is_monotone_in_threshold() -> None:
    curve = selective.risk_coverage_curve(_frame())
    coverages = [point["coverage"] for point in curve]
    assert coverages == sorted(coverages, reverse=True)
    assert len(curve) >= 5


def test_operating_point_prefers_max_coverage_under_miss_cap() -> None:
    point = selective.operating_point(selective.risk_coverage_curve(_frame()))
    assert point["threshold"] == 0.75
    assert point["coverage"] == pytest.approx(0.4)
    assert point["tp_miss_rate"] == 0.0
    assert point["meets_target"] is False
    assert point["coverage_shortfall"] == pytest.approx(0.2)


def test_budget_sensitivity_scales_with_review_cost() -> None:
    point = selective.curve_point(_frame(), 0.65)
    rows = selective.budget_sensitivity(point, minutes=(5, 10, 20))
    assert [row["minutes_per_review"] for row in rows] == [5, 10, 20]
    assert rows[1]["review_minutes_per_100_incidents"] == pytest.approx(400.0)


def test_slice_metrics_reports_each_class() -> None:
    rows = selective._slice_metrics(_frame(), "expected_label", 0.65)
    values = {row["value"] for row in rows}
    assert values == {"true_positive", "benign_positive", "false_positive"}
    tp = next(row for row in rows if row["value"] == "true_positive")
    assert tp["tp_cases"] == 5
    assert tp["tp_miss_rate"] == pytest.approx(0.2)


def test_sample_subset_is_stratified_and_fixed() -> None:
    frame = _frame().rename(columns={"expected_label": "expected_label"})
    subset = selective.sample_subset(frame, per_label=1, seed=42)
    assert len(subset) == 3
    assert subset["expected_label"].value_counts().to_dict() == {
        "true_positive": 1,
        "benign_positive": 1,
        "false_positive": 1,
    }
    again = selective.sample_subset(frame, per_label=1, seed=42)
    assert subset["incident_id"].tolist() == again["incident_id"].tolist()


def _trace(**overrides: Any) -> dict[str, Any]:
    decision = {
        "verdict": "false_positive",
        "confidence": 0.9,
        "route": "agent",
        "evidence": [
            {"source": "incident", "evidence_id": "incident:a"},
            {"source": "train_incident", "evidence_id": "train_incident:train1"},
        ],
    }
    decision.update(overrides.pop("decision", {}))
    trace: dict[str, Any] = {
        "case_id": "case",
        "incident_id": "a",
        "expected_label": "true_positive",
        "decision": decision,
        "schema_valid": True,
        "violations": [],
        "tool_calls": [],
    }
    trace.update(overrides)
    return trace


def test_categorize_error_priority_order() -> None:
    assert (
        selective.categorize_error(_trace(schema_valid=False), ["true_positive"])
        == "schema_error"
    )
    assert (
        selective.categorize_error(
            _trace(tool_calls=[{"name": "get_incident", "ok": False}]),
            ["true_positive"],
        )
        == "tool_failure"
    )
    assert (
        selective.categorize_error(
            _trace(violations=["evidence quote does not match source"]),
            ["true_positive"],
        )
        == "citation_error"
    )
    assert (
        selective.categorize_error(
            _trace(decision={"verdict": "undetermined"}), ["true_positive"]
        )
        == "abstention_error"
    )
    assert selective.categorize_error(_trace(), []) == "retrieval_miss"
    assert (
        selective.categorize_error(_trace(), ["false_positive"]) == "retrieval_noise"
    )
    assert (
        selective.categorize_error(
            _trace(decision={"confidence": 0.85}), ["true_positive"]
        )
        == "overconfidence"
    )
    assert (
        selective.categorize_error(
            _trace(
                expected_label="benign_positive",
                decision={"verdict": "false_positive", "confidence": 0.5},
            ),
            ["benign_positive"],
        )
        == "label_ambiguity"
    )
    assert (
        selective.categorize_error(
            _trace(decision={"confidence": 0.5}), ["benign_positive"]
        )
        == "reasoning_error"
    )


class FakeIndex:
    def search(self, *args: Any, **kwargs: Any) -> list[SearchHit]:
        return [
            SearchHit(
                doc_id="incident:train1",
                source="incident",
                source_id="train1",
                title="train",
                text="credential access",
                score=1.0,
                label="true_positive",
                categories=["CredentialAccess"],
                mitre=["T1078"],
            )
        ]


class FakeStore:
    def label(self, incident_id: str) -> str:
        return "true_positive"

    def public(self, incident_id: str) -> dict[str, Any]:
        return {
            "incident_id": incident_id,
            "summary": "credential access",
            "categories": ["CredentialAccess"],
            "mitre": ["T1078"],
        }


def test_rag_predictions_uses_retrieved_vote() -> None:
    rows = selective.rag_predictions(FakeIndex(), FakeStore(), ["dev:1"])
    assert rows.loc[0, "predicted_label"] == "true_positive"
    assert rows.loc[0, "confidence"] == pytest.approx(1.0)
    assert rows.loc[0, "retrieval_hits"] == 1


def test_agent_frame_flattens_trace() -> None:
    trace = {
        "incident_id": "a",
        "expected_label": "true_positive",
        "decision": {
            "verdict": "false_positive",
            "confidence": 0.7,
            "needs_human": True,
            "route": "human",
            "evidence": [{"source": "incident"}],
        },
        "schema_valid": True,
        "violations": [],
        "tool_calls": [{"name": "get_incident"}],
        "latency_ms": 12,
    }
    frame = selective.agent_frame([trace])
    assert frame.loc[0, "predicted_label"] == "false_positive"
    assert frame.loc[0, "tool_calls"] == 1
    assert frame.loc[0, "citations"] == 1


def test_queue_metrics_joins_and_ranks(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(selective, "RAW_DIR", tmp_path)
    pd.DataFrame(
        {
            "OrgId": [0, 0, 0, 0],
            "IncidentId": [1, 2, 3, 4],
            "QueueRank": [1, 2, 3, 4],
        }
    ).to_csv(tmp_path / "GUIDE_Test_Queue_Rankings.csv", index=False)
    predictions = pd.DataFrame(
        {
            "incident_id": ["0:1", "0:2", "0:3", "0:4"],
            "org_id": ["0", "0", "0", "0"],
            "incident_id_raw": [1, 2, 3, 4],
            "expected_label": [
                "true_positive",
                "false_positive",
                "true_positive",
                "benign_positive",
            ],
            "p_true_positive": [0.1, 0.9, 0.8, 0.2],
        }
    )
    result = selective._queue_metrics(predictions)
    assert result["rows"] == 4
    assert result["orgs"] == 1
    assert result["model_p_at_5"] == pytest.approx(0.5)
    assert result["analyst_p_at_5"] == pytest.approx(0.5)


def test_render_retrieval_report_marks_missing_methods() -> None:
    metrics = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "retrieval": {
            "queries": 1,
            "gold": "proxy",
            "smoke": {"passed": 1, "queries": 1},
            "ablations": {
                "bm25": {
                    "incident": {
                        "recall@5": 0.1,
                        "recall@10": 0.2,
                        "ndcg@10": 0.3,
                        "mrr": 0.4,
                    },
                    "playbook": {"recall@5": 0.5, "recall@10": 0.6},
                    "median_latency_ms": 1.0,
                }
            },
        },
    }
    report = selective.render_retrieval_report(metrics)
    assert "Week 4 retrieval ablations" in report
    assert "| dense | not measured" in report


def test_bootstrap_metric_brackets_point_estimate() -> None:
    rng = np.random.default_rng(0)
    y_true = rng.choice(["true_positive", "benign_positive", "false_positive"], 200)
    y_pred = y_true.copy()
    y_pred[:20] = "false_positive"
    low, high = selective.bootstrap_metric(y_true, y_pred, n_bootstrap=50, seed=0)
    assert low <= high
    assert 0.0 <= low <= 1.0
