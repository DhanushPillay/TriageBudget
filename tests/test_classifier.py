from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

from triage import cli as cli_module
from triage.classifier import (
    MODEL_VERSION,
    TP_INDEX,
    ClassifierArtifacts,
    IsotonicCalibrator,
    TemperatureCalibrator,
    VectorCalibrator,
    _add_engineered,
    _ece,
    _queue_ranking,
    load_classifier,
    run_classifier,
)
from triage.config import LABELS
from triage.pipeline import run_fixture_eval


def test_ece_is_zero_when_confidence_matches_accuracy() -> None:
    y = np.array([0, 1, 2, 0, 1, 2])
    probs = np.eye(3)[y]
    assert _ece(y, probs) == pytest.approx(0.0)


def test_temperature_scaling_reduces_overconfidence() -> None:
    rng = np.random.default_rng(0)
    y = rng.integers(0, 3, size=2_000)
    probs = np.full((len(y), 3), 0.005)
    probs[np.arange(len(y)), y] = 0.99
    wrong = rng.random(len(y)) < 0.3
    probs[wrong] = 0.005
    probs[wrong, (y[wrong] + 1) % 3] = 0.99

    calibrator = TemperatureCalibrator().fit(probs, y)
    assert calibrator.temperature > 1.0
    assert _ece(y, calibrator.predict_proba(probs)) <= _ece(y, probs)


def test_vector_and_isotonic_calibrators_normalize_rows() -> None:
    rng = np.random.default_rng(1)
    y = rng.integers(0, 3, size=500)
    probs = rng.dirichlet([5.0, 5.0, 5.0], size=len(y))
    for calibrator in (VectorCalibrator(), IsotonicCalibrator()):
        calibrated = calibrator.fit(probs, y).predict_proba(probs)
        assert np.allclose(calibrated.sum(axis=1), 1.0)
        assert (calibrated >= 0).all()


def test_add_engineered_features_uses_train_frequency() -> None:
    frame = pd.DataFrame(
        {
            "summary": ["alpha beta", "gamma"],
            "org_id": ["org_a", "org_b"],
            "created_at": pd.to_datetime(["2024-01-06 10:00", "2024-01-08 10:00"]),
            "event_day_of_week": [6, 1],
            "alert_count": [2, 0],
            "detector_count": [1, 0],
            "evidence_count": [4, 1],
            "entity_type_count": [2, 0],
            "threat_families": ["family_a", ""],
            "suspicious_count": [1, 0],
            "verdict_count": [0, 0],
        }
    )
    out = _add_engineered(frame, {"org_a": 0.75})
    assert out.loc[0, "org_frequency"] == pytest.approx(0.75)
    assert out.loc[1, "org_frequency"] == pytest.approx(0.0)
    assert out.loc[0, "is_weekend"] == pytest.approx(1.0)
    assert out.loc[1, "is_weekend"] == pytest.approx(0.0)
    assert out.loc[0, "alerts_per_detector"] == pytest.approx(2.0)
    assert out.loc[1, "alerts_per_detector"] == pytest.approx(0.0)
    assert out.loc[0, "threat_family_count"] == pytest.approx(1.0)


def test_queue_ranking_rewards_true_positive_order() -> None:
    per_queue = 60
    rows = per_queue * 2
    frame = pd.DataFrame(
        {
            "org_id": ["a"] * per_queue + ["b"] * per_queue,
            "malicious_count": [0] * rows,
            "verdict_count": [0] * rows,
            "has_mitre": [0] * rows,
            "suspicious_count": [0] * rows,
            "alert_count": list(range(per_queue)) * 2,
        }
    )
    y = np.full(rows, 2, dtype=int)
    y[:12] = TP_INDEX
    y[per_queue : per_queue + 12] = TP_INDEX
    probs = np.zeros((rows, 3))
    for start in (0, per_queue):
        probs[start : start + per_queue, TP_INDEX] = 1.0 - np.arange(per_queue) / per_queue

    result = _queue_ranking(frame, probs, y)
    assert result["queues"] == 2
    assert result["model"]["precision@10"] == pytest.approx(1.0)
    assert result["signal"]["precision@10"] == pytest.approx(0.0)
    assert result["beats_signal_at_10"] is True


@pytest.fixture(scope="session")
def classifier_fixture_run(tmp_path_factory: pytest.TempPathFactory) -> dict:
    work_dir = tmp_path_factory.mktemp("classifier_fixture")
    fixture = run_fixture_eval(work_dir / "pipeline")
    processed = Path(fixture["work_dir"]) / "processed"
    metadata = run_classifier(
        train_path=processed / "train.parquet",
        dev_path=processed / "dev.parquet",
        test_path=processed / "test.parquet",
        manifest_path=Path(fixture["manifest"]),
        report_path=work_dir / "reports" / "w2_classifier.md",
        metrics_path=work_dir / "reports" / "w2_metrics.json",
        model_dir=work_dir / "models" / "classifier_v1",
        dataset_label="fixture",
    )
    return {
        "work_dir": str(work_dir),
        "report": str(work_dir / "reports" / "w2_classifier.md"),
        "reliability": str(work_dir / "reports" / "w2_reliability.svg"),
        "model_dir": str(work_dir / "models" / "classifier_v1"),
        "metadata": metadata,
    }


def test_fixture_classifier_writes_artifacts(classifier_fixture_run: dict) -> None:
    assert Path(classifier_fixture_run["report"]).is_file()
    assert Path(classifier_fixture_run["reliability"]).is_file()
    model_dir = Path(classifier_fixture_run["model_dir"])
    for name in ("model.txt", "vectorizer.joblib", "calibrator.joblib", "metadata.json"):
        assert (model_dir / name).is_file()
    assert (model_dir / "model_card.md").is_file()


def test_fixture_classifier_is_usable(classifier_fixture_run: dict) -> None:
    metadata = classifier_fixture_run["metadata"]
    assert metadata["models"]["calibrated"]["macro_f1"] > 0.8
    assert metadata["calibration"]["selected"] in {
        "raw",
        "temperature",
        "vector",
        "isotonic",
    }
    report = Path(classifier_fixture_run["report"]).read_text(encoding="utf-8")
    assert "not GUIDE benchmark results" in report
    assert "Queue ranking proxy" in report


def test_classify_command_returns_failure_when_checks_fail(monkeypatch) -> None:
    metadata = {
        "dataset": "guide",
        "models": {
            "raw": {"macro_f1": 0.1, "scores": {"ece": 0.2}},
            "calibrated": {"macro_f1": 0.2, "scores": {"ece": 0.1}},
        },
        "calibration": {"selected": "raw"},
        "manifest": {"validation_passed": True},
        "data_checks": {"passed": False},
        "gates": {},
    }
    monkeypatch.setattr(cli_module, "run_classifier", lambda **_: metadata)
    args = SimpleNamespace(
        train="train.parquet",
        dev=None,
        test="test.parquet",
        manifest="split_v1.json",
        report="report.md",
        metrics="metrics.json",
        model_dir="model",
        reliability=None,
        dataset="guide",
        seed=42,
        grid=True,
    )
    assert cli_module._cmd_classify(args) == 1
    metadata["data_checks"]["passed"] = True
    assert cli_module._cmd_classify(args) == 0

def test_predict_frame_rejects_wrong_label_order() -> None:
    artifacts = ClassifierArtifacts(
        booster=None,
        vectorizer=None,
        calibrator=None,
        metadata={
            "model_version": MODEL_VERSION,
            "label_order": ["false_positive", "benign_positive", "true_positive"],
        },
    )
    with pytest.raises(ValueError, match="label order"):
        artifacts.predict_frame(pd.DataFrame())


def test_load_classifier_rejects_stale_version(tmp_path: Path) -> None:
    (tmp_path / "metadata.json").write_text(
        json.dumps({"model_version": "old", "label_order": list(LABELS)}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Unsupported classifier version"):
        load_classifier(tmp_path)


def test_load_classifier_rejects_wrong_label_order(tmp_path: Path) -> None:
    (tmp_path / "metadata.json").write_text(
        json.dumps(
            {
                "model_version": MODEL_VERSION,
                "label_order": ["false_positive", "benign_positive", "true_positive"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="label order"):
        load_classifier(tmp_path)
