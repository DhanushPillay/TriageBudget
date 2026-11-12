from __future__ import annotations

import json
from pathlib import Path

import pytest

from triage.data import quality_report, validate_manifest
from triage.pipeline import run_fixture_eval


@pytest.fixture(scope="session")
def fixture_run(tmp_path_factory: pytest.TempPathFactory) -> dict:
    work_dir = tmp_path_factory.mktemp("fixture_run")
    return run_fixture_eval(work_dir)


def test_fixture_pipeline_shapes(fixture_run: dict) -> None:
    manifest = json.loads(Path(fixture_run["manifest"]).read_text(encoding="utf-8"))
    assert manifest["test_source"] == "official"
    assert manifest["splits"]["train"]["rows"] == 80
    assert manifest["splits"]["dev"]["rows"] == 0
    assert manifest["splits"]["test"]["rows"] == 40
    assert manifest["splits"]["test"]["label_counts"] == {
        "true_positive": 16,
        "benign_positive": 12,
        "false_positive": 12,
    }


def test_fixture_manifest_validates(fixture_run: dict) -> None:
    assert validate_manifest(Path(fixture_run["manifest"]))["passed"]


def test_fixture_data_quality_passes(fixture_run: dict) -> None:
    report = quality_report(
        incidents_path=Path(fixture_run["work_dir"]) / "processed" / "incidents.parquet",
        manifest_path=Path(fixture_run["manifest"]),
    )
    assert report["passed"], report


def test_lgbm_beats_baselines(fixture_run: dict) -> None:
    metrics = json.loads(Path(fixture_run["metrics"]).read_text(encoding="utf-8"))
    scores = {name: result["macro_f1"] for name, result in metrics["models"].items()}
    assert scores["tfidf_lgbm"] > scores["majority"]
    assert scores["tfidf_lgbm"] > scores["rules"]
    assert scores["tfidf_lgbm"] == 1.0


def test_report_marks_fixture_as_non_benchmark(fixture_run: dict) -> None:
    report = Path(fixture_run["report"]).read_text(encoding="utf-8")
    assert "not GUIDE benchmark results" in report
    assert "GUIDE split manifest is frozen. Pending real files." in report
    assert "Fixture pipeline runs end to end." in report
