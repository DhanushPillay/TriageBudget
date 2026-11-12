from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from triage import cli as cli_module
from triage.baselines import _verify_split_provenance
from triage.data import quality_report, sha256_file, validate_manifest
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


def _write_ids(path: Path, ids: list[str]) -> None:
    pd.DataFrame({"incident_id": ids}).to_parquet(path, index=False)


def test_provenance_rejects_split_hash_mismatch(tmp_path: Path) -> None:
    train = tmp_path / "train.parquet"
    test = tmp_path / "test.parquet"
    _write_ids(train, ["a"])
    _write_ids(test, ["b"])
    manifest = {
        "splits": {
            "train": {"file_sha256": sha256_file(train)},
            "test": {"file_sha256": "0" * 64},
        }
    }
    with pytest.raises(ValueError, match="test split does not match"):
        _verify_split_provenance(manifest, train, None, test, dev_rows=0)


def test_provenance_rejects_incident_overlap(tmp_path: Path) -> None:
    train = tmp_path / "train.parquet"
    test = tmp_path / "test.parquet"
    _write_ids(train, ["a"])
    _write_ids(test, ["a"])
    manifest = {
        "splits": {
            "train": {"file_sha256": sha256_file(train)},
            "test": {"file_sha256": sha256_file(test)},
        }
    }
    with pytest.raises(ValueError, match="share 1 incident"):
        _verify_split_provenance(manifest, train, None, test, dev_rows=0)


def test_baselines_command_returns_failure_when_checks_fail(monkeypatch) -> None:
    metadata = {
        "dataset": "guide",
        "models": {"majority": {"macro_f1": 0.1}},
        "manifest": {"validation_passed": True},
        "data_checks": {"passed": False},
    }
    monkeypatch.setattr(cli_module, "run_baselines", lambda **_: metadata)
    args = SimpleNamespace(
        train="train.parquet",
        dev=None,
        test="test.parquet",
        manifest="split_v1.json",
        report="report.md",
        metrics="metrics.json",
        dataset="guide",
        seed=42,
    )
    assert cli_module._cmd_baselines(args) == 1
    metadata["data_checks"]["passed"] = True
    assert cli_module._cmd_baselines(args) == 0
