from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from triage.data import (
    build_manifest,
    normalize_label,
    quality_report,
    run_etl,
    validate_manifest,
)
from triage.fixture import write_fixture


def _minimal_incidents(path: Path, rows: int = 60) -> None:
    labels = ["true_positive", "benign_positive", "false_positive"]
    records = []
    for index in range(rows):
        split = "test" if index >= 40 else "train"
        records.append(
            {
                "incident_id": f"org:{index}",
                "triage_label": labels[index % len(labels)],
                "split": split,
                "label_conflict": False,
                "split_conflict": False,
                "created_at": pd.Timestamp("2024-01-01") + pd.Timedelta(hours=index),
                "summary": f"incident {index} suspicious",
            }
        )
    pd.DataFrame.from_records(records).to_parquet(path, index=False)


def test_label_mapping() -> None:
    assert normalize_label("TruePositive") == "true_positive"
    assert normalize_label("BenignPositive") == "benign_positive"
    assert normalize_label("FalsePositive") == "false_positive"
    assert normalize_label("unexpected") is None
    assert normalize_label(None) is None


def test_fixture_has_guide_columns(tmp_path: Path) -> None:
    info = write_fixture(tmp_path)
    train_header = Path(info["train_path"]).read_text(encoding="utf-8").splitlines()[0]
    test_header = Path(info["test_path"]).read_text(encoding="utf-8").splitlines()[0]
    assert len(train_header.split(",")) == 45
    assert len(test_header.split(",")) == 46
    assert "Usage" in test_header


def test_etl_aggregates_rows_to_incidents(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    write_fixture(raw_dir)
    stats = run_etl(raw_dir, tmp_path / "incidents.parquet")
    assert stats["incidents_parquet"]["rows"] == 120
    assert stats["split_counts"] == {"test": 40, "train": 80}
    assert stats["label_conflicts"] == 0
    assert stats["null_timestamps"] == 0


def test_etl_rejects_missing_columns(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    pd.DataFrame({"IncidentId": ["1"], "IncidentGrade": ["TruePositive"]}).to_csv(
        raw_dir / "GUIDE_Train.csv", index=False
    )
    with pytest.raises(ValueError, match="missing required columns"):
        run_etl(raw_dir, tmp_path / "incidents.parquet")


def test_manifest_freezes_and_validates(tmp_path: Path) -> None:
    incidents = tmp_path / "incidents.parquet"
    _minimal_incidents(incidents)
    manifest_path = tmp_path / "split_v1.json"
    manifest = build_manifest(
        incidents,
        out_dir=tmp_path,
        manifest_path=manifest_path,
        sample_size=1_000,
    )
    assert manifest["test_source"] == "official"
    assert manifest["splits"]["train"]["rows"] == 40
    assert manifest["splits"]["test"]["rows"] == 20

    frozen = build_manifest(
        incidents,
        out_dir=tmp_path,
        manifest_path=manifest_path,
        sample_size=1_000,
    )
    assert frozen["splits"]["train"]["ids_sha256"] == manifest["splits"]["train"]["ids_sha256"]
    assert validate_manifest(manifest_path)["passed"]


def test_manifest_detects_source_change(tmp_path: Path) -> None:
    incidents = tmp_path / "incidents.parquet"
    _minimal_incidents(incidents)
    manifest_path = tmp_path / "split_v1.json"
    build_manifest(
        incidents,
        out_dir=tmp_path,
        manifest_path=manifest_path,
        sample_size=1_000,
    )

    frame = pd.read_parquet(incidents)
    extra = frame.iloc[[0]].copy()
    extra.loc[:, "incident_id"] = "org:999"
    pd.concat([frame, extra], ignore_index=True).to_parquet(incidents, index=False)

    with pytest.raises(FileExistsError, match="does not validate"):
        build_manifest(
            incidents,
            out_dir=tmp_path,
            manifest_path=manifest_path,
            sample_size=1_000,
        )


def test_quality_report_flags_duplicate_incidents(tmp_path: Path) -> None:
    path = tmp_path / "duplicates.parquet"
    frame = pd.DataFrame(
        {
            "incident_id": ["org:1", "org:1"],
            "triage_label": ["true_positive", "true_positive"],
            "split": ["train", "train"],
            "label_conflict": [False, False],
            "split_conflict": [False, False],
            "created_at": [pd.Timestamp("2024-01-01"), pd.Timestamp("2024-01-02")],
            "summary": ["one", "two"],
        }
    )
    frame.to_parquet(path, index=False)
    report = quality_report(path)
    assert not report["passed"]
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "incident id unique" in failed
