from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from triage.config import LABELS, REQUIRED_RAW_COLUMNS
from triage.data import (
    build_manifest,
    normalize_label,
    quality_report,
    run_etl,
    validate_manifest,
)
from triage.fixture import write_fixture


def _minimal_incidents(path: Path, rows: int = 60, train_rows: int = 40) -> None:
    labels = ["true_positive", "benign_positive", "false_positive"]
    records = []
    for index in range(rows):
        split = "test" if index >= train_rows else "train"
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
    assert train_header.split(",") == list(REQUIRED_RAW_COLUMNS)
    assert test_header.split(",") == [*REQUIRED_RAW_COLUMNS, "Usage"]


def test_etl_aggregates_rows_to_incidents(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    write_fixture(raw_dir)
    stats = run_etl(raw_dir, tmp_path / "incidents.parquet")
    assert stats["incidents_parquet"]["rows"] == 120
    assert stats["split_counts"] == {"test": 40, "train": 80}
    assert stats["label_conflicts"] == 0
    assert stats["null_timestamps"] == 0


def test_etl_aggregates_known_incident(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    write_fixture(raw_dir)
    out = tmp_path / "incidents.parquet"
    run_etl(raw_dir, out)
    frame = pd.read_parquet(out).set_index("incident_id")
    incident = frame.loc["1:10000"]
    assert incident["split"] == "train"
    assert incident["triage_label"] == "true_positive"
    assert incident["alert_count"] == 1
    assert incident["evidence_count"] == 2
    assert incident["has_mitre"] == 1
    assert incident["malicious_count"] == 2
    assert incident["suspicious_count"] == 2
    assert incident["summary"] == (
        "InitialAccess T1078 Account Device Actor Target "
        "Suspicious Malicious Device Victim Malware 1"
    )


def test_etl_rejects_missing_columns(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    pd.DataFrame({"IncidentId": ["1"], "IncidentGrade": ["TruePositive"]}).to_csv(
        raw_dir / "GUIDE_Train.csv", index=False
    )
    with pytest.raises(ValueError, match="missing required columns"):
        run_etl(raw_dir, tmp_path / "incidents.parquet")


def test_etl_checks_columns_in_each_file(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    info = write_fixture(raw_dir)
    test_path = Path(info["test_path"])
    frame = pd.read_csv(test_path, dtype=str).drop(columns=["OrgId"])
    frame.to_csv(test_path, index=False)
    with pytest.raises(ValueError, match="GUIDE_Test.csv is missing required columns"):
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


def test_manifest_rejects_changed_arguments(tmp_path: Path) -> None:
    incidents = tmp_path / "incidents.parquet"
    _minimal_incidents(incidents)
    manifest_path = tmp_path / "split_v1.json"
    build_manifest(
        incidents,
        out_dir=tmp_path,
        manifest_path=manifest_path,
        sample_size=1_000,
    )
    with pytest.raises(ValueError, match="Use --force"):
        build_manifest(
            incidents,
            out_dir=tmp_path,
            manifest_path=manifest_path,
            sample_size=500,
        )


def test_manifest_holds_out_dev_without_losing_classes(tmp_path: Path) -> None:
    incidents = tmp_path / "incidents.parquet"
    _minimal_incidents(incidents, rows=150, train_rows=110)
    manifest = build_manifest(
        incidents,
        out_dir=tmp_path,
        manifest_path=tmp_path / "split_v1.json",
        sample_size=1_000,
    )
    assert manifest["splits"]["dev"]["rows"] > 0
    assert set(manifest["splits"]["dev"]["label_counts"]) == set(LABELS)
    assert validate_manifest(tmp_path / "split_v1.json")["passed"]


def test_manifest_keeps_single_row_class_in_train(tmp_path: Path) -> None:
    incidents = tmp_path / "incidents.parquet"
    _minimal_incidents(incidents, rows=150, train_rows=110)
    frame = pd.read_parquet(incidents)
    train_benign = frame.index[
        (frame["split"] == "train") & (frame["triage_label"] == "benign_positive")
    ]
    frame.loc[train_benign[1:], "triage_label"] = "true_positive"
    frame.to_parquet(incidents, index=False)
    manifest = build_manifest(
        incidents,
        out_dir=tmp_path,
        manifest_path=tmp_path / "split_v1.json",
        sample_size=1_000,
    )
    assert manifest["splits"]["train"]["label_counts"]["benign_positive"] == 1
    assert manifest["splits"]["dev"]["label_counts"]["benign_positive"] == 0


def test_manifest_reports_local_carve_out(tmp_path: Path) -> None:
    incidents = tmp_path / "incidents.parquet"
    _minimal_incidents(incidents, rows=150, train_rows=110)
    frame = pd.read_parquet(incidents)
    frame.loc[frame["split"] == "test", "triage_label"] = None
    frame.to_parquet(incidents, index=False)
    manifest = build_manifest(
        incidents,
        out_dir=tmp_path,
        manifest_path=tmp_path / "split_v1.json",
        sample_size=1_000,
    )
    assert manifest["test_source"] == "local_carve_out"
    assert any("local_carve_out" in warning for warning in manifest["warnings"])


def test_manifest_reports_partial_official_test(tmp_path: Path) -> None:
    incidents = tmp_path / "incidents.parquet"
    _minimal_incidents(incidents, rows=60)
    frame = pd.read_parquet(incidents)
    test_rows = frame.index[frame["split"] == "test"]
    frame.loc[test_rows[0], "triage_label"] = None
    frame.to_parquet(incidents, index=False)
    manifest = build_manifest(
        incidents,
        out_dir=tmp_path,
        manifest_path=tmp_path / "split_v1.json",
        sample_size=1_000,
    )
    assert manifest["test_source"] == "official_partial"
    assert manifest["splits"]["test"]["rows"] == 19
    assert any("official_partial" in warning for warning in manifest["warnings"])


def test_malformed_manifest_fails_validation(tmp_path: Path) -> None:
    manifest_path = tmp_path / "split_v1.json"
    manifest_path.write_text("{not json", encoding="utf-8")
    report = validate_manifest(manifest_path)
    assert not report["passed"]
    assert report["checks"][0]["name"] == "manifest parses"


def test_quality_report_flags_duplicate_incidents(tmp_path: Path) -> None:
    path = tmp_path / "duplicates.parquet"
    frame = pd.DataFrame(
        {
            "incident_id": ["org:1", "org:1"],
            "triage_label": ["true_positive", "true_positive"],
            "triage_label_raw": ["True Positive", "True Positive"],
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
