from __future__ import annotations

from pathlib import Path
from typing import Any

from triage.baselines import run_baselines
from triage.config import SEED
from triage.data import build_manifest, run_etl
from triage.fixture import write_fixture


def run_fixture_eval(work_dir: Path, seed: int = SEED) -> dict[str, Any]:
    work_dir = Path(work_dir)
    raw_dir = work_dir / "raw"
    processed_dir = work_dir / "processed"
    manifest_dir = work_dir / "manifests"
    reports_dir = work_dir / "reports"

    write_fixture(raw_dir)
    stats = run_etl(
        raw_dir=raw_dir,
        out_path=processed_dir / "incidents.parquet",
        stats_path=processed_dir / "etl_stats.json",
    )
    manifest = build_manifest(
        incidents_path=processed_dir / "incidents.parquet",
        out_dir=processed_dir,
        manifest_path=manifest_dir / "split_v1.json",
        sample_size=10_000,
        seed=seed,
        force=True,
    )
    metadata = run_baselines(
        train_path=processed_dir / "train.parquet",
        dev_path=processed_dir / "dev.parquet",
        test_path=processed_dir / "test.parquet",
        manifest_path=manifest_dir / "split_v1.json",
        report_path=reports_dir / "w1_baselines.md",
        metrics_path=reports_dir / "w1_metrics.json",
        dataset_label="fixture",
        seed=seed,
    )
    return {
        "work_dir": str(work_dir),
        "report": str(reports_dir / "w1_baselines.md"),
        "metrics": str(reports_dir / "w1_metrics.json"),
        "manifest": str(manifest_dir / "split_v1.json"),
        "test_source": manifest.get("test_source"),
        "raw_rows": stats["incidents_parquet"]["rows"],
        "macro_f1": {
            name: round(result["macro_f1"], 4)
            for name, result in metadata["models"].items()
        },
    }
