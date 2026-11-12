from __future__ import annotations

import argparse
import json
from pathlib import Path

from triage.baselines import run_baselines
from triage.config import SAMPLE_SIZE, SEED
from triage.data import build_manifest, quality_report, run_etl
from triage.fixture import write_fixture
from triage.pipeline import run_fixture_eval


def _emit(payload: object) -> None:
    print(json.dumps(payload, indent=2))


def _cmd_etl(args: argparse.Namespace) -> int:
    stats = run_etl(
        raw_dir=Path(args.raw_dir),
        out_path=Path(args.out),
        stats_path=Path(args.stats) if args.stats else None,
    )
    _emit(stats)
    return 0


def _cmd_split(args: argparse.Namespace) -> int:
    manifest = build_manifest(
        incidents_path=Path(args.incidents),
        out_dir=Path(args.out_dir),
        manifest_path=Path(args.manifest),
        sample_size=args.sample_size,
        seed=args.seed,
        force=args.force,
    )
    _emit(
        {
            "manifest": args.manifest,
            "test_source": manifest.get("test_source"),
            "splits": {
                name: split.get("rows") for name, split in manifest.get("splits", {}).items()
            },
            "warnings": manifest.get("warnings", []),
        }
    )
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    report = quality_report(
        incidents_path=Path(args.incidents),
        manifest_path=Path(args.manifest) if args.manifest else None,
    )
    _emit(report)
    return 0 if report["passed"] else 1


def _cmd_baselines(args: argparse.Namespace) -> int:
    metadata = run_baselines(
        train_path=Path(args.train),
        dev_path=Path(args.dev) if args.dev else None,
        test_path=Path(args.test),
        manifest_path=Path(args.manifest),
        report_path=Path(args.report),
        metrics_path=Path(args.metrics),
        dataset_label=args.dataset,
        seed=args.seed,
    )
    _emit(
        {
            "dataset": metadata["dataset"],
            "report": args.report,
            "metrics": args.metrics,
            "macro_f1": {
                name: round(result["macro_f1"], 4)
                for name, result in metadata["models"].items()
            },
        }
    )
    passed = (
        metadata["manifest"]["validation_passed"] and metadata["data_checks"]["passed"]
    )
    return 0 if passed else 1


def _cmd_fixture(args: argparse.Namespace) -> int:
    info = write_fixture(
        raw_dir=Path(args.raw_dir),
        train_incidents=args.train_incidents,
        test_incidents=args.test_incidents,
    )
    _emit(info)
    return 0


def _cmd_fixture_eval(args: argparse.Namespace) -> int:
    result = run_fixture_eval(work_dir=Path(args.work_dir), seed=args.seed)
    _emit(result)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="triage")
    subparsers = parser.add_subparsers(dest="command", required=True)

    etl = subparsers.add_parser("etl", help="Aggregate GUIDE CSVs to incident Parquet")
    etl.add_argument("--raw-dir", default="data/raw")
    etl.add_argument("--out", default="data/processed/incidents.parquet")
    etl.add_argument("--stats", default="data/processed/etl_stats.json")
    etl.set_defaults(func=_cmd_etl)

    split = subparsers.add_parser("split", help="Freeze the train/dev/test manifest")
    split.add_argument("--incidents", default="data/processed/incidents.parquet")
    split.add_argument("--out-dir", default="data/processed")
    split.add_argument("--manifest", default="data/manifests/split_v1.json")
    split.add_argument("--sample-size", type=int, default=SAMPLE_SIZE)
    split.add_argument("--seed", type=int, default=SEED)
    split.add_argument("--force", action="store_true")
    split.set_defaults(func=_cmd_split)

    check = subparsers.add_parser("check", help="Run data-integrity and manifest checks")
    check.add_argument("--incidents", default="data/processed/incidents.parquet")
    check.add_argument("--manifest", default=None)
    check.set_defaults(func=_cmd_check)

    baselines = subparsers.add_parser(
        "baselines", help="Run majority, rules, and LightGBM baselines"
    )
    baselines.add_argument("--train", default="data/processed/train.parquet")
    baselines.add_argument("--dev", default="data/processed/dev.parquet")
    baselines.add_argument("--test", default="data/processed/test.parquet")
    baselines.add_argument("--manifest", default="data/manifests/split_v1.json")
    baselines.add_argument("--report", default="reports/w1_baselines.md")
    baselines.add_argument("--metrics", default="reports/w1_metrics.json")
    baselines.add_argument("--dataset", choices=["guide", "fixture"], default="guide")
    baselines.add_argument("--seed", type=int, default=SEED)
    baselines.set_defaults(func=_cmd_baselines)

    fixture = subparsers.add_parser("fixture", help="Generate synthetic GUIDE-shaped CSVs")
    fixture.add_argument("--raw-dir", default="tests/fixtures/guide_tiny")
    fixture.add_argument("--train-incidents", type=int, default=80)
    fixture.add_argument("--test-incidents", type=int, default=40)
    fixture.set_defaults(func=_cmd_fixture)

    fixture_eval = subparsers.add_parser(
        "fixture-eval", help="Generate fixture, run ETL, freeze split, and run baselines"
    )
    fixture_eval.add_argument("--work-dir", default="reports/fixture_run")
    fixture_eval.add_argument("--seed", type=int, default=SEED)
    fixture_eval.set_defaults(func=_cmd_fixture_eval)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
