from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from sklearn.utils.class_weight import compute_sample_weight

from triage.config import LABELS, NUMERIC_FEATURES, ROOT, SEED
from triage.data import quality_report, validate_manifest

MODEL_VERSION = "tfidf_word_1_2_plus_numeric_lgbm_v1"


def _sql_path(path: Path) -> str:
    return path.resolve().as_posix().replace("'", "''")


def _display_path(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def load_frame(path: Path) -> pd.DataFrame:
    con = duckdb.connect()
    try:
        return con.execute(
            f"SELECT * FROM read_parquet('{_sql_path(Path(path))}')"
        ).df()
    finally:
        con.close()


def _check_labels(frame: pd.DataFrame, name: str) -> None:
    counts = frame["triage_label"].value_counts().to_dict()
    missing = [label for label in LABELS if counts.get(label, 0) == 0]
    if missing:
        raise ValueError(f"{name} split is missing labels: {missing}. Counts: {counts}")


def _numeric_matrix(frame: pd.DataFrame) -> csr_matrix:
    missing = [name for name in NUMERIC_FEATURES if name not in frame.columns]
    if missing:
        raise ValueError(f"Missing numeric features: {missing}")
    numeric = frame.loc[:, NUMERIC_FEATURES].apply(pd.to_numeric, errors="coerce")
    return csr_matrix(numeric.fillna(0).to_numpy(dtype=np.float32))


def _text_matrix(train: pd.DataFrame, test: pd.DataFrame) -> tuple[csr_matrix, csr_matrix]:
    train_text = train["summary"].fillna("").astype(str)
    test_text = test["summary"].fillna("").astype(str)
    min_df = 2 if len(train_text) >= 1_000 else 1
    vectorizer = TfidfVectorizer(
        max_features=5_000,
        ngram_range=(1, 2),
        min_df=min_df,
        sublinear_tf=True,
        strip_accents="unicode",
    )
    train_text_matrix = vectorizer.fit_transform(train_text)
    test_text_matrix = vectorizer.transform(test_text)
    return train_text_matrix, test_text_matrix


def _features(
    train: pd.DataFrame, test: pd.DataFrame
) -> tuple[csr_matrix, csr_matrix, int]:
    train_text, test_text = _text_matrix(train, test)
    train_features = hstack([train_text, _numeric_matrix(train)], format="csr")
    test_features = hstack([test_text, _numeric_matrix(test)], format="csr")
    return train_features, test_features, train_text.shape[1]


def _metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, Any]:
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=LABELS, zero_division=0
    )
    per_class = {
        label: {
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
            "support": int(support[index]),
        }
        for index, label in enumerate(LABELS)
    }
    matrix = confusion_matrix(y_true, y_pred, labels=LABELS)
    macro_f1 = f1_score(y_true, y_pred, labels=LABELS, average="macro", zero_division=0)
    return {
        "macro_f1": float(macro_f1),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "per_class": per_class,
        "confusion_matrix": {
            "labels": list(LABELS),
            "rows_true": [list(map(int, row)) for row in matrix],
        },
    }


def _bootstrap_ci(
    y_true: np.ndarray, y_pred: np.ndarray, n_bootstrap: int = 200, seed: int = SEED
) -> tuple[float, float]:
    rng = np.random.default_rng(seed)
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    scores: list[float] = []
    for _ in range(n_bootstrap):
        indices = rng.integers(0, len(y_true), len(y_true))
        scores.append(
            float(
                f1_score(
                    y_true[indices],
                    y_pred[indices],
                    labels=LABELS,
                    average="macro",
                    zero_division=0,
                )
            )
        )
    low, high = np.percentile(scores, [2.5, 97.5])
    return float(low), float(high)


def _rules_predict(frame: pd.DataFrame) -> np.ndarray:
    """High-precision keyword rule: MITRE or malicious verdict means true positive.

    This rule deliberately ignores benign-positive signals. It is a reference
    point, not a tuned classifier.
    """
    predictions = np.full(len(frame), "false_positive", dtype=object)
    has_mitre = pd.to_numeric(frame["has_mitre"], errors="coerce").fillna(0).to_numpy() > 0
    malicious = (
        pd.to_numeric(frame["malicious_count"], errors="coerce").fillna(0).to_numpy() > 0
    )
    predictions[has_mitre | malicious] = "true_positive"
    return predictions


def _majority_predict(train: pd.DataFrame, test: pd.DataFrame) -> np.ndarray:
    majority = train["triage_label"].value_counts().idxmax()
    return np.full(len(test), majority, dtype=object)


def _fit_lgbm(
    train_features: csr_matrix,
    y_train: np.ndarray,
    seed: int,
) -> LGBMClassifier:
    model = LGBMClassifier(
        objective="multiclass",
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=31,
        min_child_samples=20,
        subsample=0.9,
        colsample_bytree=0.8,
        reg_lambda=0.1,
        random_state=seed,
        n_jobs=-1,
        verbose=-1,
        force_col_wise=True,
        deterministic=True,
    )
    sample_weight = compute_sample_weight(class_weight="balanced", y=y_train)
    model.fit(train_features, y_train, sample_weight=sample_weight)
    return model


def _confusion_table(matrix: dict[str, Any]) -> str:
    labels = matrix["labels"]
    rows = matrix["rows_true"]
    header = "| true \\ predicted | " + " | ".join(labels) + " |"
    divider = "|---|" + "|".join(["---"] * len(labels)) + "|"
    body = [
        "| " + label + " | " + " | ".join(str(value) for value in row) + " |"
        for label, row in zip(labels, rows, strict=False)
    ]
    return "\n".join([header, divider, *body])


def _format_ci(interval: tuple[float, float]) -> str:
    return f"{interval[0]:.3f} to {interval[1]:.3f}"


def run_baselines(
    train_path: Path,
    dev_path: Path | None,
    test_path: Path,
    manifest_path: Path,
    report_path: Path,
    metrics_path: Path,
    dataset_label: str = "guide",
    seed: int = SEED,
) -> dict[str, Any]:
    train = load_frame(train_path)
    test = load_frame(test_path)
    dev_rows = len(load_frame(dev_path)) if dev_path and Path(dev_path).exists() else 0
    _check_labels(train, "train")
    _check_labels(test, "test")

    y_train = train["triage_label"].to_numpy()
    y_test = test["triage_label"].to_numpy()

    majority_pred = _majority_predict(train, test)
    rules_pred = _rules_predict(test)

    train_features, test_features, text_features = _features(train, test)
    lgbm = _fit_lgbm(train_features, y_train, seed)
    lgbm_pred = lgbm.predict(test_features)
    lgbm_pred = np.asarray(lgbm_pred)

    predictions = {
        "majority": majority_pred,
        "rules": rules_pred,
        "tfidf_lgbm": lgbm_pred,
    }
    results: dict[str, Any] = {}
    for name, prediction in predictions.items():
        result = _metrics(y_test, prediction)
        result["macro_f1_ci95"] = _bootstrap_ci(y_test, prediction, seed=seed)
        results[name] = result

    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    manifest_validation = validate_manifest(Path(manifest_path))
    source = manifest.get("source", {}).get("incidents_parquet", {})
    incidents_path = Path(source.get("path", ""))
    if not incidents_path.is_absolute():
        incidents_path = ROOT / incidents_path
    data_checks = quality_report(incidents_path, Path(manifest_path))
    split_sizes = {
        name: split.get("rows", 0) for name, split in manifest.get("splits", {}).items()
    }
    split_sizes["dev_loaded"] = dev_rows

    metadata = {
        "dataset": dataset_label,
        "generated_at": datetime.now(UTC).isoformat(),
        "model_version": MODEL_VERSION,
        "feature_version": "guide_csv_v1",
        "seed": seed,
        "manifest": {
            "path": _display_path(Path(manifest_path)),
            "test_source": manifest.get("test_source"),
            "source_sha256": manifest.get("source", {})
            .get("incidents_parquet", {})
            .get("sha256"),
            "validation_passed": manifest_validation["passed"],
            "warnings": manifest.get("warnings", []),
        },
        "split_sizes": split_sizes,
        "data_checks": {
            "passed": data_checks["passed"],
            "failed": [
                check["name"]
                for check in data_checks["checks"]
                if not check["passed"] and not check.get("warning")
            ],
            "warnings": data_checks["warnings"],
        },
        "features": {
            "text": "summary field from GUIDE categorical and alert-title tokens",
            "text_features": int(text_features),
            "numeric_features": list(NUMERIC_FEATURES),
        },
        "rules": {
            "definition": (
                "true_positive if has_mitre or malicious_count > 0; "
                "false_positive otherwise"
            ),
            "note": "Deliberately ignores benign-positive signals; a reference point, not tuned.",
        },
        "models": results,
    }

    metrics_path = Path(metrics_path)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(_render_report(metadata, results), encoding="utf-8")
    return metadata


def _render_report(metadata: dict[str, Any], results: dict[str, Any]) -> str:
    fixture = metadata["dataset"] == "fixture"
    if fixture:
        status = (
            "**Status: fixture smoke run. These are not GUIDE benchmark results. "
            "They do not satisfy Week 1's real-data gate.**"
        )
    else:
        status = (
            "**Status: GUIDE run on the frozen manifest. Check the gate boxes below "
            "before treating any number as a result.**"
        )

    split_rows = metadata["split_sizes"]
    warnings = metadata["manifest"].get("warnings", [])
    warning_text = "\n".join(f"- {warning}" for warning in warnings) if warnings else "- None"

    lines = [
        "# Week 1 baselines",
        "",
        status,
        "",
        "## Data",
        "",
        "| Item | Value |",
        "|---|---|",
        f"| Dataset | {metadata['dataset']} |",
        f"| Test source | {metadata['manifest'].get('test_source')} |",
        f"| Train incidents | {split_rows.get('train', 0)} |",
        f"| Dev incidents | {split_rows.get('dev', 0)} |",
        f"| Test incidents | {split_rows.get('test', 0)} |",
        f"| Seed | {metadata['seed']} |",
        f"| Model version | `{metadata['model_version']}` |",
        f"| Manifest validates | {metadata['manifest'].get('validation_passed')} |",
        f"| Data checks pass | {metadata['data_checks']['passed']} |",
        "",
        "Manifest warnings:",
        "",
        warning_text,
        "",
        "## Results",
        "",
        "| Model | Macro-F1 | 95% bootstrap CI | Accuracy |",
        "|---|---:|---|---:|",
    ]
    display_names = {
        "majority": "Majority class",
        "rules": "Rules (MITRE or malicious verdict)",
        "tfidf_lgbm": "TF-IDF + LightGBM",
    }
    for key in ("majority", "rules", "tfidf_lgbm"):
        result = results[key]
        lines.append(
            f"| {display_names[key]} | {result['macro_f1']:.3f} | "
            f"{_format_ci(result['macro_f1_ci95'])} | {result['accuracy']:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Per-class metrics",
            "",
            "| Model | Class | Precision | Recall | F1 | Support |",
            "|---|---|---:|---:|---:|---:|",
        ]
    )
    for key in ("majority", "rules", "tfidf_lgbm"):
        for label in LABELS:
            values = results[key]["per_class"][label]
            lines.append(
                f"| {display_names[key]} | {label} | {values['precision']:.3f} | "
                f"{values['recall']:.3f} | {values['f1']:.3f} | {values['support']} |"
            )

    lines.extend(
        [
            "",
            "## Confusion matrix: TF-IDF + LightGBM",
            "",
            _confusion_table(results["tfidf_lgbm"]["confusion_matrix"]),
            "",
            "## Rules baseline",
            "",
            metadata["rules"]["definition"] + ".",
            "",
            metadata["rules"]["note"],
            "",
            "## Gate status",
            "",
        ]
    )

    lgbm_f1 = results["tfidf_lgbm"]["macro_f1"]
    majority_f1 = results["majority"]["macro_f1"]
    rules_f1 = results["rules"]["macro_f1"]
    if fixture:
        lines.extend(
            [
                "- [x] Fixture pipeline runs end to end.",
                "- [ ] GUIDE data tests pass. Pending real files.",
                "- [ ] GUIDE split manifest is frozen. Pending real files.",
                f"- [ ] LightGBM beats majority and rules on GUIDE macro-F1. "
                f"Fixture gap: {lgbm_f1 - max(majority_f1, rules_f1):.3f}.",
                "- [x] A clean fixture run reproduces this table from generated data.",
            ]
        )
    else:
        lines.extend(
            [
                f"- [{'x' if metadata['manifest'].get('validation_passed') else ' '}] "
                "Split manifest validates.",
                f"- [{'x' if lgbm_f1 > majority_f1 else ' '}] "
                "LightGBM beats majority on macro-F1.",
                f"- [{'x' if lgbm_f1 > rules_f1 else ' '}] "
                "LightGBM beats rules on macro-F1.",
                f"- [{'x' if metadata['data_checks']['passed'] else ' '}] "
                "Data checks pass.",
            ]
        )

    lines.extend(
        [
            "",
            "## What this does not prove",
            "",
            *(
                ["- Fixture results do not measure GUIDE performance."]
                if fixture
                else []
            ),
            "- The rules baseline is intentionally simple and not tuned.",
            "- The classifier is not calibrated yet. Calibration and the router "
            "belong to later weeks.",
            "- The test split is not used for threshold tuning here.",
            "",
            "## Reproduce",
            "",
            "Fixture run:",
            "",
            "```bash",
            "uv run python -m triage.cli fixture-eval --work-dir reports/fixture_run",
            "```",
            "",
            "GUIDE run:",
            "",
            "```bash",
            "uv run python -m triage.cli etl --raw-dir data/raw "
            "--out data/processed/incidents.parquet "
            "--stats data/processed/etl_stats.json",
            "uv run python -m triage.cli split "
            "--incidents data/processed/incidents.parquet "
            "--out-dir data/processed --manifest data/manifests/split_v1.json",
            "uv run python -m triage.cli baselines "
            "--train data/processed/train.parquet --dev data/processed/dev.parquet "
            "--test data/processed/test.parquet --manifest data/manifests/split_v1.json "
            "--report reports/w1_baselines.md --metrics reports/w1_metrics.json "
            "--dataset guide",
            "uv run python -m triage.cli check "
            "--incidents data/processed/incidents.parquet "
            "--manifest data/manifests/split_v1.json",
            "```",
            "",
            "The `Makefile` mirrors these commands for Unix and CI.",
            "",
            "Artifacts:",
            "",
            "- The metrics JSON sits next to this report.",
            f"- Manifest: `{metadata['manifest']['path']}`.",
            "- Use the manifest hash and model version when comparing runs.",
            "",
        ]
    )
    return "\n".join(lines)
