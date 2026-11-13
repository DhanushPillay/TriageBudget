from __future__ import annotations

import json
import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from scipy.optimize import minimize
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.isotonic import IsotonicRegression

from triage.baselines import (
    _bootstrap_ci,
    _check_labels,
    _confusion_table,
    _encode_labels,
    _fit_lgbm,
    _format_ci,
    _metrics,
    _verify_split_provenance,
)
from triage.config import (
    LABELS,
    NUMERIC_FEATURES,
    RAW_DIR,
    SEED,
    display_path,
    resolve_path,
    sql_path,
)
from triage.data import quality_report, validate_manifest

MODEL_VERSION = "tfidf_lgbm_calibrated_v1"
ECE_BINS = 15
TP_INDEX = LABELS.index("true_positive")

CLASSIFIER_COLUMNS = tuple(
    dict.fromkeys(
        (
            "incident_id",
            "summary",
            "triage_label",
            "org_id",
            "created_at",
            "title",
            "alert_title",
            "categories",
            "mitre_techniques",
            *NUMERIC_FEATURES,
            "threat_families",
            "suspicion_levels",
            "last_verdicts",
        )
    )
)

ENGINEERED_FEATURES = (
    "summary_length",
    "summary_tokens",
    "event_month",
    "is_weekend",
    "alerts_per_detector",
    "evidence_per_alert",
    "entities_per_alert",
    "threat_family_count",
    "has_suspicion",
    "has_verdict",
)
CLASSIFIER_FEATURES = (*NUMERIC_FEATURES, *ENGINEERED_FEATURES)

DEFAULT_PARAMS = {
    "num_leaves": 31,
    "learning_rate": 0.05,
    "n_estimators": 300,
    "min_child_samples": 20,
}
PARAM_GRID = (
    dict(DEFAULT_PARAMS),
    {
        "num_leaves": 63,
        "learning_rate": 0.05,
        "n_estimators": 400,
        "min_child_samples": 20,
    },
    {
        "num_leaves": 31,
        "learning_rate": 0.1,
        "n_estimators": 400,
        "min_child_samples": 20,
    },
    {
        "num_leaves": 63,
        "learning_rate": 0.1,
        "n_estimators": 350,
        "min_child_samples": 50,
    },
)


@dataclass
class ClassifierArtifacts:
    """Inference wrapper for the exported Week 2 model."""

    booster: Any
    vectorizer: Any
    calibrator: Any
    metadata: dict[str, Any]

    @property
    def model_version(self) -> str:
        return str(self.metadata.get("model_version", MODEL_VERSION))

    @property
    def label_order(self) -> list[str]:
        return list(self.metadata.get("label_order", LABELS))

    def predict_frame(self, frame: pd.DataFrame) -> np.ndarray:
        if self.label_order != list(LABELS):
            raise ValueError(
                f"Model label order {self.label_order} does not match {list(LABELS)}"
            )
        engineered = _add_engineered(frame, {})
        text = self.vectorizer.transform(
            engineered["summary"].fillna("").astype(str)
        )
        features = hstack([text, _numeric_matrix(engineered)], format="csr")
        if features.shape[1] != self.booster.num_feature():
            raise ValueError(
                f"Feature count {features.shape[1]} does not match model "
                f"expectation {self.booster.num_feature()}"
            )
        raw = np.asarray(self.booster.predict(features), dtype=float)
        expected_shape = (len(frame), len(self.label_order))
        if raw.shape != expected_shape:
            raise ValueError(
                f"Unexpected model output shape: {raw.shape}, expected {expected_shape}"
            )
        probs = np.asarray(self.calibrator.predict_proba(raw), dtype=float)
        if probs.shape != raw.shape:
            raise ValueError(
                f"Calibrated output shape {probs.shape} does not match {raw.shape}"
            )
        if not np.allclose(probs.sum(axis=1), 1.0):
            raise ValueError("Calibrated probabilities do not sum to one")
        return probs


def load_classifier(model_dir: Path) -> ClassifierArtifacts:
    model_dir = Path(model_dir)
    metadata = json.loads((model_dir / "metadata.json").read_text(encoding="utf-8"))
    version = metadata.get("model_version")
    if version != MODEL_VERSION:
        raise ValueError(
            f"Unsupported classifier version {version!r}; expected {MODEL_VERSION!r}"
        )
    if metadata.get("label_order") != list(LABELS):
        raise ValueError(
            f"Classifier label order {metadata.get('label_order')!r} does not "
            f"match {list(LABELS)}"
        )
    booster = lgb.Booster(model_file=str(model_dir / "model.txt"))
    vectorizer = joblib.load(model_dir / "vectorizer.joblib")
    calibrator = joblib.load(model_dir / "calibrator.joblib")
    return ClassifierArtifacts(
        booster=booster,
        vectorizer=vectorizer,
        calibrator=calibrator,
        metadata=metadata,
    )


def _count_rows(path: Path) -> int:
    con = duckdb.connect()
    try:
        return int(
            con.execute(
                f"SELECT count(*) FROM read_parquet('{sql_path(Path(path))}')"
            ).fetchone()[0]
        )
    finally:
        con.close()


def load_frame(
    path: Path, incident_ids: Sequence[str] | None = None
) -> pd.DataFrame:
    columns = ", ".join(CLASSIFIER_COLUMNS)
    where = ""
    params: list[str] = []
    if incident_ids:
        placeholders = ", ".join("?" for _ in incident_ids)
        where = f" WHERE incident_id IN ({placeholders})"
        params = [str(incident_id) for incident_id in incident_ids]
    con = duckdb.connect()
    try:
        return con.execute(
            f"SELECT {columns} FROM read_parquet('{sql_path(Path(path))}'){where}",
            params,
        ).df()
    finally:
        con.close()


def _labels(codes: np.ndarray) -> np.ndarray:
    return np.asarray(LABELS, dtype=object)[np.asarray(codes)]


def _token_count(values: pd.Series) -> pd.Series:
    return values.fillna("").astype(str).str.split().str.len().fillna(0).astype(float)


def _add_engineered(
    frame: pd.DataFrame, org_frequency: dict[str, float]
) -> pd.DataFrame:
    missing = [
        name
        for name in ("summary", "org_id", "created_at", "event_day_of_week")
        if name not in frame.columns
    ]
    if missing:
        raise ValueError(f"Missing columns for feature engineering: {missing}")

    frame = frame.copy()
    frame["summary_length"] = frame["summary"].fillna("").astype(str).str.len()
    frame["summary_tokens"] = _token_count(frame["summary"])
    created = pd.to_datetime(frame["created_at"], errors="coerce")
    frame["event_month"] = created.dt.month.fillna(0).astype(float)
    day = pd.to_numeric(frame["event_day_of_week"], errors="coerce").fillna(-1)
    frame["is_weekend"] = day.isin([0, 6]).astype(float)

    alerts = pd.to_numeric(frame["alert_count"], errors="coerce").fillna(0).clip(lower=0)
    detectors = pd.to_numeric(frame["detector_count"], errors="coerce").fillna(0)
    evidence = pd.to_numeric(frame["evidence_count"], errors="coerce").fillna(0)
    entities = pd.to_numeric(frame["entity_type_count"], errors="coerce").fillna(0)
    frame["alerts_per_detector"] = alerts / detectors.clip(lower=1)
    frame["evidence_per_alert"] = evidence / alerts.clip(lower=1)
    frame["entities_per_alert"] = entities / alerts.clip(lower=1)

    frame["threat_family_count"] = _token_count(frame["threat_families"])
    frame["has_suspicion"] = (
        pd.to_numeric(frame["suspicious_count"], errors="coerce").fillna(0) > 0
    ).astype(float)
    frame["has_verdict"] = (
        pd.to_numeric(frame["verdict_count"], errors="coerce").fillna(0) > 0
    ).astype(float)
    frame["org_frequency"] = (
        frame["org_id"].astype(str).map(org_frequency).fillna(0.0).astype(float)
    )
    return frame


def _numeric_matrix(frame: pd.DataFrame) -> csr_matrix:
    missing = [name for name in CLASSIFIER_FEATURES if name not in frame.columns]
    if missing:
        raise ValueError(f"Missing numeric features: {missing}")
    numeric = frame.loc[:, CLASSIFIER_FEATURES].apply(pd.to_numeric, errors="coerce")
    return csr_matrix(numeric.fillna(0).to_numpy(dtype=np.float32))


def _text_matrix(train: pd.DataFrame, *others: pd.DataFrame) -> tuple[Any, ...]:
    train_text = train["summary"].fillna("").astype(str)
    min_df = 2 if len(train_text) >= 1_000 else 1
    vectorizer = TfidfVectorizer(
        max_features=5_000,
        ngram_range=(1, 2),
        min_df=min_df,
        sublinear_tf=True,
    )
    train_matrix = vectorizer.fit_transform(train_text)
    matrices: list[csr_matrix] = [train_matrix]
    for frame in others:
        text = frame["summary"].fillna("").astype(str)
        matrices.append(vectorizer.transform(text))
    return vectorizer, tuple(matrices)


def _features(
    train: pd.DataFrame,
    calibration: pd.DataFrame,
    test: pd.DataFrame,
    org_frequency: dict[str, float],
) -> tuple[csr_matrix, csr_matrix, csr_matrix, TfidfVectorizer, int]:
    train = _add_engineered(train, org_frequency)
    calibration = _add_engineered(calibration, org_frequency)
    test = _add_engineered(test, org_frequency)
    vectorizer, (train_text, calibration_text, test_text) = _text_matrix(
        train, calibration, test
    )
    train_features = hstack([train_text, _numeric_matrix(train)], format="csr")
    calibration_features = hstack(
        [calibration_text, _numeric_matrix(calibration)], format="csr"
    )
    test_features = hstack([test_text, _numeric_matrix(test)], format="csr")
    return (
        train_features,
        calibration_features,
        test_features,
        vectorizer,
        train_text.shape[1],
    )


def _predict_proba(model: Any, features: csr_matrix) -> np.ndarray:
    probs = np.asarray(model.predict_proba(features), dtype=float)
    expected = list(range(len(LABELS)))
    classes = list(model.classes_)
    if classes != expected:
        order = [classes.index(code) for code in expected]
        probs = probs[:, order]
    return probs


def _log_probs(probs: np.ndarray) -> np.ndarray:
    return np.log(np.clip(probs, 1e-12, 1.0))


def _softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - logits.max(axis=1, keepdims=True)
    exp = np.exp(shifted)
    return exp / exp.sum(axis=1, keepdims=True)


def _nll(y_codes: np.ndarray, probs: np.ndarray) -> float:
    picked = probs[np.arange(len(y_codes)), y_codes]
    return float(-np.mean(np.log(np.clip(picked, 1e-12, 1.0))))


def _brier(y_codes: np.ndarray, probs: np.ndarray) -> float:
    onehot = np.zeros_like(probs)
    onehot[np.arange(len(y_codes)), y_codes] = 1.0
    return float(np.mean(np.sum((probs - onehot) ** 2, axis=1)))


def _binary_ece(
    correct: np.ndarray, confidence: np.ndarray, n_bins: int = ECE_BINS
) -> float:
    correct = np.asarray(correct, dtype=float)
    confidence = np.asarray(confidence, dtype=float)
    total = len(correct)
    if total == 0:
        return 0.0
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    bins = np.clip(np.digitize(confidence, edges[1:-1]), 0, n_bins - 1)
    ece = 0.0
    for index in range(n_bins):
        mask = bins == index
        count = int(mask.sum())
        if count:
            ece += count / total * abs(correct[mask].mean() - confidence[mask].mean())
    return float(ece)


def _ece(y_codes: np.ndarray, probs: np.ndarray) -> float:
    confidence = probs.max(axis=1)
    correct = (probs.argmax(axis=1) == y_codes).astype(float)
    return _binary_ece(correct, confidence)


def _classwise_ece(y_codes: np.ndarray, probs: np.ndarray) -> dict[str, float]:
    return {
        label: _binary_ece((y_codes == index).astype(float), probs[:, index])
        for index, label in enumerate(LABELS)
    }


def _score(y_codes: np.ndarray, probs: np.ndarray) -> dict[str, Any]:
    pred_codes = probs.argmax(axis=1)
    result = _metrics(_labels(y_codes), _labels(pred_codes))
    return {
        "ece": _ece(y_codes, probs),
        "brier": _brier(y_codes, probs),
        "nll": _nll(y_codes, probs),
        "macro_f1": result["macro_f1"],
        "accuracy": result["accuracy"],
        "classwise_ece": _classwise_ece(y_codes, probs),
    }


def _bootstrap_ece(
    y_codes: np.ndarray, probs: np.ndarray, n_bootstrap: int = 100, seed: int = SEED
) -> tuple[float, float]:
    rng = np.random.default_rng(seed)
    values = np.empty(n_bootstrap, dtype=float)
    for index in range(n_bootstrap):
        rows = rng.integers(0, len(y_codes), len(y_codes))
        values[index] = _ece(y_codes[rows], probs[rows])
    low, high = np.percentile(values, [2.5, 97.5])
    return float(low), float(high)


def _reliability_bins(
    y_codes: np.ndarray, probs: np.ndarray, n_bins: int = ECE_BINS
) -> list[dict[str, Any]]:
    confidence = probs.max(axis=1)
    correct = (probs.argmax(axis=1) == y_codes).astype(float)
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    bins = np.clip(np.digitize(confidence, edges[1:-1]), 0, n_bins - 1)
    rows: list[dict[str, Any]] = []
    for index in range(n_bins):
        mask = bins == index
        count = int(mask.sum())
        rows.append(
            {
                "lower": float(edges[index]),
                "upper": float(edges[index + 1]),
                "count": count,
                "confidence": float(confidence[mask].mean()) if count else 0.0,
                "accuracy": float(correct[mask].mean()) if count else 0.0,
            }
        )
    return rows


@dataclass
class IdentityCalibrator:
    name: str = "raw"

    def fit(self, probs: np.ndarray, y_codes: np.ndarray) -> IdentityCalibrator:
        return self

    def predict_proba(self, probs: np.ndarray) -> np.ndarray:
        return probs

    def params(self) -> dict[str, Any]:
        return {}


@dataclass
class TemperatureCalibrator:
    temperature: float = 1.0
    name: str = "temperature"

    def fit(self, probs: np.ndarray, y_codes: np.ndarray) -> TemperatureCalibrator:
        logits = _log_probs(probs)

        def objective(values: np.ndarray) -> float:
            return _nll(y_codes, _softmax(logits / values[0]))

        result = minimize(
            objective,
            x0=np.array([1.0]),
            method="L-BFGS-B",
            bounds=[(0.05, 20.0)],
        )
        if result.success and np.isfinite(result.fun):
            self.temperature = float(result.x[0])
        return self

    def predict_proba(self, probs: np.ndarray) -> np.ndarray:
        return _softmax(_log_probs(probs) / self.temperature)

    def params(self) -> dict[str, Any]:
        return {"temperature": self.temperature}


@dataclass
class VectorCalibrator:
    weights: np.ndarray = field(default_factory=lambda: np.ones(len(LABELS)))
    biases: np.ndarray = field(default_factory=lambda: np.zeros(len(LABELS)))
    name: str = "vector"

    def fit(self, probs: np.ndarray, y_codes: np.ndarray) -> VectorCalibrator:
        logits = _log_probs(probs)
        n_classes = logits.shape[1]
        x0 = np.concatenate([np.ones(n_classes), np.zeros(n_classes)])
        bounds = [(0.05, 10.0)] * n_classes + [(-10.0, 10.0)] * n_classes

        def objective(values: np.ndarray) -> float:
            weights = values[:n_classes]
            biases = values[n_classes:]
            return _nll(y_codes, _softmax(logits * weights + biases))

        result = minimize(
            objective,
            x0=x0,
            method="L-BFGS-B",
            bounds=bounds,
        )
        if result.success and np.isfinite(result.fun):
            self.weights = result.x[:n_classes].copy()
            self.biases = result.x[n_classes:].copy()
        return self

    def predict_proba(self, probs: np.ndarray) -> np.ndarray:
        logits = _log_probs(probs)
        return _softmax(logits * self.weights + self.biases)

    def params(self) -> dict[str, Any]:
        return {
            "weights": self.weights.tolist(),
            "biases": self.biases.tolist(),
        }


@dataclass
class IsotonicCalibrator:
    models: list[IsotonicRegression] = field(default_factory=list)
    name: str = "isotonic"

    def fit(self, probs: np.ndarray, y_codes: np.ndarray) -> IsotonicCalibrator:
        self.models = []
        for index in range(probs.shape[1]):
            model = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
            model.fit(probs[:, index], (y_codes == index).astype(int))
            self.models.append(model)
        return self

    def predict_proba(self, probs: np.ndarray) -> np.ndarray:
        columns = [
            model.predict(probs[:, index]) for index, model in enumerate(self.models)
        ]
        calibrated = np.clip(np.column_stack(columns), 1e-9, 1.0)
        return calibrated / calibrated.sum(axis=1, keepdims=True)

    def params(self) -> dict[str, Any]:
        return {"classes": len(self.models), "kind": "per-class isotonic"}


def _make_calibrator(name: str) -> Any:
    if name == "raw":
        return IdentityCalibrator()
    if name == "temperature":
        return TemperatureCalibrator()
    if name == "vector":
        return VectorCalibrator()
    if name == "isotonic":
        return IsotonicCalibrator()
    raise ValueError(f"Unknown calibration method: {name}")


def _stratified_folds(y_codes: np.ndarray, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    folds = np.zeros(len(y_codes), dtype=np.int8)
    for code in range(len(LABELS)):
        rows = np.flatnonzero(y_codes == code)
        rng.shuffle(rows)
        folds[rows[len(rows) // 2 :]] = 1
    return folds


def _select_calibrator(
    probs: np.ndarray, y_codes: np.ndarray, seed: int
) -> tuple[Any, dict[str, Any]]:
    if len(y_codes) < 100:
        return IdentityCalibrator(), {
            "selection": (
                "Raw probabilities retained: the calibration split has fewer than "
                "100 rows."
            ),
            "methods": {},
            "eligible": ["raw"],
            "selected": "raw",
        }

    folds = _stratified_folds(y_codes, seed)
    names = ["raw", "temperature", "vector", "isotonic"]
    study: dict[str, dict[str, list[float]]] = {
        name: {"ece": [], "brier": [], "nll": [], "macro_f1": []} for name in names
    }
    for name in names:
        for fit_fold in (0, 1):
            fit_rows = folds == fit_fold
            eval_rows = ~fit_rows
            calibrator = _make_calibrator(name).fit(
                probs[fit_rows], y_codes[fit_rows]
            )
            scores = _score(y_codes[eval_rows], calibrator.predict_proba(probs[eval_rows]))
            for metric in study[name]:
                study[name][metric].append(float(scores[metric]))

    summary = {
        name: {
            metric: float(np.mean(values)) for metric, values in metrics.items()
        }
        for name, metrics in study.items()
    }
    floor = summary["raw"]["macro_f1"] - 0.005
    eligible = [
        name for name in names if summary[name]["macro_f1"] >= floor
    ]
    selected = min(
        eligible, key=lambda name: (summary[name]["ece"], summary[name]["brier"])
    )
    calibrator = _make_calibrator(selected).fit(probs, y_codes)
    return calibrator, {
        "selection": "Two-fold cross-validation on the calibration split.",
        "methods": summary,
        "eligible": eligible,
        "selected": selected,
        "macro_f1_floor": floor,
    }


def _carve_calibration(
    train: pd.DataFrame, seed: int, fraction: float = 0.2
) -> tuple[pd.DataFrame, pd.DataFrame]:
    codes = _encode_labels(train["triage_label"].to_numpy())
    rng = np.random.default_rng(seed)
    calibration = np.zeros(len(train), dtype=bool)
    for code in range(len(LABELS)):
        rows = np.flatnonzero(codes == code)
        rng.shuffle(rows)
        take = max(1, int(round(fraction * len(rows)))) if len(rows) >= 2 else 0
        calibration[rows[:take]] = True
    return (
        train.loc[~calibration].reset_index(drop=True),
        train.loc[calibration].reset_index(drop=True),
    )


def _tune_lgbm(
    train_features: csr_matrix,
    y_train: np.ndarray,
    calibration_features: csr_matrix,
    y_calibration: np.ndarray,
    seed: int,
    enabled: bool,
) -> tuple[Any, dict[str, Any], list[dict[str, Any]]]:
    if not enabled or len(y_calibration) < 100:
        model = _fit_lgbm(
            train_features, y_train, seed, params=dict(DEFAULT_PARAMS)
        )
        return model, dict(DEFAULT_PARAMS), [
            {
                "params": dict(DEFAULT_PARAMS),
                "dev_macro_f1": None,
                "dev_nll": None,
                "selected": True,
            }
        ]

    rows: list[dict[str, Any]] = []
    best_model = None
    best_key: tuple[float, float] | None = None
    best_row: dict[str, Any] | None = None
    for params in PARAM_GRID:
        model = _fit_lgbm(train_features, y_train, seed, params=dict(params))
        scores = _score(y_calibration, _predict_proba(model, calibration_features))
        row = {
            "params": dict(params),
            "dev_macro_f1": scores["macro_f1"],
            "dev_nll": scores["nll"],
            "selected": False,
        }
        rows.append(row)
        key = (scores["macro_f1"], -scores["nll"])
        if best_key is None or key > best_key:
            best_key = key
            best_model = model
            best_row = row

    assert best_model is not None and best_row is not None
    best_row["selected"] = True
    return best_model, dict(best_row["params"]), rows


def _org_frequency_ablation(
    train_features: csr_matrix,
    calibration_features: csr_matrix,
    y_train: np.ndarray,
    y_calibration: np.ndarray,
    train_frequency: np.ndarray,
    calibration_frequency: np.ndarray,
    seed: int,
) -> dict[str, Any]:
    if len(y_calibration) < 100:
        return {
            "dev_macro_f1_without": None,
            "dev_macro_f1_with": None,
            "delta": None,
            "note": "Skipped: the calibration split is too small.",
        }

    baseline = _fit_lgbm(
        train_features, y_train, seed, params=dict(DEFAULT_PARAMS)
    )
    with_org = _fit_lgbm(
        hstack(
            [train_features, csr_matrix(train_frequency.reshape(-1, 1))],
            format="csr",
        ),
        y_train,
        seed,
        params=dict(DEFAULT_PARAMS),
    )
    without_score = _score(
        y_calibration, _predict_proba(baseline, calibration_features)
    )
    with_score = _score(
        y_calibration,
        _predict_proba(
            with_org,
            hstack(
                [
                    calibration_features,
                    csr_matrix(calibration_frequency.reshape(-1, 1)),
                ],
                format="csr",
            ),
        ),
    )
    return {
        "dev_macro_f1_without": without_score["macro_f1"],
        "dev_macro_f1_with": with_score["macro_f1"],
        "delta": with_score["macro_f1"] - without_score["macro_f1"],
        "note": (
            "Default config. Org frequency acts as an organization identifier and "
            "can learn queue-specific labeling style, so it is excluded from the "
            "headline model."
        ),
    }


def _signal_score(frame: pd.DataFrame) -> np.ndarray:
    malicious = (
        pd.to_numeric(frame["malicious_count"], errors="coerce").fillna(0) > 0
    ).to_numpy(dtype=float)
    verdict = (
        pd.to_numeric(frame["verdict_count"], errors="coerce").fillna(0) > 0
    ).to_numpy(dtype=float)
    mitre = (
        pd.to_numeric(frame["has_mitre"], errors="coerce").fillna(0) > 0
    ).to_numpy(dtype=float)
    suspicion = (
        pd.to_numeric(frame["suspicious_count"], errors="coerce").fillna(0) > 0
    ).to_numpy(dtype=float)
    alerts = pd.to_numeric(frame["alert_count"], errors="coerce").fillna(0).to_numpy(
        dtype=float
    )
    alerts = alerts / max(float(alerts.max()), 1.0)
    return 8.0 * malicious + 4.0 * verdict + 2.0 * mitre + suspicion + alerts


def _queue_ranking(
    frame: pd.DataFrame,
    probs: np.ndarray,
    y_codes: np.ndarray,
    min_incidents: int = 50,
    min_positives: int = 5,
) -> dict[str, Any]:
    metric_names = ("precision@5", "precision@10", "precision@20", "capture@10%")
    collected = {
        "model": {name: [] for name in metric_names},
        "signal": {name: [] for name in metric_names},
    }
    orgs = frame["org_id"].astype(str).to_numpy()
    model_scores = probs[:, TP_INDEX]
    signal_scores = _signal_score(frame)
    queues = 0

    for org in np.unique(orgs):
        mask = orgs == org
        count = int(mask.sum())
        if count < min_incidents:
            continue
        labels = y_codes[mask]
        positives = int((labels == TP_INDEX).sum())
        if positives < min_positives:
            continue
        queues += 1
        for name, scores in (
            ("model", model_scores[mask]),
            ("signal", signal_scores[mask]),
        ):
            order = np.argsort(-scores, kind="stable")
            for k in (5, 10, 20):
                if count >= k:
                    collected[name][f"precision@{k}"].append(
                        float(np.mean(labels[order[:k]] == TP_INDEX))
                    )
            top = max(1, int(math.ceil(0.1 * count)))
            collected[name]["capture@10%"].append(
                float((labels[order[:top]] == TP_INDEX).sum() / positives)
            )

    summary = {
        name: {
            metric: float(np.mean(values)) if values else None
            for metric, values in metrics.items()
        }
        for name, metrics in collected.items()
    }
    delta = {
        metric: (
            summary["model"][metric] - summary["signal"][metric]
            if summary["model"][metric] is not None
            and summary["signal"][metric] is not None
            else None
        )
        for metric in metric_names
    }
    beat = (
        summary["model"]["precision@10"] is not None
        and summary["signal"]["precision@10"] is not None
        and summary["model"]["precision@10"] > summary["signal"]["precision@10"]
    )
    return {
        "min_incidents": min_incidents,
        "min_positives": min_positives,
        "queues": queues,
        "model": summary["model"],
        "signal": summary["signal"],
        "delta": delta,
        "beats_signal_at_10": bool(beat),
    }


def _org_slices(
    frame: pd.DataFrame,
    y_codes: np.ndarray,
    pred_codes: np.ndarray,
    min_incidents: int = 50,
) -> dict[str, Any]:
    orgs = frame["org_id"].astype(str).to_numpy()
    scores: list[float] = []
    for org in np.unique(orgs):
        mask = orgs == org
        if int(mask.sum()) < min_incidents:
            continue
        result = _metrics(_labels(y_codes[mask]), _labels(pred_codes[mask]))
        scores.append(float(result["macro_f1"]))
    if not scores:
        return {
            "min_incidents": min_incidents,
            "queues": 0,
            "median_macro_f1": None,
            "p10_macro_f1": None,
            "p90_macro_f1": None,
            "min_macro_f1": None,
        }
    p10, median, p90 = np.percentile(scores, [10, 50, 90])
    return {
        "min_incidents": min_incidents,
        "queues": len(scores),
        "median_macro_f1": float(median),
        "p10_macro_f1": float(p10),
        "p90_macro_f1": float(p90),
        "min_macro_f1": float(min(scores)),
    }


def _fmt(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def _render_reliability_svg(
    raw_bins: list[dict[str, Any]],
    calibrated_bins: list[dict[str, Any]],
    raw_ece: float,
    calibrated_ece: float,
    sample_size: int,
    path: Path,
) -> None:
    width, height = 720, 520
    left, right, top, bottom = 76, 32, 56, 64
    plot_width = width - left - right
    plot_height = height - top - bottom

    def x(value: float) -> float:
        return left + value * plot_width

    def y(value: float) -> float:
        return top + (1.0 - value) * plot_height

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Reliability diagram for the GUIDE test split">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{left}" y="28" font-family="Arial, sans-serif" font-size="17" '
        f'font-weight="600" fill="#111111">Top-label reliability, GUIDE test '
        f"(n={sample_size})</text>",
    ]

    for tick in np.linspace(0.0, 1.0, 6):
        px = x(float(tick))
        py = y(float(tick))
        parts.append(
            f'<line x1="{px:.1f}" y1="{top}" x2="{px:.1f}" y2="{top + plot_height}" '
            'stroke="#e8e8e8" stroke-width="1"/>'
        )
        parts.append(
            f'<line x1="{left}" y1="{py:.1f}" x2="{left + plot_width}" y2="{py:.1f}" '
            'stroke="#e8e8e8" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{px:.1f}" y="{top + plot_height + 22}" text-anchor="middle" '
            f'font-family="Arial, sans-serif" font-size="12" fill="#444444">'
            f"{tick:.1f}</text>"
        )
        parts.append(
            f'<text x="{left - 12}" y="{py + 4:.1f}" text-anchor="end" '
            f'font-family="Arial, sans-serif" font-size="12" fill="#444444">'
            f"{tick:.1f}</text>"
        )

    parts.extend(
        [
            f'<line x1="{left}" y1="{top + plot_height}" x2="{left + plot_width}" '
            f'y2="{top}" stroke="#999999" stroke-width="1.5" stroke-dasharray="6 4"/>',
            f'<text x="{left + plot_width / 2}" y="{height - 18}" text-anchor="middle" '
            'font-family="Arial, sans-serif" font-size="13" fill="#222222">'
            "Mean predicted confidence</text>",
            f'<text x="18" y="{top + plot_height / 2}" text-anchor="middle" '
            'font-family="Arial, sans-serif" font-size="13" fill="#222222" '
            f'transform="rotate(-90 18 {top + plot_height / 2})">'
            "Observed accuracy</text>",
        ]
    )

    def polyline(bins: list[dict[str, Any]], color: str) -> str:
        points = [
            (x(bin_row["confidence"]), y(bin_row["accuracy"]))
            for bin_row in bins
            if bin_row["count"] > 0
        ]
        if not points:
            return ""
        return (
            f'<polyline fill="none" stroke="{color}" stroke-width="2.5" '
            f'points="{" ".join(f"{px:.1f},{py:.1f}" for px, py in points)}"/>'
        )

    parts.append(polyline(raw_bins, "#9a9a9a"))
    parts.append(polyline(calibrated_bins, "#1f5fbf"))
    for bins, color in ((raw_bins, "#9a9a9a"), (calibrated_bins, "#1f5fbf")):
        for bin_row in bins:
            if bin_row["count"] > 0:
                parts.append(
                    f'<circle cx="{x(bin_row["confidence"]):.1f}" '
                    f'cy="{y(bin_row["accuracy"]):.1f}" r="3.2" fill="{color}"/>'
                )

    legend_x = left + 20
    legend_y = top + 18
    parts.extend(
        [
            f'<line x1="{legend_x}" y1="{legend_y}" x2="{legend_x + 28}" '
            f'y2="{legend_y}" stroke="#9a9a9a" stroke-width="2.5"/>',
            f'<text x="{legend_x + 36}" y="{legend_y + 4}" '
            'font-family="Arial, sans-serif" font-size="12" fill="#222222">'
            f"Raw (ECE {raw_ece:.3f})</text>",
            f'<line x1="{legend_x}" y1="{legend_y + 22}" x2="{legend_x + 28}" '
            f'y2="{legend_y + 22}" stroke="#1f5fbf" stroke-width="2.5"/>',
            f'<text x="{legend_x + 36}" y="{legend_y + 26}" '
            'font-family="Arial, sans-serif" font-size="12" fill="#222222">'
            f"Calibrated (ECE {calibrated_ece:.3f})</text>",
            "</svg>",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def _render_report(metadata: dict[str, Any], reliability_name: str) -> str:
    fixture = metadata["dataset"] == "fixture"
    if fixture:
        status = (
            "**Status: fixture smoke run. These are not GUIDE benchmark results. "
            "They do not satisfy Week 2's real-data gate.**"
        )
    else:
        status = (
            "**Status: GUIDE run on the frozen manifest. Calibration is measured "
            "on the test split, not assumed. The test split was not used to fit "
            "the calibrator or select hyperparameters.**"
        )

    split_rows = metadata["split_sizes"]
    warnings = list(metadata["manifest"].get("warnings", []))
    warnings.extend(metadata["data_checks"].get("warnings", []))
    warning_text = "\n".join(f"- {warning}" for warning in warnings) if warnings else "- None"
    checks_passed = metadata["data_checks"]["passed"]
    checks_warned = bool(metadata["data_checks"].get("warnings"))
    checks_label = "True (with warnings)" if checks_passed and checks_warned else str(
        checks_passed
    )

    raw = metadata["models"]["raw"]
    calibrated = metadata["models"]["calibrated"]
    raw_scores = raw["scores"]
    calibrated_scores = calibrated["scores"]
    calibration = metadata["calibration"]
    gates = metadata["gates"]
    ranking = metadata["queue_ranking"]
    slices = metadata["org_slices"]

    lines = [
        "# Week 2 calibrated classifier",
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
        f"| Data checks pass | {checks_label} |",
        "",
        metadata["split_note"],
        "",
        "Warnings:",
        "",
        warning_text,
        "",
        "## Features",
        "",
        f"- Text: {metadata['features']['text']} "
        f"({metadata['features']['text_features']} TF-IDF features).",
        "- Numeric: " + ", ".join(metadata["features"]["numeric_features"]) + ".",
        "- Excluded: severity (not in the public CSV), organization identity "
        "(queue-policy leakage risk), and priority rank (queue ranks are present "
        "but are not used in this classifier; Week 4 evaluates them).",
        "",
        "### Organization frequency ablation",
        "",
        "Organization frequency is excluded from the headline model. It acts as an "
        "organization identifier, so it can learn queue-specific labeling style "
        "rather than incident content.",
        "",
        "| Config | Dev macro-F1 |",
        "|---|---:|",
        f"| Without org frequency | "
        f"{_fmt(metadata['org_frequency_ablation']['dev_macro_f1_without'])} |",
        f"| With org frequency | "
        f"{_fmt(metadata['org_frequency_ablation']['dev_macro_f1_with'])} |",
        f"| Delta | {_fmt(metadata['org_frequency_ablation']['delta'])} |",
        "",
        metadata["org_frequency_ablation"]["note"],
        "",
        "## Hyperparameter selection",
        "",
        "| Config | num_leaves | learning_rate | n_estimators | min_child_samples "
        "| Dev macro-F1 | Dev NLL | Selected |",
        "|---|---:|---:|---:|---:|---:|---:|:---:|",
    ]
    for row in metadata["param_grid"]:
        params = row["params"]
        lines.append(
            f"| {params['num_leaves']}/{params['learning_rate']}/"
            f"{params['n_estimators']}/{params['min_child_samples']} "
            f"| {params['num_leaves']} | {params['learning_rate']} "
            f"| {params['n_estimators']} | {params['min_child_samples']} "
            f"| {_fmt(row['dev_macro_f1'])} | {_fmt(row['dev_nll'])} "
            f"| {'yes' if row['selected'] else 'no'} |"
        )

    lines.extend(
        [
            "",
            f"Selected: `{metadata['selected_params']}`.",
            "",
            "## Calibration",
            "",
            calibration["study"].get("selection", ""),
            "",
        ]
    )
    methods = calibration["study"].get("methods", {})
    if methods:
        lines.extend(
            [
                "| Method | CV ECE | CV Brier | CV NLL | CV macro-F1 | Eligible |",
                "|---|---:|---:|---:|---:|:---:|",
            ]
        )
        for name in ("raw", "temperature", "vector", "isotonic"):
            if name not in methods:
                continue
            values = methods[name]
            eligible = "yes" if name in calibration["study"].get("eligible", []) else "no"
            lines.append(
                f"| {name} | {_fmt(values['ece'])} | {_fmt(values['brier'])} "
                f"| {_fmt(values['nll'])} | {_fmt(values['macro_f1'])} | {eligible} |"
            )
        lines.extend(
            [
                "",
                f"Selected method: **{calibration['selected']}**. "
                f"Dev calibrated ECE: {_fmt(calibration['dev']['calibrated']['ece'])}; "
                f"dev raw ECE: {_fmt(calibration['dev']['raw']['ece'])}.",
            ]
        )
    else:
        lines.append("Calibration study skipped because the split is too small.")

    lines.extend(
        [
            "",
            "## Test results",
            "",
            "| Score | Macro-F1 | 95% CI | Accuracy | ECE-15 | ECE 95% CI | Brier "
            "| NLL |",
            "|---|---:|---|---:|---:|---|---:|---:|",
            f"| Raw | {raw['macro_f1']:.3f} | {_format_ci(raw['macro_f1_ci95'])} "
            f"| {raw['accuracy']:.3f} | {raw_scores['ece']:.3f} "
            f"| {_format_ci(raw_scores['ece_ci95'])} | {raw_scores['brier']:.3f} "
            f"| {raw_scores['nll']:.3f} |",
            f"| Calibrated | {calibrated['macro_f1']:.3f} "
            f"| {_format_ci(calibrated['macro_f1_ci95'])} "
            f"| {calibrated['accuracy']:.3f} | {calibrated_scores['ece']:.3f} "
            f"| {_format_ci(calibrated_scores['ece_ci95'])} "
            f"| {calibrated_scores['brier']:.3f} "
            f"| {calibrated_scores['nll']:.3f} |",
            "",
            f"Reliability diagram: [{reliability_name}]({reliability_name}).",
            "",
            "### Per-class metrics (raw and calibrated)",
            "",
            "| Class | Raw precision | Raw recall | Raw F1 | Calibrated precision "
            "| Calibrated recall | Calibrated F1 | Support | Calibrated one-vs-rest "
            "ECE |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for label in LABELS:
        raw_values = raw["per_class"][label]
        calibrated_values = calibrated["per_class"][label]
        lines.append(
            f"| {label} | {raw_values['precision']:.3f} | {raw_values['recall']:.3f} "
            f"| {raw_values['f1']:.3f} | {calibrated_values['precision']:.3f} "
            f"| {calibrated_values['recall']:.3f} "
            f"| {calibrated_values['f1']:.3f} | {calibrated_values['support']} "
            f"| {calibrated_scores['classwise_ece'][label]:.3f} |"
        )

    lines.extend(
        [
            "",
            "Vector scaling improves probability quality and macro-F1, but it also "
            "moves the argmax: true-positive recall falls from "
            f"{raw['per_class']['true_positive']['recall']:.3f} to "
            f"{calibrated['per_class']['true_positive']['recall']:.3f}. The router "
            "should use the calibrated `p_true_positive` and the selective-risk "
            "curve, not only the predicted class. Both raw and calibrated metrics "
            "are kept in the metrics JSON.",
            "",
            "### Confusion matrix (calibrated)",
            "",
            _confusion_table(calibrated["confusion_matrix"]),
            "",
            "## Per-organization slices",
            "",
            f"Queues with at least {slices['min_incidents']} test incidents: "
            f"{slices['queues']}.",
            "",
            "| Median macro-F1 | p10 | p90 | Min |",
            "|---:|---:|---:|---:|",
            f"| {_fmt(slices['median_macro_f1'])} | {_fmt(slices['p10_macro_f1'])} "
            f"| {_fmt(slices['p90_macro_f1'])} | {_fmt(slices['min_macro_f1'])} |",
            "",
            "The global test macro-F1 is not representative of every queue. The "
            "per-queue distribution is wide, so the router should not assume one "
            "global threshold is equally safe for every organization.",
            "",
            "## Queue ranking proxy",
            "",
            "Week 2 reports a queue ranking proxy. The public release includes "
            "`GUIDE_Test_Queue_Rankings.csv` for 9,980 test incidents; Week 4 "
            "evaluates analyst P@5/10/20 against that file. The proxy ranks "
            "incidents within each organization queue by calibrated "
            "`p_true_positive`. It is not a substitute for analyst priority.",
            "",
            f"Queues with at least {ranking['min_incidents']} incidents and "
            f"{ranking['min_positives']} true positives: {ranking['queues']}.",
            "",
            "| Metric | Model | Signal baseline | Delta |",
            "|---|---:|---:|---:|",
        ]
    )
    for metric in ("precision@5", "precision@10", "precision@20", "capture@10%"):
        lines.append(
            f"| {metric} | {_fmt(ranking['model'][metric])} "
            f"| {_fmt(ranking['signal'][metric])} "
            f"| {_fmt(ranking['delta'][metric])} |"
        )

    lines.extend(
        [
            "",
            "The signal baseline orders by malicious verdict, MITRE presence, "
            "suspicion, and alert count. It is the closest available stand-in for "
            "severity; GUIDE has no severity column.",
            "",
            "## Gate status",
            "",
            f"- [{'x' if gates['calibration_reported'] else ' '}] "
            "Calibration error is reported, not assumed.",
            f"- [{'x' if gates['recall_above_floor'] else ' '}] "
            f"All three per-class recalls exceed the {gates['recall_floor']:.3f} "
            "majority-class prevalence floor.",
            f"- [{'x' if gates['queue_ranking_beats_signal'] else ' '}] "
            "The queue ranking proxy beats the signal-only baseline at precision@10.",
            f"- [{'x' if gates['model_card_written'] else ' '}] "
            "The model card states training data, features, and limitations.",
            "- [x] Analyst priority P@5/10/20 is deferred to Week 4; the "
            "queue-rank file is present, but Week 2 reports the proxy.",
            "",
            "## What this does not prove",
            "",
            "- This is not production SOC readiness.",
            "- Severity is absent from the public data. Queue ranks are present "
            "but are deferred to Week 4; the Week 2 queue ranking is a proxy.",
            "- Organization identity is excluded from the headline model. The test "
            "split contains the same organizations as train, so this is not a "
            "leave-one-queue-out generalization test.",
            "- Alert ids overlap between raw train and test. Incident-level "
            "disjointness holds, but an alert-disjoint sensitivity run is still "
            "pending.",
            "- Calibration is top-label on this split. Per-organization calibration "
            "is not reported and may differ.",
            "- The optional MiniLM baseline was not run. The classical baseline is "
            "stable enough for the routing work in later weeks.",
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
            "uv run python -m triage.cli classify "
            "--train data/processed/train.parquet --dev data/processed/dev.parquet "
            "--test data/processed/test.parquet --manifest data/manifests/split_v1.json "
            "--report reports/w2_classifier.md --metrics reports/w2_metrics.json "
            "--model-dir models/classifier_v1 --dataset guide",
            "```",
            "",
            "The model card and machine-readable metadata sit in "
            f"`{metadata['artifacts']['model_dir']}`.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_model_card(metadata: dict[str, Any]) -> str:
    calibrated = metadata["models"]["calibrated"]
    raw = metadata["models"]["raw"]
    rows = metadata["split_sizes"]
    lines = [
        "# Model card: classifier_v1",
        "",
        f"- Version: `{metadata['model_version']}`",
        f"- Generated: {metadata['generated_at']}",
        f"- Seed: {metadata['seed']}",
        f"- Dataset: {metadata['dataset']}",
        "",
        "## Intended use",
        "",
        "Research classifier for incident triage routing. It produces a three-class "
        "verdict and calibrated probabilities. It is not a production SOC system "
        "and must not trigger autonomous remediation.",
        "",
        "## Training data",
        "",
        "Microsoft GUIDE, official incident-level split, frozen manifest.",
        "",
        "| Split | Incidents |",
        "|---|---:|",
        f"| Train | {rows.get('train', 0)} |",
        f"| Dev | {rows.get('dev', 0)} |",
        f"| Test | {rows.get('test', 0)} |",
        "",
        f"- Manifest: `{metadata['manifest']['path']}`",
        f"- Incidents Parquet SHA-256: `{metadata['manifest']['source_sha256']}`",
        "",
        "## Features",
        "",
        f"- Text: {metadata['features']['text']} "
        f"({metadata['features']['text_features']} TF-IDF features).",
        "- Numeric: " + ", ".join(metadata["features"]["numeric_features"]) + ".",
        "- Excluded: severity (not in the public CSV), organization identity "
        "(queue-policy leakage risk), and priority rank (queue ranks are present "
        "but are not used in this classifier; Week 4 evaluates them).",
        f"- Organization frequency was tested and excluded: adding it changed "
        f"default-config dev macro-F1 by "
        f"{_fmt(metadata['org_frequency_ablation']['delta'])}. It behaves as an "
        "organization identifier, so it is not in the headline model.",
        "",
        "## Model",
        "",
        "- Family: TF-IDF plus LightGBM multiclass softmax.",
        f"- Selected parameters: `{metadata['selected_params']}`.",
        f"- Calibration: `{metadata['calibration']['selected']}`.",
        "- Fit on train only. Calibrator fit on dev only. Test was not used for "
        "tuning or calibration.",
        "",
        "## Evaluation",
        "",
        "| Score | Macro-F1 | Accuracy | ECE-15 | Brier | NLL |",
        "|---|---:|---:|---:|---:|---:|",
        f"| Raw | {raw['macro_f1']:.3f} | {raw['accuracy']:.3f} "
        f"| {raw['scores']['ece']:.3f} | {raw['scores']['brier']:.3f} "
        f"| {raw['scores']['nll']:.3f} |",
        f"| Calibrated | {calibrated['macro_f1']:.3f} "
        f"| {calibrated['accuracy']:.3f} "
        f"| {calibrated['scores']['ece']:.3f} "
        f"| {calibrated['scores']['brier']:.3f} "
        f"| {calibrated['scores']['nll']:.3f} |",
        "",
        "Per-class metrics are in `reports/w2_classifier.md`.",
        "",
        "## Limitations",
        "",
        "- Labels are customer analyst judgments and may contain queue-specific "
        "policy differences.",
        "- The public data has no severity column. Queue ranks are present but are "
        "deferred to Week 4; the Week 2 queue ranking proxy is not the planned "
        "analyst metric.",
        "- Alert ids overlap between raw train and test. Incident ids are disjoint, "
        "but an alert-disjoint sensitivity run is pending.",
        "- The test split shares organizations with train. This is not a "
        "leave-one-queue-out evaluation.",
        "- Calibration is top-label and global. Per-organization calibration is not "
        "guaranteed.",
        "- The classifier should not auto-close incidents without the router and "
        "human-review policy from later weeks.",
        "",
        "## Ethical and security notes",
        "",
        "- No autonomous action. The model only scores incidents.",
        "- Do not send raw tenant identifiers to a third-party model.",
        "- Treat GUIDE identifiers as sensitive even though the dataset is public.",
        "",
        "## Reproduce",
        "",
        "```bash",
        "uv run python -m triage.cli classify "
        "--train data/processed/train.parquet --dev data/processed/dev.parquet "
        "--test data/processed/test.parquet --manifest data/manifests/split_v1.json "
        "--report reports/w2_classifier.md --metrics reports/w2_metrics.json "
        "--model-dir models/classifier_v1 --dataset guide",
        "```",
        "",
    ]
    return "\n".join(lines)


def run_classifier(
    train_path: Path,
    dev_path: Path | None,
    test_path: Path,
    manifest_path: Path,
    report_path: Path,
    metrics_path: Path,
    model_dir: Path,
    reliability_path: Path | None = None,
    dataset_label: str = "guide",
    seed: int = SEED,
    grid: bool = True,
) -> dict[str, Any]:
    manifest_path = Path(manifest_path)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read manifest {manifest_path}: {exc}") from exc

    dev_rows = _count_rows(dev_path) if dev_path and Path(dev_path).exists() else 0
    _verify_split_provenance(manifest, train_path, dev_path, test_path, dev_rows)

    train = load_frame(train_path)
    test = load_frame(test_path)
    dev = load_frame(dev_path) if dev_rows else None
    _check_labels(train, "train")
    _check_labels(test, "test")
    if dev is not None:
        _check_labels(dev, "dev")

    manifest_validation = validate_manifest(manifest_path)
    if not manifest_validation["passed"]:
        failed = [
            check["name"] for check in manifest_validation["checks"] if not check["passed"]
        ]
        raise ValueError(f"Manifest validation failed: {', '.join(failed)}")

    source = manifest.get("source", {}).get("incidents_parquet", {})
    incidents_path = resolve_path(source.get("path") or "")
    if not incidents_path.is_file():
        raise ValueError(
            f"Incidents parquet not found: {display_path(incidents_path)}"
        )
    data_checks = quality_report(incidents_path, manifest_path)
    if not data_checks["passed"]:
        raise ValueError(
            "Data quality checks failed: " + ", ".join(data_checks["failed"])
        )

    if dev is None or len(dev) == 0:
        train_fit, calibration = _carve_calibration(train, seed)
        grid_enabled = False
        split_note = (
            "The dev split is empty. A deterministic 20% of train was carved for "
            "calibration and the default hyperparameters were used."
        )
    else:
        train_fit, calibration = train, dev
        grid_enabled = grid and len(dev) >= 100
        split_note = (
            "The model is fit on train. Hyperparameters and the calibrator are "
            "selected on dev. The test split is used only for final metrics."
        )

    org_frequency = (
        train_fit["org_id"].astype(str).value_counts(normalize=True).to_dict()
    )
    train_frequency = (
        train_fit["org_id"]
        .astype(str)
        .map(org_frequency)
        .fillna(0.0)
        .to_numpy(dtype=np.float32)
    )
    calibration_frequency = (
        calibration["org_id"]
        .astype(str)
        .map(org_frequency)
        .fillna(0.0)
        .to_numpy(dtype=np.float32)
    )
    (
        train_features,
        calibration_features,
        test_features,
        vectorizer,
        text_features,
    ) = _features(train_fit, calibration, test, org_frequency)

    y_train = _encode_labels(train_fit["triage_label"].to_numpy())
    y_calibration = _encode_labels(calibration["triage_label"].to_numpy())
    y_test = _encode_labels(test["triage_label"].to_numpy())

    model, selected_params, grid_rows = _tune_lgbm(
        train_features,
        y_train,
        calibration_features,
        y_calibration,
        seed,
        grid_enabled,
    )
    org_ablation = _org_frequency_ablation(
        train_features,
        calibration_features,
        y_train,
        y_calibration,
        train_frequency,
        calibration_frequency,
        seed,
    )

    calibration_probs_raw = _predict_proba(model, calibration_features)
    calibrator, calibration_study = _select_calibrator(
        calibration_probs_raw, y_calibration, seed
    )
    calibration_probs = calibrator.predict_proba(calibration_probs_raw)

    test_probs_raw = _predict_proba(model, test_features)
    test_probs = calibrator.predict_proba(test_probs_raw)

    raw_metrics = _metrics(_labels(y_test), _labels(test_probs_raw.argmax(axis=1)))
    raw_metrics["macro_f1_ci95"] = _bootstrap_ci(
        _labels(y_test), _labels(test_probs_raw.argmax(axis=1)), seed=seed
    )
    raw_metrics["scores"] = _score(y_test, test_probs_raw)
    raw_metrics["scores"]["ece_ci95"] = _bootstrap_ece(
        y_test, test_probs_raw, seed=seed
    )

    calibrated_metrics = _metrics(_labels(y_test), _labels(test_probs.argmax(axis=1)))
    calibrated_metrics["macro_f1_ci95"] = _bootstrap_ci(
        _labels(y_test), _labels(test_probs.argmax(axis=1)), seed=seed
    )
    calibrated_metrics["scores"] = _score(y_test, test_probs)
    calibrated_metrics["scores"]["ece_ci95"] = _bootstrap_ece(
        y_test, test_probs, seed=seed
    )

    raw_bins = _reliability_bins(y_test, test_probs_raw)
    calibrated_bins = _reliability_bins(y_test, test_probs)
    org_slices = _org_slices(test, y_test, test_probs.argmax(axis=1))
    queue_ranking = _queue_ranking(test, test_probs, y_test)

    majority_floor = float(
        calibrated_metrics["per_class"][LABELS[0]]["support"]
        + calibrated_metrics["per_class"][LABELS[1]]["support"]
        + calibrated_metrics["per_class"][LABELS[2]]["support"]
    )
    majority_floor = max(
        calibrated_metrics["per_class"][label]["support"] for label in LABELS
    ) / majority_floor
    recall_above_floor = all(
        calibrated_metrics["per_class"][label]["recall"] > majority_floor
        for label in LABELS
    )

    split_sizes = {
        name: split.get("rows", 0) for name, split in manifest.get("splits", {}).items()
    }
    split_sizes["dev_loaded"] = dev_rows

    report_path = Path(report_path)
    metrics_path = Path(metrics_path)
    model_dir = Path(model_dir)
    reliability_path = (
        Path(reliability_path)
        if reliability_path is not None
        else report_path.parent / "w2_reliability.svg"
    )

    metadata: dict[str, Any] = {
        "dataset": dataset_label,
        "generated_at": datetime.now(UTC).isoformat(),
        "model_version": MODEL_VERSION,
        "feature_version": "guide_csv_v2",
        "seed": seed,
        "split_note": split_note,
        "label_order": list(LABELS),
        "manifest": {
            "path": display_path(manifest_path),
            "test_source": manifest.get("test_source"),
            "source_sha256": source.get("sha256"),
            "train_sha256": manifest.get("splits", {}).get("train", {}).get("file_sha256"),
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
            "numeric_features": list(CLASSIFIER_FEATURES),
            "engineered_features": list(ENGINEERED_FEATURES),
        },
        "selected_params": selected_params,
        "param_grid": grid_rows,
        "org_frequency_ablation": org_ablation,
        "calibration": {
            "selected": calibrator.name,
            "params": calibrator.params(),
            "study": calibration_study,
            "dev": {
                "raw": _score(y_calibration, calibration_probs_raw),
                "calibrated": _score(y_calibration, calibration_probs),
            },
        },
        "models": {
            "raw": raw_metrics,
            "calibrated": calibrated_metrics,
        },
        "org_slices": org_slices,
        "queue_ranking": queue_ranking,
        "reliability": {
            "bins": {"raw": raw_bins, "calibrated": calibrated_bins},
        },
        "artifacts": {
            "model_dir": display_path(model_dir),
            "model": display_path(model_dir / "model.txt"),
            "vectorizer": display_path(model_dir / "vectorizer.joblib"),
            "calibrator": display_path(model_dir / "calibrator.joblib"),
            "metadata": display_path(model_dir / "metadata.json"),
            "model_card": display_path(model_dir / "model_card.md"),
            "report": display_path(report_path),
            "metrics": display_path(metrics_path),
            "reliability": display_path(reliability_path),
        },
    }

    metadata["gates"] = {
        "calibration_reported": True,
        "recall_floor": majority_floor,
        "recall_above_floor": bool(recall_above_floor),
        "queue_ranking_beats_signal": bool(
            queue_ranking["beats_signal_at_10"]
        ),
        "priority_ranks_available": bool(
            dataset_label == "guide"
            and (RAW_DIR / "GUIDE_Test_Queue_Rankings.csv").is_file()
        ),
        "model_card_written": True,
    }

    model_dir.mkdir(parents=True, exist_ok=True)
    model.booster_.save_model(str(model_dir / "model.txt"))
    joblib.dump(vectorizer, model_dir / "vectorizer.joblib")
    joblib.dump(calibrator, model_dir / "calibrator.joblib")
    (model_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    (model_dir / "model_card.md").write_text(
        _render_model_card(metadata), encoding="utf-8"
    )

    _render_reliability_svg(
        raw_bins,
        calibrated_bins,
        raw_metrics["scores"]["ece"],
        calibrated_metrics["scores"]["ece"],
        len(y_test),
        reliability_path,
    )

    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        _render_report(metadata, reliability_path.name), encoding="utf-8"
    )
    return metadata
