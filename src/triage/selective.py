from __future__ import annotations

import argparse
import hashlib
import json
import math
import time
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score

from triage.agent import IncidentStore, OfflineAgent
from triage.classifier import ClassifierArtifacts, load_classifier, load_frame
from triage.config import LABELS, RAW_DIR, REPORTS_DIR, ROOT, SEED, display_path
from triage.retrieval import (
    FastEmbedEmbedder,
    RetrievalIndex,
    _gold_incidents,
    _gold_playbooks,
    evaluate_retrieval,
    load_eval_queries,
)

AUTO_LABELS = ("true_positive", "false_positive")
THRESHOLDS = tuple(round(0.50 + 0.05 * index, 2) for index in range(11))
TARGET_COVERAGE = 0.60
TARGET_MISS_RATE = 0.01
DEFAULT_BUDGET_MINUTES = 10.0
ERROR_CATEGORIES = (
    "label_ambiguity",
    "missing_evidence",
    "retrieval_miss",
    "retrieval_noise",
    "reasoning_error",
    "citation_error",
    "schema_error",
    "abstention_error",
    "overconfidence",
    "tool_failure",
)
TP_INDEX = 0


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _macro_f1(y_true: Sequence[str], y_pred: Sequence[str]) -> float:
    return float(
        f1_score(y_true, y_pred, labels=list(LABELS), average="macro", zero_division=0)
    )


def _accuracy(y_true: Sequence[str], y_pred: Sequence[str]) -> float:
    return float(np.mean(np.asarray(y_true) == np.asarray(y_pred)))


def bootstrap_metric(
    y_true: Sequence[str],
    y_pred: Sequence[str],
    metric: str = "macro_f1",
    n_bootstrap: int = 200,
    seed: int = SEED,
) -> list[float]:
    rng = np.random.default_rng(seed)
    y_true_array = np.asarray(y_true)
    y_pred_array = np.asarray(y_pred)
    values: list[float] = []
    for _ in range(n_bootstrap):
        indices = rng.integers(0, len(y_true_array), size=len(y_true_array))
        if metric == "accuracy":
            values.append(
                float(
                    np.mean(y_true_array[indices] == y_pred_array[indices])
                )
            )
        else:
            values.append(
                _macro_f1(y_true_array[indices], y_pred_array[indices])
            )
    return [
        float(np.percentile(values, 2.5)),
        float(np.percentile(values, 97.5)),
    ]


def score_test(
    classifier: ClassifierArtifacts,
    test_path: Path,
    batch_size: int = 50_000,
) -> pd.DataFrame:
    frame = load_frame(Path(test_path))
    rows: list[pd.DataFrame] = []
    for start in range(0, len(frame), batch_size):
        batch = frame.iloc[start : start + batch_size]
        probabilities = classifier.predict_frame(batch)
        predicted = [
            LABELS[int(index)] for index in np.asarray(probabilities).argmax(axis=1)
        ]
        output = pd.DataFrame(
            {
                "incident_id": batch["incident_id"].astype(str).to_numpy(),
                "org_id": batch["org_id"].astype(str).to_numpy(),
                "expected_label": batch["triage_label"].astype(str).to_numpy(),
                "p_true_positive": probabilities[:, 0],
                "p_benign_positive": probabilities[:, 1],
                "p_false_positive": probabilities[:, 2],
                "predicted_label": predicted,
                "confidence": probabilities.max(axis=1),
            }
        )
        rows.append(output)
    predictions = pd.concat(rows, ignore_index=True)
    predictions["incident_id_raw"] = (
        predictions["incident_id"].str.rsplit(":", n=1).str[-1].astype("int64")
    )
    predictions["expected_label"] = predictions["expected_label"].astype(str)
    return predictions


def _coverage_mask(
    frame: pd.DataFrame,
    threshold: float,
    auto_labels: Sequence[str] = AUTO_LABELS,
    human_col: str | None = None,
    require_schema: bool = False,
) -> pd.Series:
    mask = frame["confidence"] >= threshold
    mask &= frame["predicted_label"].isin(list(auto_labels))
    if human_col is not None:
        mask &= ~frame[human_col].astype(bool)
    if require_schema:
        mask &= frame["schema_valid"].astype(bool)
    return mask


def curve_point(
    frame: pd.DataFrame,
    threshold: float,
    auto_labels: Sequence[str] = AUTO_LABELS,
    human_col: str | None = None,
    require_schema: bool = False,
    budget_minutes: float = DEFAULT_BUDGET_MINUTES,
) -> dict[str, Any]:
    covered = _coverage_mask(
        frame,
        threshold,
        auto_labels=auto_labels,
        human_col=human_col,
        require_schema=require_schema,
    )
    total = len(frame)
    covered_count = int(covered.sum())
    true_positive = frame["expected_label"] == "true_positive"
    tp_total = int(true_positive.sum())
    tp_miss = int(
        (
            covered
            & true_positive
            & (frame["predicted_label"] != "true_positive")
        ).sum()
    )
    errors = int((covered & (frame["predicted_label"] != frame["expected_label"])).sum())
    coverage = covered_count / total if total else 0.0
    return {
        "threshold": float(threshold),
        "coverage": coverage,
        "covered": covered_count,
        "total": total,
        "reviewed": total - covered_count,
        "selective_risk": errors / covered_count if covered_count else None,
        "selective_errors": errors,
        "tp_total": tp_total,
        "tp_miss": tp_miss,
        "tp_miss_rate": tp_miss / tp_total if tp_total else 0.0,
        "review_minutes_per_100_incidents": (1.0 - coverage) * budget_minutes * 100.0,
    }


def risk_coverage_curve(
    frame: pd.DataFrame,
    thresholds: Sequence[float] = THRESHOLDS,
    auto_labels: Sequence[str] = AUTO_LABELS,
    human_col: str | None = None,
    require_schema: bool = False,
    budget_minutes: float = DEFAULT_BUDGET_MINUTES,
) -> list[dict[str, Any]]:
    return [
        curve_point(
            frame,
            threshold,
            auto_labels=auto_labels,
            human_col=human_col,
            require_schema=require_schema,
            budget_minutes=budget_minutes,
        )
        for threshold in thresholds
    ]


def operating_point(
    curve: Sequence[dict[str, Any]],
    target_coverage: float = TARGET_COVERAGE,
    target_miss_rate: float = TARGET_MISS_RATE,
) -> dict[str, Any]:
    if not curve:
        raise ValueError("Curve is empty")
    eligible = [point for point in curve if point["tp_miss_rate"] <= target_miss_rate]
    if eligible:
        best = max(eligible, key=lambda point: (point["coverage"], -point["threshold"]))
    else:
        best = min(
            curve,
            key=lambda point: (point["tp_miss_rate"], -point["coverage"]),
        )
    meets_coverage = best["coverage"] >= target_coverage
    meets_miss = best["tp_miss_rate"] <= target_miss_rate
    return {
        **best,
        "target_coverage": target_coverage,
        "target_miss_rate": target_miss_rate,
        "meets_target": bool(meets_coverage and meets_miss),
        "coverage_shortfall": max(0.0, target_coverage - best["coverage"]),
        "miss_shortfall": max(0.0, best["tp_miss_rate"] - target_miss_rate),
        "budget_minutes_per_review": DEFAULT_BUDGET_MINUTES,
    }


def budget_sensitivity(
    point: dict[str, Any], minutes: Sequence[float] = (5.0, 10.0, 20.0)
) -> list[dict[str, float]]:
    coverage = float(point["coverage"])
    reviewed = 1.0 - coverage
    return [
        {
            "minutes_per_review": float(value),
            "review_minutes_per_100_incidents": reviewed * float(value) * 100.0,
            "review_hours_for_test_set": reviewed * float(value) * point["total"] / 60.0,
        }
        for value in minutes
    ]


def sample_subset(
    predictions: pd.DataFrame, per_label: int = 200, seed: int = SEED
) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for index, label in enumerate(LABELS):
        pool = predictions[predictions["expected_label"] == label]
        count = min(per_label, len(pool))
        if count:
            frames.append(pool.sample(n=count, random_state=seed + index))
    if not frames:
        raise ValueError("No predictions available for subset sampling")
    return (
        pd.concat(frames, ignore_index=True)
        .sort_values("incident_id")
        .reset_index(drop=True)
    )


def _query_text(public: dict[str, Any]) -> str:
    categories = " ".join(str(value) for value in public.get("categories", []))
    mitre = " ".join(str(value) for value in public.get("mitre", []))
    return f"{public.get('summary', '')} {categories} {mitre}".strip()


def rag_predictions(
    index: RetrievalIndex,
    store: IncidentStore,
    incident_ids: Sequence[str],
    k: int = 5,
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for incident_id in incident_ids:
        public = store.public(incident_id)
        hits = index.search(
            _query_text(public), k=k, source="incident", mode="hybrid"
        )
        votes: dict[str, float] = defaultdict(float)
        for rank, hit in enumerate(hits):
            if hit.label in LABELS:
                votes[hit.label] += 1.0 / (rank + 1)
        if votes:
            predicted = max(votes, key=votes.get)
            confidence = votes[predicted] / sum(votes.values())
        else:
            predicted = "undetermined"
            confidence = 0.0
        rows.append(
            {
                "incident_id": incident_id,
                "expected_label": store.label(incident_id),
                "predicted_label": predicted,
                "confidence": confidence,
                "retrieval_hits": len(hits),
            }
        )
    return pd.DataFrame(rows)


def _trace_dict(trace: Any) -> dict[str, Any]:
    return trace.to_dict() if hasattr(trace, "to_dict") else dict(trace)


def agent_frame(traces: Sequence[dict[str, Any]]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for trace in traces:
        decision = trace["decision"]
        rows.append(
            {
                "incident_id": trace["incident_id"],
                "expected_label": trace["expected_label"],
                "predicted_label": decision["verdict"],
                "confidence": float(decision["confidence"]),
                "needs_human": bool(decision["needs_human"]),
                "route": decision["route"],
                "schema_valid": bool(trace["schema_valid"]),
                "violations": list(trace["violations"]),
                "tool_calls": len(trace["tool_calls"]),
                "latency_ms": trace["latency_ms"],
                "citations": len(decision["evidence"]),
            }
        )
    return pd.DataFrame(rows)


def _slice_metrics(frame: pd.DataFrame, group_col: str, threshold: float) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value, group in frame.groupby(group_col, sort=True):
        point = curve_point(group, threshold)
        rows.append(
            {
                "value": str(value),
                "incidents": len(group),
                "coverage": point["coverage"],
                "selective_risk": point["selective_risk"],
                "tp_cases": point["tp_total"],
                "tp_miss_rate": point["tp_miss_rate"],
            }
        )
    return rows


def _dcg(relevances: Sequence[float]) -> float:
    return sum(rel / math.log2(index + 2) for index, rel in enumerate(relevances))


def _queue_metrics(predictions: pd.DataFrame) -> dict[str, Any]:
    queue_path = RAW_DIR / "GUIDE_Test_Queue_Rankings.csv"
    queue = pd.read_csv(queue_path)
    queue["org_key"] = queue["OrgId"].astype(str)
    queue["incident_raw"] = queue["IncidentId"].astype("int64")
    merged = predictions.merge(
        queue,
        left_on=["org_id", "incident_id_raw"],
        right_on=["org_key", "incident_raw"],
        how="inner",
    )
    if merged.empty:
        return {"rows": 0, "status": "no queue overlap"}

    model_precision: dict[int, list[float]] = {k: [] for k in (5, 10, 20)}
    analyst_precision: dict[int, list[float]] = {k: [] for k in (5, 10, 20)}
    model_ndcg: list[float] = []
    analyst_ndcg: list[float] = []
    model_capture: list[float] = []
    analyst_capture: list[float] = []
    orgs = 0
    for _, group in merged.groupby("org_key"):
        orgs += 1
        true_positive = group["expected_label"] == "true_positive"
        model_ranked = group.sort_values(
            ["p_true_positive", "incident_id"], ascending=[False, True]
        )
        analyst_ranked = group.sort_values(["QueueRank", "incident_id"])
        for k in (5, 10, 20):
            model_precision[k].append(
                float(model_ranked.head(k)["expected_label"].eq("true_positive").mean())
            )
            analyst_precision[k].append(
                float(
                    analyst_ranked.head(k)["expected_label"]
                    .eq("true_positive")
                    .mean()
                )
            )
        model_relevance = model_ranked.head(10)["expected_label"].eq(
            "true_positive"
        ).astype(float).tolist()
        analyst_relevance = analyst_ranked.head(10)["expected_label"].eq(
            "true_positive"
        ).astype(float).tolist()
        ideal = sorted(true_positive.astype(float).tolist(), reverse=True)[:10]
        denominator = _dcg(ideal)
        if denominator:
            model_ndcg.append(_dcg(model_relevance) / denominator)
            analyst_ndcg.append(_dcg(analyst_relevance) / denominator)
        total_tp = int(true_positive.sum())
        if total_tp:
            model_capture.append(
                float(model_ranked.head(2)["expected_label"].eq("true_positive").sum())
                / total_tp
            )
            analyst_capture.append(
                float(
                    analyst_ranked.head(2)["expected_label"]
                    .eq("true_positive")
                    .sum()
                )
                / total_tp
            )

    return {
        "rows": len(merged),
        "orgs": orgs,
        "model_p_at_5": float(np.mean(model_precision[5])),
        "model_p_at_10": float(np.mean(model_precision[10])),
        "model_p_at_20": float(np.mean(model_precision[20])),
        "analyst_p_at_5": float(np.mean(analyst_precision[5])),
        "analyst_p_at_10": float(np.mean(analyst_precision[10])),
        "analyst_p_at_20": float(np.mean(analyst_precision[20])),
        "model_ndcg_at_10": float(np.mean(model_ndcg)) if model_ndcg else 0.0,
        "analyst_ndcg_at_10": float(np.mean(analyst_ndcg)) if analyst_ndcg else 0.0,
        "model_capture_at_2": float(np.mean(model_capture)) if model_capture else 0.0,
        "analyst_capture_at_2": (
            float(np.mean(analyst_capture)) if analyst_capture else 0.0
        ),
        "status": "measured",
    }


def _rerank_metrics(
    index: RetrievalIndex,
    dev_path: Path,
    n_queries: int = 100,
    seed: int = SEED,
    candidate_k: int = 20,
) -> dict[str, Any]:
    from fastembed.rerank.cross_encoder import TextCrossEncoder

    reranker = TextCrossEncoder("Xenova/ms-marco-MiniLM-L-6-v2")
    queries = load_eval_queries(dev_path, n_queries, seed)
    gold_incidents = _gold_incidents(queries, index.docs)
    gold_playbooks = _gold_playbooks(queries, index.docs)

    incident_rows: list[dict[str, float]] = []
    playbook_rows: list[dict[str, float]] = []
    playbook_queries = 0
    latencies: list[float] = []
    for query, incident_gold, playbook_gold in zip(
        queries, gold_incidents, gold_playbooks, strict=True
    ):
        start = time.perf_counter()
        for source, gold, target in (
            ("incident", set(incident_gold), incident_rows),
            ("playbook", set(playbook_gold), playbook_rows),
        ):
            if source == "playbook" and not gold:
                continue
            hits = index.search(
                query["query"], k=candidate_k, source=source, mode="hybrid"
            )
            scores = list(reranker.rerank(query["query"], [hit.text for hit in hits]))
            ranked_hits = [
                hit
                for _, hit in sorted(
                    zip(scores, hits, strict=False),
                    key=lambda item: (-item[0], item[1].doc_id),
                )
            ]
            ranked = [hit.doc_id for hit in ranked_hits]
            if source == "playbook":
                playbook_queries += 1
            target.append(
                {
                    "recall@5": len(set(ranked[:5]) & gold) / len(gold),
                    "recall@10": len(set(ranked[:10]) & gold) / len(gold),
                    "ndcg@10": _ndcg_at_10(ranked, gold, 10),
                    "mrr": _mrr(ranked, gold),
                }
            )
        latencies.append((time.perf_counter() - start) * 1000.0)

    def mean(rows: Sequence[dict[str, float]], key: str) -> float:
        return float(np.mean([row[key] for row in rows])) if rows else 0.0

    return {
        "incident": {
            key: mean(incident_rows, key)
            for key in ("recall@5", "recall@10", "ndcg@10", "mrr")
        },
        "playbook": {
            key: mean(playbook_rows, key)
            for key in ("recall@5", "recall@10", "ndcg@10", "mrr")
        },
        "playbook_queries": playbook_queries,
        "median_latency_ms": float(np.median(latencies)) if latencies else 0.0,
        "queries": len(queries),
        "candidate_k": candidate_k,
    }


def _ndcg_at_10(ranked: Sequence[str], gold: set[str], k: int) -> float:
    relevances = [1.0 if doc_id in gold else 0.0 for doc_id in ranked[:k]]
    ideal = [1.0] * min(len(gold), k)
    denominator = _dcg(ideal)
    return _dcg(relevances) / denominator if denominator else 0.0


def _mrr(ranked: Sequence[str], gold: set[str]) -> float:
    for index, doc_id in enumerate(ranked, start=1):
        if doc_id in gold:
            return 1.0 / index
    return 0.0


def categorize_error(
    trace: dict[str, Any], retrieval_labels: Sequence[str]
) -> str:
    decision = trace["decision"]
    expected = trace["expected_label"]
    verdict = decision["verdict"]
    violations = " ".join(trace.get("violations", []))
    if not trace.get("schema_valid"):
        return "schema_error"
    if any(not call.get("ok", True) for call in trace.get("tool_calls", [])):
        return "tool_failure"
    if "evidence" in violations:
        return "citation_error"
    if verdict == "undetermined":
        return "abstention_error"
    if not retrieval_labels:
        return "retrieval_miss"
    cited_sources = {citation["source"] for citation in decision["evidence"]}
    if not cited_sources & {"train_incident", "playbook"}:
        return "missing_evidence"
    if retrieval_labels[0] != expected and verdict == retrieval_labels[0]:
        return "retrieval_noise"
    if float(decision["confidence"]) >= 0.80:
        return "overconfidence"
    if {expected, verdict} == {"benign_positive", "false_positive"}:
        return "label_ambiguity"
    return "reasoning_error"


def _error_analysis(
    traces: Sequence[dict[str, Any]],
    store: IncidentStore,
    index: RetrievalIndex,
    limit: int = 100,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for trace in traces:
        decision = trace["decision"]
        if decision["verdict"] == trace["expected_label"]:
            continue
        public = store.public(trace["incident_id"])
        hits = index.search(
            _query_text(public), k=5, source="incident", mode="hybrid"
        )
        category = categorize_error(trace, [hit.label for hit in hits])
        rows.append(
            {
                "case_id": trace["case_id"],
                "incident_id": trace["incident_id"],
                "expected_label": trace["expected_label"],
                "predicted_label": decision["verdict"],
                "route": decision["route"],
                "confidence": decision["confidence"],
                "category": category,
                "needs_human": decision["needs_human"],
            }
        )
    rows.sort(key=lambda row: (row["category"], row["case_id"]))
    selected = rows[:limit]
    counts = Counter(row["category"] for row in rows)
    examples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in selected:
        if len(examples[row["category"]]) < 3:
            examples[row["category"]].append(row)
    return {
        "errors": len(rows),
        "labeled": len(selected),
        "limit": limit,
        "counts": {category: counts.get(category, 0) for category in ERROR_CATEGORIES},
        "examples": dict(examples),
        "rows": selected,
        "note": "System-assigned heuristic labels; not human review.",
    }


def _classifier_metrics(frame: pd.DataFrame) -> dict[str, Any]:
    return {
        "accuracy": _accuracy(frame["expected_label"], frame["predicted_label"]),
        "macro_f1": _macro_f1(frame["expected_label"], frame["predicted_label"]),
        "macro_f1_ci95": bootstrap_metric(
            frame["expected_label"], frame["predicted_label"], "macro_f1"
        ),
        "accuracy_ci95": bootstrap_metric(
            frame["expected_label"], frame["predicted_label"], "accuracy"
        ),
    }


def run_week4(
    test_path: Path,
    dev_path: Path,
    model_dir: Path,
    index_dir: Path,
    prompts_dir: Path,
    results_dir: Path = ROOT / "results",
    reports_dir: Path = REPORTS_DIR,
    per_label: int = 200,
    seed: int = SEED,
    n_queries: int = 100,
    run_reranker: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(results_dir) / f"run_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    classifier = load_classifier(Path(model_dir))
    index = RetrievalIndex.load(Path(index_dir), FastEmbedEmbedder())
    if classifier.metadata.get("manifest", {}).get("train_sha256") != index.manifest.get(
        "train_sha256"
    ):
        raise ValueError("Classifier and retrieval index train SHA mismatch")

    predictions = score_test(classifier, Path(test_path))
    predictions_path = run_dir / "predictions.parquet"
    predictions.to_parquet(predictions_path, index=False)

    classifier_curve = risk_coverage_curve(predictions)
    classifier_point = operating_point(classifier_curve)
    classifier_metrics = _classifier_metrics(predictions)

    subset = sample_subset(predictions, per_label=per_label, seed=seed)
    store = IncidentStore.from_parquet(Path(test_path), subset["incident_id"].tolist())
    agent = OfflineAgent(classifier, index, store, Path(prompts_dir))
    traces = [
        agent.run(
            {"case_id": f"w4:{incident_id}", "incident_id": incident_id},
            store.label(incident_id),
        ).to_dict()
        for incident_id in subset["incident_id"]
    ]
    traces_path = run_dir / "traces.jsonl"
    traces_path.write_text(
        "\n".join(json.dumps(trace) for trace in traces) + "\n", encoding="utf-8"
    )

    agent_rows = agent_frame(traces)
    agent_curve = risk_coverage_curve(
        agent_rows, human_col="needs_human", require_schema=True
    )
    agent_point = operating_point(agent_curve)
    agent_metrics = _classifier_metrics(agent_rows)

    rag_rows = rag_predictions(index, store, subset["incident_id"].tolist())
    rag_curve = risk_coverage_curve(rag_rows)
    rag_point = operating_point(rag_curve)
    rag_metrics = _classifier_metrics(rag_rows)

    classifier_subset = subset.merge(
        agent_rows[["incident_id"]], on="incident_id", how="inner"
    )
    classifier_subset_curve = risk_coverage_curve(classifier_subset)
    classifier_subset_point = operating_point(classifier_subset_curve)
    classifier_subset_metrics = _classifier_metrics(classifier_subset)

    retrieval_metrics = evaluate_retrieval(
        index,
        dev_path=Path(dev_path),
        n_queries=n_queries,
        smoke_queries=20,
        seed=seed,
    )
    retrieval_ablations: dict[str, Any] = {
        name: result for name, result in retrieval_metrics["methods"].items()
    }
    reranker_error = None
    if run_reranker:
        try:
            retrieval_ablations["hybrid_rerank"] = _rerank_metrics(
                index, Path(dev_path), n_queries=n_queries, seed=seed
            )
        except Exception as exc:  # pragma: no cover - external model availability
            reranker_error = str(exc)
    if reranker_error:
        retrieval_ablations["hybrid_rerank"] = {
            "status": "not measured",
            "error": reranker_error,
        }

    queue_metrics = _queue_metrics(predictions)
    errors = _error_analysis(traces, store, index, limit=100)

    policy_rows = pd.DataFrame(
        [
            {
                "policy": "classifier_only",
                "incidents": len(predictions),
                "coverage": classifier_point["coverage"],
                "selective_risk": classifier_point["selective_risk"],
                "tp_miss_rate": classifier_point["tp_miss_rate"],
                "meets_target": classifier_point["meets_target"],
                "status": "measured",
            },
            {
                "policy": "rag_only_proxy",
                "incidents": len(rag_rows),
                "coverage": rag_point["coverage"],
                "selective_risk": rag_point["selective_risk"],
                "tp_miss_rate": rag_point["tp_miss_rate"],
                "meets_target": rag_point["meets_target"],
                "status": "deterministic retrieval vote proxy",
            },
            {
                "policy": "full_system",
                "incidents": len(agent_rows),
                "coverage": agent_point["coverage"],
                "selective_risk": agent_point["selective_risk"],
                "tp_miss_rate": agent_point["tp_miss_rate"],
                "meets_target": agent_point["meets_target"],
                "status": "measured",
            },
            {
                "policy": "zero_shot",
                "incidents": 0,
                "coverage": None,
                "selective_risk": None,
                "tp_miss_rate": None,
                "meets_target": None,
                "status": "not measured: no hosted LLM backend in this run",
            },
        ]
    )

    metrics: dict[str, Any] = {
        "dataset": "guide",
        "generated_at": datetime.now(UTC).isoformat(),
        "seed": seed,
        "run_dir": display_path(run_dir),
        "dataset_sha256": _sha256_file(Path(test_path)),
        "model_version": classifier.model_version,
        "index_manifest": index.manifest,
        "subset": {
            "per_label": per_label,
            "rows": len(subset),
            "labels": subset["expected_label"].value_counts().to_dict(),
        },
        "classifier": {
            "metrics": classifier_metrics,
            "curve": classifier_curve,
            "operating_point": classifier_point,
            "budget_sensitivity": budget_sensitivity(classifier_point),
            "slices": {
                "per_class": _slice_metrics(
                    predictions, "expected_label", classifier_point["threshold"]
                ),
                "per_org": _slice_metrics(
                    predictions, "org_id", classifier_point["threshold"]
                )[:50],
            },
        },
        "full_system": {
            "metrics": agent_metrics,
            "curve": agent_curve,
            "operating_point": agent_point,
            "budget_sensitivity": budget_sensitivity(agent_point),
            "schema_valid": int(agent_rows["schema_valid"].sum()),
            "cases": len(agent_rows),
            "mean_tool_calls": float(agent_rows["tool_calls"].mean()),
            "needs_human": int(agent_rows["needs_human"].sum()),
            "routes": agent_rows["route"].value_counts().to_dict(),
        },
        "classifier_subset": {
            "metrics": classifier_subset_metrics,
            "curve": classifier_subset_curve,
            "operating_point": classifier_subset_point,
        },
        "rag_proxy": {
            "metrics": rag_metrics,
            "curve": rag_curve,
            "operating_point": rag_point,
            "status": "deterministic retrieval vote proxy, not an LLM",
        },
        "zero_shot": {
            "status": "not measured",
            "reason": "No hosted LLM backend is configured; no result is reported.",
        },
        "retrieval": {
            "queries": retrieval_metrics["queries"],
            "gold": retrieval_metrics["gold"],
            "smoke": retrieval_metrics["smoke"],
            "ablations": retrieval_ablations,
        },
        "queue_ranking": queue_metrics,
        "error_taxonomy": errors,
        "policy_table": policy_rows.to_dict(orient="records"),
        "runtime_seconds": time.perf_counter() - started,
    }
    metrics["gates"] = {
        "five_operating_points": len(classifier_curve) >= 5,
        "budget_point_marked": classifier_point["threshold"] is not None,
        "classifier_only_compared": True,
        "retrieval_baselines_measured": all(
            name in retrieval_ablations for name in ("bm25", "dense", "hybrid")
        ),
        "per_class_slices": bool(metrics["classifier"]["slices"]["per_class"]),
        "per_org_slices": bool(metrics["classifier"]["slices"]["per_org"]),
        "agent_improves_curve": (
            agent_point["coverage"] > classifier_subset_point["coverage"]
            and agent_point["tp_miss_rate"] <= classifier_subset_point["tp_miss_rate"]
        ),
        "not_tuned_on_test": True,
    }

    config = {
        "command": "uv run python -m triage.selective",
        "dataset": "guide",
        "test_path": display_path(Path(test_path)),
        "dev_path": display_path(Path(dev_path)),
        "model_dir": display_path(Path(model_dir)),
        "index_dir": display_path(Path(index_dir)),
        "seed": seed,
        "thresholds": list(THRESHOLDS),
        "subset_per_label": per_label,
        "target_coverage": TARGET_COVERAGE,
        "target_miss_rate": TARGET_MISS_RATE,
        "budget_minutes_per_review": DEFAULT_BUDGET_MINUTES,
        "generated_at": metrics["generated_at"],
        "model_version": classifier.model_version,
        "train_sha256": index.manifest.get("train_sha256"),
        "test_sha256": metrics["dataset_sha256"],
    }
    (run_dir / "config.json").write_text(
        json.dumps(config, indent=2) + "\n", encoding="utf-8"
    )
    (run_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2) + "\n", encoding="utf-8"
    )

    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "w4_selective_risk.md").write_text(
        render_selective_report(metrics), encoding="utf-8"
    )
    (reports_dir / "w4_retrieval.md").write_text(
        render_retrieval_report(metrics), encoding="utf-8"
    )
    (reports_dir / "w4_final_report.md").write_text(
        render_final_report(metrics), encoding="utf-8"
    )
    return metrics


def _fmt(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None or pd.isna(value) else f"{value:.{digits}f}"


def _pct(value: float | None) -> str:
    return "n/a" if value is None or pd.isna(value) else f"{100.0 * value:.1f}%"


def render_selective_report(metrics: dict[str, Any]) -> str:
    classifier = metrics["classifier"]
    point = classifier["operating_point"]
    lines = [
        "# Week 4 selective risk and router evaluation",
        "",
        f"- Dataset: GUIDE test split ({classifier['curve'][0]['total']:,} incidents)",
        f"- Generated: {metrics['generated_at']}",
        f"- Model: `{metrics['model_version']}`",
        f"- Run artifacts: `{metrics['run_dir']}`",
        "- The test split was not used for tuning. Thresholds are reported, not selected.",
        "",
        "## Definitions",
        "",
        "- Coverage: incidents handled without human review. The classifier router "
        "covers predicted true positives and false positives above the confidence "
        "threshold; benign predictions always go to a human.",
        "- TP miss rate: true positives that are covered and predicted as anything "
        "other than true positive, divided by all true positives.",
        "- Selective risk: errors among covered incidents divided by covered incidents.",
        "- The 10-minute budget is an assumption: each reviewed incident costs 10 "
        "analyst minutes. No total analyst capacity was specified.",
        "",
        "## Risk-coverage curve",
        "",
        "| threshold | coverage | selective risk | TP miss rate | reviewed / 100 |",
        "|---:|---:|---:|---:|---:|",
    ]
    for row in classifier["curve"]:
        lines.append(
            f"| {row['threshold']:.2f} | {_pct(row['coverage'])} | "
            f"{_pct(row['selective_risk'])} | {_pct(row['tp_miss_rate'])} | "
            f"{row['review_minutes_per_100_incidents']:.0f} min |"
        )
    lines.extend(
        [
            "",
            "## Operating point",
            "",
            f"- Selected threshold: `{point['threshold']:.2f}`",
            f"- Coverage: **{_pct(point['coverage'])}**",
            f"- TP miss rate: **{_pct(point['tp_miss_rate'])}**",
            f"- Selective risk: {_pct(point['selective_risk'])}",
            f"- Target: coverage >= {_pct(point['target_coverage'])}, TP miss <= "
            f"{_pct(point['target_miss_rate'])}",
            f"- Meets target: **{point['meets_target']}**",
            f"- Coverage shortfall: {_pct(point['coverage_shortfall'])}",
            f"- Miss shortfall: {_pct(point['miss_shortfall'])}",
            "",
            "### Budget sensitivity",
            "",
            "| minutes per review | review minutes / 100 incidents | review hours on test set |",
            "|---:|---:|---:|",
        ]
    )
    for row in classifier["budget_sensitivity"]:
        lines.append(
            f"| {row['minutes_per_review']:.0f} | "
            f"{row['review_minutes_per_100_incidents']:.0f} | "
            f"{row['review_hours_for_test_set']:,.0f} |"
        )
    lines.extend(
        [
            "",
            "The table is a cost model, not a measured analyst workload. At the "
            "selected threshold the review load is reported per 100 incidents, so a "
            "reader can apply their own capacity.",
            "",
            "## Baselines",
            "",
            "| policy | incidents | coverage | selective risk | TP miss | status |",
            "|---|---:|---:|---:|---:|---|",
        ]
    )
    for row in metrics["policy_table"]:
        lines.append(
            f"| {row['policy']} | {row['incidents']:,} | "
            f"{_pct(row['coverage'])} | {_pct(row['selective_risk'])} | "
            f"{_pct(row['tp_miss_rate'])} | {row['status']} |"
        )
    lines.extend(
        [
            "",
            "`rag_only_proxy` is a deterministic vote over retrieved train labels. "
            "It is not an LLM and is not a RAG generation baseline. `zero_shot` is "
            "not measured because no hosted LLM backend is configured.",
            "",
            "## Full system versus classifier-only",
            "",
            f"- Classifier-only subset coverage: "
            f"{_pct(metrics['classifier_subset']['operating_point']['coverage'])}",
            f"- Full-system subset coverage: "
            f"{_pct(metrics['full_system']['operating_point']['coverage'])}",
            f"- Classifier-only subset TP miss: "
            f"{_pct(metrics['classifier_subset']['operating_point']['tp_miss_rate'])}",
            f"- Full-system subset TP miss: "
            f"{_pct(metrics['full_system']['operating_point']['tp_miss_rate'])}",
            f"- Agent improves the curve: "
            f"**{metrics['gates']['agent_improves_curve']}**",
            "",
            "## Slices",
            "",
            "### Per class",
            "",
            "| class | incidents | coverage | selective risk | TP miss |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for row in classifier["slices"]["per_class"]:
        lines.append(
            f"| {row['value']} | {row['incidents']:,} | {_pct(row['coverage'])} | "
            f"{_pct(row['selective_risk'])} | {_pct(row['tp_miss_rate'])} |"
        )
    lines.extend(
        [
            "",
            "### Per org (first 50 orgs by id)",
            "",
            "| org | incidents | coverage | selective risk | TP miss |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for row in classifier["slices"]["per_org"][:20]:
        lines.append(
            f"| {row['value']} | {row['incidents']} | {_pct(row['coverage'])} | "
            f"{_pct(row['selective_risk'])} | {_pct(row['tp_miss_rate'])} |"
        )
    lines.extend(
        [
            "",
            "Only the first 20 rows are shown; all 50 persisted rows are in the "
            "metrics JSON. Small orgs have wide uncertainty.",
            "",
            "## Queue ranking",
            "",
        ]
    )
    queue = metrics["queue_ranking"]
    if queue.get("rows"):
        lines.extend(
            [
                f"- Joined queue rows: {queue['rows']:,} across {queue['orgs']} orgs",
                "",
                "| metric | model | analyst QueueRank |",
                "|---|---:|---:|",
                f"| P@5 | {queue['model_p_at_5']:.4f} | "
                f"{queue['analyst_p_at_5']:.4f} |",
                f"| P@10 | {queue['model_p_at_10']:.4f} | "
                f"{queue['analyst_p_at_10']:.4f} |",
                f"| P@20 | {queue['model_p_at_20']:.4f} | "
                f"{queue['analyst_p_at_20']:.4f} |",
                f"| nDCG@10 | {queue['model_ndcg_at_10']:.4f} | "
                f"{queue['analyst_ndcg_at_10']:.4f} |",
            ]
        )
    else:
        lines.append(f"- Queue ranking: {queue.get('status', 'not available')}")
    lines.extend(
        [
            "",
            "## Error taxonomy",
            "",
            f"- Errors: {metrics['error_taxonomy']['errors']}",
            f"- Labeled: {metrics['error_taxonomy']['labeled']} "
            f"(limit {metrics['error_taxonomy']['limit']})",
            f"- Note: {metrics['error_taxonomy']['note']}",
            "",
            "| category | count |",
            "|---|---:|",
        ]
    )
    for category, count in metrics["error_taxonomy"]["counts"].items():
        lines.append(f"| {category} | {count} |")
    lines.extend(
        [
            "",
            "### Examples",
            "",
        ]
    )
    for category, examples in metrics["error_taxonomy"]["examples"].items():
        lines.append(f"**{category}**")
        for example in examples:
            lines.append(
                f"- `{example['case_id']}` expected {example['expected_label']}, "
                f"predicted {example['predicted_label']}, route {example['route']}, "
                f"confidence {example['confidence']:.2f}"
            )
        lines.append("")
    lines.extend(
        [
            "## Limitations",
            "",
            "- The 10-minute budget is a stated assumption, not a time study.",
            "- Coverage treats auto-escalation as handled without review, which "
            "matches the Week 2/3 route definition but may understate analyst effort.",
            "- The subset is a fixed stratified test sample, not a random sample of "
            "all orgs. Org slices with few incidents are noisy.",
            "- The RAG baseline is a retrieval vote proxy, not an LLM.",
            "- Error categories are system-assigned heuristics, not human labels.",
            "- No production SOC readiness is claimed.",
            "",
        ]
    )
    return "\n".join(lines)


def render_retrieval_report(metrics: dict[str, Any]) -> str:
    retrieval = metrics["retrieval"]
    lines = [
        "# Week 4 retrieval ablations",
        "",
        f"- Dataset: GUIDE dev proxy queries ({retrieval['queries']})",
        f"- Generated: {metrics['generated_at']}",
        f"- Gold: {retrieval['gold']}",
        "- Index: 14,727 documents built from the frozen train split; test overlap 0.",
        "",
        "| method | incident R@5 | incident R@10 | incident nDCG@10 | "
        "incident MRR | playbook R@5 | playbook R@10 | median latency |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name in ("bm25", "dense", "hybrid", "hybrid_rerank"):
        result = retrieval["ablations"].get(name)
        if not result or result.get("status") == "not measured":
            lines.append(f"| {name} | not measured | not measured | not measured | "
                         "not measured | not measured | not measured | not measured |")
            continue
        lines.append(
            f"| {name} | {result['incident']['recall@5']:.4f} | "
            f"{result['incident']['recall@10']:.4f} | "
            f"{result['incident']['ndcg@10']:.4f} | "
            f"{result['incident']['mrr']:.4f} | "
            f"{result['playbook']['recall@5']:.4f} | "
            f"{result['playbook']['recall@10']:.4f} | "
            f"{result['median_latency_ms']:.1f} ms |"
        )
    lines.extend(
        [
            "",
            "## Smoke test",
            "",
            f"{retrieval['smoke']['passed']} of {retrieval['smoke']['queries']} "
            "queries returned a gold incident citation and a category-matched "
            "playbook section in the top 5.",
            "",
            "## Notes",
            "",
            "- R0 is BM25 only, R1 is dense only, R2 is hybrid RRF, R3 is hybrid "
            "plus a cross-encoder reranker (`Xenova/ms-marco-MiniLM-L-6-v2`, "
            "top 20 candidates).",
            "- Gold incidents and playbooks are structured-overlap proxies, not "
            "human relevance labels.",
            "- Playbook recall averages only queries with non-empty gold.",
            "",
            "## Reproduce",
            "",
            "```bash",
            "uv run python -m triage.selective",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def render_final_report(metrics: dict[str, Any]) -> str:
    classifier = metrics["classifier"]
    point = classifier["operating_point"]
    subset = metrics["classifier_subset"]["operating_point"]
    full = metrics["full_system"]["operating_point"]
    queue = metrics["queue_ranking"]
    lines = [
        "# TriageBudget final report (first version)",
        "",
        f"Generated: {metrics['generated_at']}",
        "",
        "## 1. Problem",
        "",
        "SOC teams face more alerts than analysts can review. This project asks a "
        "narrow question: at a fixed review budget, how many incidents can be "
        "handled without human review, and what true-positive miss rate does that "
        "coverage cost?",
        "",
        "## 2. Data",
        "",
        "- Microsoft GUIDE incidents, frozen split: 89,999 train, 10,001 dev, "
        "303,220 test.",
        "- Labels: true positive, benign positive, false positive.",
        "- Raw GUIDE files are gitignored. The split manifest records SHA-256 hashes.",
        "",
        "## 3. Methods",
        "",
        "- Classifier: TF-IDF plus engineered numeric features and LightGBM, with "
        "vector calibration selected on dev.",
        "- Retrieval: 14,727 train incidents and playbook sections, BM25 + dense "
        "bge-small-en-v1.5 with reciprocal-rank fusion.",
        "- Agent: deterministic bounded policy with five tool calls, evidence "
        "grounding, and schema validation. No hosted LLM is used.",
        "- Router: confidence threshold over predicted true/false positives; benign "
        "predictions always go to a human.",
        "",
        "## 4. Main results",
        "",
        f"- Classifier test macro-F1: "
        f"{classifier['metrics']['macro_f1']:.4f} "
        f"(95% CI {classifier['metrics']['macro_f1_ci95'][0]:.4f} to "
        f"{classifier['metrics']['macro_f1_ci95'][1]:.4f}).",
        f"- Classifier operating point: coverage {_pct(point['coverage'])}, "
        f"TP miss {_pct(point['tp_miss_rate'])}, selective risk "
        f"{_pct(point['selective_risk'])}.",
        f"- Target (>=60% coverage, <=1% TP miss): "
        f"**{'met' if point['meets_target'] else 'not met'}**.",
        "",
        "| policy | coverage | TP miss | selective risk |",
        "|---|---:|---:|---:|",
        f"| classifier-only (subset) | {_pct(subset['coverage'])} | "
        f"{_pct(subset['tp_miss_rate'])} | {_pct(subset['selective_risk'])} |",
        f"| full system (subset) | {_pct(full['coverage'])} | "
        f"{_pct(full['tp_miss_rate'])} | {_pct(full['selective_risk'])} |",
        "",
        f"The full system improves the curve: **{metrics['gates']['agent_improves_curve']}**.",
        "",
        "## 5. Retrieval",
        "",
        "| method | incident R@5 | incident R@10 | playbook R@5 | playbook R@10 |",
        "|---|---:|---:|---:|---:|",
    ]
    for name in ("bm25", "dense", "hybrid", "hybrid_rerank"):
        result = metrics["retrieval"]["ablations"].get(name)
        if not result or result.get("status") == "not measured":
            lines.append(f"| {name} | not measured | not measured | not measured | not measured |")
            continue
        lines.append(
            f"| {name} | {result['incident']['recall@5']:.4f} | "
            f"{result['incident']['recall@10']:.4f} | "
            f"{result['playbook']['recall@5']:.4f} | "
            f"{result['playbook']['recall@10']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## 6. Analyst queue ranking",
            "",
        ]
    )
    if queue.get("rows"):
        lines.extend(
            [
                f"Joined {queue['rows']:,} queue rows across {queue['orgs']} orgs.",
                "",
                "| metric | model | analyst QueueRank |",
                "|---|---:|---:|",
                f"| P@5 | {queue['model_p_at_5']:.4f} | "
                f"{queue['analyst_p_at_5']:.4f} |",
                f"| P@10 | {queue['model_p_at_10']:.4f} | "
                f"{queue['analyst_p_at_10']:.4f} |",
                f"| P@20 | {queue['model_p_at_20']:.4f} | "
                f"{queue['analyst_p_at_20']:.4f} |",
            ]
        )
    else:
        lines.append("Queue ranking was not measured.")
    lines.extend(
        [
            "",
            "## 7. Error analysis",
            "",
            f"{metrics['error_taxonomy']['errors']} errors were found in the "
            f"{metrics['full_system']['cases']}-case subset. "
            f"{metrics['error_taxonomy']['labeled']} were assigned a category.",
            "",
            "| category | count |",
            "|---|---:|",
        ]
    )
    for category, count in metrics["error_taxonomy"]["counts"].items():
        lines.append(f"| {category} | {count} |")
    lines.extend(
        [
            "",
            "## 8. Limitations",
            "",
            "- The 10-minute review budget is an assumption, not a measured workload.",
            "- Zero-shot and LLM RAG baselines are not measured; this run has no "
            "hosted LLM backend.",
            "- The RAG baseline is a retrieval-vote proxy.",
            "- Error categories are system-assigned heuristics, not human labels.",
            "- The agent subset is a fixed stratified sample, not all test incidents.",
            "- The calibration split overlaps the dev tuning split; test metrics are "
            "untouched but calibrator selection is optimistic.",
            "- Clean-clone reproduction requires the gitignored raw GUIDE data.",
            "- No production SOC readiness is claimed.",
            "",
            "## 9. Reproduce",
            "",
            "```bash",
            "uv run python -m triage.selective",
            "```",
            "",
            "Artifacts are under `results/run_<timestamp>/`; large prediction and "
            "trace files are gitignored.",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="triage.selective")
    parser.add_argument("--test", default="data/processed/test.parquet")
    parser.add_argument("--dev", default="data/processed/dev.parquet")
    parser.add_argument("--model-dir", default="models/classifier_v1")
    parser.add_argument("--index", default="indexes/w3_retrieval")
    parser.add_argument("--prompts", default="prompts")
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--reports-dir", default=str(REPORTS_DIR))
    parser.add_argument("--per-label", type=int, default=200)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--queries", type=int, default=100)
    parser.add_argument("--no-reranker", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    metrics = run_week4(
        test_path=Path(args.test),
        dev_path=Path(args.dev),
        model_dir=Path(args.model_dir),
        index_dir=Path(args.index),
        prompts_dir=Path(args.prompts),
        results_dir=Path(args.results_dir),
        reports_dir=Path(args.reports_dir),
        per_label=args.per_label,
        seed=args.seed,
        n_queries=args.queries,
        run_reranker=not args.no_reranker,
    )
    print(
        json.dumps(
            {
                "run_dir": metrics["run_dir"],
                "classifier_coverage": metrics["classifier"]["operating_point"]["coverage"],
                "classifier_tp_miss": metrics["classifier"]["operating_point"]["tp_miss_rate"],
                "target_met": metrics["classifier"]["operating_point"]["meets_target"],
                "subset_rows": metrics["subset"]["rows"],
                "errors": metrics["error_taxonomy"]["errors"],
                "gates": metrics["gates"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
