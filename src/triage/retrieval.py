from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import duckdb
import numpy as np
import pandas as pd

from triage.config import LABELS, SEED, display_path, sql_path

INDEX_VERSION = "w3_retrieval_v1"
DEFAULT_EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
DENSE_DIM = 384
BM25_K1 = 1.5
BM25_B = 0.75
RRF_K = 60
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.:/-]*")
SLUG_RE = re.compile(r"[^a-z0-9]+")


class Embedder(Protocol):
    name: str
    dim: int

    def embed_documents(self, texts: Sequence[str]) -> np.ndarray: ...

    def embed_query(self, text: str) -> np.ndarray: ...


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(str(text).lower())


def split_tokens(value: Any) -> list[str]:
    if value is None:
        return []
    return [token for token in re.split(r"[,\s;]+", str(value)) if token]


def _normalize(vectors: np.ndarray) -> np.ndarray:
    vectors = np.asarray(vectors, dtype=np.float32)
    if vectors.ndim == 1:
        vectors = vectors.reshape(1, -1)
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    return vectors / np.clip(norms, 1e-12, None)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class FastEmbedEmbedder:
    """Lazy fastembed wrapper so tests and indexing stay independent."""

    name = DEFAULT_EMBEDDING_MODEL
    dim = DENSE_DIM

    def __init__(self, model_name: str = DEFAULT_EMBEDDING_MODEL) -> None:
        self.name = model_name
        self._model: Any | None = None

    @property
    def model(self) -> Any:
        if self._model is None:
            from fastembed import TextEmbedding

            self._model = TextEmbedding(model_name=self.name)
        return self._model

    def embed_documents(self, texts: Sequence[str]) -> np.ndarray:
        vectors = list(self.model.embed(list(texts), batch_size=64))
        return _normalize(np.vstack(vectors))

    def embed_query(self, text: str) -> np.ndarray:
        vectors = list(self.model.query_embed([text]))
        return _normalize(np.vstack(vectors))[0]


@dataclass
class Doc:
    doc_id: str
    source: str
    source_id: str
    title: str
    text: str
    label: str | None = None
    categories: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    member_count: int = 1
    incident_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "source": self.source,
            "source_id": self.source_id,
            "title": self.title,
            "text": self.text,
            "label": self.label,
            "categories": self.categories,
            "mitre": self.mitre,
            "member_count": self.member_count,
            "incident_ids": self.incident_ids,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Doc:
        return cls(**payload)


@dataclass
class SearchHit:
    doc_id: str
    source: str
    source_id: str
    title: str
    text: str
    score: float
    label: str | None = None
    categories: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "source": self.source,
            "source_id": self.source_id,
            "title": self.title,
            "text": self.text,
            "score": self.score,
            "label": self.label,
            "categories": self.categories,
            "mitre": self.mitre,
            "metadata": self.metadata,
        }


class BM25:
    def __init__(self, documents: Sequence[Sequence[str]]) -> None:
        self.n_docs = len(documents)
        self.doc_lengths = np.asarray([len(tokens) for tokens in documents], dtype=float)
        self.avg_length = float(self.doc_lengths.mean()) if self.n_docs else 0.0
        self.postings: dict[str, dict[int, int]] = {}
        for index, tokens in enumerate(documents):
            for token, count in Counter(tokens).items():
                self.postings.setdefault(token, {})[index] = count
        self.idf = {
            token: math.log(
                1.0 + (self.n_docs - len(postings) + 0.5) / (len(postings) + 0.5)
            )
            for token, postings in self.postings.items()
        }

    def scores(self, query_tokens: Sequence[str]) -> np.ndarray:
        scores = np.zeros(self.n_docs, dtype=float)
        if not self.n_docs:
            return scores
        for token in Counter(query_tokens):
            postings = self.postings.get(token)
            if not postings:
                continue
            idf = self.idf[token]
            for index, count in postings.items():
                length = self.doc_lengths[index]
                denominator = count + BM25_K1 * (
                    1.0 - BM25_B + BM25_B * length / max(self.avg_length, 1e-9)
                )
                scores[index] += idf * count * (BM25_K1 + 1.0) / denominator
        return scores


def load_incident_docs(train_path: Path) -> list[Doc]:
    con = duckdb.connect()
    try:
        frame = con.execute(
            "SELECT incident_id, summary, title, triage_label, categories, "
            "mitre_techniques FROM read_parquet("
            f"'{sql_path(Path(train_path))}') "
            "WHERE summary IS NOT NULL AND summary <> '' ORDER BY incident_id"
        ).df()
    finally:
        con.close()

    frame["summary"] = frame["summary"].fillna("").astype(str)
    docs: list[Doc] = []
    grouped = frame.groupby(["summary", "triage_label"], sort=True)
    for (summary, label), group in grouped:
        first = group.iloc[0]
        incident_ids = group["incident_id"].astype(str).tolist()
        representative = incident_ids[0]
        docs.append(
            Doc(
                doc_id=f"incident:{representative}",
                source="incident",
                source_id=representative,
                title=str(first["title"] or summary[:80]),
                text=str(summary),
                label=str(label),
                categories=split_tokens(first["categories"]),
                mitre=split_tokens(first["mitre_techniques"]),
                member_count=len(incident_ids),
                incident_ids=incident_ids,
                metadata={"summary": str(summary)},
            )
        )
    return docs


def _slug(text: str) -> str:
    return SLUG_RE.sub("-", text.lower()).strip("-")


def parse_playbook(path: Path) -> list[Doc]:
    path = Path(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    title = ""
    metadata: dict[str, str] = {}
    sections: list[tuple[str, list[str]]] = []
    current: str | None = None
    body: list[str] = []

    for line in lines:
        if line.startswith("# "):
            title = line[2:].strip()
            continue
        metadata_match = re.match(r"\*\*(.+?):\*\*\s*(.*)", line)
        if metadata_match and current is None:
            metadata[metadata_match.group(1).strip().lower()] = metadata_match.group(2).strip()
            continue
        if line.startswith("## "):
            if current is not None:
                sections.append((current, body))
            current = line[3:].strip()
            body = []
            continue
        if current is not None:
            body.append(line)

    if current is not None:
        sections.append((current, body))
    if not title or not sections:
        raise ValueError(f"Playbook has no title or sections: {path}")

    categories = split_tokens(metadata.get("categories", ""))
    docs: list[Doc] = []
    for heading, lines_in_section in sections:
        text = " ".join(line.strip() for line in lines_in_section if line.strip())
        if not text:
            continue
        section_id = f"playbook:{path.stem}:{_slug(heading)}"
        docs.append(
            Doc(
                doc_id=section_id,
                source="playbook",
                source_id=section_id,
                title=f"{title} / {heading}",
                text=f"{title} {heading}. {text}",
                categories=categories,
                metadata={
                    "file": path.name,
                    "section": heading,
                    "role": metadata.get("role", ""),
                    "effective": metadata.get("effective", ""),
                    "source": metadata.get("source", ""),
                    "heading": heading,
                },
            )
        )
    return docs


def load_playbook_docs(playbooks_dir: Path) -> list[Doc]:
    docs: list[Doc] = []
    for path in sorted(Path(playbooks_dir).glob("*.md")):
        if path.name.lower() == "readme.md":
            continue
        docs.extend(parse_playbook(path))
    if not docs:
        raise ValueError(f"No playbook sections found in {playbooks_dir}")
    return docs


def _write_jsonl(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def build_index(
    train_path: Path,
    playbooks_dir: Path,
    out_dir: Path,
    embedder: Embedder | None = None,
    dataset_label: str = "guide",
) -> tuple[list[Doc], np.ndarray, dict[str, Any]]:
    embedder = embedder or FastEmbedEmbedder()
    train_path = Path(train_path)
    out_dir = Path(out_dir)
    incident_docs = load_incident_docs(train_path)
    playbook_docs = load_playbook_docs(playbooks_dir)
    docs = [*incident_docs, *playbook_docs]

    started = time.perf_counter()
    embeddings = embedder.embed_documents([doc.text for doc in docs])
    embed_seconds = time.perf_counter() - started
    if embeddings.shape != (len(docs), embedder.dim):
        raise ValueError(f"Unexpected embedding shape: {embeddings.shape}")

    out_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(out_dir / "docs.jsonl", [doc.to_dict() for doc in docs])
    np.save(out_dir / "embeddings.npy", embeddings.astype(np.float32))

    con = duckdb.connect()
    try:
        train_rows = int(
            con.execute(
                f"SELECT count(*) FROM read_parquet('{sql_path(train_path)}')"
            ).fetchone()[0]
        )
    finally:
        con.close()

    manifest: dict[str, Any] = {
        "index_version": INDEX_VERSION,
        "built_at": datetime.now(UTC).isoformat(),
        "dataset": dataset_label,
        "train_path": display_path(train_path),
        "train_sha256": _sha256_file(train_path),
        "train_rows": train_rows,
        "documents": len(docs),
        "incident_documents": len(incident_docs),
        "playbook_documents": len(playbook_docs),
        "playbook_files": sorted(
            {doc.metadata.get("file") for doc in playbook_docs if doc.metadata.get("file")}
        ),
        "member_incidents": sum(doc.member_count for doc in incident_docs),
        "embedding_model": embedder.name,
        "embedding_dim": int(embeddings.shape[1]),
        "normalized": True,
        "embed_seconds": embed_seconds,
        "doc_bytes": (out_dir / "docs.jsonl").stat().st_size,
        "embedding_bytes": (out_dir / "embeddings.npy").stat().st_size,
    }
    manifest["index_bytes"] = manifest["doc_bytes"] + manifest["embedding_bytes"]
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return docs, embeddings, manifest


class RetrievalIndex:
    def __init__(
        self,
        docs: Sequence[Doc],
        embeddings: np.ndarray,
        embedder: Embedder,
        manifest: dict[str, Any],
    ) -> None:
        self.docs = list(docs)
        self.embeddings = np.asarray(embeddings, dtype=np.float32)
        self.embedder = embedder
        self.manifest = manifest
        if self.embeddings.shape[0] != len(self.docs):
            raise ValueError("Embedding rows do not match document count")
        self.bm25 = BM25([tokenize(doc.text) for doc in self.docs])
        self._indices: dict[str, np.ndarray] = {}
        for source in ("incident", "playbook"):
            self._indices[source] = np.asarray(
                [index for index, doc in enumerate(self.docs) if doc.source == source],
                dtype=int,
            )
        self._doc_category_tokens: list[set[str]] = []
        for doc in self.docs:
            tokens: set[str] = set()
            for category in doc.categories:
                tokens.update(tokenize(category))
            self._doc_category_tokens.append(tokens)

    @classmethod
    def load(cls, index_dir: Path, embedder: Embedder | None = None) -> RetrievalIndex:
        index_dir = Path(index_dir)
        manifest = json.loads(
            (index_dir / "manifest.json").read_text(encoding="utf-8")
        )
        docs = [
            Doc.from_dict(json.loads(line))
            for line in (index_dir / "docs.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        embeddings = np.load(index_dir / "embeddings.npy")
        embedder = embedder or FastEmbedEmbedder(
            str(manifest.get("embedding_model", DEFAULT_EMBEDDING_MODEL))
        )
        return cls(docs, embeddings, embedder, manifest)

    def stats(self) -> dict[str, Any]:
        return {
            "documents": len(self.docs),
            "incident_documents": sum(1 for doc in self.docs if doc.source == "incident"),
            "playbook_documents": sum(1 for doc in self.docs if doc.source == "playbook"),
            "member_incidents": sum(
                doc.member_count for doc in self.docs if doc.source == "incident"
            ),
            "embedding_model": self.manifest.get("embedding_model"),
            "embedding_dim": int(self.embeddings.shape[1]),
            "index_bytes": self.manifest.get("index_bytes"),
            "train_sha256": self.manifest.get("train_sha256"),
        }

    def _top_k(
        self,
        scores: np.ndarray,
        k: int,
        source: str | None,
        allowed: Sequence[int] | None = None,
    ) -> list[int]:
        scores = np.asarray(scores, dtype=float)
        if source is not None:
            source_mask = np.full(len(scores), -np.inf)
            source_mask[self._indices[source]] = scores[self._indices[source]]
            scores = source_mask
        if allowed is not None:
            allowed_mask = np.full(len(scores), -np.inf)
            allowed_array = np.asarray(list(allowed), dtype=int)
            allowed_mask[allowed_array] = scores[allowed_array]
            scores = allowed_mask
        if k <= 0:
            return []
        k = min(k, len(scores))
        if k == len(scores):
            order = np.argsort(-scores)
        else:
            order = np.argpartition(-scores, k - 1)[:k]
            order = order[np.argsort(-scores[order])]
        return [int(index) for index in order if np.isfinite(scores[index])]

    def _playbook_category_candidates(self, query_tokens: Sequence[str]) -> list[int] | None:
        query_set = set(query_tokens)
        if not query_set:
            return None
        candidates = [
            index
            for index, tokens in enumerate(self._doc_category_tokens)
            if self.docs[index].source == "playbook" and tokens & query_set
        ]
        return candidates or None

    def search(
        self,
        query: str,
        k: int = 10,
        source: str | None = None,
        mode: str = "hybrid",
        candidate_k: int = 50,
    ) -> list[SearchHit]:
        if mode not in {"bm25", "dense", "hybrid"}:
            raise ValueError(f"Unknown retrieval mode: {mode}")
        if source not in {None, "incident", "playbook"}:
            raise ValueError(f"Unknown source filter: {source}")
        if not query.strip():
            return []

        query_tokens = tokenize(query)
        playbook_filter = (
            self._playbook_category_candidates(query_tokens)
            if source == "playbook"
            else None
        )
        bm25_scores = self.bm25.scores(query_tokens) if mode != "dense" else None
        dense_scores = (
            self.embeddings @ self.embedder.embed_query(query) if mode != "bm25" else None
        )

        if mode == "bm25":
            order = self._top_k(bm25_scores, k, source, playbook_filter)
            scores = [float(bm25_scores[index]) for index in order]
        elif mode == "dense":
            order = self._top_k(dense_scores, k, source, playbook_filter)
            scores = [float(dense_scores[index]) for index in order]
        else:
            pool = max(candidate_k, k)
            bm25_top = self._top_k(bm25_scores, pool, source, playbook_filter)
            dense_top = self._top_k(dense_scores, pool, source, playbook_filter)
            fused: dict[int, float] = {}
            for rank, index in enumerate(bm25_top, start=1):
                fused[index] = fused.get(index, 0.0) + 1.0 / (RRF_K + rank)
            for rank, index in enumerate(dense_top, start=1):
                fused[index] = fused.get(index, 0.0) + 1.0 / (RRF_K + rank)
            order = sorted(fused, key=lambda index: (-fused[index], index))[:k]
            scores = [fused[index] for index in order]

        return [
            SearchHit(
                doc_id=self.docs[index].doc_id,
                source=self.docs[index].source,
                source_id=self.docs[index].source_id,
                title=self.docs[index].title,
                text=self.docs[index].text,
                score=score,
                label=self.docs[index].label,
                categories=self.docs[index].categories,
                mitre=self.docs[index].mitre,
                metadata=self.docs[index].metadata,
            )
            for index, score in zip(order, scores, strict=False)
        ]


def check_leakage(index: RetrievalIndex, test_path: Path) -> dict[str, Any]:
    con = duckdb.connect()
    try:
        test_ids = {
            str(row[0])
            for row in con.execute(
                "SELECT incident_id FROM read_parquet("
                f"'{sql_path(Path(test_path))}')"
            ).fetchall()
        }
    finally:
        con.close()
    indexed_ids = {
        incident_id
        for doc in index.docs
        if doc.source == "incident"
        for incident_id in doc.incident_ids
    }
    overlap = sorted(indexed_ids & test_ids)
    return {
        "passed": not overlap,
        "test_incidents": len(test_ids),
        "indexed_incidents": len(indexed_ids),
        "overlap_count": len(overlap),
        "overlap_examples": overlap[:5],
    }


def _query_text(row: pd.Series) -> str:
    parts = [str(getattr(row, "summary", None) or "")]
    parts.extend(split_tokens(getattr(row, "categories", None)))
    parts.extend(split_tokens(getattr(row, "mitre_techniques", None)))
    return " ".join(parts)


def load_eval_queries(dev_path: Path, limit: int = 100, seed: int = SEED) -> list[dict[str, Any]]:
    con = duckdb.connect()
    try:
        frame = con.execute(
            "SELECT incident_id, summary, triage_label, categories, "
            "mitre_techniques, alert_title FROM read_parquet("
            f"'{sql_path(Path(dev_path))}') ORDER BY incident_id"
        ).df()
    finally:
        con.close()
    if frame.empty:
        raise ValueError("Dev split is empty; retrieval evaluation needs queries")

    counts = [limit // len(LABELS)] * len(LABELS)
    for index in range(limit % len(LABELS)):
        counts[index] += 1
    sampled: list[pd.DataFrame] = []
    for label, count in zip(LABELS, counts, strict=True):
        subset = frame[frame["triage_label"] == label]
        if subset.empty:
            continue
        sampled.append(subset.sample(n=min(count, len(subset)), random_state=seed))
    if not sampled:
        raise ValueError("No labeled dev queries available")
    queries = pd.concat(sampled).sort_values("incident_id")
    return [
        {
            "incident_id": str(row.incident_id),
            "label": str(row.triage_label),
            "query": _query_text(row),
            "summary": str(row.summary),
            "categories": split_tokens(row.categories),
            "mitre": split_tokens(row.mitre_techniques),
        }
        for row in queries.itertuples(index=False)
    ]


def _gold_incidents(
    queries: Sequence[dict[str, Any]], docs: Sequence[Doc], k: int = 3
) -> list[list[str]]:
    incident_docs = [doc for doc in docs if doc.source == "incident"]
    doc_tokens = [set(tokenize(doc.text)) for doc in incident_docs]
    gold: list[list[str]] = []
    for query in queries:
        query_tokens = set(tokenize(query["query"]))
        scored: list[tuple[float, str]] = []
        for doc, tokens in zip(incident_docs, doc_tokens, strict=True):
            if doc.label != query["label"]:
                continue
            union = query_tokens | tokens
            score = len(query_tokens & tokens) / len(union) if union else 0.0
            if score > 0:
                scored.append((score, doc.doc_id))
        scored.sort(key=lambda item: (-item[0], item[1]))
        gold.append([doc_id for _, doc_id in scored[:k]])
    return gold


def _gold_playbooks(
    queries: Sequence[dict[str, Any]], docs: Sequence[Doc]
) -> list[list[str]]:
    playbook_docs = [
        doc
        for doc in docs
        if doc.source == "playbook"
        and doc.metadata.get("heading") in {"Triage questions", "Containment"}
    ]
    gold: list[list[str]] = []
    for query in queries:
        categories = set(query["categories"])
        matches = [
            doc.doc_id
            for doc in playbook_docs
            if categories & set(doc.categories)
        ]
        gold.append(matches)
    return gold


def _dcg(relevances: Sequence[float]) -> float:
    return sum(rel / math.log2(index + 2) for index, rel in enumerate(relevances))


def _ndcg_at_k(ranked: Sequence[str], gold: set[str], k: int) -> float:
    relevances = [1.0 if doc_id in gold else 0.0 for doc_id in ranked[:k]]
    ideal = [1.0] * min(len(gold), k)
    denominator = _dcg(ideal)
    return _dcg(relevances) / denominator if denominator else 0.0


def evaluate_retrieval(
    index: RetrievalIndex,
    dev_path: Path,
    n_queries: int = 100,
    smoke_queries: int = 20,
    seed: int = SEED,
) -> dict[str, Any]:
    queries = load_eval_queries(dev_path, n_queries, seed)
    gold_incidents = _gold_incidents(queries, index.docs)
    gold_playbooks = _gold_playbooks(queries, index.docs)
    for query, incident_gold, playbook_gold in zip(
        queries, gold_incidents, gold_playbooks, strict=True
    ):
        query["gold_incidents"] = incident_gold
        query["gold_playbooks"] = playbook_gold

    methods: dict[str, Any] = {}
    for mode in ("bm25", "dense", "hybrid"):
        incident_rows: list[dict[str, float]] = []
        playbook_rows: list[dict[str, float]] = []
        latencies: list[float] = []
        for query in queries:
            started = time.perf_counter()
            hits = index.search(query["query"], k=10, source="incident", mode=mode)
            latencies.append((time.perf_counter() - started) * 1000)
            gold = set(query["gold_incidents"])
            ranked = [hit.doc_id for hit in hits]
            incident_rows.append(
                {
                    "recall@5": len(set(ranked[:5]) & gold) / len(gold) if gold else 0.0,
                    "recall@10": len(set(ranked) & gold) / len(gold) if gold else 0.0,
                    "ndcg@10": _ndcg_at_k(ranked, gold, 10),
                    "mrr": next(
                        (1.0 / (rank + 1) for rank, doc_id in enumerate(ranked) if doc_id in gold),
                        0.0,
                    ),
                }
            )
            playbook_hits = index.search(
                query["query"], k=10, source="playbook", mode=mode
            )
            playbook_gold = set(query["gold_playbooks"])
            playbook_ranked = [hit.doc_id for hit in playbook_hits]
            playbook_rows.append(
                {
                    "recall@5": (
                        len(set(playbook_ranked[:5]) & playbook_gold) / len(playbook_gold)
                        if playbook_gold
                        else 0.0
                    ),
                    "recall@10": (
                        len(set(playbook_ranked) & playbook_gold) / len(playbook_gold)
                        if playbook_gold
                        else 0.0
                    ),
                }
            )
        methods[mode] = {
            "incident": {
                key: float(np.mean([row[key] for row in incident_rows]))
                for key in ("recall@5", "recall@10", "ndcg@10", "mrr")
            },
            "playbook": {
                key: float(np.mean([row[key] for row in playbook_rows]))
                for key in ("recall@5", "recall@10")
            },
            "median_latency_ms": float(np.median(latencies)),
            "queries": len(queries),
        }

    smoke_rows: list[dict[str, Any]] = []
    for query in queries[:smoke_queries]:
        incident_hits = index.search(
            query["query"], k=5, source="incident", mode="hybrid"
        )
        playbook_hits = index.search(
            query["query"], k=5, source="playbook", mode="hybrid"
        )
        incident_ok = any(
            hit.doc_id in set(query["gold_incidents"]) for hit in incident_hits
        )
        playbook_ok = any(
            hit.doc_id in set(query["gold_playbooks"]) for hit in playbook_hits
        )
        smoke_rows.append(
            {
                "incident_id": query["incident_id"],
                "incident_citation": incident_ok,
                "playbook_citation": playbook_ok,
                "passed": incident_ok and playbook_ok,
            }
        )

    return {
        "queries": len(queries),
        "gold": "structured-overlap proxy; not human relevance labels",
        "methods": methods,
        "smoke": {
            "queries": len(smoke_rows),
            "passed": sum(row["passed"] for row in smoke_rows),
            "rows": smoke_rows,
        },
    }


def _fmt(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def render_report(metrics: dict[str, Any]) -> str:
    index = metrics["index"]
    leakage = metrics["leakage"]
    lines = [
        "# Week 3 retrieval report",
        "",
        "Measured on the frozen GUIDE split with the real train and dev files. "
        "The retrieval gold sets are structured-overlap proxies, not human "
        "relevance labels. Treat them as a regression check, not a benchmark.",
        "",
        "## Corpus",
        "",
        "| item | value |",
        "|---|---:|",
        f"| incident documents | {index['incident_documents']:,} |",
        f"| train incidents represented | {index['member_incidents']:,} |",
        f"| playbook sections | {index['playbook_documents']:,} |",
        f"| playbook files | {len(index.get('playbook_files', []))} |",
        f"| embedding model | `{index.get('embedding_model')}` |",
        f"| embedding dimension | {index.get('embedding_dim')} |",
        f"| index bytes | {index.get('index_bytes', 0):,} |",
        "",
        "Incident documents are deduplicated by `(summary, triage_label)`. The "
        "representative incident id is cited; member incidents with the same "
        "summary and label are kept as provenance.",
        "",
        "## Leakage check",
        "",
        f"- Indexed incident ids: {leakage['indexed_incidents']:,}",
        f"- Test incident ids: {leakage['test_incidents']:,}",
        f"- Overlap: {leakage['overlap_count']}",
        f"- Gate: {'pass' if leakage['passed'] else 'fail'}",
        "",
        "## Retrieval metrics",
        "",
        "| method | incident Recall@5 | incident Recall@10 | "
        "incident nDCG@10 | incident MRR | playbook Recall@5 | "
        "playbook Recall@10 | median latency |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, result in metrics["methods"].items():
        incident = result["incident"]
        lines.append(
            f"| {name} | {_fmt(incident['recall@5'])} | "
            f"{_fmt(incident['recall@10'])} | {_fmt(incident['ndcg@10'])} | "
            f"{_fmt(incident['mrr'])} | {_fmt(result['playbook']['recall@5'])} | "
            f"{_fmt(result['playbook']['recall@10'])} | "
            f"{_fmt(result['median_latency_ms'], 1)} ms |"
        )
    smoke = metrics["smoke"]
    lines.extend(
        [
            "",
            "## Citation smoke test",
            "",
            f"{smoke['passed']} of {smoke['queries']} queries returned at least "
            "one gold incident citation in the top 5 and one category-matched "
            "playbook section in the top 5.",
            "",
            "## Limitations",
            "",
            "- Gold incident documents are selected by summary-token Jaccard "
            "overlap within the same label. They are not analyst judgments.",
            "- Gold playbook sections are selected by category metadata. The "
            "playbooks are synthetic and are not an operational policy.",
            "- Summary text is derived from GUIDE categorical and alert-title "
            "tokens. The public release does not include free-form analyst notes.",
            "- The index uses exact numpy inner product, not FAISS or pgvector. "
            "That is adequate for the deduplicated local corpus and keeps the "
            "artifact reproducible without a service.",
            "- No cross-encoder reranker is measured. The pipeline is BM25, dense, "
            "and reciprocal rank fusion only.",
            "",
            "## Reproduce",
            "",
            "```bash",
            "make w3-retrieval",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _cmd_build(args: argparse.Namespace) -> int:
    embedder = FastEmbedEmbedder(args.model)
    docs, embeddings, manifest = build_index(
        train_path=Path(args.train),
        playbooks_dir=Path(args.playbooks),
        out_dir=Path(args.out),
        embedder=embedder,
        dataset_label=args.dataset,
    )
    index = RetrievalIndex(docs, embeddings, embedder, manifest)
    leakage = check_leakage(index, Path(args.test))
    metrics: dict[str, Any] = {
        "dataset": args.dataset,
        "generated_at": datetime.now(UTC).isoformat(),
        "index": {**manifest, **index.stats()},
        "leakage": leakage,
        "methods": {},
        "smoke": {"queries": 0, "passed": 0, "rows": []},
    }
    if not args.no_eval:
        metrics.update(
            evaluate_retrieval(
                index,
                dev_path=Path(args.dev),
                n_queries=args.queries,
                smoke_queries=args.smoke,
                seed=args.seed,
            )
        )

    report_path = Path(args.report)
    metrics_path = Path(args.metrics)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    report_path.write_text(render_report(metrics), encoding="utf-8")
    print(
        json.dumps(
            {
                "index": display_path(Path(args.out)),
                "documents": len(docs),
                "leakage": leakage["passed"],
                "methods": {
                    name: {
                        "incident_recall@5": round(result["incident"]["recall@5"], 4),
                        "incident_recall@10": round(result["incident"]["recall@10"], 4),
                        "playbook_recall@5": round(result["playbook"]["recall@5"], 4),
                        "playbook_recall@10": round(result["playbook"]["recall@10"], 4),
                    }
                    for name, result in metrics["methods"].items()
                },
                "smoke": f"{metrics['smoke']['passed']}/{metrics['smoke']['queries']}",
                "report": args.report,
                "metrics": args.metrics,
            },
            indent=2,
        )
    )
    return 0 if leakage["passed"] else 1


def _cmd_search(args: argparse.Namespace) -> int:
    index = RetrievalIndex.load(Path(args.index))
    hits = index.search(
        args.query,
        k=args.k,
        source=args.source,
        mode=args.mode,
    )
    print(json.dumps([hit.to_dict() for hit in hits], indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="triage.retrieval")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="Build and evaluate the retrieval index")
    build.add_argument("--train", default="data/processed/train.parquet")
    build.add_argument("--dev", default="data/processed/dev.parquet")
    build.add_argument("--test", default="data/processed/test.parquet")
    build.add_argument("--playbooks", default="data/playbooks")
    build.add_argument("--out", default="indexes/w3_retrieval")
    build.add_argument("--report", default="reports/w3_retrieval.md")
    build.add_argument("--metrics", default="reports/w3_retrieval_metrics.json")
    build.add_argument("--model", default=DEFAULT_EMBEDDING_MODEL)
    build.add_argument("--dataset", choices=["guide", "fixture"], default="guide")
    build.add_argument("--queries", type=int, default=100)
    build.add_argument("--smoke", type=int, default=20)
    build.add_argument("--seed", type=int, default=SEED)
    build.add_argument("--no-eval", action="store_true")
    build.set_defaults(func=_cmd_build)

    search = subparsers.add_parser("search", help="Search a built index")
    search.add_argument("--index", default="indexes/w3_retrieval")
    search.add_argument("--query", required=True)
    search.add_argument("--k", type=int, default=10)
    search.add_argument("--source", choices=["incident", "playbook"], default=None)
    search.add_argument("--mode", choices=["bm25", "dense", "hybrid"], default="hybrid")
    search.set_defaults(func=_cmd_search)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
