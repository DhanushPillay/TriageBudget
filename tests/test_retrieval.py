from __future__ import annotations

import json
import zlib
from pathlib import Path

import numpy as np
import pandas as pd

from triage.retrieval import (
    Doc,
    RetrievalIndex,
    _normalize,
    build_index,
    check_leakage,
    load_incident_docs,
    load_playbook_docs,
    parse_playbook,
    tokenize,
)


class FakeEmbedder:
    name = "fake"
    dim = 16

    def _embed(self, text: str) -> np.ndarray:
        vector = np.zeros(self.dim, dtype=np.float32)
        for token in tokenize(text):
            vector[zlib.crc32(token.encode("utf-8")) % self.dim] += 1.0
        return vector

    def embed_documents(self, texts: list[str]) -> np.ndarray:
        matrix = np.vstack([self._embed(text) for text in texts])
        return _normalize(matrix).astype(np.float32)

    def embed_query(self, text: str) -> np.ndarray:
        return _normalize(self._embed(text))[0]


def _playbook(path: Path) -> Path:
    path.write_text(
        "# Credential playbook\n\n"
        "**Source:** synthetic\n"
        "**Effective:** 2026-01-01\n"
        "**Categories:** CredentialAccess, InitialAccess\n"
        "**Role:** triage\n\n"
        "## Triage questions\n\n"
        "Did the account travel impossibly fast? Check MFA and source IP.\n\n"
        "## Containment\n\n"
        "Reset credentials and revoke active sessions.\n",
        encoding="utf-8",
    )
    return path


def _index() -> RetrievalIndex:
    docs = [
        Doc(
            doc_id="incident:1",
            source="incident",
            source_id="1",
            title="Impossible travel",
            text="CredentialAccess T1078 impossible travel cloud login",
            label="true_positive",
            categories=["CredentialAccess"],
            mitre=["T1078"],
            incident_ids=["1"],
            metadata={"summary": "credential access"},
        ),
        Doc(
            doc_id="incident:2",
            source="incident",
            source_id="2",
            title="Phishing attachment",
            text="InitialAccess T1566 phishing email attachment macro",
            label="benign_positive",
            categories=["InitialAccess"],
            mitre=["T1566"],
            incident_ids=["2"],
            metadata={"summary": "phishing"},
        ),
        Doc(
            doc_id="playbook:credential:containment",
            source="playbook",
            source_id="playbook:credential:containment",
            title="Credential playbook / Containment",
            text="Credential Access Containment reset credentials revoke sessions",
            categories=["CredentialAccess"],
            metadata={"heading": "Containment"},
        ),
    ]
    embedder = FakeEmbedder()
    return RetrievalIndex(
        docs,
        embedder.embed_documents([doc.text for doc in docs]),
        embedder,
        {"embedding_model": "fake", "embedding_dim": 16, "index_bytes": 1},
    )


def test_bm25_and_hybrid_rank_credential_doc_first():
    index = _index()
    bm25 = index.search("credential access", k=2, source="incident", mode="bm25")
    hybrid = index.search("credential access", k=2, source="incident", mode="hybrid")
    assert bm25[0].doc_id == "incident:1"
    assert hybrid[0].doc_id == "incident:1"
    assert all(hit.source == "incident" for hit in hybrid)


def test_source_filter_and_empty_query():
    index = _index()
    hits = index.search("credential access", k=5, source="playbook", mode="bm25")
    assert [hit.source for hit in hits] == ["playbook"]
    assert index.search("   ", k=5) == []


def test_playbook_category_filter_uses_metadata():
    docs = [
        Doc(
            doc_id="playbook:malware:containment",
            source="playbook",
            source_id="playbook:malware:containment",
            title="Malware / Containment",
            text="CredentialAccess credential access containment",
            categories=["Malware"],
        ),
        Doc(
            doc_id="playbook:credential:containment",
            source="playbook",
            source_id="playbook:credential:containment",
            title="Credential / Containment",
            text="Containment reset credentials",
            categories=["CredentialAccess"],
        ),
    ]
    embedder = FakeEmbedder()
    index = RetrievalIndex(
        docs,
        embedder.embed_documents([doc.text for doc in docs]),
        embedder,
        {"embedding_model": "fake", "embedding_dim": 16},
    )
    hits = index.search("CredentialAccess", k=5, source="playbook", mode="bm25")
    assert [hit.doc_id for hit in hits] == ["playbook:credential:containment"]


def test_playbook_parser_has_stable_sections(tmp_path):
    path = _playbook(tmp_path / "credential.md")
    docs = parse_playbook(path)
    assert [doc.metadata["heading"] for doc in docs] == [
        "Triage questions",
        "Containment",
    ]
    assert docs[0].doc_id.startswith("playbook:credential:")
    assert docs[0].categories == ["CredentialAccess", "InitialAccess"]


def test_load_incident_docs_deduplicates_summary_and_label(tmp_path):
    path = tmp_path / "train.parquet"
    pd.DataFrame(
        {
            "incident_id": ["1", "2", "3"],
            "summary": ["same summary", "same summary", "other summary"],
            "title": ["one", "two", "three"],
            "triage_label": ["true_positive", "true_positive", "false_positive"],
            "categories": ["CredentialAccess", "CredentialAccess", "InitialAccess"],
            "mitre_techniques": ["T1078", "T1078", "T1566"],
        }
    ).to_parquet(path, index=False)
    docs = load_incident_docs(path)
    assert len(docs) == 2
    first = next(doc for doc in docs if doc.label == "true_positive")
    assert first.member_count == 2
    assert first.incident_ids == ["1", "2"]


def test_build_index_roundtrip_and_leakage(tmp_path):
    train = tmp_path / "train.parquet"
    pd.DataFrame(
        {
            "incident_id": ["1", "2"],
            "summary": ["credential access", "phishing email"],
            "title": ["one", "two"],
            "triage_label": ["true_positive", "benign_positive"],
            "categories": ["CredentialAccess", "InitialAccess"],
            "mitre_techniques": ["T1078", "T1566"],
        }
    ).to_parquet(train, index=False)
    playbooks = tmp_path / "playbooks"
    playbooks.mkdir()
    _playbook(playbooks / "credential.md")
    out = tmp_path / "index"

    docs, embeddings, manifest = build_index(
        train, playbooks, out, embedder=FakeEmbedder()
    )
    assert len(docs) == 4
    assert embeddings.shape == (4, 16)
    assert manifest["incident_documents"] == 2
    assert manifest["playbook_documents"] == 2

    index = RetrievalIndex.load(out, FakeEmbedder())
    assert index.stats()["documents"] == 4
    assert index.search("credential", k=5, source="incident")[0].doc_id == "incident:1"

    test = tmp_path / "test.parquet"
    pd.DataFrame({"incident_id": ["99"]}).to_parquet(test, index=False)
    clean = check_leakage(index, test)
    assert clean["passed"] is True
    pd.DataFrame({"incident_id": ["2"]}).to_parquet(test, index=False)
    leaked = check_leakage(index, test)
    assert leaked["passed"] is False
    assert leaked["overlap_examples"] == ["2"]


def test_index_manifest_is_written(tmp_path):
    train = tmp_path / "train.parquet"
    pd.DataFrame(
        {
            "incident_id": ["1"],
            "summary": ["credential access"],
            "title": ["one"],
            "triage_label": ["true_positive"],
            "categories": ["CredentialAccess"],
            "mitre_techniques": ["T1078"],
        }
    ).to_parquet(train, index=False)
    playbooks = tmp_path / "playbooks"
    playbooks.mkdir()
    _playbook(playbooks / "credential.md")
    out = tmp_path / "index"
    build_index(train, playbooks, out, embedder=FakeEmbedder())
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["index_version"] == "w3_retrieval_v1"
    assert manifest["train_rows"] == 1
    assert (out / "docs.jsonl").exists()
    assert (out / "embeddings.npy").exists()


def test_load_playbook_docs_skips_readme(tmp_path):
    _playbook(tmp_path / "credential.md")
    (tmp_path / "README.md").write_text("# Readme\n", encoding="utf-8")
    docs = load_playbook_docs(tmp_path)
    assert len(docs) == 2
    assert all(doc.source == "playbook" for doc in docs)
