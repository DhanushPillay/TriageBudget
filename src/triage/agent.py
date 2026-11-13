from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from triage.classifier import (
    TP_INDEX,
    ClassifierArtifacts,
    load_classifier,
    load_frame,
)
from triage.config import LABELS, display_path
from triage.retrieval import (
    FastEmbedEmbedder,
    RetrievalIndex,
    SearchHit,
    split_tokens,
)

PROMPT_VERSION = "w3_agent_v1"
MAX_TOOL_CALLS = 6
HUMAN_CONFIDENCE = 0.60
UNDETERMINED_CONFIDENCE = 0.40

VERDICTS = {"true_positive", "benign_positive", "false_positive", "undetermined"}
PRIORITIES = {"critical", "high", "medium", "low"}
ROUTES = {"auto_close", "auto_escalate", "agent", "human"}
ACTIONS = {
    "monitor",
    "collect_more_evidence",
    "contain_host",
    "disable_account",
    "reset_credentials",
    "block_indicator",
    "quarantine_email",
    "isolate_device",
    "escalate_to_incident_response",
    "close_no_action",
    "user_awareness_training",
    "tune_detection",
}
CONTAINMENT_ACTIONS = {
    "contain_host",
    "disable_account",
    "reset_credentials",
    "block_indicator",
    "quarantine_email",
    "isolate_device",
}
ACTION_TARGETS = {
    "monitor": "incident_queue",
    "collect_more_evidence": "incident_queue",
    "contain_host": "affected_host",
    "disable_account": "affected_account",
    "reset_credentials": "affected_account",
    "block_indicator": "network_indicator",
    "quarantine_email": "mailbox",
    "isolate_device": "affected_device",
    "escalate_to_incident_response": "incident_response",
    "close_no_action": "incident_queue",
    "user_awareness_training": "user_group",
    "tune_detection": "detection_rule",
}
CATEGORY_TECHNIQUES = {
    "InitialAccess": ["T1078", "T1566", "T1190"],
    "CredentialAccess": ["T1110", "T1003", "T1528"],
    "PrivilegeEscalation": ["T1068", "T1548"],
    "Execution": ["T1059", "T1204"],
    "Persistence": ["T1053", "T1543", "T1547"],
    "DefenseEvasion": ["T1070", "T1562", "T1027"],
    "Discovery": ["T1082", "T1087", "T1046"],
    "LateralMovement": ["T1021", "T1570"],
    "Collection": ["T1005", "T1114"],
    "CommandAndControl": ["T1071", "T1105", "T1573"],
    "Exfiltration": ["T1041", "T1567"],
    "Impact": ["T1486", "T1490"],
    "Ransomware": ["T1486", "T1490"],
    "Malware": ["T1204", "T1105"],
    "Exploit": ["T1190", "T1203"],
    "UnwantedSoftware": ["T1176"],
    "SuspiciousActivity": ["T1078", "T1566"],
}


@dataclass
class EvidenceCitation:
    evidence_id: str
    quote: str
    source: str

    def to_dict(self) -> dict[str, str]:
        return {
            "evidence_id": self.evidence_id,
            "quote": self.quote,
            "source": self.source,
        }


@dataclass
class Remediation:
    action: str
    target: str
    rationale: str

    def to_dict(self) -> dict[str, str]:
        return {
            "action": self.action,
            "target": self.target,
            "rationale": self.rationale,
        }


@dataclass
class TriageDecision:
    incident_id: str
    verdict: str
    priority: str
    remediation: list[Remediation]
    evidence: list[EvidenceCitation]
    confidence: float
    needs_human: bool
    route: str
    classifier_version: str
    prompt_version: str
    tool_calls: int
    latency_ms: int
    cost_usd: float

    def validate(self, evidence_sources: dict[str, str] | None = None) -> list[str]:
        problems: list[str] = []
        if not self.incident_id:
            problems.append("incident_id is empty")
        if self.verdict not in VERDICTS:
            problems.append(f"invalid verdict: {self.verdict}")
        if self.priority not in PRIORITIES:
            problems.append(f"invalid priority: {self.priority}")
        if self.route not in ROUTES:
            problems.append(f"invalid route: {self.route}")
        if not isinstance(self.confidence, (int, float)) or isinstance(
            self.confidence, bool
        ):
            problems.append("confidence must be numeric")
        elif not 0.0 <= float(self.confidence) <= 1.0:
            problems.append("confidence outside [0, 1]")
        if not self.classifier_version:
            problems.append("classifier_version is empty")
        if not self.prompt_version:
            problems.append("prompt_version is empty")
        if self.tool_calls < 0 or self.latency_ms < 0 or self.cost_usd < 0:
            problems.append("tool_calls, latency_ms, and cost_usd must be non-negative")
        if self.verdict == "undetermined" and self.route != "human":
            problems.append("undetermined decisions must route to a human")
        if self.verdict == "true_positive" and not self.evidence:
            problems.append("true_positive requires at least one citation")
        if self.remediation and not self.evidence:
            problems.append("remediation requires at least one citation")
        if self.route in {"human", "agent"} and self.confidence < HUMAN_CONFIDENCE:
            if not self.needs_human:
                problems.append("low-confidence human or agent route must set needs_human")
        if self.route in {"auto_close", "auto_escalate"} and self.needs_human:
            problems.append("automatic routes cannot require a human")
        if self.verdict == "true_positive" and self.route == "auto_close":
            problems.append("true_positive decisions cannot be auto-closed")
        if self.verdict == "true_positive" and not self.remediation:
            problems.append("true_positive decisions must include remediation")
        if self.verdict == "true_positive" and any(
            item.action == "close_no_action" for item in self.remediation
        ):
            problems.append("true_positive decisions cannot close with no action")
        if self.route == "auto_escalate" and self.verdict != "true_positive":
            problems.append("auto_escalate requires a true_positive verdict")
        if self.route == "auto_close" and self.verdict != "false_positive":
            problems.append("auto_close requires a false_positive verdict")
        if any(item.action in CONTAINMENT_ACTIONS for item in self.remediation):
            if self.route not in {"auto_escalate", "human"} and not self.needs_human:
                problems.append("containment actions require human review")

        evidence_ids = [citation.evidence_id for citation in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            problems.append("evidence citations contain duplicate ids")
        for citation in self.evidence:
            if not citation.evidence_id or not citation.quote or not citation.source:
                problems.append("evidence citation fields must be non-empty")
            if citation.source not in {"incident", "train_incident", "playbook", "tool"}:
                problems.append(f"invalid evidence source: {citation.source}")
            if evidence_sources is not None:
                source_text = evidence_sources.get(citation.evidence_id)
                if source_text is None:
                    problems.append(
                        f"evidence id not found in tool results: {citation.evidence_id}"
                    )
                elif citation.quote not in source_text:
                    problems.append(
                        f"evidence quote does not match source: {citation.evidence_id}"
                    )

        for item in self.remediation:
            if item.action not in ACTIONS:
                problems.append(f"invalid remediation action: {item.action}")
            if not item.target or not item.rationale:
                problems.append("remediation target and rationale must be non-empty")
            if self.verdict != "true_positive" and item.action in CONTAINMENT_ACTIONS:
                problems.append(
                    f"containment action {item.action} is incompatible with {self.verdict}"
                )
            text = f"{item.target} {item.rationale}"
            if "://" in text or "`" in text or "$(" in text:
                problems.append("remediation contains a URL or executable payload")
            if evidence_ids and not any(
                evidence_id in item.rationale for evidence_id in evidence_ids
            ):
                problems.append(
                    f"remediation {item.action} does not cite an evidence id"
                )
        return problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "verdict": self.verdict,
            "priority": self.priority,
            "remediation": [item.to_dict() for item in self.remediation],
            "evidence": [citation.to_dict() for citation in self.evidence],
            "confidence": float(self.confidence),
            "needs_human": bool(self.needs_human),
            "route": self.route,
            "classifier_version": self.classifier_version,
            "prompt_version": self.prompt_version,
            "tool_calls": int(self.tool_calls),
            "latency_ms": int(self.latency_ms),
            "cost_usd": float(self.cost_usd),
        }


@dataclass
class ToolCallRecord:
    name: str
    args: dict[str, Any]
    ok: bool
    latency_ms: int
    result_size: int
    preview: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "args": self.args,
            "ok": self.ok,
            "latency_ms": self.latency_ms,
            "result_size": self.result_size,
            "preview": self.preview,
            "error": self.error,
        }


@dataclass
class AgentTrace:
    case_id: str
    incident_id: str
    expected_label: str | None
    decision: TriageDecision
    probabilities: dict[str, float]
    top_label: str
    tool_calls: list[ToolCallRecord]
    revision_count: int
    prompt_version: str
    prompt_sha256: str
    prompt_chars: int
    llm_backend: str
    schema_valid: bool
    violations: list[str]
    latency_ms: int
    cost_usd: float
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "incident_id": self.incident_id,
            "expected_label": self.expected_label,
            "decision": self.decision.to_dict(),
            "probabilities": self.probabilities,
            "top_label": self.top_label,
            "tool_calls": [call.to_dict() for call in self.tool_calls],
            "revision_count": self.revision_count,
            "prompt_version": self.prompt_version,
            "prompt_sha256": self.prompt_sha256,
            "prompt_chars": self.prompt_chars,
            "llm_backend": self.llm_backend,
            "schema_valid": self.schema_valid,
            "violations": self.violations,
            "latency_ms": self.latency_ms,
            "cost_usd": self.cost_usd,
            "notes": self.notes,
        }


class IncidentStore:
    def __init__(self, frame: pd.DataFrame) -> None:
        if frame.empty:
            raise ValueError("Incident frame is empty")
        self.frame = frame.set_index("incident_id", drop=False)

    @classmethod
    def from_parquet(cls, path: Path, incident_ids: Sequence[str]) -> IncidentStore:
        frame = load_frame(Path(path), incident_ids)
        missing = sorted(set(incident_ids) - set(frame["incident_id"].astype(str)))
        if missing:
            raise ValueError(f"Incidents not found in dev split: {missing}")
        return cls(frame)

    def row(self, incident_id: str) -> pd.Series:
        if incident_id not in self.frame.index:
            raise KeyError(f"Unknown incident: {incident_id}")
        return self.frame.loc[incident_id]

    def inference_frame(self, incident_id: str) -> pd.DataFrame:
        return self.frame.loc[[incident_id]].copy()

    def label(self, incident_id: str) -> str:
        return str(self.row(incident_id)["triage_label"])

    def public(self, incident_id: str) -> dict[str, Any]:
        row = self.row(incident_id)
        org_hash = hashlib.sha256(str(row["org_id"]).encode("utf-8")).hexdigest()[:12]
        return {
            "incident_id": str(row["incident_id"]),
            "title": str(row.get("title") or ""),
            "alert_title": str(row.get("alert_title") or ""),
            "summary": str(row.get("summary") or ""),
            "created_at": str(row.get("created_at") or ""),
            "org_hash": org_hash,
            "alert_count": int(row.get("alert_count") or 0),
            "evidence_count": int(row.get("evidence_count") or 0),
            "detector_count": int(row.get("detector_count") or 0),
            "entity_type_count": int(row.get("entity_type_count") or 0),
            "category_count": int(row.get("category_count") or 0),
            "has_mitre": int(row.get("has_mitre") or 0),
            "suspicious_count": int(row.get("suspicious_count") or 0),
            "verdict_count": int(row.get("verdict_count") or 0),
            "malicious_count": int(row.get("malicious_count") or 0),
            "sha256_count": int(row.get("sha256_count") or 0),
            "ip_count": int(row.get("ip_count") or 0),
            "url_count": int(row.get("url_count") or 0),
            "account_count": int(row.get("account_count") or 0),
            "device_count": int(row.get("device_count") or 0),
            "registry_count": int(row.get("registry_count") or 0),
            "file_count": int(row.get("file_count") or 0),
            "email_count": int(row.get("email_count") or 0),
            "categories": split_tokens(row.get("categories")),
            "mitre": split_tokens(row.get("mitre_techniques")),
            "threat_families": split_tokens(row.get("threat_families")),
            "suspicion_levels": split_tokens(row.get("suspicion_levels")),
            "last_verdicts": split_tokens(row.get("last_verdicts")),
        }


def _query_from_public(public: dict[str, Any]) -> str:
    parts = [str(public.get("summary") or "")]
    parts.extend(public.get("categories", []))
    parts.extend(public.get("mitre", []))
    return " ".join(part for part in parts if part)


def _hit_payload(hit: SearchHit) -> dict[str, Any]:
    return {
        "doc_id": hit.doc_id,
        "source": hit.source,
        "source_id": hit.source_id,
        "title": hit.title,
        "text": hit.text[:600],
        "score": hit.score,
        "label": hit.label,
        "categories": hit.categories,
        "mitre": hit.mitre,
        "metadata": hit.metadata,
    }


class ToolBudgetExceeded(RuntimeError):
    pass


class ToolContext:
    def __init__(self, tools: dict[str, Callable[..., Any]], max_calls: int) -> None:
        self.tools = tools
        self.max_calls = max_calls
        self.records: list[ToolCallRecord] = []

    def call(self, name: str, **kwargs: Any) -> Any:
        if len(self.records) >= self.max_calls:
            raise ToolBudgetExceeded(f"Tool budget exhausted before {name}")
        if name not in self.tools:
            raise KeyError(f"Tool not allowed: {name}")
        started = time.perf_counter()
        try:
            result = self.tools[name](**kwargs)
        except Exception as exc:  # noqa: BLE001 - trace the failure, then re-raise
            self.records.append(
                ToolCallRecord(
                    name=name,
                    args=_safe_args(kwargs),
                    ok=False,
                    latency_ms=int((time.perf_counter() - started) * 1000),
                    result_size=0,
                    preview="",
                    error=str(exc)[:300],
                )
            )
            raise
        payload = json.dumps(result, default=str)
        self.records.append(
            ToolCallRecord(
                name=name,
                args=_safe_args(kwargs),
                ok=True,
                latency_ms=int((time.perf_counter() - started) * 1000),
                result_size=len(payload),
                preview=payload[:300],
            )
        )
        return result


SENSITIVE_ARG_KEYS = {"host", "hostname", "account", "user", "ioc", "url", "value"}


def _safe_args(args: dict[str, Any]) -> dict[str, Any]:
    return {
        key: "<redacted>" if key.lower() in SENSITIVE_ARG_KEYS else value
        for key, value in args.items()
    }


class AgentTools:
    def __init__(self, index: RetrievalIndex, store: IncidentStore) -> None:
        self.index = index
        self.store = store

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        return self.store.public(incident_id)

    def search_similar_incidents(self, incident_id: str, k: int = 5) -> list[dict[str, Any]]:
        public = self.store.public(incident_id)
        hits = self.index.search(
            _query_from_public(public), k=k, source="incident", mode="hybrid"
        )
        return [_hit_payload(hit) for hit in hits]

    def retrieve_playbook(
        self, incident_id: str, query: str | None = None, k: int = 4
    ) -> list[dict[str, Any]]:
        if not query:
            public = self.store.public(incident_id)
            query = _query_from_public(public)
        hits = self.index.search(query, k=k, source="playbook", mode="hybrid")
        return [_hit_payload(hit) for hit in hits]

    def lookup_asset(self, value: str) -> dict[str, Any]:
        if not value.strip():
            raise ValueError("asset lookup requires a non-empty value")
        return {
            "found": False,
            "value": "<redacted>",
            "reason": "the public GUIDE release has no asset inventory or ownership table",
        }

    def lookup_ioc(self, value: str) -> dict[str, Any]:
        if not value.strip():
            raise ValueError("IOC lookup requires a non-empty value")
        return {
            "found": False,
            "value": "<redacted>",
            "reason": "the public GUIDE release has no IOC reputation feed",
        }

    def map_attack(self, incident_id: str) -> dict[str, Any]:
        public = self.store.public(incident_id)
        suggested: list[str] = []
        for category in public["categories"]:
            suggested.extend(CATEGORY_TECHNIQUES.get(category, []))
        return {
            "observed_categories": public["categories"],
            "observed_techniques": public["mitre"],
            "suggested_techniques": sorted(set(suggested)),
            "note": "heuristic category mapping, not an ATT&CK classifier",
        }

    def propose_action(
        self,
        incident_id: str,
        verdict: str,
        evidence_ids: Sequence[str],
        categories: Sequence[str],
        counts: dict[str, int],
    ) -> list[dict[str, str]]:
        return _propose_actions(verdict, categories, counts, evidence_ids)


def _propose_actions(
    verdict: str,
    categories: Sequence[str],
    counts: dict[str, int],
    evidence_ids: Sequence[str],
) -> list[dict[str, str]]:
    citation = evidence_ids[0] if evidence_ids else ""
    actions: list[str] = []
    if verdict == "true_positive":
        if counts.get("device_count", 0) > 0:
            actions.append("contain_host")
        if counts.get("account_count", 0) > 0:
            actions.append("disable_account")
        if (
            counts.get("ip_count", 0)
            + counts.get("url_count", 0)
            + counts.get("sha256_count", 0)
            > 0
        ):
            actions.append("block_indicator")
        actions.append("escalate_to_incident_response")
    elif verdict == "benign_positive":
        actions.append("monitor")
        if "InitialAccess" in categories or counts.get("suspicious_count", 0) > 0:
            actions.append("user_awareness_training")
        if counts.get("malicious_count", 0) > 0:
            actions.append("tune_detection")
    elif verdict == "false_positive":
        actions.append("close_no_action")
        if counts.get("malicious_count", 0) > 0 or counts.get("has_mitre", 0) > 0:
            actions.append("tune_detection")
    else:
        actions.append("collect_more_evidence")

    proposals: list[dict[str, str]] = []
    for action in dict.fromkeys(actions):
        proposals.append(
            {
                "action": action,
                "target": ACTION_TARGETS[action],
                "rationale": (
                    f"Evidence {citation} supports {action} at the incident level."
                    if citation
                    else f"{action} has no citation and must be reviewed."
                ),
            }
        )
    return proposals


def _policy(
    public: dict[str, Any],
    probabilities: np.ndarray,
    similar: Sequence[dict[str, Any]],
) -> tuple[str, str, str, bool, float]:
    top_index = int(np.argmax(probabilities))
    top_label = LABELS[top_index]
    confidence = float(probabilities[top_index])
    verdict = top_label if confidence >= UNDETERMINED_CONFIDENCE else "undetermined"

    neighbor_labels = Counter(hit.get("label") for hit in similar)
    if (
        verdict == "benign_positive"
        and probabilities[TP_INDEX] >= 0.45
        and neighbor_labels["true_positive"] >= 3
    ):
        verdict = "true_positive"
    if verdict == "false_positive" and public["malicious_count"] > 0:
        if probabilities[TP_INDEX] >= 0.30:
            verdict = "undetermined"
    if verdict == "true_positive" and probabilities[TP_INDEX] < 0.30:
        verdict = "undetermined"

    if verdict == "true_positive":
        if public["malicious_count"] >= 10 or public["alert_count"] >= 100:
            priority = "critical"
        elif (
            public["malicious_count"] > 0
            or public["suspicious_count"] > 0
            or public["has_mitre"] > 0
        ):
            priority = "high"
        else:
            priority = "medium"
    elif verdict == "benign_positive":
        priority = (
            "medium"
            if public["malicious_count"] > 0 or public["suspicious_count"] > 0
            else "low"
        )
    elif verdict == "false_positive":
        priority = "low"
    else:
        priority = "medium"

    if verdict == "undetermined" or confidence < 0.50:
        route = "human"
    elif (
        verdict == "true_positive"
        and confidence >= 0.70
        and probabilities[TP_INDEX] >= 0.70
    ):
        route = "auto_escalate"
    elif (
        verdict == "false_positive"
        and probabilities[LABELS.index("false_positive")] >= 0.90
        and probabilities[TP_INDEX] <= 0.05
        and public["malicious_count"] == 0
        and public["suspicious_count"] == 0
        and public["has_mitre"] == 0
    ):
        route = "auto_close"
    else:
        route = "agent"

    needs_human = route == "human" or (
        route == "agent" and confidence < HUMAN_CONFIDENCE
    )
    if route == "agent" and (
        any(hit.get("label") == "true_positive" for hit in similar[:3])
        or (
            verdict == "false_positive"
            and (
                public["malicious_count"] > 0
                or public["suspicious_count"] > 0
                or public["has_mitre"] > 0
            )
        )
    ):
        needs_human = True
    return verdict, priority, route, needs_human, confidence


def _citations(
    public: dict[str, Any],
    similar: Sequence[dict[str, Any]],
    playbooks: Sequence[dict[str, Any]],
) -> list[EvidenceCitation]:
    citations: list[EvidenceCitation] = [
        EvidenceCitation(
            evidence_id=f"incident:{public['incident_id']}",
            quote=str(public.get("summary") or "")[:500],
            source="incident",
        )
    ]
    if similar:
        hit = similar[0]
        citations.append(
            EvidenceCitation(
                evidence_id=f"train_incident:{hit['source_id']}",
                quote=str(hit.get("text") or "")[:500],
                source="train_incident",
            )
        )
    if playbooks:
        hit = playbooks[0]
        citations.append(
            EvidenceCitation(
                evidence_id=str(hit["doc_id"]),
                quote=str(hit.get("text") or "")[:500],
                source="playbook",
            )
        )
    unique: dict[str, EvidenceCitation] = {}
    for citation in citations:
        unique.setdefault(citation.evidence_id, citation)
    return list(unique.values())


class OfflineAgent:
    """Bounded deterministic policy over the same typed tools an LLM would use."""

    def __init__(
        self,
        classifier: ClassifierArtifacts,
        index: RetrievalIndex,
        store: IncidentStore,
        prompts_dir: Path,
        max_calls: int = MAX_TOOL_CALLS,
    ) -> None:
        self.classifier = classifier
        self.index = index
        self.store = store
        self.max_calls = max_calls
        self.tools = AgentTools(index, store)
        self.system_prompt = (Path(prompts_dir) / "agent_system.md").read_text(
            encoding="utf-8"
        )
        self.decision_prompt = (Path(prompts_dir) / "agent_decision.md").read_text(
            encoding="utf-8"
        )

    def _prompt(
        self,
        public: dict[str, Any],
        probabilities: dict[str, float],
        tool_results: dict[str, Any],
    ) -> str:
        body = self.decision_prompt
        body = body.replace("{{INCIDENT_JSON}}", json.dumps(public, indent=2))
        body = body.replace("{{CLASSIFIER_JSON}}", json.dumps(probabilities, indent=2))
        body = body.replace("{{TOOL_RESULTS_JSON}}", json.dumps(tool_results, indent=2))
        return f"{self.system_prompt}\n\n{body}"

    def run(self, case: dict[str, Any], expected_label: str | None = None) -> AgentTrace:
        started = time.perf_counter()
        incident_id = str(case["incident_id"])
        public = self.store.public(incident_id)
        frame = self.store.inference_frame(incident_id)
        probabilities_array = self.classifier.predict_frame(frame)[0]
        probabilities = {
            label: float(probabilities_array[index])
            for index, label in enumerate(LABELS)
        }
        context = ToolContext(
            {
                "get_incident": self.tools.get_incident,
                "search_similar_incidents": self.tools.search_similar_incidents,
                "retrieve_playbook": self.tools.retrieve_playbook,
                "lookup_asset": self.tools.lookup_asset,
                "lookup_ioc": self.tools.lookup_ioc,
                "map_attack": self.tools.map_attack,
                "propose_action": self.tools.propose_action,
            },
            max_calls=self.max_calls,
        )

        context.call("get_incident", incident_id=incident_id)
        similar = context.call(
            "search_similar_incidents", incident_id=incident_id, k=5
        )
        playbooks = context.call("retrieve_playbook", incident_id=incident_id, k=5)
        attack = context.call("map_attack", incident_id=incident_id)
        verdict, priority, route, needs_human, confidence = _policy(
            public, probabilities_array, similar
        )
        citations = _citations(public, similar, playbooks)
        evidence_ids = [citation.evidence_id for citation in citations]
        counts = {
            key: int(public[key])
            for key in (
                "alert_count",
                "device_count",
                "account_count",
                "ip_count",
                "url_count",
                "sha256_count",
                "malicious_count",
                "suspicious_count",
                "has_mitre",
            )
        }
        proposals = context.call(
            "propose_action",
            incident_id=incident_id,
            verdict=verdict,
            evidence_ids=evidence_ids,
            categories=public["categories"],
            counts=counts,
        )
        remediation = [Remediation(**proposal) for proposal in proposals]
        decision = TriageDecision(
            incident_id=incident_id,
            verdict=verdict,
            priority=priority,
            remediation=remediation,
            evidence=citations,
            confidence=confidence,
            needs_human=needs_human,
            route=route,
            classifier_version=self.classifier.model_version,
            prompt_version=PROMPT_VERSION,
            tool_calls=len(context.records),
            latency_ms=0,
            cost_usd=0.0,
        )
        prompt = self._prompt(
            public,
            probabilities,
            {
                "similar_incidents": similar,
                "playbooks": playbooks,
                "attack_mapping": attack,
                "action_proposals": proposals,
            },
        )
        evidence_sources = {
            f"incident:{incident_id}": str(public.get("summary") or "")
        }
        for hit in similar:
            evidence_sources[f"train_incident:{hit['source_id']}"] = str(
                hit.get("text") or ""
            )
        for hit in playbooks:
            evidence_sources[str(hit["doc_id"])] = str(hit.get("text") or "")
        violations = decision.validate(evidence_sources=evidence_sources)
        revision_count = 0
        if violations:
            revision_count = 1
            incident_citation = EvidenceCitation(
                evidence_id=f"incident:{incident_id}",
                quote=str(public.get("summary") or "")[:500],
                source="incident",
            )
            if all(
                citation.evidence_id != incident_citation.evidence_id
                for citation in decision.evidence
            ):
                decision.evidence.append(incident_citation)
            violations = decision.validate(evidence_sources=evidence_sources)
        decision.latency_ms = int((time.perf_counter() - started) * 1000)
        schema_valid = not violations
        return AgentTrace(
            case_id=str(case.get("case_id", incident_id)),
            incident_id=incident_id,
            expected_label=expected_label,
            decision=decision,
            probabilities=probabilities,
            top_label=max(probabilities, key=probabilities.get),
            tool_calls=context.records,
            revision_count=revision_count,
            prompt_version=PROMPT_VERSION,
            prompt_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            prompt_chars=len(prompt),
            llm_backend="offline_policy",
            schema_valid=schema_valid,
            violations=violations,
            latency_ms=decision.latency_ms,
            cost_usd=0.0,
            notes=[
                "No external LLM is called. The decision comes from a deterministic "
                "policy over the calibrated classifier and retrieved evidence."
            ],
        )


def _summarize(traces: Sequence[dict[str, Any]], dataset_label: str) -> dict[str, Any]:
    if not traces:
        raise ValueError("No traces to summarize")
    total = len(traces)
    valid = sum(trace["schema_valid"] for trace in traces)
    hard_violations = sum(1 for trace in traces if trace["violations"])
    mean_tool_calls = float(np.mean([len(trace["tool_calls"]) for trace in traces]))
    tp_traces = [trace for trace in traces if trace["expected_label"] == "true_positive"]
    tp_with_retrieval = sum(
        1
        for trace in tp_traces
        if any(
            citation["source"] in {"train_incident", "playbook"}
            for citation in trace["decision"]["evidence"]
        )
    )
    predicted = Counter(trace["decision"]["verdict"] for trace in traces)
    routes = Counter(trace["decision"]["route"] for trace in traces)
    exact = sum(
        1
        for trace in traces
        if trace["expected_label"] == trace["decision"]["verdict"]
    )
    return {
        "dataset": dataset_label,
        "generated_at": datetime.now(UTC).isoformat(),
        "cases": total,
        "schema_valid": valid,
        "schema_valid_rate": valid / total,
        "hard_constraint_violations": hard_violations,
        "mean_tool_calls": mean_tool_calls,
        "max_tool_calls": max(len(trace["tool_calls"]) for trace in traces),
        "exact_label_agreement": exact / total,
        "abstention_rate": predicted["undetermined"] / total,
        "tp_cases": len(tp_traces),
        "tp_retrieval_cited": tp_with_retrieval,
        "tp_retrieval_complete": tp_with_retrieval == len(tp_traces),
        "tp_missed": sum(
            1
            for trace in tp_traces
            if trace["decision"]["verdict"] != "true_positive"
        ),
        "tp_missed_auto_closed": sum(
            1
            for trace in tp_traces
            if trace["decision"]["verdict"] != "true_positive"
            and trace["decision"]["route"] == "auto_close"
        ),
        "tp_missed_human_flagged": sum(
            1
            for trace in tp_traces
            if trace["decision"]["verdict"] != "true_positive"
            and trace["decision"]["needs_human"]
        ),
        "human_review_flagged": sum(
            1 for trace in traces if trace["decision"]["needs_human"]
        ),
        "auto_closed_cases": routes.get("auto_close", 0),
        "human_routed_cases": routes.get("human", 0),
        "predicted": dict(predicted),
        "routes": dict(routes),
        "gates": {
            "schema_valid_18_of_20": valid >= 18,
            "zero_hard_constraint_violations": hard_violations == 0,
            "mean_tool_calls_under_8": mean_tool_calls < 8,
            "tp_retrieval_citation": tp_with_retrieval == len(tp_traces),
            "trace_logged": True,
        },
        "case_results": [
            {
                "case_id": trace["case_id"],
                "incident_id": trace["incident_id"],
                "expected_label": trace["expected_label"],
                "predicted_label": trace["decision"]["verdict"],
                "route": trace["decision"]["route"],
                "confidence": trace["decision"]["confidence"],
                "priority": trace["decision"]["priority"],
                "tool_calls": len(trace["tool_calls"]),
                "schema_valid": trace["schema_valid"],
                "citations": len(trace["decision"]["evidence"]),
                "needs_human": trace["decision"]["needs_human"],
                "violations": trace["violations"],
            }
            for trace in traces
        ],
    }


def _fmt(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def render_report(metrics: dict[str, Any], traces: Sequence[dict[str, Any]]) -> str:
    lines = [
        "# Week 3 agent report",
        "",
        "Twenty hand-picked exception cases from the frozen GUIDE dev split. "
        "Expected labels are shown for evaluation only and are not exposed to "
        "the tools or the decision policy. The policy is deterministic and "
        "offline; no external LLM is called.",
        "",
        "## Aggregate",
        "",
        "| metric | value |",
        "|---|---:|",
        f"| cases | {metrics['cases']} |",
        f"| schema valid | {metrics['schema_valid']}/{metrics['cases']} |",
        f"| hard-constraint violations | {metrics['hard_constraint_violations']} |",
        f"| mean tool calls | {_fmt(metrics['mean_tool_calls'], 2)} |",
        f"| max tool calls | {metrics['max_tool_calls']} |",
        f"| exact label agreement | {_fmt(metrics['exact_label_agreement'])} |",
        f"| abstention rate | {_fmt(metrics['abstention_rate'])} |",
        f"| true-positive retrieval citation rate | "
        f"{metrics['tp_retrieval_cited']}/{metrics['tp_cases']} |",
        "",
        "## Gates",
        "",
        "| gate | pass |",
        "|---|---|",
    ]
    for name, passed in metrics["gates"].items():
        lines.append(f"| {name} | {'yes' if passed else 'no'} |")
    lines.extend(
        [
            "",
            "## Safety notes",
            "",
            f"- {metrics['tp_missed']} of {metrics['tp_cases']} true-positive cases "
            "were predicted as another label. "
            f"{metrics['tp_missed_human_flagged']} of those were flagged for human "
            f"review and {metrics['tp_missed_auto_closed']} were auto-closed.",
            f"- {metrics['human_review_flagged']} of {metrics['cases']} decisions "
            "set `needs_human`.",
            f"- {metrics['auto_closed_cases']} cases were auto-closed in total. "
            "Auto-close requires false-positive probability at least 0.90, "
            "true-positive probability at most 0.05, and no malicious, "
            "suspicious, or MITRE signal.",
            "",
            "## Cases",
            "",
            "| case | incident | expected | predicted | route | human | "
            "confidence | calls | valid | citations |",
            "|---|---|---|---|---|---|---:|---:|---|---:|",
        ]
    )
    for result in metrics["case_results"]:
        lines.append(
            f"| {result['case_id']} | `{result['incident_id']}` | "
            f"{result['expected_label']} | {result['predicted_label']} | "
            f"{result['route']} | {'yes' if result['needs_human'] else 'no'} | "
            f"{_fmt(result['confidence'])} | "
            f"{result['tool_calls']} | {'yes' if result['schema_valid'] else 'no'} | "
            f"{result['citations']} |"
        )
    lines.extend(
        [
            "",
            "## Tool use",
            "",
            "| tool | calls |",
            "|---|---:|",
        ]
    )
    tool_counts = Counter(
        call["name"] for trace in traces for call in trace["tool_calls"]
    )
    for name, count in sorted(tool_counts.items()):
        lines.append(f"| `{name}` | {count} |")
    lines.extend(
        [
            "",
            "## Decision schema",
            "",
            "`TriageDecision` is validated before it is written. Hard constraints "
            "include enum membership, confidence range, mandatory citations for "
            "true positives and remediation, containment actions only for true "
            "positives, no URLs or executable payloads in remediation, and "
            "`needs_human` for low-confidence human/agent routes.",
            "",
            "## Artifacts",
            "",
            "| artifact | path |",
            "|---|---|",
        ]
    )
    for name, path in metrics.get("artifacts", {}).items():
        lines.append(f"| {name} | `{path}` |")
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- The agent is a deterministic policy over the calibrated classifier "
            "and retrieved evidence. It is not an LLM agent and does not measure "
            "LLM cost or latency.",
            "- The twenty cases are hand-picked exception cases, not a random "
            "sample. Exact label agreement is descriptive only.",
            "- Retrieval precedents are train incidents with labels. Playbooks are "
            "synthetic and are not an operational policy.",
            "- Tool outputs are truncated in traces. Full prompts are not logged; "
            "only their SHA-256 hash and length are recorded.",
            "- No production SOC readiness is claimed.",
            "",
            "## Reproduce",
            "",
            "```bash",
            "uv run python -m triage.agent --case case_01",
            "uv run python -m triage.agent",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def run_agent(
    dev_path: Path,
    cases_path: Path,
    index_dir: Path,
    model_dir: Path,
    report_path: Path,
    traces_path: Path,
    metrics_path: Path,
    prompts_dir: Path,
    case_id: str | None = None,
    dataset_label: str = "guide",
) -> dict[str, Any]:
    payload = json.loads(Path(cases_path).read_text(encoding="utf-8"))
    cases = list(payload.get("cases", []))
    if not cases:
        raise ValueError(f"No cases found in {cases_path}")
    if case_id is not None:
        cases = [case for case in cases if case.get("case_id") == case_id]
        if not cases:
            raise ValueError(f"Unknown case id: {case_id}")

    incident_ids = [str(case["incident_id"]) for case in cases]
    store = IncidentStore.from_parquet(Path(dev_path), incident_ids)
    classifier = load_classifier(Path(model_dir))
    index = RetrievalIndex.load(Path(index_dir), FastEmbedEmbedder())

    classifier_train_sha = classifier.metadata.get("manifest", {}).get("train_sha256")
    index_train_sha = index.manifest.get("train_sha256")
    if classifier_train_sha and index_train_sha and classifier_train_sha != index_train_sha:
        raise ValueError(
            "Classifier and retrieval index were built from different train files: "
            f"{classifier_train_sha} != {index_train_sha}"
        )

    agent = OfflineAgent(classifier, index, store, Path(prompts_dir))

    traces: list[dict[str, Any]] = []
    for case in cases:
        incident_id = str(case["incident_id"])
        expected = store.label(incident_id)
        declared = case.get("expected_label")
        if declared is not None and declared != expected:
            raise ValueError(
                f"Case {case.get('case_id', incident_id)} expects {declared}, "
                f"but dev label is {expected}"
            )
        trace = agent.run(case, expected)
        traces.append(trace.to_dict())

    metrics = _summarize(traces, dataset_label)
    metrics["artifacts"] = {
        "traces": display_path(Path(traces_path)),
        "report": display_path(Path(report_path)),
        "metrics": display_path(Path(metrics_path)),
        "index": display_path(Path(index_dir)),
        "model_dir": display_path(Path(model_dir)),
    }
    if case_id is not None:
        return {"decision": traces[0]["decision"], "trace": traces[0], "metrics": metrics}

    Path(traces_path).parent.mkdir(parents=True, exist_ok=True)
    Path(metrics_path).parent.mkdir(parents=True, exist_ok=True)
    Path(report_path).parent.mkdir(parents=True, exist_ok=True)
    Path(traces_path).write_text(
        json.dumps(traces, indent=2) + "\n", encoding="utf-8"
    )
    Path(metrics_path).write_text(
        json.dumps(metrics, indent=2) + "\n", encoding="utf-8"
    )
    Path(report_path).write_text(
        render_report(metrics, traces), encoding="utf-8"
    )
    return metrics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="triage.agent")
    parser.add_argument("--case", default=None, help="Run one case id, e.g. case_01")
    parser.add_argument("--dev", default="data/processed/dev.parquet")
    parser.add_argument("--cases", default="data/cases/w3_cases.json")
    parser.add_argument("--index", default="indexes/w3_retrieval")
    parser.add_argument("--model-dir", default="models/classifier_v1")
    parser.add_argument("--prompts", default="prompts")
    parser.add_argument("--report", default="reports/w3_agent.md")
    parser.add_argument("--traces", default="reports/w3_traces.json")
    parser.add_argument("--metrics", default="reports/w3_agent_metrics.json")
    parser.add_argument("--dataset", choices=["guide", "fixture"], default="guide")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_agent(
        dev_path=Path(args.dev),
        cases_path=Path(args.cases),
        index_dir=Path(args.index),
        model_dir=Path(args.model_dir),
        report_path=Path(args.report),
        traces_path=Path(args.traces),
        metrics_path=Path(args.metrics),
        prompts_dir=Path(args.prompts),
        case_id=args.case,
        dataset_label=args.dataset,
    )
    if args.case:
        print(json.dumps(result, indent=2))
        return 0 if result["trace"]["schema_valid"] else 1
    print(json.dumps(result, indent=2))
    return 0 if all(result["gates"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
