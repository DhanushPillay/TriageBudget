# TriageBudget final report (first version)

Generated: 2026-11-13T10:15:48.383782+00:00

## 1. Problem

SOC teams face more alerts than analysts can review. This project asks a narrow question: at a fixed review budget, how many incidents can be handled without human review, and what true-positive miss rate does that coverage cost?

## 2. Data

- Microsoft GUIDE incidents, frozen split: 89,999 train, 10,001 dev, 303,220 test.
- Labels: true positive, benign positive, false positive.
- Raw GUIDE files are gitignored. The split manifest records SHA-256 hashes.

## 3. Methods

- Classifier: TF-IDF plus engineered numeric features and LightGBM, with vector calibration selected on dev.
- Retrieval: 14,727 train incidents and playbook sections, BM25 + dense bge-small-en-v1.5 with reciprocal-rank fusion.
- Agent: deterministic bounded policy with five tool calls, evidence grounding, and schema validation. No hosted LLM is used.
- Router: confidence threshold over predicted true/false positives; benign predictions always go to a human.

## 4. Main results

- Classifier test macro-F1: 0.7282 (95% CI 0.7263 to 0.7301).
- Classifier operating point: coverage 9.9%, TP miss 0.2%, selective risk 1.0%.
- Target (>=60% coverage, <=1% TP miss): **not met**.

| policy | coverage | TP miss | selective risk |
|---|---:|---:|---:|
| classifier-only (subset) | 12.0% | 1.0% | 2.8% |
| full system (subset) | 15.0% | 0.0% | 2.2% |

The full system improves the curve: **True**.

## 5. Retrieval

| method | incident R@5 | incident R@10 | playbook R@5 | playbook R@10 |
|---|---:|---:|---:|---:|
| bm25 | 0.4067 | 0.6833 | 0.3067 | 0.6217 |
| dense | 0.3067 | 0.6067 | 0.5133 | 0.6758 |
| hybrid | 0.4267 | 0.6733 | 0.4217 | 0.6750 |
| hybrid_rerank | 0.3167 | 0.5067 | 0.3233 | 0.6225 |

## 6. Analyst queue ranking

Joined 9,980 queue rows across 499 orgs.

| metric | model | analyst QueueRank |
|---|---:|---:|
| P@5 | 0.3226 | 0.2269 |
| P@10 | 0.2802 | 0.2216 |
| P@20 | 0.2219 | 0.2219 |

## 7. Error analysis

182 errors were found in the 600-case subset. 100 were assigned a category.

| category | count |
|---|---:|
| label_ambiguity | 33 |
| missing_evidence | 0 |
| retrieval_miss | 0 |
| retrieval_noise | 49 |
| reasoning_error | 82 |
| citation_error | 0 |
| schema_error | 0 |
| abstention_error | 6 |
| overconfidence | 12 |
| tool_failure | 0 |

## 8. Limitations

- The 10-minute review budget is an assumption, not a measured workload.
- Zero-shot and LLM RAG baselines are not measured; this run has no hosted LLM backend.
- The RAG baseline is a retrieval-vote proxy.
- Error categories are system-assigned heuristics, not human labels.
- The agent subset is a fixed stratified sample, not all test incidents.
- The calibration split overlaps the dev tuning split; test metrics are untouched but calibrator selection is optimistic.
- Clean-clone reproduction requires the gitignored raw GUIDE data.
- No production SOC readiness is claimed.

## 9. Reproduce

```bash
uv run python -m triage.selective
```

Artifacts are under `results/run_<timestamp>/`; large prediction and trace files are gitignored.
