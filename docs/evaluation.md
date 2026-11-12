# Evaluation

This document defines how TriageBudget is measured. Metrics, splits, and baselines are fixed before results are reported so they cannot be chosen after seeing outcomes.

**Current status: Week 1 baselines measured on the frozen GUIDE split.** TF-IDF + LightGBM reaches macro-F1 0.706 on the official test split, versus 0.219 for the majority class and 0.191 for rules. Figures marked as targets or external facts are not results.

---

## 1. Principles

1. **External labels over self-grading.** The primary labels come from GUIDE customer analysts. The project does not invent its own definition of a true positive for the headline metric.
2. **Cost-aware metrics.** A triage system is useful only if it reduces analyst minutes without hiding real incidents. Coverage and miss rate are reported together.
3. **Frozen test set.** The test split is fixed before tuning. Prompts, thresholds, and hyperparameters are chosen on dev only.
4. **No LLM judge for the headline.** The main metrics are classification agreement and execution results. LLM judges are allowed only for secondary explanation checks, and must be calibrated against human labels.
5. **Per-slice reporting.** Aggregate numbers hide failures. Report per class, per organization queue, and per severity.
6. **Negative results are results.** If the agent does not beat the classifier-plus-router baseline, the report says so and explains why.
7. **Retrieval is measured on its own.** A good verdict cannot excuse bad evidence. Recall@k, nDCG, and citation support are reported separately.

---

## 2. Splits

GUIDE provides an official incident-level split. Use it if the labels are available.

| Split | Purpose | Rule |
|---|---|---|
| Train | Fit classifier, calibration, retrieval index | Official train split |
| Dev | Tune thresholds, prompts, ablations | Held out from train |
| Test | Final report only | Frozen, touched once |
| Agent subset | Agent evaluation | Stratified sample of test, fixed seed |
| Per-org slices | Robustness reporting | Organization queues with at least 50 test incidents |

If the official test labels are hidden:

- Carve a local test set from the official train split before any tuning.
- Freeze the manifest and hash it.
- Call it `local_test`, not `official_test`.
- Report the limitation in every results table.

Leakage controls:

- Split by incident, never by alert or evidence item. The same incident must not appear in two splits.
- Remove incident ids, organization names, and timestamps that leak the label definition from model inputs where they are not legitimately predictive.
- Build retrieval indexes only from the train split. Test incidents cannot retrieve other test incidents.
- For time-based checks, train on earlier incidents and test on later ones. Report this as a secondary split.

---

## 3. Class definitions

GUIDE labels incidents from the customer analyst's perspective:

- **True positive:** the incident was a real security issue that required action.
- **Benign positive:** activity was suspicious but legitimate, or the detector fired as designed on non-malicious behavior.
- **False positive:** the alert or incident was not a security issue.

GUIDE uses `TruePositive`, `BenignPositive`, and `FalsePositive`. The mapping is in `docs/data.md` section 3.3. Unknown or conflicting labels are excluded from the frozen split, and the exclusion is reported.

---

## 4. Metrics

### 4.1 Classification

| Metric | Definition | Why |
|---|---|---|
| Macro-F1 | Unweighted mean of per-class F1 | Treats all three classes as important |
| Per-class precision | TP / (TP + FP) | False positives cost analyst time |
| Per-class recall | TP / (TP + FN) | False negatives cost security |
| Confusion matrix | Counts by predicted and true class | Shows which classes are confused |
| Expected calibration error | Weighted gap between confidence and accuracy across bins | The router depends on calibrated confidence |
| Brier score | Mean squared error of predicted probabilities | Proper scoring rule |

Report macro-F1 with bootstrap confidence intervals over incidents.

### 4.2 Priority ranking

GUIDE includes expert-ranked incidents. Treat priority as a ranking problem, not a regression.

| Metric | Definition |
|---|---|
| P@5 | Share of the top 5 ranked incidents that are in the analyst's top 5 |
| P@10 | Same for top 10 |
| P@20 | Same for top 20 |
| NDCG@10 | Normalized discounted cumulative gain against the analyst ranking |

Baseline: random ranking and severity-only ranking.

### 4.3 Remediation

If remediation labels are available:

- Macro-F1 over remediation action classes.
- Top-3 accuracy for the recommended action.
- Abstention rate when no action is supported by evidence.

The action taxonomy will be fixed after the schema audit. No free-form actions in the headline metric.

### 4.4 Retrieval quality

RAG is measured separately so a good verdict cannot hide bad retrieval.

Retrieval set:

- 100 queries drawn from dev incidents.
- Each query has gold evidence ids and gold playbook section ids.
- The first 30 queries are labelled by two people. Report agreement.
- The test split is never used to build the index or tune retrieval.

| Metric | Definition |
|---|---|
| Recall@5 | Fraction of gold items retrieved in the top 5, averaged over queries |
| Recall@10 | Same for the top 10 |
| nDCG@10 | Ranking quality with graded relevance |
| MRR | Mean reciprocal rank of the first gold item |
| Citation support | Share of cited items that actually support the decision, human checked |

Baselines: BM25-only, dense-only with `bge-small-en-v1.5`, hybrid with reciprocal rank fusion, and hybrid plus a cross-encoder reranker.

Report per query type: similar incident, playbook, and incident evidence. Include index size and retrieval latency.

### 4.5 Selective risk

This is the headline evaluation.

Definitions:

- **Coverage:** share of incidents the system handles without human review. Includes auto-close, auto-escalate, and agent decisions that are marked `needs_human=false`.
- **Miss rate:** share of true-positive incidents that were auto-closed or marked benign/false positive without human review.
- **Selective risk:** the error rate on the covered set.
- **Risk-coverage curve:** miss rate (or error rate) as a function of coverage, sweeping the confidence threshold.

Procedure:

1. Score every test incident with calibrated probabilities.
2. Sort by confidence, descending.
3. For each threshold, compute coverage and the error rate on covered incidents.
4. Plot coverage on the x-axis and miss rate on the y-axis.
5. Report the curve for the classifier-only router, the RAG-only baseline, the zero-shot LLM baseline, and the full system.
6. Mark the 10-minute analyst budget operating point.

The 10-minute budget is an assumption, not a measurement. State it explicitly: each human-reviewed incident is assumed to cost 10 analyst minutes. The cost model can be varied in a sensitivity table at 5, 10, and 20 minutes.

Target claim to test: at a 10-minute budget, coverage of at least 60% with a true-positive miss rate no higher than 1%. If the curve cannot reach that point, report the best achievable point and the shortfall.

### 4.6 Cost and latency

| Metric | Definition |
|---|---|
| Cost per 1,000 incidents | Mean token cost plus compute cost, scaled to 1,000 |
| Agent cost per routed incident | Mean tokens and wall-clock for agent calls |
| p50 / p95 latency | End-to-end decision latency, warm |
| Cold-start latency | First request after idle, for the deployed demo |
| Tool calls per incident | Mean and distribution |
| Cache hit rate | Share of LLM calls served from cache |

Cost is reported in USD using provider list prices at the time of the run. Free-tier usage is reported as "free-tier equivalent" with the quota assumptions.

### 4.7 Citation accuracy

For every decision with evidence:

- Does each cited evidence id exist in the incident?
- Does the quoted text appear in the evidence item?
- Does the quote support the verdict? This needs a human check.

Procedure: sample 100 decisions stratified by verdict and route. Two reviewers rate each citation as supported, partially supported, or unsupported. Report agreement (Cohen's kappa) and the share of fully supported citations. Target: 90% fully supported, with kappa above 0.7. If only one reviewer is available, re-check a random 20% and report the disagreement rate.

---

## 5. Baselines

All baselines run on the same frozen split.

| ID | Baseline | Purpose |
|---|---|---|
| B0 | Majority class | Floor |
| B1 | Rules: MITRE technique present or malicious verdict (`has_mitre or malicious_count > 0`) | Non-ML reference |
| B2 | TF-IDF + logistic regression | Simple linear baseline |
| B3 | TF-IDF + LightGBM | Classical ML baseline |
| B4 | MiniLM embeddings + LightGBM | Dense feature baseline, optional |
| B5 | Zero-shot LLM with incident summary | LLM-only reference |
| B6 | RAG-only: retrieve similar incidents, then LLM | Retrieval without routing |
| B7 | Classifier + router, no agent | Tests whether the agent adds value |
| B8 | Full system: classifier + router + bounded agent | Proposed system |

B5 and B6 are expensive. Run them on the agent subset, not the full test set. B7 and B8 run on the same subset for a fair comparison.

### 5.1 Retrieval baselines

Run these on the 100-query retrieval set.

| ID | Retrieval baseline | Purpose |
|---|---|---|
| R0 | BM25-only | Keyword floor |
| R1 | Dense-only with `bge-small-en-v1.5` | Vector search floor |
| R2 | Hybrid BM25 plus dense, reciprocal rank fusion | Default retriever |
| R3 | Hybrid plus cross-encoder reranker | Tests the reranker |

R0 to R2 are required. R3 is optional and depends on the fine-tune budget.

---

## 6. Ablations

Run on the agent subset with a fixed seed.

| Ablation | What changes | Question |
|---|---|---|
| BM25 only | Replace hybrid retrieval with BM25 | Does dense retrieval help? |
| Dense only | Replace hybrid retrieval with dense vectors | Does keyword matching help? |
| No reranker | Skip the cross-encoder | Does reranking justify its cost? |
| No retrieval | Agent sees only the incident and classifier output | Does retrieval help? |
| No similar incidents | Remove `search_similar_incidents` | Does precedent help? |
| No ATT&CK mapping | Remove `map_attack` | Does technique context help? |
| No playbook | Remove `retrieve_playbook` | Does remediation grounding help? |
| No citation verifier | Accept unverified evidence | How many unsupported citations appear? |
| No calibration | Use raw classifier scores for routing | Does calibration change the risk curve? |
| Point estimate router | Use a fixed threshold instead of the curve | How much does budget-aware routing add? |
| Full agent on all incidents | Remove the router | What does the agent cost when it runs everywhere? |
| Local model vs hosted model | Ollama qwen3:4b vs Gemini Flash-Lite | How much quality is lost for zero cost? |

Report each ablation as a delta against B8, with cost and latency deltas.

---

## 7. Error taxonomy

Every error in the test set is assigned one primary category. The taxonomy is fixed before analysis.

1. **Label ambiguity.** The incident has mixed signals or the GUIDE label is questionable.
2. **Missing evidence.** The decisive evidence is not in the incident record.
3. **Retrieval miss.** The right playbook or precedent exists but was not retrieved.
4. **Retrieval noise.** Retrieved evidence is irrelevant and distracts the model.
5. **Reasoning error.** Evidence is present but the model reaches the wrong conclusion.
6. **Citation error.** The verdict is right but the cited evidence does not support it.
7. **Schema error.** The output is invalid or incomplete.
8. **Abstention error.** The system asks for human review when it could have decided.
9. **Overconfidence.** The system decides incorrectly with high confidence.
10. **Tool failure.** A tool times out or returns an error and the decision degrades.

Report counts and examples. Include at least three anonymized examples per category in the final report.

---

## 8. Reproducibility

Every evaluation run produces:

- `results/run_<timestamp>/config.json`: model versions, prompt versions, thresholds, seed, dataset manifest hash.
- `results/run_<timestamp>/predictions.parquet`: one row per incident.
- `results/run_<timestamp>/metrics.json`: machine-readable metrics.
- `results/run_<timestamp>/report.md`: human-readable tables and figures.
- `results/run_<timestamp>/errors.csv`: sampled errors with categories.

Rules:

- Fixed random seeds for sampling and model training.
- Pinned dependency versions.
- Prompt templates stored as files, not inline strings.
- Dataset manifest with file hashes.
- No manual edits to predictions after the run.
- One command regenerates every table and figure from the saved predictions.

```bash
make eval
make eval-agent
make report
```

---

## 9. CI regression gates

GitHub Actions currently runs on every push and pull request:

1. Ruff lint.
2. Data-integrity and baseline tests on the synthetic GUIDE-shaped fixture.
3. An end-to-end fixture run: ETL, frozen manifest validation, and the baseline table.
4. The fixture report is uploaded as a build artifact.

Later weeks add:

1. A retrieval index build and a 20-query Recall@5 smoke check.
2. A classifier smoke evaluation on a fixed sample.
3. A schema check on generated decisions.
4. A documentation link check.

The full evaluation is too slow and too rate-limited for every push. It runs on a manual trigger and on release tags. The planned regression gate fails if macro-F1 drops by more than 2 points versus the stored baseline, or if schema validation fails.

---

## 10. Falsification plan

The project is designed to be falsifiable. These outcomes would weaken or kill the thesis:

- The classifier plus router reaches the 60% coverage and 1% miss target without the agent. Then the agent is unnecessary for the headline claim, and the report should say so.
- The selective-risk curve is flat. Then confidence does not separate easy from hard incidents, and the router adds no value.
- The agent improves accuracy but costs more than the analyst time it saves. Then the economics do not work at the stated budget.
- Per-organization slices show large variance. Then the global claim is misleading and the report must lead with the slice distribution.
- The LLM cites evidence that does not support its verdict more than 10% of the time. Then the citation layer is not trustworthy and needs a redesign.
- The full agent on all incidents beats the router on cost-adjusted performance. Then routing is the wrong design.

Each outcome has a place in the final report. None of them will be hidden.

---

## 11. Human rationale rubric

For 50 sampled decisions, a reviewer scores the explanation on five items:

| Item | Question | Score |
|---|---|---|
| Evidence grounding | Does the explanation rely on cited evidence rather than unsupported claims? | 0-2 |
| Verdict consistency | Does the explanation match the verdict and priority? | 0-2 |
| Actionability | Is the proposed remediation specific enough to act on? | 0-2 |
| Uncertainty | Does it state what is unknown or ambiguous? | 0-2 |
| Conciseness | Is it free of filler and repetition? | 0-2 |

Two reviewers if possible. Report mean scores, agreement, and examples of the best and worst outputs. Do not use an LLM as the primary rater.

---

## 12. Reporting template

The final report will contain, in this order:

1. What was measured and on which split.
2. Dataset limitations and label caveats.
3. Retrieval results: Recall@5, Recall@10, nDCG@10, MRR, and retrieval ablations.
4. Classifier results: macro-F1, per-class P/R, calibration.
5. Priority results: P@5/10/20, NDCG@10.
6. Selective-risk curve with the 10-minute operating point.
7. Agent results: accuracy, citation accuracy, tool calls, cost, latency.
8. Ablations.
9. Error taxonomy with examples.
10. Per-organization slices.
11. What failed and what would change the conclusion.

No result is reported without its split, sample size, and confidence interval.
