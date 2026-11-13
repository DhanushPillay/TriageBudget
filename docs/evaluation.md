# Evaluation

This document defines how TriageBudget is measured. Metrics, splits, and baselines are fixed before results are reported so they cannot be chosen after seeing outcomes.

**Current status: Week 4 selective-risk evaluation measured on the frozen GUIDE split.** The calibrated classifier's best safe operating point is threshold 0.95, with 9.9% coverage at a 0.2% true-positive miss rate and 1.0% selective risk. The 60% coverage target at 1% miss is not met; the report states the 50.1-point coverage shortfall rather than tuning on test. On the fixed 600-case stratified test subset, the full agent reaches 15.0% coverage at 0.0% true-positive miss versus 12.0% at 1.0% for classifier-only. Hybrid retrieval reaches incident Recall@5 0.4267 and Recall@10 0.6733; the cross-encoder reranker is worse on every metric and much slower. Queue ranking beats the analyst queue at P@5 and nDCG@10. Error analysis labels 100 of 182 errors with system-assigned categories. Zero-shot LLM and LLM-generated RAG baselines are not measured and are not reported as results. Week 2 classifier: macro-F1 0.7199 raw and 0.7282 after vector calibration, ECE 0.0184 to 0.0051.

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
| Expected calibration error | Weighted gap between confidence and accuracy across 15 equal-width bins | The router depends on calibrated confidence |
| Brier score | Mean squared error of the predicted probability vector | Proper scoring rule |
| Negative log-likelihood | Mean negative log probability of the true class | Proper scoring rule, used to fit temperature scaling |

Report macro-F1 with bootstrap confidence intervals over incidents.

Calibration rules:

- The calibrator is fit on dev only. It is never fit on test.
- Candidate methods are temperature scaling, vector scaling (temperature plus a per-class bias), and per-class isotonic regression. The method is selected by two-fold cross-validation on dev, then refit on all of dev. A method is eligible only if its cross-validated macro-F1 is within 0.005 of raw.
- Known limitation: the same dev rows tune LightGBM and select the calibrator. The test split stays untouched, so the headline test metrics remain valid, but calibrator selection is optimistic. Week 4 did not address this; nested cross-validation or a separate calibration split is future work.
- ECE is computed on the top-label confidence. The reliability diagram plots observed accuracy against mean confidence for the same bins. Class-wise one-vs-rest ECE is reported separately.
- A calibrated classifier must report raw and calibrated ECE, Brier, and NLL on the same split. Calibration must not be assumed from the training objective.
- Calibration can change the argmax. Raw and calibrated per-class metrics are both reported, and the router consumes `p_true_positive` rather than assuming the predicted class is unchanged.
- The per-class recall floor is the majority-class prevalence on the frozen test split (0.489). All three class recalls must exceed it.

### 4.2 Priority ranking

The GUIDE paper includes expert-ranked incidents. Treat priority as a ranking problem, not a regression.

| Metric | Definition |
|---|---|
| P@5 | Share of the top 5 ranked incidents that are in the analyst's top 5 |
| P@10 | Same for top 10 |
| P@20 | Same for top 20 |
| NDCG@10 | Normalized discounted cumulative gain against the analyst ranking |

Baseline: random ranking and severity-only ranking.

The public release includes `data/raw/GUIDE_Test_Queue_Rankings.csv` with `OrgId`, `IncidentId`, and `QueueRank` for 9,980 test incidents across 499 organizations. The count matches the ranked set reported in the paper. There is still no severity column. Week 2 predates this audit and reports a queue-level proxy instead:

- Rank incidents within each organization queue by calibrated `p_true_positive`.
- Report macro precision@5/10/20 and true-positive capture@10% across queues with at least 50 test incidents and at least 5 true positives.
- Compare with a signal-only baseline that orders by malicious verdict, MITRE presence, suspicion, and alert count.
- Label the Week 2 result as a queue risk-ranking proxy. Week 4 measured model versus analyst queue ranking on 9,980 incidents across 499 organizations: P@5 0.3226 vs 0.2269, P@10 0.2802 vs 0.2216, P@20 0.2219 vs 0.2219, and nDCG@10 0.6877 vs 0.5192.

### 4.3 Remediation

If remediation labels are available:

- Macro-F1 over remediation action classes.
- Top-3 accuracy for the recommended action.
- Abstention rate when no action is supported by evidence.

The action taxonomy will be fixed after the schema audit. No free-form actions in the headline metric.

### 4.4 Retrieval quality

RAG is measured separately so a good verdict cannot hide bad retrieval.

Week 3 retrieval set:

- 100 dev queries, stratified 34 true positive, 33 benign positive, 33 false positive.
- Gold incident docs are the top 3 same-label train docs by Jaccard overlap over categories, MITRE techniques, and alert titles. Gold playbook docs are the Triage questions and Containment sections of playbooks whose category metadata intersects the query categories.
- These gold sets are structured-overlap proxies. They are reproducible and independent of the retrieval model, but they are not human relevance labels. The planned double-labelling of 30 queries is still open, so citation support is not measured.
- The test split is never used to build the index or tune retrieval.

| Metric | Definition |
|---|---|
| Recall@5 | Fraction of proxy gold items retrieved in the top 5, averaged over queries |
| Recall@10 | Same for the top 10 |
| nDCG@10 | Ranking quality with graded relevance against the proxy gold set |
| MRR | Mean reciprocal rank of the first proxy gold item |
| Citation support | Share of cited items that actually support the decision, human checked |
| Leakage | Indexed train incident ids that also appear in the test split; must be zero |

Measured Week 3 baselines: BM25-only, dense-only with `bge-small-en-v1.5`, and hybrid with reciprocal rank fusion. Week 4 also measured a cross-encoder reranker (`Xenova/ms-marco-MiniLM-L-6-v2`) over the hybrid top 20. It was worse on every metric: incident Recall@5 fell from 0.4267 to 0.3167 and Recall@10 from 0.6733 to 0.5067, while median latency rose from 35.0 ms to 832.9 ms. The report treats this as a negative result, not a win.

Report per source: similar incident and playbook. Include index size, doc count, and retrieval latency. Week 3 results are in `reports/w3_retrieval.md`.

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

Measured Week 4 outcome: the classifier-only router reaches 9.9% coverage at a 0.2% true-positive miss rate and 1.0% selective risk (threshold 0.95). The 60% coverage target is not met; the shortfall is 50.1 percentage points. On the fixed 600-case stratified test subset, the full agent reaches 15.0% coverage at a 0.0% true-positive miss rate, against 12.0% coverage at a 1.0% miss rate for the classifier-only router on the same subset. The deterministic RAG-vote proxy reaches 21.7% coverage at a 0.5% miss rate but has 30.0% selective risk. Zero-shot LLM and LLM-generated RAG are not measured because no hosted model backend is wired. The curve is reported as measured; thresholds were not selected on test.

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

Procedure: sample 100 decisions stratified by verdict and route. Two reviewers rate each citation as supported, partially supported, or unsupported. Report agreement (Cohen's kappa) and the share of fully supported citations. Target: 90% fully supported, with kappa above 0.7. If only one reviewer is available, re-check a random 20% and report the disagreement rate. Week 3 does not measure citation support.

### 4.8 Agent decision validity

Week 3 uses 20 hand-picked dev exception cases: 7 true positive, 7 benign positive, and 6 false positive. They include weak positives, benign incidents with malicious signals, MITRE-present false positives, and high-volume false positives. Labels are used for evaluation and are hidden from the tools and policy.

Report:

- Schema validity and hard-constraint violations.
- Tool calls per case, mean and maximum, against the six-call cap.
- True-positive citation coverage.
- Exact label agreement and abstention rate.
- Route distribution and whether missed true positives were flagged for human review or auto-closed.

The cases are not a random sample. Exact label agreement is descriptive and must not be presented as a test-set benchmark. Week 3 results are in `reports/w3_agent.md`.

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
