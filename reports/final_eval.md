# TriageBudget final evaluation

Generated: 2026-11-13

This report consolidates the measured results from Weeks 1 to 5. It separates
measured numbers from assumptions, proxies, and results that were not measured.
The project is a research prototype, not a production SOC system.

## 1. Question

At a fixed analyst review budget, how many incidents can be handled without
human review, and what true-positive miss rate does that coverage cost?

The 10-minute review cost is an assumption, not a measurement. The project
reports the cost at 5, 10, and 20 minutes per reviewed incident. No total
analyst capacity was supplied, so the budget is expressed as review load rather
than a hard capacity constraint.

## 2. Data

| split | rows | source |
|---|---:|---|
| train | 89,999 | frozen label-stratified sample of GUIDE train |
| dev | 10,001 | stratified holdout from the frozen train sample |
| test | 303,220 | official GUIDE test split |

- Dataset: Microsoft GUIDE, Kaggle release.
- Test incident ids are disjoint from the frozen train sample.
- Train file SHA-256: `a4b83b5755109cfa27bb2e502d8dc9a60bd7c4ac41b256974d4bb6aac5db89b1`.
- Incidents Parquet SHA-256: `efd105e630b4e07854fa851bcd60d74ed8ef57933514c0c0541d305d86e993e3`.
- Raw GUIDE files are gitignored. They must be downloaded separately to rebuild
  the split.
- The test split has 62,540 true positives, 148,215 benign positives, and
  92,465 false positives.

## 3. Methods

- **Classifier.** TF-IDF over derived summary text plus numeric incident
  features, LightGBM, and vector calibration selected on dev. Label order is
  `true_positive`, `benign_positive`, `false_positive`.
- **Retrieval.** 14,727 incident and playbook documents. BM25 plus dense
  `BAAI/bge-small-en-v1.5` embeddings, fused with reciprocal rank fusion.
- **Agent.** Deterministic bounded policy with five tool calls. It retrieves
  similar incidents and playbooks, maps ATT&CK, proposes actions, grounds
  citations, and validates the decision. The decision path calls no hosted LLM.
- **Router.** A threshold on calibrated confidence. Only true-positive and
  false-positive predictions are eligible for automatic handling. Benign
  predictions always go to a human.
- **Review console.** FastAPI API with SQLite locally and Postgres support,
  seeded from 20 tracked Week 3 traces. Reviewer actions are written to an audit
  log. An optional Groq explanation endpoint summarizes an existing decision and
  must cite retrieved evidence; it cannot change the verdict, close an incident,
  or execute remediation. Vercel and Neon packaging is in the repo, but no hosted
  deployment has been verified.

## 4. Main results

### 4.1 Baselines and classifier

| model | test rows | macro-F1 | accuracy |
|---|---:|---:|---:|
| majority | 303,220 | 0.2189 | 0.4888 |
| rules | 303,220 | 0.1910 | 0.2247 |
| TF-IDF + LightGBM, calibrated | 303,220 | 0.7282 | 0.7635 |

Calibrated classifier macro-F1 95% bootstrap CI: **0.7263 to 0.7301**.
Accuracy 95% CI: **0.7621 to 0.7651**.

Calibrated per-class results:

| class | precision | recall | F1 |
|---|---:|---:|---:|
| true_positive | 0.7499 | 0.5157 | 0.6111 |
| benign_positive | 0.7351 | 0.9115 | 0.8138 |
| false_positive | 0.8395 | 0.6939 | 0.7598 |

The classifier is clearly better than the trivial baselines, but true-positive
recall is the weak point. Calibration raises macro-F1 and lowers true-positive
recall from 0.684 to 0.516.

### 4.2 Selective risk

Classifier-only, full test set:

| metric | value |
|---|---:|
| operating threshold | 0.95 |
| coverage | 9.9% |
| covered incidents | 29,999 |
| true-positive miss rate | 0.2% |
| selective risk | 1.0% |
| review load at 10 minutes | 901 minutes per 100 incidents |

The target was at least 60% coverage with at most 1% true-positive miss. The
classifier reaches 9.9% coverage, so the target is **not met**. The coverage
shortfall is **50.1 percentage points**. This is reported as a finding, not
tuned away on test.

On the fixed 600-case test subset:

| policy | rows | coverage | TP miss | selective risk |
|---|---:|---:|---:|---:|
| classifier-only | 600 | 12.0% | 1.0% | 2.8% |
| full agent | 600 | 15.0% | 0.0% | 2.2% |
| RAG vote proxy | 600 | 21.7% | 0.5% | 30.0% |

The full agent improves coverage and true-positive miss on this subset, but the
subset is a fixed stratified sample, not an org-random sample. The RAG proxy
reaches higher coverage with unacceptable selective risk.

### 4.3 Retrieval

100 dev proxy queries. Gold sets are structured-overlap proxies, not human
relevance labels.

| method | incident R@5 | incident R@10 | nDCG@10 | MRR | playbook R@5 | playbook R@10 | median latency |
|---|---:|---:|---:|---:|---:|---:|---:|
| BM25 | 0.4067 | 0.6833 | 0.4918 | 0.5323 | 0.3067 | 0.6217 | 22.4 ms |
| dense | 0.3067 | 0.6067 | 0.4398 | 0.5035 | 0.5133 | 0.6758 | 6.3 ms |
| hybrid | 0.4267 | 0.6733 | 0.5013 | 0.5747 | 0.4217 | 0.6750 | 35.0 ms |
| hybrid + reranker | 0.3167 | 0.5067 | 0.3654 | 0.4263 | 0.3233 | 0.6225 | 832.9 ms |

Hybrid is the best incident retriever. The cross-encoder reranker was worse on
every retrieval metric and about 24 times slower. It is a negative result and is
not in the default path. Citation smoke test: 19 of 20 queries returned both a
gold incident citation and a category-matched playbook section in the top 5.

### 4.4 Analyst queue ranking

9,980 ranked test incidents across 499 organizations.

| metric | model | analyst QueueRank |
|---|---:|---:|
| P@5 | 0.3226 | 0.2269 |
| P@10 | 0.2802 | 0.2216 |
| P@20 | 0.2219 | 0.2219 |
| nDCG@10 | 0.6877 | 0.5192 |
| capture@2 | 0.2563 | 0.1664 |

The model beats the analyst queue at P@5 and nDCG@10 and ties at P@20. These are
true-positive proxies, not analyst-judged relevance.

### 4.5 Error analysis

182 agent decisions differed from the expected label. 100 were labeled with a
fixed heuristic taxonomy; these are system-assigned labels, not human review.

| category | count |
|---|---:|
| reasoning_error | 82 |
| retrieval_noise | 49 |
| label_ambiguity | 33 |
| overconfidence | 12 |
| abstention_error | 6 |
| citation_error | 0 |
| missing_evidence | 0 |
| retrieval_miss | 0 |
| schema_error | 0 |
| tool_failure | 0 |

### 4.6 Review console

The local console exposes:

- `GET /health`
- `GET /api/incidents`
- `GET /api/incidents/{id}`
- `GET /api/decisions`
- `POST /api/incidents/{id}/review`
- `POST /api/incidents/{id}/explain`
- `GET /api/audit`
- `GET /api/metrics`

The queue UI shows the decision, evidence, remediation, review form, and audit
timeline. Reviewer actions require `X-Review-Token`, use an idempotency key, and
write both a review row and an audit event. The console is demo-only until
authentication, rate limiting, and production database operations are hardened.

The explanation endpoint is optional and also requires `X-Review-Token`. It sends
only the derived incident summary, classifier probabilities, retrieved evidence,
and proposed remediation to Groq (`openai/gpt-oss-120b`, fallback
`openai/gpt-oss-20b`). Responses must match a fixed JSON schema and may cite only
retrieved evidence ids; an unknown id is rejected and nothing is stored.
Explanations are cached by incident, model, prompt version, and a hash of the
source fields. The UI labels the output as model-generated and requires review.
No explanation quality, citation usefulness, or analyst time saving was measured
with human raters.

## 5. What was not measured

- **Zero-shot LLM baseline.** No LLM was evaluated as a classifier on the test
  set. It is reported as not measured, not as a result.
- **LLM-generated RAG.** The RAG-only baseline is a deterministic retrieval-vote
  proxy, not generation. The Groq layer explains decisions after the fact and is
  not a decision baseline.
- **Explanation quality.** No human rated whether explanations are correct,
  useful, or supported by the cited evidence.
- **Human citation support.** Citation grounding is checked against retrieved
  source text, but no human rated citation usefulness.
- **Human error labels.** The 100-error table is heuristic.
- **Alert-disjoint sensitivity.** 15,301 test incidents (5.0%) share at least one
  alert with the frozen train sample. Incident ids are disjoint; the alert-level
  sensitivity run is still pending.
- **Live deployment.** Vercel and Neon packaging is in the repo, but no live URL
  exists yet. SQLite does not persist on Vercel, so Neon is required.

## 6. Limitations

- The 10-minute review cost is an assumption, not a measured analyst workload.
- The full-agent comparison uses a fixed 600-case stratified subset.
- Classifier tuning and calibrator selection both use dev. Test is untouched,
  but calibrator selection is optimistic.
- Retrieval gold sets and queue relevance are proxies.
- The playbooks are synthetic and are not an organization's policy.
- Raw GUIDE evidence text is unavailable, so citations use derived summaries.
- The review console has a demo token, not a full identity system. A shared
  token limits cost abuse on the explanation endpoint but is not user-level auth.
- AI explanations can be wrong even when the JSON is valid and every citation
  exists. A citation check verifies provenance, not reasoning.
- No production SOC readiness is claimed.

## 7. Reproduce

```bash
uv sync --all-groups
uv run pytest
uv run ruff check .

# Real GUIDE data must be placed in data/raw/ first.
uv run python -m triage.cli etl --raw-dir data/raw --out data/processed/incidents.parquet --stats data/processed/etl_stats.json
uv run python -m triage.cli split --incidents data/processed/incidents.parquet --out-dir data/processed --manifest data/manifests/split_v1.json --sample-size 100000
uv run python -m triage.cli baselines --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --manifest data/manifests/split_v1.json --report reports/w1_baselines.md --metrics reports/w1_metrics.json --dataset guide
uv run python -m triage.cli classify --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --manifest data/manifests/split_v1.json --report reports/w2_classifier.md --metrics reports/w2_metrics.json --model-dir models/classifier_v1 --dataset guide
uv run python -m triage.retrieval build --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --playbooks data/playbooks --out indexes/w3_retrieval --report reports/w3_retrieval.md --metrics reports/w3_retrieval_metrics.json --dataset guide
uv run python -m triage.agent
uv run python -m triage.cli week4
```

Local review console:

```bash
uv run python -m triage.web seed --if-empty
uv run python -m triage.web serve
```

Open `http://127.0.0.1:8000`.

## 8. Artifacts

| artifact | path |
|---|---|
| Week 1 baselines | `reports/w1_baselines.md` |
| Week 2 classifier | `reports/w2_classifier.md` |
| Week 3 retrieval | `reports/w3_retrieval.md` |
| Week 3 agent | `reports/w3_agent.md` |
| Week 4 selective risk | `reports/w4_selective_risk.md` |
| Week 4 retrieval ablations | `reports/w4_retrieval.md` |
| Week 4 run metrics | `results/run_20261113T100909Z/metrics.json` |
| Week 5 demo script | `reports/w5_demo.md` |
| Week 5 deployment notes | `docs/deployment.md` |
| Week 6 final report | `reports/final_eval.md` |

The review console is a local-first demo. Vercel plus Neon is the packaged hosted
path, with Render as a fallback. Deployment has not been verified, so no hosted
result or URL is claimed.
