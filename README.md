# TriageBudget

A budget-aware RAG and agent system for security incident triage.

**Status: Week 5 local review console is in, with an optional Groq explanation layer.** The calibrated classifier reaches macro-F1 0.7282 on 303,220 test incidents. The Week 4 selective-risk router reaches 9.9% coverage at a 0.2% true-positive miss rate, so the 60% coverage target is missed by 50.1 points. On a fixed 600-case test subset the full agent reaches 15.0% coverage at 0.0% true-positive miss versus 12.0% at 1.0% for classifier-only. Hybrid retrieval reaches incident Recall@5 0.4267 and Recall@10 0.6733; the tested cross-encoder reranker was worse and is not in the default path. The FastAPI review console, SQLite/Postgres storage, demo seed, audit log, Docker Compose, tests, and Groq explanation endpoint run locally. Vercel and Neon deployment files are in the repo; no live URL is claimed until the deployment is verified. The clean-clone reproduction check remains open because raw GUIDE data is gitignored.

---

## Skills at a glance

Rows marked **planned** are not built yet. Week 1 to Week 5 rows, plus the Groq explanation layer, have runnable artifacts. Hosted deployment files are ready; no live URL is claimed.

| Skill | How TriageBudget uses it | Proof a reviewer can inspect |
|---|---|---|
| RAG | Retrieves similar train incidents and playbook sections before a decision; hybrid BM25 + dense + reciprocal rank fusion | `reports/w3_retrieval.md`, 19/20 smoke citations |
| Vector database | Exact numpy inner product over 384-d `bge-small-en-v1.5` vectors locally; pgvector is not used | Index manifest, leakage check, Recall@k |
| Data engineering | GUIDE ingestion, Parquet, DuckDB, split manifests, data-quality checks | `data/` pipeline, `tests/test_data.py` |
| Agents and tool calling | Bounded offline policy over seven typed tools with a hard six-call cap | `reports/w3_agent.md`, tool traces |
| Evaluation | Macro-F1, calibration, retrieval Recall@k and nDCG, selective risk, schema validity, tool budget | Week 1 to Week 5 reports |
| Prompt engineering | Versioned decision templates plus a live explanation prompt with JSON output and citation validation | `prompts/`, `src/triage/web/ai.py`, `tests/test_explain.py` |
| LLM integration | Groq `openai/gpt-oss-120b` explains an existing decision, cites retrieved evidence, and cannot change the verdict | `src/triage/web/ai.py`, `POST /api/incidents/{id}/explain` |
| FastAPI | Incident, decision, review, audit, health, metrics, and explain endpoints | `src/triage/web/app.py`, `/docs`, `tests/test_web.py` |
| Postgres | Incidents, reviews, audit events, and explanation cache; SQLite locally, Postgres through `DATABASE_URL` | `src/triage/web/db.py`, Docker Compose |
| SQL | DuckDB queries for features, metrics, and evaluation slices; parameterized SQLite/Postgres for the console | `src/triage/data.py`, `src/triage/web/db.py` |
| Structured outputs | Dataclass `TriageDecision`, JSON explanation schema, citation and uncertainty validation | `tests/test_agent.py`, `tests/test_explain.py` |
| Human-in-the-loop | Reviewer queue with approve, edit, reject, idempotency, and audit log; AI stays advisory | `public/`, `reports/w5_demo.md` |
| Classical ML | TF-IDF plus LightGBM with calibration | Model card, reliability diagram |
| PyTorch (**planned**) | MiniLM or cross-encoder fine-tune | Not built |
| Testing | pytest unit, data-integrity, and web API tests, including a mocked Groq transport | `tests/`, CI test run |
| Docker | Local app plus Postgres stack | `Dockerfile`, `docker-compose.yml` |
| CI/CD | Tests and fixture evaluation on every push | GitHub Actions workflow |
| Cloud deployment | Vercel plus Neon packaging is in the repo, with Render as fallback | `vercel.json`, `requirements.txt`, `docs/deployment.md`; no live URL yet |
| Git and GitHub | Public repo, small commits, issues, pull requests | Commit history and PRs |
| Observability | Structured JSON request logs, AI model/latency/token logs, prompt hashes | `reports/w3_traces.json`, web logs |
| Security | Redaction, injection defense, demo review token, no autonomous action | Validator tests, token tests |

---

## Problem

Security operations centers do not lack alerts. They lack analyst minutes.

- 73% of SOC teams cite false positives as a top detection-and-response challenge, up from 64% the previous year (SANS 2025).
- About half of alerts go uninvestigated (SANS 2026).
- The security workforce gap is roughly 4.8 million people (ISC2 / SANS).
- A worked example of 4,500 alerts per day needs about 94 full-time analysts at 10 minutes per alert (SANS 2026).

Most AI SOC products answer "can a model triage this alert?" The more useful question is: **at a fixed analyst budget, how many incidents can be closed safely, and what is the miss rate when we do?**

TriageBudget is built around that question.

---

## What it does

1. **Loads incidents.** Ingests Microsoft GUIDE incident records: alerts, evidence, entities, labels, and organization queue metadata.
2. **Classifies.** A calibrated TF-IDF + LightGBM baseline scores each incident for true positive, benign positive, and false positive.
3. **Routes by confidence.** The calibrated classifier scores each incident, and the Week 4 selective-risk router turns those scores into auto-close and auto-escalate decisions. At the 1% TP-miss constraint the best classifier operating point reaches 9.9% coverage at 0.2% TP miss, below the 60% target. The report states the shortfall rather than tuning on test.
4. **Investigates with RAG.** The bounded agent retrieves similar incidents and playbook sections, maps ATT&CK techniques, and proposes remediation. It has a hard six-call budget and logs every tool call.
5. **Produces a decision packet.** Every verdict includes a priority, proposed remediation, cited evidence, confidence, and a `needs_human` flag.
6. **Hands off to a queue.** A local review console lists the queue, shows evidence and remediation, accepts approve/edit/reject actions, and writes every action to an audit log. Week 3 still writes a trace for every decision.
7. **Explains on request.** An analyst can ask Groq to explain a queued decision. The model returns a short rationale, the evidence ids it used, an uncertainty level, and one suggested check. It cannot change the verdict, close or escalate the incident, or execute remediation.

The deterministic policy and tools produce the numbers and the decision in Weeks 3 and 4. That decision path does not call a language model. The explanation layer is a separate, optional request over a decision that already exists. Zero-shot and LLM-generated RAG for the decision itself are therefore reported as not measured, not as results.

---

## Why this is different

| Common SOC demo | TriageBudget |
|---|---|
| "Chat with your alerts" | A triage queue with structured decisions |
| Accuracy on a toy set | Selective-risk curve on external GUIDE labels |
| Agent runs on every alert | Agent runs only on routed low-confidence incidents |
| Model reports its own confidence | Calibration is measured against analyst labels |
| No cost model | Cost per 1,000 incidents and p95 latency are reported |
| No audit trail | Every decision has citations and an append-only log |
| One aggregate score | Per-class, per-organization, and per-budget slices |

The headline artifact is not a chatbot. It is a **selective-risk curve**: coverage (share of incidents handled without human review) against miss rate (share of true positives that were auto-closed incorrectly), with cost and latency attached.

---

## What you can inspect

Week 1 to Week 5 artifacts:

- `src/triage/`: GUIDE ETL, frozen split manifest, baselines, calibrated classifier, retrieval index, selective-risk router, bounded agent, local review console, and integrity checks.
- `tests/`: fixture-backed data, baseline, classifier, retrieval, agent, selective-risk, and web API tests.
- `reports/w1_baselines.md` and `reports/w1_metrics.json`: real GUIDE baseline report and machine-readable metrics.
- `reports/w2_classifier.md`, `reports/w2_metrics.json`, and `reports/w2_reliability.svg`: real GUIDE calibration report, metrics, and reliability diagram.
- `reports/w3_retrieval.md` and `reports/w3_retrieval_metrics.json`: hybrid retrieval metrics, index size, latency, and leakage check.
- `reports/w3_agent.md`, `reports/w3_agent_metrics.json`, and `reports/w3_traces.json`: 20 exception-case decisions, schema validity, tool calls, and per-case traces.
- `models/classifier_v1/`: trained model, vectorizer, calibrator, metadata, and model card.
- `indexes/w3_retrieval/`: local index, document store, and manifest. Gitignored because it holds GUIDE-derived text.
- `data/playbooks/`: nine synthetic playbooks with 63 sections, explicitly labelled synthetic.
- `data/cases/w3_cases.json`: 20 hand-picked dev cases and expected labels. Labels are used for evaluation only.
- `prompts/`: versioned system and decision templates. Week 3 does not call an external LLM.
- `data/manifests/split_v1.json`: frozen split manifest with source and split hashes.
- `reports/fixture_run/`: fixture-only smoke report. Not a GUIDE result.
- `.github/workflows/ci.yml`: lint, tests, and fixture smoke run.

- `reports/w4_selective_risk.md`: measured risk-coverage curve, operating point, slices, queue ranking, and error taxonomy.
- `reports/w4_retrieval.md`: BM25, dense, hybrid, and hybrid-plus-reranker ablations.
- `reports/w4_final_report.md`: first full report with measured results and limitations.
- `reports/final_eval.md`: consolidated Week 1-5 results, split details, confidence intervals, and limitations.
- `reports/w5_demo.md`: three local demo scenarios with expected actions.
- `docs/deployment.md`: local, Docker, Vercel, Neon, and Render deployment notes.
- `public/`: review console HTML, CSS, and JavaScript.
- `src/triage/web/ai.py`: Groq explanation client, prompt, citation validation, retry, and cache key.
- `tests/test_explain.py`: mocked Groq tests for caching, token gating, validation, and retry.
- `app.py`, `requirements.txt`, `vercel.json`, and `.vercelignore`: Vercel entrypoint and packaging.
- `results/run_20261113T100909Z/`: run config and metrics. Predictions and traces stay gitignored.

Week 1 to Week 5 GUIDE artifacts are measured on the frozen split. The review console and explanation endpoint run locally and in Docker. The Vercel/Neon files are ready, but no hosted URL is claimed until the user deploys and verifies it.

---

## Architecture: RAG, classifier, and agent

```mermaid
flowchart TD
    A[Microsoft GUIDE incidents] --> B[Incident store]
    B --> C[Calibrated classifier]
    C --> D{Confidence router}
    D -->|high confidence| E[Auto-close or auto-escalate]
    D -->|low confidence| F[Bounded agent]
    F --> G[Tool layer]
    G --> G1[get_incident]
    G --> G2[search_similar_incidents]
    G --> G3[lookup_asset]
    G --> G4[lookup_ioc]
    G --> G5[map_attack]
    G --> G6[retrieve_playbook]
    G --> G7[propose_action]
    G2 --> V[(Exact numpy index over bge-small vectors)]
    G6 --> V
    V --> P[(Incident and playbook chunks)]
    F --> H[TriageDecision]
    E --> H
    H --> I[Review queue]
    H --> J[Audit log]
    I --> K[Human approve, edit, or reject]
    K --> J
    I -. optional request .-> L[Groq explanation layer]
    L -. cites evidence .-> P
```

The agent is optional by design. If the classifier is confident, the system does not pay for an LLM call. If the agent is unavailable or over budget, the incident falls back to the human queue.

### RAG and retrieval

RAG is not a separate chatbot. It is the evidence layer the agent uses before it writes a decision.

- `search_similar_incidents` retrieves past train incidents with known labels.
- `retrieve_playbook` retrieves synthetic remediation and triage sections.
- The public GUIDE release has evidence ids but not raw evidence text. Week 3 cites the derived incident summary, the nearest train precedent, and the top playbook section. It cannot cite a raw log line.
- The agent uses the retrieved material in a deterministic policy, cites the evidence ids it used, and abstains when the calibrated score is weak.

Retrieval is hybrid: BM25 plus dense vectors fused with reciprocal rank fusion. A cross-encoder reranker was measured and made every retrieval metric worse while running about 24 times slower, so it is not used. The evaluation compares BM25-only, dense-only, hybrid, and hybrid-plus-reranker retrieval.

### Vector database

Embeddings are generated locally with `bge-small-en-v1.5` (384 dimensions). Retrieval uses an exact numpy inner-product index over 14,727 documents. The Week 5 review console stores decisions, reviews, and audit events in SQLite locally or Postgres when `DATABASE_URL` is set. A hosted vector index is not used.

The index stores deduplicated incident summaries and playbook sections. It does not store raw evidence text. The test split is never added to the index; the build fails if an indexed train incident id appears in test. A retrieval run reports Recall@5, Recall@10, nDCG@10, mean reciprocal rank, index size, and latency.

### AI explanation layer

`POST /api/incidents/{id}/explain` asks Groq `openai/gpt-oss-120b` to explain a decision that the classifier and agent already made. The fallback is `openai/gpt-oss-20b`. The endpoint requires the review token, so a public deployment cannot be used as an open model proxy.

The model receives the incident summary, verdict, priority, confidence, class probabilities, retrieved evidence ids with short quotes, and remediation targets. It does not receive raw GUIDE logs, reviewer identity, or review notes. It must return JSON with four fields: `explanation`, `evidence_ids`, `uncertainty`, and `next_step`.

Every cited id is checked against the evidence that was actually retrieved. Unknown ids reject the whole response with 502, and the result is not stored. The output is cached by incident, model, prompt version, and a hash of the source fields, so reopening a case does not pay for another call. Model, prompt version, token counts, and latency are stored and logged with the explanation.

The layer is advisory. It cannot approve, edit, close, or escalate an incident, and it cannot call a remediation tool. Analyst action still goes through the review endpoint and the audit log. The project has not measured explanation correctness or citation support with human raters; the tests cover schema, citation validation, caching, token gating, and retry behavior only.

See [docs/architecture.md](docs/architecture.md) for components, data contracts, and failure handling.

---

## Evaluation

Week 1 to Week 3 metrics are measured. Cost, selective risk, citation support, and remediation quality are planned.

Week 3 retrieval, hybrid BM25 + dense + RRF, 100 dev proxy queries:

| Metric | Incident retrieval | Playbook retrieval |
|---|---:|---:|
| Recall@5 | 0.4267 | 0.4217 |
| Recall@10 | 0.6733 | 0.6750 |
| nDCG@10 | 0.5013 | n/a |
| MRR | 0.5747 | n/a |
| median latency | 41.3 ms | 41.3 ms |

The gold sets are structured-overlap proxies, not human relevance labels. Smoke citations are 19/20. The index has 0 test incident overlap. Agent results: 20/20 schema-valid, 0 hard-constraint violations, 5.00 mean tool calls, 7/7 true positives with a retrieval citation, and 3/3 missed true positives flagged for human review.

| Metric | What it measures | Baseline |
|---|---|---|
| Macro-F1 | Three-class triage quality | Majority class, rules, TF-IDF + LightGBM |
| Per-class precision / recall | True positive, benign positive, false positive | Same |
| Queue ranking proxy P@5 / P@10 / P@20 | True-positive ranking within organization queues | Signal-only score |
| Remediation macro-F1 | Recommended action quality | Majority action |
| Retrieval Recall@5 / Recall@10 | Did the right evidence or playbook appear in the top results? | BM25-only, dense-only, hybrid |
| nDCG@10 | Ranking quality of retrieved evidence | BM25-only, dense-only, hybrid |
| Selective risk at 10-minute budget | Coverage vs miss rate | Zero-shot LLM, RAG-only, full agent |
| Citation accuracy | Does the cited evidence support the decision? | Human spot check |
| Cost per 1,000 incidents | Token and compute cost | Full-agent baseline |
| p95 latency | Warm and cold start | Same |

Target claim, to be tested: at a 10-minute analyst review budget, auto-close at least 60% of incidents while missing no more than 1% of true positives. If the data does not support that claim, the report will say so.

See [docs/evaluation.md](docs/evaluation.md) for metric definitions, splits, ablations, and the falsification plan.

---

## Data

| Item | Value |
|---|---|
| Dataset | Microsoft GUIDE |
| Incidents | 1,000,000 |
| Evidence items | 13,000,000 |
| Alerts | 1,600,000 |
| Triage labels | True positive, benign positive, false positive |
| Remediation labels | 26,000 |
| Queue-ranked test incidents (public CSV) | 9,980 across 499 organization queues |
| License | CDLA-Permissive-2.0 |
| Size | About 3.5 GB |
| Source | [Kaggle](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction) |
| Paper | [arXiv:2407.09017](https://arxiv.org/abs/2407.09017) |

The dataset has an official incident-level train/test split. TriageBudget will use it where available. If the Kaggle test labels are hidden, the project will use a frozen local held-out split and label it as such. It will not claim official test numbers.

See [docs/data.md](docs/data.md) for schema, sampling, quality checks, and PII handling.

---

## Commands

Week 1 to Week 3 commands:

```bash
uv sync --all-groups
uv run pytest
uv run ruff check .
uv run python -m triage.cli fixture-eval --work-dir reports/fixture_run
```

The fixture run writes a report and metrics under `reports/fixture_run/`. It is a smoke test, not a GUIDE benchmark.

Real GUIDE run, after placing `GUIDE_Train.csv` and `GUIDE_Test.csv` in `data/raw/`:

```bash
uv run python -m triage.cli etl --raw-dir data/raw --out data/processed/incidents.parquet --stats data/processed/etl_stats.json
uv run python -m triage.cli split --incidents data/processed/incidents.parquet --out-dir data/processed --manifest data/manifests/split_v1.json --sample-size 100000
uv run python -m triage.cli baselines --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --manifest data/manifests/split_v1.json --report reports/w1_baselines.md --metrics reports/w1_metrics.json --dataset guide
uv run python -m triage.cli classify --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --manifest data/manifests/split_v1.json --report reports/w2_classifier.md --metrics reports/w2_metrics.json --model-dir models/classifier_v1 --dataset guide
uv run python -m triage.cli check --incidents data/processed/incidents.parquet --manifest data/manifests/split_v1.json
uv run python -m triage.retrieval build --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --playbooks data/playbooks --out indexes/w3_retrieval --report reports/w3_retrieval.md --metrics reports/w3_retrieval_metrics.json --dataset guide
uv run python -m triage.agent --case case_01
uv run python -m triage.agent
uv run python -m triage.cli week4
uv run python -m triage.web seed --if-empty
uv run python -m triage.web serve
```

The Week 4 command scores the full test split, evaluates a 600-case stratified subset, builds the selective-risk curves, runs the retrieval ablations, computes queue-ranking metrics, and writes the reports under `reports/` plus run artifacts under `results/`.

The `Makefile` mirrors these commands for Unix and CI. `make` is not installed on the current Windows machine, so the CLI commands above are canonical. The first retrieval build downloads `bge-small-en-v1.5` and embeds the train corpus; later runs reuse the local index.

Every evaluation writes machine-readable results and a human-readable report. A clean clone with a Kaggle token should reproduce the same numbers.

---

## Repository layout

```text
src/triage/
  config.py      constants and column contracts
  data.py        GUIDE ETL, manifest, integrity checks
  baselines.py   majority, rules, TF-IDF + LightGBM, metrics
  classifier.py  tuned calibrated classifier, reliability, queue ranking
  retrieval.py   incident/playbook corpus, BM25, dense index, hybrid search
  agent.py       typed tools, TriageDecision, bounded offline policy, traces
  fixture.py     synthetic GUIDE-shaped CSVs
  pipeline.py    end-to-end fixture run
  cli.py         command line entry point
  selective.py   confidence router, selective-risk curve, Week 4 evaluation
  web/           FastAPI review API, SQLite/Postgres storage, Groq explanation layer, demo seed
public/          review console HTML, CSS, and JavaScript
tests/           data, classifier, retrieval, agent, selective-risk, web, and explanation tests
docs/            architecture, data, evaluation, roadmap, deployment
reports/         generated reports, metrics, and traces
results/         Week 4 run configs and metrics (predictions/traces gitignored)
prompts/         versioned agent prompt templates
data/playbooks/  nine synthetic playbooks, 63 sections
data/cases/      20 hand-picked Week 3 exception cases
indexes/         local retrieval index (gitignored)
app.py           Vercel ASGI entrypoint
requirements.txt web-only dependencies for Vercel
vercel.json      function duration and security headers
```

---

## Six-week plan

| Week | Focus | Artifact |
|---|---|---|
| 0 | Load 10k incidents, profile labels, LightGBM baseline | First macro-F1 table |
| 1 | Full data pipeline, split manifest, majority and rules baselines | Reproducible baseline report |
| 2 | Calibrated classifier, per-class metrics, optional MiniLM or cross-encoder fine-tune | Calibration and per-class table |
| 3 | RAG index, hybrid retrieval, agent tools, structured output, trace logging | Agent demo on 20 incidents |
| 4 | Confidence router, selective-risk curve, retrieval ablations, error taxonomy | Headline curve and ablation table |
| 5 | FastAPI, queue UI, audit log, Docker, SQLite/Postgres, CI | Local review console and demo script |
| 6 | Frozen test, bootstrap intervals, per-organization slices, README, demo video | Final report and demo |

Cut list, in order: 1M to 100k incidents, 499 to 50 queues, agent subset 2,000 to 500, skip the fine-tune, React to Streamlit. The Vercel and Neon packaging is in the repo; the hosted URL is not claimed until the user supplies credentials and verifies the deployment. Docker Compose plus a recorded demo remains the fallback. The external labels, selective-risk curve, citations, and audit log stay.

See [docs/roadmap.md](docs/roadmap.md) for gates and the risk register.

---

## Skills in depth

- RAG over incident evidence, playbooks, and similar past incidents, with hybrid retrieval and citations.
- Vector search with exact numpy search over `bge-small-en-v1.5`, evaluated with Recall@5, Recall@10, and nDCG@10.
- Data engineering with GUIDE ingestion, Parquet, DuckDB, split manifests, and data-quality tests.
- Bounded agent tool use with a hard call budget and full tool traces.
- External evaluation with real analyst labels, calibration, and selective prediction.
- Prompt engineering with versioned templates, prompt-injection defense, and schema-constrained output.
- Classical ML baseline with TF-IDF, LightGBM, and probability calibration.
- Optional PyTorch fine-tune for a MiniLM or cross-encoder reranker.
- FastAPI and Postgres for the API, decisions, reviews, audit events, and a cached explanation layer.
- SQL with DuckDB and Postgres for features, evaluation slices, and audit queries.
- Structured outputs with Pydantic schemas, JSON validation, citation checks, repair, and abstention.
- Testing with pytest unit tests, data-integrity checks, API integration tests, and a mocked Groq transport.
- Human-in-the-loop review with approve, edit, reject, an append-only audit log, and advisory-only AI explanations.
- Docker for a reproducible local stack.
- Vercel plus Neon deployment packaging, with Render as a fallback. No live URL is claimed until deployed.
- CI with tests, data checks, and an evaluation regression gate.
- Git and GitHub with a public repo, small commits, and pull requests.
- Observability with structured JSON request logs, model/token/latency logs for explanations, and tool latency. Langfuse is not used.
- Security-minded design: redaction, no autonomous action, citations, audit log, server-side API keys, and PII handling.

---

## Limitations

- This is a research prototype, not a production SOC tool.
- GUIDE comes from Microsoft customer environments. Performance may not transfer to other telemetry.
- The classifier runs on the full test set. The Week 4 agent runs on a fixed stratified 600-case test subset (200 per class). The agent is deterministic and offline, so this limit is compute, not rate limits.
- Human approval is required for closures and escalations. The system does not take autonomous action.
- The explanation layer has no human-rated correctness or citation-support evaluation yet. Citation validation proves an evidence id was retrieved; it does not prove the sentence is supported by that evidence.
- Live explanations require `GROQ_API_KEY`; without it the endpoint returns 503 and the console disables the AI panel. The key is server-side and never sent to the browser.
- Each explanation costs tokens and adds latency. Results are cached per incident and model, but there is no per-user budget or rate limit beyond the review token.
- Vercel has not been deployed or verified yet. SQLite does not persist there; Neon Postgres through `DATABASE_URL` is required.
- This project is not affiliated with Microsoft.
- Benchmark numbers come from one frozen GUIDE split. They are not production estimates.
- Organization identity and organization frequency are excluded from the headline classifier because queue-specific labeling styles leak into the score. The org-frequency ablation is reported, not used.
- The public GUIDE release includes queue ranks for 9,980 test incidents but no severity column. On that subset, the model beats the analyst queue on P@5 (0.3226 vs 0.2269), P@10 (0.2802 vs 0.2216), and nDCG@10 (0.6877 vs 0.5192); P@20 ties at 0.2219. These are true-positive proxies, not analyst-judged relevance.
- Calibration improves macro-F1 but lowers true-positive recall from 0.684 to 0.516. The Week 4 router uses calibrated `p_true_positive`; its best safe operating point reaches 9.9% coverage at a 0.2% true-positive miss rate, below the 60% coverage target. The report states the shortfall instead of tuning on test.
- Hyperparameter tuning and calibrator selection both use the same dev rows. The test split is untouched, but the calibrator choice is optimistic; nested cross-validation or a separate calibration split is future work.
- Week 3 retrieval gold sets are structured-overlap proxies. They are not human relevance labels, so the retrieval numbers measure a reproducible proxy, not analyst-judged quality.
- Playbooks are synthetic and do not represent an organization's real policy. Raw GUIDE evidence text is unavailable, so citations use derived summaries and ids, not log lines.
- The Week 3 agent is an offline deterministic policy, not an LLM. Prompt templates exist but were not executed. Exact label agreement on the 20 hand-picked cases is 0.75; that number is descriptive, not a benchmark.
- The Week 3 agent missed 3 of 7 true-positive cases and flagged all three for human review. It auto-closed none of the 20 exception cases. One miss, `36:1064`, is a 0.937 false-positive prediction with no malicious verdict; suspicious signals and a true-positive precedent kept it out of auto-close. In Week 4 the classifier router reaches 9.9% coverage at a 0.2% TP miss rate on the full test set; on the 600-case subset the full agent reaches 15.0% coverage with a 0.0% miss rate versus 12.0% and 1.0% for the classifier alone.
- The cross-encoder reranker is measured in Week 4 and does not help. Hybrid plus `ms-marco-MiniLM-L-6-v2` reranking drops incident Recall@5 from 0.4267 to 0.3167 and Recall@10 from 0.6733 to 0.5067, while median query latency rises from 35.0 ms to 832.9 ms. The local index is exact numpy search, not pgvector.
- Alert IDs overlap between raw train and test: 15,301 test incidents (5.0%) share at least one alert with the frozen train sample. Incident-level disjointness holds; an alert-disjoint sensitivity run is still pending.

---

## Documentation

- [Architecture](docs/architecture.md)
- [Evaluation](docs/evaluation.md)
- [Data](docs/data.md)
- [Roadmap](docs/roadmap.md)
- [B2B data feasibility research](b2b-ai-data-feasibility.md)

---

## License

Code: MIT. Data: Microsoft GUIDE under CDLA-Permissive-2.0. See the dataset card before redistributing.
