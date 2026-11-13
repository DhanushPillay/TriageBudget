# Roadmap

Six weeks at 20 to 25 focused hours per week. The plan is ordered so that the evaluation harness exists before the agent, and the agent exists before the UI.

**Rule: do not build the agent until the classifier baseline and the data pipeline are trustworthy.** A weak foundation makes every later number meaningless.

---

## Week 0: data spike

**Goal:** prove the dataset is usable before committing to the design.

Tasks:

1. Create the repo, `pyproject.toml`, `Makefile`, and a Python 3.11 environment.
2. Configure Kaggle access and download GUIDE.
3. Inspect the file layout and schema. Write `docs/label_audit.md` with counts.
4. Load 10,000 incidents into DuckDB.
5. Build a minimal TF-IDF + LightGBM baseline on the 10k sample.
6. Write the first macro-F1 and per-class table.
7. Confirm the official split and the label mapping.

Artifact:

- `reports/w0_spike.md` with schema notes, label counts, and the first baseline table.
- `make spike` reproduces it.

Gate:

- [ ] Kaggle download works.
- [ ] Incident, alert, evidence, and label tables are identified.
- [ ] Triage label distribution is known.
- [ ] A baseline trains and scores in under 30 minutes.
- [ ] The official split is incident-level.

If the gate fails, stop. Do not start Week 1 until the data is understood.

**Hours:** 20.

---

## Week 1: pipeline and baselines

**Goal:** a reproducible pipeline and honest baselines.

**Status:** pipeline implemented and verified on GUIDE. Real baselines are complete: TF-IDF + LightGBM reaches macro-F1 0.706 on the official test split, versus 0.219 for majority and 0.191 for rules. The clean-clone reproduction check remains open because raw GUIDE files are not committed.

Tasks:

1. Write the ETL from raw GUIDE files to normalized Parquet.
2. Create the split manifest and hash it.
3. Implement majority-class and rules baselines.
4. Implement the TF-IDF + LightGBM baseline on the 100k sample.
5. Add data-integrity tests.
6. Write `docs/data.md` updates with the verified schema.

Artifact:

- `reports/w1_baselines.md` with majority, rules, and LightGBM results.
- `make eval` runs the baselines from a clean checkout.
- `data/manifests/split_v1.json` committed.

Gate:

- [x] Data tests pass.
- [x] Split manifest is frozen.
- [x] LightGBM beats majority and rules on macro-F1.
- [ ] A clean clone reproduces the baseline table. Raw GUIDE files are not committed, so this check is documented as pending in the README.

**Hours:** 24.

---

## Week 2: calibrated classifier

**Goal:** a classifier good enough to route incidents.

Tasks:

1. Add features: alert counts, evidence types, entity counts, time, and organization frequency. The public CSV has no severity column; none is invented. A queue-rank file is present and is used in Week 4. Organization identity and org frequency are excluded from the headline model because a queue-specific labeling style can leak into the score; the org-frequency gain is reported as an ablation. Per-org slices are reported.
2. Tune LightGBM with a small grid on the dev split.
3. Calibrate with temperature scaling, vector scaling, or isotonic regression. The method is selected by two-fold cross-validation on dev, then refit on all of dev.
4. Report expected calibration error and a reliability diagram.
5. Add per-class precision and recall.
6. Optional: MiniLM embeddings and a fine-tune, only if the baseline is stable.
7. Ranking: the public release includes `GUIDE_Test_Queue_Rankings.csv` with 9,980 queue ranks. Week 4 evaluates analyst P@5/10/20 against that file. Week 2 reports a queue-level true-positive proxy (precision@5/10/20 and true-positive capture@10%) against a signal-only baseline.

Artifact:

- `reports/w2_classifier.md` with the reliability diagram, macro-F1, per-class metrics, calibration results, and the queue ranking proxy.
- `reports/w2_reliability.svg` and `reports/w2_metrics.json`.
- `models/classifier_v1/` with the model, calibrator, metadata, and model card.

Gate:

- [x] Calibration error is reported, not assumed.
- [x] Per-class recall is above the majority-class prevalence floor (0.489 on the frozen test split) for all three classes.
- [x] The queue ranking proxy beats the signal-only baseline at precision@10.
- [x] The model card states training data, features, and limitations.
- [x] Analyst priority P@5/10/20 is deferred to Week 4; the queue-rank file is present, but Week 2 reports the proxy.

If calibration is poor, fix it before building the router. A router on uncalibrated scores is a random threshold.

**Hours:** 25.

---

## Week 3: RAG index and agent

**Goal:** a bounded agent that retrieves evidence and produces valid decisions on ambiguous incidents.

Tasks:

1. Build the RAG corpus: incident chunks from the train split and playbook sections.
2. Build the `bge-small-en-v1.5` index with FAISS locally or pgvector in Postgres. Confirm the test split is excluded.
3. Implement hybrid BM25 plus dense retrieval with reciprocal rank fusion.
4. Add an optional cross-encoder reranker for the top 20 candidates.
5. Implement `search_similar_incidents` with citations.
6. Implement `retrieve_playbook` with citations.
7. Implement the remaining tools with typed inputs and outputs.
8. Define the `TriageDecision` schema and validator.
9. Build the bounded agent loop with a six-call cap and trace logging.
10. Create 20 hand-picked exception cases for a smoke test.
11. Add prompt templates as files.

Artifact:

- `reports/w3_retrieval.md` with Recall@5, Recall@10, nDCG@10, and index size.
- `reports/w3_agent.md` with 20 traces, schema validity, and tool-call counts.
- `python -m triage.agent --case case_01` runs one case.

Gate:

- [x] The 20-query retrieval smoke test returns relevant citations. Measured 20/20.
- [x] The index contains no test incident ids. Measured 0 overlap.
- [x] 18 of 20 decisions are schema-valid. Measured 20/20.
- [x] Zero hard-constraint violations. Measured 0.
- [x] Mean tool calls are below 8. Measured 5.00.
- [x] Every true-positive decision has at least one evidence citation. Measured 7/7.

Implementation notes: the local index is an exact numpy inner-product index, not FAISS or pgvector. The optional cross-encoder reranker was skipped. The agent is a deterministic offline policy over the typed tools; prompt templates exist but no LLM is called. Gate evidence is in `reports/w3_retrieval.md` and `reports/w3_agent.md`.

If retrieval is weak, fix chunking and hybrid search before tuning the agent. If schema validity is below 80%, replace the free-form agent with a deterministic decision tree plus LLM explanation for the demo. Keep the schema, tools, and trace.

**Hours:** 25.

---

## Week 4: router, selective risk, ablations

**Goal:** the headline evaluation.

Tasks:

1. Implement the confidence router.
2. Sweep thresholds and build the risk-coverage curve.
3. Run the classifier-only, RAG-only, zero-shot, and full-system baselines on the agent subset.
4. Run the retrieval ablations: BM25-only, dense-only, hybrid, and hybrid plus reranker.
5. Run the remaining ablations in `docs/evaluation.md`.
6. Build the error taxonomy and label 100 errors.
7. Add bootstrap confidence intervals.
8. Write the first version of the final report.

Artifact:

- `reports/w4_selective_risk.md` with the curve and the ablation table.
- `reports/w4_retrieval.md` with the retrieval ablation table.
- `results/` with predictions, metrics, and the run config.

Gate:

- [ ] The curve has at least five operating points.
- [ ] The 10-minute budget point is marked.
- [ ] The full system is compared to the classifier-only baseline.
- [ ] Retrieval results are reported for all four baselines.
- [ ] Per-class and per-org slices are reported.
- [ ] If the agent does not improve the curve, the report says so.

Do not tune on test. If the curve is flat, report it. A flat curve is a finding.

**Hours:** 25.

---

## Week 5: API, UI, deployment

**Goal:** a live demo a reviewer can use.

Tasks:

1. Build FastAPI endpoints: `/incidents`, `/incidents/{id}`, `/decisions`, `/approve`, `/audit`.
2. Build the queue UI: sorted list, decision detail, evidence panel, approve/edit/reject.
3. Add the audit log and the review flow.
4. Add Docker Compose for local use.
5. Deploy to Neon and Render. Add a static frontend or Streamlit demo.
6. Add structured logs, cost tracking, and a health check.
7. Add GitHub Actions: tests, data checks, smoke evaluation.

Artifact:

- Live URL.
- OpenAPI docs.
- Three-minute demo video.
- `docker compose up` works locally.

Gate:

- [ ] Three demo scenarios run end to end in under 30 seconds each.
- [ ] The deployed URL works in a clean browser.
- [ ] No secrets in the repo.
- [ ] The audit log records every reviewer action.
- [ ] CI passes.

If deployment blocks progress, ship Docker Compose plus the recorded demo. Do not spend Week 6 on infrastructure.

**Hours:** 25.

---

## Week 6: final evaluation and packaging

**Goal:** a defensible report and a portfolio-ready package.

Tasks:

1. Run the frozen test set once.
2. Run the agent on the fixed subset.
3. Bootstrap confidence intervals.
4. Produce per-organization and per-severity slices.
5. Finalize the error taxonomy with examples.
6. Write the README with the final numbers and limitations.
7. Record the demo video.
8. Write a short blog post or technical report.
9. Verify `make reproduce` on a clean clone.

Artifact:

- `reports/final_eval.md`.
- README with the results table.
- Demo video.
- Blog post or technical report.

Gate:

- [ ] A clean clone reproduces the headline table.
- [ ] Every number has a split and sample size.
- [ ] Limitations are written before the results are celebrated.
- [ ] The demo works without manual patching.
- [ ] Negative results are included.

**Hours:** 20.

---

## Cut list

Cut in this order. Keep the evaluation harness and the audit trail.

| Trigger | Cut | Keep |
|---|---|---|
| Week 0 data is slow | 1M to 100k incidents | Split manifest, label audit, baseline table |
| Week 1 pipeline slips | 100k to 25k incidents | Data tests, frozen split |
| Week 2 calibration is unstable | MiniLM fine-tune | LightGBM, calibration report |
| Week 3 agent is unreliable | Free-form agent to deterministic tree plus LLM explanation | Schema, validator, tool trace |
| Week 3 retrieval is weak | Hybrid plus reranker to BM25 plus structured playbook ids | Citations, retrieval report |
| Week 4 curve is flat | Full ablations to three | Headline curve, per-class metrics |
| Week 5 deploy slips | React to Streamlit; live URL to Docker Compose plus video | API, approval flow, audit log |
| Week 6 time is short | Per-org slices to top 10 queues | Frozen test, confidence intervals, README |

Minimum shippable version:

- 25k incidents, one classifier, one router, one bounded agent on 200 incidents.
- FastAPI and Streamlit.
- Docker Compose or a live URL.
- Macro-F1, selective-risk curve, retrieval Recall@10 and nDCG@10, citation check, cost table.
- README and a three-minute video.

This is smaller, not weaker. It still demonstrates the skills.

---

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| GUIDE schema is harder than expected | Medium | High | Week 0 gate, 10k spike before committing |
| Test labels are hidden | Medium | Medium | Frozen local split, label it clearly |
| Class imbalance makes macro-F1 unstable | High | Medium | Per-class recall, bootstrap intervals |
| Calibration is poor | Medium | High | Fix before router, try isotonic and temperature |
| Retrieval quality is weak | Medium | High | Hybrid retrieval, labelled 100-query set, reranker, fix chunking |
| Agent output is invalid JSON | Medium | High | Schema validation, repair attempt, human fallback |
| Free LLM quota is too small | High | Medium | Cache, 500-incident subset, local Ollama fallback |
| Render cold start ruins the demo | High | Low | Precompute demo decisions, record a video |
| Neon storage limit | Low | Medium | Store only the demo slice and decisions |
| Prompt injection through evidence | Medium | High | Delimit untrusted text, no network tools, schema validation |
| Per-org slices are too small | Medium | Medium | Top 10 queues only, report sample sizes |
| Scope creep into a full SOC platform | High | High | Non-goals list, cut list, one-week gates |
| Results do not support the target claim | Medium | High | Report the negative result, keep the harness |

---

## Definition of done

The project is done when all of these are true:

- [ ] A clean clone can install, download the data, and run the evaluation.
- [ ] The split manifest is committed and hashed.
- [ ] The classifier has macro-F1, per-class P/R, and calibration reported.
- [ ] Retrieval has Recall@5, Recall@10, nDCG@10, and MRR for BM25, dense, and hybrid.
- [ ] The selective-risk curve is published with the 10-minute operating point.
- [ ] The agent has a schema-valid decision for at least 90% of its subset.
- [ ] Citation accuracy is measured on at least 50 decisions.
- [ ] The API and UI work end to end for three scenarios.
- [ ] The audit log records every reviewer action.
- [ ] The README states the results, the limitations, and the negative findings.
- [ ] The demo video is under four minutes.
- [ ] No secrets or raw tenant data are committed.

If a box cannot be checked, the README says why. An honest gap is better than a fake result.
