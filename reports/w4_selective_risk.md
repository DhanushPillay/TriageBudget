# Week 4 selective risk and router evaluation

- Dataset: GUIDE test split (303,220 incidents)
- Generated: 2026-11-13T10:15:48.383782+00:00
- Model: `tfidf_lgbm_calibrated_v1`
- Run artifacts: `results/run_20261113T100909Z`
- The test split was not used for tuning. Thresholds are reported, not selected.

## Definitions

- Coverage: incidents handled without human review. The classifier router covers predicted true positives and false positives above the confidence threshold; benign predictions always go to a human.
- TP miss rate: true positives that are covered and predicted as anything other than true positive, divided by all true positives.
- Selective risk: errors among covered incidents divided by covered incidents.
- The 10-minute budget is an assumption: each reviewed incident costs 10 analyst minutes. No total analyst capacity was specified.

## Risk-coverage curve

| threshold | coverage | selective risk | TP miss rate | reviewed / 100 |
|---:|---:|---:|---:|---:|
| 0.50 | 35.3% | 14.9% | 7.1% | 647 min |
| 0.55 | 32.7% | 12.4% | 6.3% | 673 min |
| 0.60 | 30.5% | 10.4% | 5.6% | 695 min |
| 0.65 | 28.6% | 8.7% | 4.9% | 714 min |
| 0.70 | 26.8% | 7.2% | 4.4% | 732 min |
| 0.75 | 25.2% | 6.0% | 3.6% | 748 min |
| 0.80 | 23.4% | 5.0% | 2.9% | 766 min |
| 0.85 | 21.9% | 4.3% | 2.4% | 781 min |
| 0.90 | 20.0% | 3.8% | 1.9% | 800 min |
| 0.95 | 9.9% | 1.0% | 0.2% | 901 min |
| 1.00 | 0.0% | n/a | 0.0% | 1000 min |

## Operating point

- Selected threshold: `0.95`
- Coverage: **9.9%**
- TP miss rate: **0.2%**
- Selective risk: 1.0%
- Target: coverage >= 60.0%, TP miss <= 1.0%
- Meets target: **False**
- Coverage shortfall: 50.1%
- Miss shortfall: 0.0%

### Budget sensitivity

| minutes per review | review minutes / 100 incidents | review hours on test set |
|---:|---:|---:|
| 5 | 451 | 22,768 |
| 10 | 901 | 45,537 |
| 20 | 1802 | 91,074 |

The table is a cost model, not a measured analyst workload. At the selected threshold the review load is reported per 100 incidents, so a reader can apply their own capacity.

## Baselines

| policy | incidents | coverage | selective risk | TP miss | status |
|---|---:|---:|---:|---:|---|
| classifier_only | 303,220 | 9.9% | 1.0% | 0.2% | measured |
| rag_only_proxy | 600 | 21.7% | 30.0% | 0.5% | deterministic retrieval vote proxy |
| full_system | 600 | 15.0% | 2.2% | 0.0% | measured |
| zero_shot | 0 | n/a | n/a | n/a | not measured: no hosted LLM backend in this run |

`rag_only_proxy` is a deterministic vote over retrieved train labels. It is not an LLM and is not a RAG generation baseline. `zero_shot` is not measured because no hosted LLM backend is configured.

## Full system versus classifier-only

- Classifier-only subset coverage: 12.0%
- Full-system subset coverage: 15.0%
- Classifier-only subset TP miss: 1.0%
- Full-system subset TP miss: 0.0%
- Agent improves the curve: **True**

## Slices

### Per class

| class | incidents | coverage | selective risk | TP miss |
|---|---:|---:|---:|---:|
| benign_positive | 148,215 | 0.1% | 100.0% | 0.0% |
| false_positive | 92,465 | 19.4% | 0.1% | 0.0% |
| true_positive | 62,540 | 19.1% | 1.1% | 0.2% |

### Per org (first 50 orgs by id)

| org | incidents | coverage | selective risk | TP miss |
|---|---:|---:|---:|---:|
| 0 | 651 | 13.4% | 4.6% | 0.6% |
| 1 | 130 | 20.0% | 0.0% | 0.0% |
| 10 | 206 | 9.2% | 0.0% | 0.0% |
| 100 | 134 | 0.0% | n/a | 0.0% |
| 1000 | 41 | 0.0% | n/a | 0.0% |
| 1001 | 91 | 0.0% | n/a | 0.0% |
| 1002 | 19 | 0.0% | n/a | 0.0% |
| 1003 | 35 | 0.0% | n/a | 0.0% |
| 1004 | 41 | 0.0% | n/a | 0.0% |
| 1005 | 20 | 0.0% | n/a | 0.0% |
| 1007 | 17 | 0.0% | n/a | 0.0% |
| 1008 | 17 | 0.0% | n/a | 0.0% |
| 1009 | 36 | 0.0% | n/a | 0.0% |
| 101 | 21 | 4.8% | 0.0% | 0.0% |
| 1010 | 27 | 0.0% | n/a | 0.0% |
| 1011 | 20 | 5.0% | 0.0% | 0.0% |
| 1012 | 11 | 0.0% | n/a | 0.0% |
| 1013 | 15 | 0.0% | n/a | 0.0% |
| 1014 | 17 | 0.0% | n/a | 0.0% |
| 1015 | 32 | 0.0% | n/a | 0.0% |

Only the first 20 rows are shown; all 50 persisted rows are in the metrics JSON. Small orgs have wide uncertainty.

## Queue ranking

- Joined queue rows: 9,980 across 499 orgs

| metric | model | analyst QueueRank |
|---|---:|---:|
| P@5 | 0.3226 | 0.2269 |
| P@10 | 0.2802 | 0.2216 |
| P@20 | 0.2219 | 0.2219 |
| nDCG@10 | 0.6877 | 0.5192 |

## Error taxonomy

- Errors: 182
- Labeled: 100 (limit 100)
- Note: System-assigned heuristic labels; not human review.

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

### Examples

**abstention_error**
- `w4:19:33744` expected true_positive, predicted undetermined, route human, confidence 0.36
- `w4:200:142924` expected false_positive, predicted undetermined, route human, confidence 0.38
- `w4:2279:67921` expected false_positive, predicted undetermined, route human, confidence 0.40

**label_ambiguity**
- `w4:106:110192` expected false_positive, predicted benign_positive, route agent, confidence 0.71
- `w4:1092:39163` expected false_positive, predicted benign_positive, route human, confidence 0.42
- `w4:1375:92412` expected false_positive, predicted benign_positive, route agent, confidence 0.73

**overconfidence**
- `w4:0:342657` expected true_positive, predicted false_positive, route agent, confidence 0.91
- `w4:1144:58492` expected false_positive, predicted true_positive, route auto_escalate, confidence 0.81
- `w4:114:26258` expected false_positive, predicted benign_positive, route agent, confidence 0.86

**reasoning_error**
- `w4:1031:176294` expected true_positive, predicted benign_positive, route agent, confidence 0.72
- `w4:1039:13753` expected benign_positive, predicted true_positive, route human, confidence 0.49
- `w4:107:89875` expected true_positive, predicted benign_positive, route agent, confidence 0.73

## Limitations

- The 10-minute budget is a stated assumption, not a time study.
- Coverage treats auto-escalation as handled without review, which matches the Week 2/3 route definition but may understate analyst effort.
- The subset is a fixed stratified test sample, not a random sample of all orgs. Org slices with few incidents are noisy.
- The RAG baseline is a retrieval vote proxy, not an LLM.
- Error categories are system-assigned heuristics, not human labels.
- No production SOC readiness is claimed.
