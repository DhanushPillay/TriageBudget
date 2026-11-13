# Week 2 calibrated classifier

**Status: GUIDE run on the frozen manifest. Calibration is measured on the test split, not assumed. The test split was not used to fit the calibrator or select hyperparameters.**

## Data

| Item | Value |
|---|---|
| Dataset | guide |
| Test source | official |
| Train incidents | 89999 |
| Dev incidents | 10001 |
| Test incidents | 303220 |
| Seed | 42 |
| Model version | `tfidf_lgbm_calibrated_v1` |
| Manifest validates | True |
| Data checks pass | True (with warnings) |

The model is fit on train. Hyperparameters and the calibrator are selected on dev. The test split is used only for final metrics.

Warnings:

- 23670 train incidents without a triage label were excluded.
- labels present: 23670 incidents without a triage label

## Features

- Text: summary field from GUIDE categorical and alert-title tokens (5000 TF-IDF features).
- Numeric: alert_count, evidence_count, detector_count, entity_type_count, alert_title_count, category_count, evidence_role_count, has_mitre, suspicious_count, verdict_count, malicious_count, sha256_count, ip_count, url_count, account_count, device_count, registry_count, file_count, email_count, event_hour, event_day_of_week, summary_length, summary_tokens, event_month, is_weekend, alerts_per_detector, evidence_per_alert, entities_per_alert, threat_family_count, has_suspicion, has_verdict.
- Excluded: severity (not in the public CSV), organization identity (queue-policy leakage risk), and priority rank (not in the public CSV).

### Organization frequency ablation

Organization frequency is excluded from the headline model. It acts as an organization identifier, so it can learn queue-specific labeling style rather than incident content.

| Config | Dev macro-F1 |
|---|---:|
| Without org frequency | 0.698 |
| With org frequency | 0.822 |
| Delta | 0.124 |

Default config. Org frequency acts as an organization identifier and can learn queue-specific labeling style, so it is excluded from the headline model.

## Hyperparameter selection

| Config | num_leaves | learning_rate | n_estimators | min_child_samples | Dev macro-F1 | Dev NLL | Selected |
|---|---:|---:|---:|---:|---:|---:|:---:|
| 31/0.05/300/20 | 31 | 0.05 | 300 | 20 | 0.698 | 0.639 | no |
| 63/0.05/400/20 | 63 | 0.05 | 400 | 20 | 0.708 | 0.617 | no |
| 31/0.1/400/20 | 31 | 0.1 | 400 | 20 | 0.708 | 0.620 | no |
| 63/0.1/350/50 | 63 | 0.1 | 350 | 50 | 0.712 | 0.619 | yes |

Selected: `{'num_leaves': 63, 'learning_rate': 0.1, 'n_estimators': 350, 'min_child_samples': 50}`.

## Calibration

Two-fold cross-validation on the calibration split.

| Method | CV ECE | CV Brier | CV NLL | CV macro-F1 | Eligible |
|---|---:|---:|---:|---:|:---:|
| raw | 0.024 | 0.361 | 0.619 | 0.712 | yes |
| temperature | 0.024 | 0.361 | 0.619 | 0.712 | yes |
| vector | 0.014 | 0.338 | 0.586 | 0.725 | yes |
| isotonic | 0.015 | 0.339 | 0.598 | 0.725 | yes |

Selected method: **vector**. Dev calibrated ECE: 0.010; dev raw ECE: 0.021.

## Test results

| Score | Macro-F1 | 95% CI | Accuracy | ECE-15 | ECE 95% CI | Brier | NLL |
|---|---:|---|---:|---:|---|---:|---:|
| Raw | 0.720 | 0.718 to 0.722 | 0.738 | 0.018 | 0.017 to 0.020 | 0.350 | 0.600 |
| Calibrated | 0.728 | 0.726 to 0.730 | 0.763 | 0.005 | 0.005 to 0.007 | 0.329 | 0.571 |

Reliability diagram: [w2_reliability.svg](w2_reliability.svg).

### Per-class metrics (raw and calibrated)

| Class | Raw precision | Raw recall | Raw F1 | Calibrated precision | Calibrated recall | Calibrated F1 | Support | Calibrated one-vs-rest ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| true_positive | 0.564 | 0.684 | 0.618 | 0.750 | 0.516 | 0.611 | 62540 | 0.006 |
| benign_positive | 0.798 | 0.762 | 0.780 | 0.735 | 0.911 | 0.814 | 148215 | 0.007 |
| false_positive | 0.791 | 0.734 | 0.762 | 0.840 | 0.694 | 0.760 | 92465 | 0.005 |

Vector scaling improves probability quality and macro-F1, but it also moves the argmax: true-positive recall falls from 0.684 to 0.516. The router should use the calibrated `p_true_positive` and the selective-risk curve, not only the predicted class. Both raw and calibrated metrics are kept in the metrics JSON.

### Confusion matrix (calibrated)

| true \ predicted | true_positive | benign_positive | false_positive |
|---|---|---|---|
| true_positive | 32251 | 24363 | 5926 |
| benign_positive | 6779 | 135096 | 6340 |
| false_positive | 3978 | 24328 | 64159 |

## Per-organization slices

Queues with at least 50 test incidents: 763.

| Median macro-F1 | p10 | p90 | Min |
|---:|---:|---:|---:|
| 0.360 | 0.196 | 0.612 | 0.000 |

The global test macro-F1 is not representative of every queue. The per-queue distribution is wide, so the router should not assume one global threshold is equally safe for every organization.

## Queue ranking proxy

The public GUIDE release has no analyst priority ranks, so P@5/10/20 against an analyst top-5 cannot be computed. The proxy ranks incidents within each organization queue by calibrated `p_true_positive`. It is not a substitute for analyst priority.

Queues with at least 50 incidents and 5 true positives: 448.

| Metric | Model | Signal baseline | Delta |
|---|---:|---:|---:|
| precision@5 | 0.618 | 0.483 | 0.135 |
| precision@10 | 0.605 | 0.471 | 0.134 |
| precision@20 | 0.576 | 0.450 | 0.126 |
| capture@10% | 0.269 | 0.179 | 0.090 |

The signal baseline orders by malicious verdict, MITRE presence, suspicion, and alert count. It is the closest available stand-in for severity; GUIDE has no severity column.

## Gate status

- [x] Calibration error is reported, not assumed.
- [x] All three per-class recalls exceed the 0.489 majority-class prevalence floor.
- [x] The queue ranking proxy beats the signal-only baseline at precision@10.
- [x] The model card states training data, features, and limitations.
- [x] Analyst priority P@5/10/20 is marked blocked: the public release has no priority labels.

## What this does not prove

- This is not production SOC readiness.
- Severity and analyst priority are absent from the public data. The queue ranking is a proxy, not the planned analyst metric.
- Organization identity is excluded from the headline model. The test split contains the same organizations as train, so this is not a leave-one-queue-out generalization test.
- Alert ids overlap between raw train and test. Incident-level disjointness holds, but an alert-disjoint sensitivity run is still pending.
- Calibration is top-label on this split. Per-organization calibration is not reported and may differ.
- The optional MiniLM baseline was not run. The classical baseline is stable enough for the routing work in later weeks.

## Reproduce

Fixture run:

```bash
uv run python -m triage.cli fixture-eval --work-dir reports/fixture_run
```

GUIDE run:

```bash
uv run python -m triage.cli classify --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --manifest data/manifests/split_v1.json --report reports/w2_classifier.md --metrics reports/w2_metrics.json --model-dir models/classifier_v1 --dataset guide
```

The model card and machine-readable metadata sit in `models/classifier_v1`.
