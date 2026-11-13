# Model card: classifier_v1

- Version: `tfidf_lgbm_calibrated_v1`
- Generated: 2026-11-13T09:25:19.859691+00:00
- Seed: 42
- Dataset: guide

## Intended use

Research classifier for incident triage routing. It produces a three-class verdict and calibrated probabilities. It is not a production SOC system and must not trigger autonomous remediation.

## Training data

Microsoft GUIDE, official incident-level split, frozen manifest.

| Split | Incidents |
|---|---:|
| Train | 89999 |
| Dev | 10001 |
| Test | 303220 |

- Manifest: `data/manifests/split_v1.json`
- Incidents Parquet SHA-256: `efd105e630b4e07854fa851bcd60d74ed8ef57933514c0c0541d305d86e993e3`

## Features

- Text: summary field from GUIDE categorical and alert-title tokens (5000 TF-IDF features).
- Numeric: alert_count, evidence_count, detector_count, entity_type_count, alert_title_count, category_count, evidence_role_count, has_mitre, suspicious_count, verdict_count, malicious_count, sha256_count, ip_count, url_count, account_count, device_count, registry_count, file_count, email_count, event_hour, event_day_of_week, summary_length, summary_tokens, event_month, is_weekend, alerts_per_detector, evidence_per_alert, entities_per_alert, threat_family_count, has_suspicion, has_verdict.
- Excluded: severity (not in the public CSV), organization identity (queue-policy leakage risk), and priority rank (queue ranks are present but are not used in this classifier; Week 4 evaluates them).
- Organization frequency was tested and excluded: adding it changed default-config dev macro-F1 by 0.124. It behaves as an organization identifier, so it is not in the headline model.

## Model

- Family: TF-IDF plus LightGBM multiclass softmax.
- Selected parameters: `{'num_leaves': 63, 'learning_rate': 0.1, 'n_estimators': 350, 'min_child_samples': 50}`.
- Calibration: `vector`.
- Fit on train only. Calibrator fit on dev only. Test was not used for tuning or calibration.

## Evaluation

| Score | Macro-F1 | Accuracy | ECE-15 | Brier | NLL |
|---|---:|---:|---:|---:|---:|
| Raw | 0.720 | 0.738 | 0.018 | 0.350 | 0.600 |
| Calibrated | 0.728 | 0.763 | 0.005 | 0.329 | 0.571 |

Per-class metrics are in `reports/w2_classifier.md`.

## Limitations

- Labels are customer analyst judgments and may contain queue-specific policy differences.
- The public data has no severity column. Queue ranks are present but are deferred to Week 4; the Week 2 queue ranking proxy is not the planned analyst metric.
- Alert ids overlap between raw train and test. Incident ids are disjoint, but an alert-disjoint sensitivity run is pending.
- The test split shares organizations with train. This is not a leave-one-queue-out evaluation.
- Calibration is top-label and global. Per-organization calibration is not guaranteed.
- The classifier should not auto-close incidents without the router and human-review policy from later weeks.

## Ethical and security notes

- No autonomous action. The model only scores incidents.
- Do not send raw tenant identifiers to a third-party model.
- Treat GUIDE identifiers as sensitive even though the dataset is public.

## Reproduce

```bash
uv run python -m triage.cli classify --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --manifest data/manifests/split_v1.json --report reports/w2_classifier.md --metrics reports/w2_metrics.json --model-dir models/classifier_v1 --dataset guide
```
