# Week 1 baselines

**Status: GUIDE run on the frozen manifest. Check the gate boxes below before treating any number as a result.**

## Data

| Item | Value |
|---|---|
| Dataset | guide |
| Test source | official |
| Train incidents | 89999 |
| Dev incidents | 10001 |
| Test incidents | 303220 |
| Seed | 42 |
| Model version | `tfidf_word_1_2_plus_numeric_lgbm_v1` |
| Manifest validates | True |
| Data checks pass | True (with warnings) |

Warnings:

- 23670 train incidents without a triage label were excluded.
- labels present: 23670 incidents without a triage label

## Results

| Model | Macro-F1 | 95% bootstrap CI | Accuracy |
|---|---:|---|---:|
| Majority class | 0.219 | 0.218 to 0.219 | 0.489 |
| Rules (MITRE or malicious verdict) | 0.191 | 0.190 to 0.192 | 0.225 |
| TF-IDF + LightGBM | 0.706 | 0.704 to 0.707 | 0.722 |

## Per-class metrics

| Model | Class | Precision | Recall | F1 | Support |
|---|---|---:|---:|---:|---:|
| Majority class | true_positive | 0.000 | 0.000 | 0.000 | 62540 |
| Majority class | benign_positive | 0.489 | 1.000 | 0.657 | 148215 |
| Majority class | false_positive | 0.000 | 0.000 | 0.000 | 92465 |
| Rules (MITRE or malicious verdict) | true_positive | 0.189 | 0.336 | 0.242 | 62540 |
| Rules (MITRE or malicious verdict) | benign_positive | 0.000 | 0.000 | 0.000 | 148215 |
| Rules (MITRE or malicious verdict) | false_positive | 0.245 | 0.510 | 0.331 | 92465 |
| TF-IDF + LightGBM | true_positive | 0.521 | 0.703 | 0.599 | 62540 |
| TF-IDF + LightGBM | benign_positive | 0.795 | 0.740 | 0.766 | 148215 |
| TF-IDF + LightGBM | false_positive | 0.806 | 0.705 | 0.752 | 92465 |

## Confusion matrix: TF-IDF + LightGBM

| true \ predicted | true_positive | benign_positive | false_positive |
|---|---|---|---|
| true_positive | 43989 | 12722 | 5829 |
| benign_positive | 28682 | 109675 | 9858 |
| false_positive | 11682 | 15592 | 65191 |

## Rules baseline

true_positive if has_mitre or malicious_count > 0; false_positive otherwise.

Deliberately ignores benign-positive signals; a reference point, not tuned.

## Gate status

- [x] Split manifest validates.
- [x] LightGBM beats majority on macro-F1.
- [x] LightGBM beats rules on macro-F1.
- [x] Data checks pass (see warnings).

## What this does not prove

- The rules baseline is intentionally simple and not tuned.
- The classifier is not calibrated yet. Calibration and the router belong to later weeks.
- The test split is not used for threshold tuning here.

## Reproduce

Fixture run:

```bash
uv run python -m triage.cli fixture-eval --work-dir reports/fixture_run
```

GUIDE run:

```bash
uv run python -m triage.cli etl --raw-dir data/raw --out data/processed/incidents.parquet --stats data/processed/etl_stats.json
uv run python -m triage.cli split --incidents data/processed/incidents.parquet --out-dir data/processed --manifest data/manifests/split_v1.json
uv run python -m triage.cli baselines --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --manifest data/manifests/split_v1.json --report reports/w1_baselines.md --metrics reports/w1_metrics.json --dataset guide
uv run python -m triage.cli check --incidents data/processed/incidents.parquet --manifest data/manifests/split_v1.json
```

The `Makefile` mirrors these commands for Unix and CI.

Artifacts:

- The metrics JSON sits next to this report.
- Manifest: `data/manifests/split_v1.json`.
- Use the manifest hash and model version when comparing runs.
