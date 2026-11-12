UV ?= uv
PYTHON ?= $(UV) run python

.PHONY: setup test lint fixture-eval data split eval check ci clean

setup:
	$(UV) sync --all-groups

test:
	$(UV) run pytest

lint:
	$(UV) run ruff check .

fixture-eval:
	$(UV) run python -m triage.cli fixture-eval --work-dir reports/fixture_run

data:
	$(PYTHON) -m triage.cli etl --raw-dir data/raw --out data/processed/incidents.parquet --stats data/processed/etl_stats.json

split:
	$(PYTHON) -m triage.cli split --incidents data/processed/incidents.parquet --out-dir data/processed --manifest data/manifests/split_v1.json --sample-size 100000

eval:
	$(PYTHON) -m triage.cli baselines --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --manifest data/manifests/split_v1.json --report reports/w1_baselines.md --metrics reports/w1_metrics.json --dataset guide

check:
	$(PYTHON) -m triage.cli check --incidents data/processed/incidents.parquet --manifest data/manifests/split_v1.json

ci: lint test fixture-eval

clean:
	rm -rf reports/fixture_run .pytest_cache .ruff_cache
