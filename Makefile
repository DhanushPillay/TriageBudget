UV ?= uv
PYTHON ?= $(UV) run python

.PHONY: setup test lint fixture-eval data split eval w2 w3-retrieval w3-agent w4 web-seed web check ci clean

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

w2:
	$(PYTHON) -m triage.cli classify --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --manifest data/manifests/split_v1.json --report reports/w2_classifier.md --metrics reports/w2_metrics.json --model-dir models/classifier_v1 --dataset guide

w3-retrieval:
	$(PYTHON) -m triage.retrieval build --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --playbooks data/playbooks --out indexes/w3_retrieval --report reports/w3_retrieval.md --metrics reports/w3_retrieval_metrics.json --dataset guide

w3-agent:
	$(PYTHON) -m triage.agent --dev data/processed/dev.parquet --cases data/cases/w3_cases.json --index indexes/w3_retrieval --model-dir models/classifier_v1 --prompts prompts --report reports/w3_agent.md --traces reports/w3_traces.json --metrics reports/w3_agent_metrics.json --dataset guide

w4:
	$(PYTHON) -m triage.cli week4

web-seed:
	$(PYTHON) -m triage.web seed --if-empty

web:
	$(PYTHON) -m triage.web serve --reload

check:
	$(PYTHON) -m triage.cli check --incidents data/processed/incidents.parquet --manifest data/manifests/split_v1.json

ci: lint test fixture-eval

clean:
	rm -rf reports/fixture_run .pytest_cache .ruff_cache
