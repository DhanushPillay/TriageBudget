# Week 4 retrieval ablations

- Dataset: GUIDE dev proxy queries (100)
- Generated: 2026-11-13T10:15:48.383782+00:00
- Gold: structured-overlap proxy; not human relevance labels
- Index: 14,727 documents built from the frozen train split; test overlap 0.

| method | incident R@5 | incident R@10 | incident nDCG@10 | incident MRR | playbook R@5 | playbook R@10 | median latency |
|---|---:|---:|---:|---:|---:|---:|---:|
| bm25 | 0.4067 | 0.6833 | 0.4918 | 0.5323 | 0.3067 | 0.6217 | 22.4 ms |
| dense | 0.3067 | 0.6067 | 0.4398 | 0.5035 | 0.5133 | 0.6758 | 6.3 ms |
| hybrid | 0.4267 | 0.6733 | 0.5013 | 0.5747 | 0.4217 | 0.6750 | 35.0 ms |
| hybrid_rerank | 0.3167 | 0.5067 | 0.3654 | 0.4263 | 0.3233 | 0.6225 | 832.9 ms |

## Smoke test

19 of 20 queries returned a gold incident citation and a category-matched playbook section in the top 5.

## Notes

- R0 is BM25 only, R1 is dense only, R2 is hybrid RRF, R3 is hybrid plus a cross-encoder reranker (`Xenova/ms-marco-MiniLM-L-6-v2`, top 20 candidates).
- Gold incidents and playbooks are structured-overlap proxies, not human relevance labels.
- Playbook recall averages only queries with non-empty gold.

## Reproduce

```bash
uv run python -m triage.selective
```
