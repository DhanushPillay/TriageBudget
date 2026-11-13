# Week 3 retrieval report

Measured on the frozen GUIDE split with the real train and dev files. The retrieval gold sets are structured-overlap proxies, not human relevance labels. Treat them as a regression check, not a benchmark.

## Corpus

| item | value |
|---|---:|
| incident documents | 14,664 |
| train incidents represented | 89,999 |
| playbook sections | 63 |
| playbook files | 9 |
| embedding model | `BAAI/bge-small-en-v1.5` |
| embedding dimension | 384 |
| index bytes | 29,701,397 |

Incident documents are deduplicated by `(summary, triage_label)`. The representative incident id is cited; member incidents with the same summary and label are kept as provenance.

## Leakage check

- Indexed incident ids: 89,999
- Test incident ids: 303,220
- Overlap: 0
- Gate: pass

## Retrieval metrics

| method | incident Recall@5 | incident Recall@10 | incident nDCG@10 | incident MRR | playbook Recall@5 | playbook Recall@10 | median latency |
|---|---:|---:|---:|---:|---:|---:|---:|
| bm25 | 0.407 | 0.683 | 0.492 | 0.532 | 0.307 | 0.622 | 25.2 ms |
| dense | 0.307 | 0.607 | 0.440 | 0.503 | 0.513 | 0.676 | 6.5 ms |
| hybrid | 0.427 | 0.673 | 0.501 | 0.575 | 0.422 | 0.675 | 36.0 ms |

Playbook recall averages only the 100 queries with non-empty proxy playbook gold.

## Citation smoke test

19 of 20 queries returned at least one gold incident citation in the top 5 and one category-matched playbook section in the top 5.

## Limitations

- Gold incident documents are selected by summary-token Jaccard overlap within the same label. They are not analyst judgments.
- Gold playbook sections are selected by category metadata. The playbooks are synthetic and are not an operational policy.
- Summary text is derived from GUIDE categorical and alert-title tokens. The public release does not include free-form analyst notes.
- The index uses exact numpy inner product, not FAISS or pgvector. That is adequate for the deduplicated local corpus and keeps the artifact reproducible without a service.
- No cross-encoder reranker is measured. The pipeline is BM25, dense, and reciprocal rank fusion only.

## Reproduce

```bash
uv run python -m triage.retrieval build --train data/processed/train.parquet --dev data/processed/dev.parquet --test data/processed/test.parquet --playbooks data/playbooks --out indexes/w3_retrieval --report reports/w3_retrieval.md --metrics reports/w3_retrieval_metrics.json --dataset guide
```
