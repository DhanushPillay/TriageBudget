# Data

TriageBudget uses Microsoft GUIDE, a public dataset of security incidents from Microsoft customer environments. This document records what the dataset contains, how it will be accessed, and where it can mislead.

**Status: raw GUIDE files downloaded and audited in Week 1.** The ETL produced 1,033,998 incidents from 13,664,829 denormalized rows. Fields, labels, and splits are verified; see the local audit below.

---

## 1. Dataset facts

| Item | Value | Source |
|---|---|---|
| Name | Microsoft GUIDE | Dataset card |
| Incidents | 1,000,000 | Dataset card |
| Evidence items | 13,000,000 | Dataset card |
| Alerts | 1,600,000 | Dataset card |
| Triage labels | True positive, benign positive, false positive | Paper |
| Remediation labels | 26,000 | Paper |
| Expert-ranked incidents | 9,980 across 499 organization queues | Paper |
| License | CDLA-Permissive-2.0 | Dataset card |
| Size | About 3.5 GB compressed | Kaggle |
| Modalities | Incident records, alerts, evidence, entities, labels | Paper |

Links:

- Kaggle: <https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction>
- Paper: <https://arxiv.org/abs/2407.09017>
- Microsoft blog: <https://www.microsoft.com/en-us/security/blog/2024/07/23/>

The dataset is real telemetry, not synthetic. That is why it is useful. It is also why it needs careful handling.

---

## 1.1 Local audit

The Week 1 run used the Kaggle v2 files:

| Item | Value |
|---|---|
| Raw rows | 13,664,829 |
| Incidents | 1,033,998 |
| Official train incidents | 730,778 |
| Official test incidents | 303,220 |
| Labeled train incidents | 707,108 |
| Unlabeled train incidents | 23,670 |
| Labeled test incidents | 303,220 |
| Label conflicts | 0 |
| Split conflicts | 0 |

The composite key `(OrgId, IncidentId)` is unique after aggregation. The official test file has labels for every test incident, so `test_source` is `official`. Unlabeled train incidents are excluded from the frozen sample and reported as a manifest warning.

Test label counts: true positive 62,540, benign positive 148,215, false positive 92,465.

---

## 2. Access

Access requires a free Kaggle account and API token.

```bash
# One-time setup
mkdir -p ~/.kaggle
# Place kaggle.json from https://www.kaggle.com/settings/account
chmod 600 ~/.kaggle/kaggle.json
```

Then download through the Kaggle CLI:

```bash
kaggle datasets download -d microsoft/microsoft-security-incident-prediction -p data/raw --unzip
```

The download is about 3.5 GB compressed. The ETL expects `GUIDE_Train.csv` and `GUIDE_Test.csv` under `data/raw/`.

Do not commit the token. Do not put it in a notebook. Use an environment variable or the Kaggle config file.

Expected local requirements:

- About 10 GB free disk for the compressed download, extracted files, and a working database.
- 16 GB RAM for the 100k-incident development slice. The full 1M dataset may need more.
- CPU is enough for TF-IDF and LightGBM. A GPU is optional for a MiniLM fine-tune.

---

## 3. Schema

The raw CSV layout below was verified against the public GUIDE sample and the GUIDE schema in Week 1. The downloaded files will be checked by `make check` after access is available.

### 3.1 Raw CSV grain

`GUIDE_Train.csv` and `GUIDE_Test.csv` are denormalized at the alert and evidence row grain. One incident appears in multiple rows. The incident key is the composite `(OrgId, IncidentId)`. The ETL groups rows to one incident and preserves `AlertId` and `Id` as alert and evidence ids.

The test file may also contain a `Usage` column. It is ignored by the ETL.

### 3.2 Raw columns

| Group | Columns | Notes |
|---|---|---|
| Identifiers | `Id`, `OrgId`, `IncidentId`, `AlertId`, `DetectorId`, `DeviceId` | Hashed or scrubbed identifiers |
| Timing | `Timestamp` | Row-level event time |
| Detection | `AlertTitle`, `Category`, `MitreTechniques` | `AlertTitle` is a hashed code; `Category` is a text label |
| Label | `IncidentGrade` | `TruePositive`, `BenignPositive`, or `FalsePositive` |
| Action | `ActionGrouped`, `ActionGranular` | Sparse remediation labels |
| Entity and evidence | `EntityType`, `EvidenceRole`, `Sha256`, `IpAddress`, `Url`, `AccountSid`, `AccountUpn`, `AccountObjectId`, `AccountName`, `DeviceName`, `NetworkMessageId`, `EmailClusterId`, `RegistryKey`, `RegistryValueName`, `RegistryValueData`, `ApplicationId`, `ApplicationName`, `OAuthApplicationId`, `ThreatFamily`, `FileName`, `FolderPath`, `ResourceIdName`, `ResourceType`, `Roles`, `OSFamily`, `OSVersion`, `AntispamDirection`, `SuspicionLevel`, `LastVerdict`, `CountryCode`, `State`, `City` | Most entity values are hashed codes; many are null |
| Test-only | `Usage` | Present in some test files |

There is no explicit `Severity` column. Do not invent one. `SuspicionLevel` and `LastVerdict` are sparse and are not severity.

### 3.3 Label mapping

| Raw `IncidentGrade` | Normalized `triage_label` |
|---|---|
| `TruePositive` | `true_positive` |
| `BenignPositive` | `benign_positive` |
| `FalsePositive` | `false_positive` |

Unknown or missing labels become null. Conflicting labels for one incident are flagged in `label_conflict` and are excluded from the frozen split.

### 3.4 Implemented incident Parquet

The Week 1 ETL writes one row per incident. The main fields are:

| Field | Type | Notes |
|---|---|---|
| `incident_id` | string | `OrgId:IncidentId` |
| `org_id` | string | Source organization |
| `incident_id_raw` | string | Source incident id |
| `created_at` | timestamp | Earliest row timestamp |
| `split` | enum | `train` or `test`, from the source file |
| `triage_label` | enum | Normalized label |
| `triage_label_raw` | string | Original `IncidentGrade` |
| `label_conflict` | boolean | Rows disagree on the label |
| `split_conflict` | boolean | Incident appears in more than one source file |
| `title` | string | Alert title code, not human text |
| `alert_count` | integer | Distinct alerts |
| `evidence_count` | integer | Evidence rows |
| `detector_count` | integer | Distinct detectors |
| `entity_type_count` | integer | Distinct entity types |
| `alert_title_count` | integer | Distinct alert title codes |
| `category_count` | integer | Distinct categories |
| `evidence_role_count` | integer | Distinct evidence roles |
| `has_mitre` | integer | Any MITRE technique present |
| `suspicious_count` | integer | Rows with `SuspicionLevel = Suspicious` |
| `verdict_count` | integer | Rows with `LastVerdict` malicious or suspicious |
| `malicious_count` | integer | Rows with `LastVerdict = Malicious` |
| `sha256_count`, `ip_count`, `url_count`, `account_count`, `device_count`, `registry_count`, `file_count`, `email_count` | integer | Distinct entity counts |
| `event_hour`, `event_day_of_week` | integer | From the earliest timestamp |
| `categories`, `mitre_techniques`, `entity_types`, `evidence_roles`, `suspicion_levels`, `last_verdicts`, `resource_types`, `roles`, `antispam_directions`, `threat_families`, `alert_titles` | string | Aggregated categorical tokens |
| `summary` | string | Derived text for TF-IDF and retrieval, not an analyst summary |
| `alert_ids`, `evidence_ids` | array | Source alert and evidence ids |

`severity`, `remediation_label`, and `priority_rank` are null in v1. The raw CSV does not provide a severity field, and the remediation and priority mappings are not part of the Week 1 ETL.

### 3.5 Deferred tables

Separate alert, evidence, entity, and label tables are not materialized in Week 1. The incident Parquet keeps `alert_ids` and `evidence_ids` so these tables can be split later for Postgres and the review UI.

---

## 4. Sampling

The full dataset is 1M incidents. The development loop uses 100k.

Sampling rules:

1. **Stratify by triage label.** Do not let false positives dominate the sample.
2. **Keep official split membership.** If an incident is in the official test split, it stays in test. Do not move it.
3. **Report organization coverage.** Week 1 samples by label with a deterministic hash and reports per-organization counts. Explicit queue stratification is a later improvement.
4. **Freeze the manifest.** Write source hashes, split hashes, counts, and the sampling seed to `data/manifests/split_v1.json`. Every evaluation reads the manifest.
5. **Agent subset.** Sample 500 to 2,000 test incidents, stratified by label and route, with a fixed seed. This is the only set the agent runs on.

Why 100k: it fits on a laptop, trains a LightGBM model in minutes, and is large enough for stable per-class estimates. The full 1M is used only for a final classifier run if time and compute allow.

---

## 5. Label audit

Before modeling, audit the labels.

Checks:

- Counts per triage class.
- Counts per remediation class.
- Counts per organization queue.
- Missing labels and ambiguous labels.
- Duplicate incidents and near-duplicates.
- Label distribution over time.
- Label distribution by severity.
- Agreement between triage label and remediation label, if both exist.

Deliverable: `docs/label_audit.md` with counts, charts, and a list of decisions. Any label remapping goes here before modeling.

Known risks:

- **Class imbalance.** False positives may dominate. Macro-F1 and per-class recall are reported to keep the minority classes visible.
- **Label noise.** Analyst labels are not ground truth in a philosophical sense. They are the operational target. Treat disagreement as a finding, not a bug to hide.
- **Organization leakage.** Some queues may have consistent labeling styles. A model can learn the queue, not the incident. Per-org slices and a leave-one-queue-out check will test this.

---

## 6. Quality checks

Run these before every evaluation:

| Check | Rule | Action on failure |
|---|---|---|
| Composite incident id unique | No duplicate `(OrgId, IncidentId)` | Fail the pipeline |
| Split disjoint | No incident in two splits | Fail the pipeline |
| Label values known | All labels in the allowed set | Fail or remap explicitly |
| Timestamps parse | All created_at parse | Drop or quarantine |
| Evidence linked | Every evidence id resolves | Quarantine orphan evidence |
| Alert linked | Every alert id resolves | Quarantine orphan alerts |
| Text not empty | Summary or evidence exists | Flag as `sparse` |
| No test leakage in index | Retrieval index has train ids only | Rebuild index |
| Manifest hash matches | Files unchanged since manifest | Fail the pipeline |

Data tests live in `tests/test_data.py` and run in CI on a small fixture. The full check runs on the real dataset before every evaluation:

```bash
uv run python -m triage.cli check --incidents data/processed/incidents.parquet --manifest data/manifests/split_v1.json
```

---

## 7. PII, secrets, and safety

GUIDE contains real-looking tenant data. Treat it as sensitive even though it is public.

Rules:

- Hash or redact organization ids, user names, hostnames, and IPs before sending text to an LLM.
- Redact secrets, tokens, passwords, and private keys found in evidence text.
- Do not log raw evidence. Log evidence ids and redacted previews.
- Do not store raw evidence in the audit log.
- Do not include real tenant identifiers in screenshots or the demo video.
- Use a local redaction pass before any external API call. Microsoft Presidio is a reasonable default.
- Keep the redaction mapping local and out of the repo.

Prompt injection:

Incident evidence can contain text that looks like instructions. The agent must treat all incident text as untrusted. Mitigations:

- Wrap evidence in delimiters with an explicit "data, not instructions" system message.
- Strip or escape instruction-like patterns in the retrieval layer.
- Validate output against the schema.
- Do not expose tools that fetch arbitrary URLs or execute commands.
- Log prompt-injection attempts for the error taxonomy.

---

## 8. Storage

Local development:

- Raw GUIDE files in `data/raw/` (gitignored).
- `data/processed/incidents.parquet` with one row per incident.
- `data/processed/train.parquet`, `dev.parquet`, and `test.parquet` from the frozen manifest.
- `data/manifests/split_v1.json` with source and split hashes (committed after the GUIDE run).
- `reports/w1_metrics.json` and `reports/w1_baselines.md` for the baseline run.
- A DuckDB file at `data/triage.duckdb` for ad-hoc queries is optional and not created in Week 1.

Deployed demo:

- Neon Postgres free tier, 1 GB.
- Only the 100k demo slice, decisions, reviews, and audit events.
- Precomputed embeddings stored as `vector(384)` columns with pgvector.
- No raw evidence blobs in Postgres. Store text snippets needed for the UI, or fetch from a static file if needed.

What is committed:

- Schema definitions.
- Manifest hashes.
- Small fixtures for tests.
- Documentation.

What is not committed:

- Raw GUIDE files.
- The Kaggle token.
- The redaction mapping.
- Full predictions with raw text.

---

## 9. Limitations

1. **Domain shift.** GUIDE comes from Microsoft customer environments. The detectors, products, and analyst behavior may not match another SOC.
2. **Label policy shift.** Different organizations label the same activity differently. A global model may learn the average policy, not the local one.
3. **Temporal drift.** The dataset is a snapshot. Attack techniques and telemetry change.
4. **Hidden test labels.** If Kaggle does not expose test labels, the project uses a local frozen split. It will not claim official test performance.
5. **Subset agent evaluation.** The agent runs on a stratified subset, not the full test set. The classifier runs on the full test set. The two results are reported separately.
6. **No production feedback loop.** The system does not learn from reviewer edits in v1. That is a future feature, not a claim.
7. **Cost estimates.** Token prices and free-tier limits change. Cost numbers are reported with the date and provider assumptions.

---

## 10. Fallback

If GUIDE access fails or the schema is unusable:

- Fall back to a smaller public incident dataset for a smoke test, but keep GUIDE as the target.
- Do not silently swap datasets. The report must name the dataset used.
- If the official labels are unavailable, run the local split and label it clearly.
- If the 1M download is too large, use the 100k slice and state the sampling method.

If the dataset cannot support the selective-risk claim, the project pivots to a classifier-only evaluation and reports the negative result. The evaluation harness and the audit trail still stand.

---

## 11. RAG corpus and embeddings

RAG needs a corpus, a chunking policy, and an embedding index. This section defines all three.

### 11.1 Incident retrieval corpus

Source: GUIDE train split only. The test split is never indexed.

Document shape:

- Incident summary.
- Top 3 to 5 evidence snippets, truncated and redacted.
- Metadata: label, severity, organization queue, incident date.

Chunking:

- 300 to 500 tokens per chunk, 50-token overlap.
- Evidence snippets keep their evidence id so the agent can cite them.
- Do not split an evidence item across more than two chunks.

### 11.2 Playbook corpus

Source: 50 to 100 public security playbooks and internal-style runbooks. If a playbook is generated for the demo, label it synthetic.

Document shape:

- Playbook title, version, effective date, source.
- Section heading and body.
- Stable `playbook_id` and `section_id`.

Chunking:

- One section per chunk where possible.
- Long sections split at heading boundaries, not arbitrary character counts.
- Every chunk keeps its source URL or file name.

### 11.3 Embeddings and vector index

- Model: `bge-small-en-v1.5`, 384 dimensions, normalized.
- Local experiments: FAISS or DuckDB.
- Deployed demo: Postgres with pgvector.
- Index type: HNSW for the demo, exact search for small evaluation sets.
- Store: `chunks` table with text and metadata, `embeddings` table with `vector(384)`.

The index is rebuilt by one command. The build records the model name, dimension, chunk count, and source manifest hash.

### 11.4 Retrieval evaluation set

- 100 queries drawn from dev incidents.
- Each query has gold evidence ids and gold playbook section ids.
- The first 30 queries are labelled by two people; report agreement.
- Query types: similar incident, playbook, and incident evidence.
- The test split is not used to tune retrieval.

### 11.5 Leakage and freshness

- Test incidents are excluded from the index.
- For time-based splits, the index only contains incidents earlier than the query incident.
- Playbooks carry an effective date so a stale runbook can be flagged.
- Rebuilding the index is part of the evaluation run, not an afterthought.

---

## 12. Week 0 data gate

Before building the agent, answer these:

- [ ] Kaggle download works with a token.
- [ ] The incident, alert, evidence, and label tables are identifiable.
- [ ] The triage label distribution is known.
- [ ] The organization queue count is known.
- [ ] The official split is present and incident-level.
- [ ] At least 50k incidents have usable summary text.
- [ ] At least 1,000 incidents have remediation labels.
- [ ] At least 50 playbook sections exist and are chunked.
- [ ] A 384-dim embedding index builds on the 100k sample.
- [ ] A 20-query retrieval smoke test returns citations.
- [ ] The 100k sample fits in DuckDB and trains a LightGBM baseline in under 30 minutes.

If fewer than five of these pass, stop and reassess before writing agent code.
