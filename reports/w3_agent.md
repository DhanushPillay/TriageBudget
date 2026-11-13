# Week 3 agent report

Twenty hand-picked exception cases from the frozen GUIDE dev split. Expected labels are shown for evaluation only and are not exposed to the tools or the decision policy. The policy is deterministic and offline; no external LLM is called.

## Aggregate

| metric | value |
|---|---:|
| cases | 20 |
| schema valid | 20/20 |
| hard-constraint violations | 0 |
| mean tool calls | 5.00 |
| max tool calls | 5 |
| exact label agreement | 0.750 |
| abstention rate | 0.000 |
| true-positive citation rate | 7/7 |

## Gates

| gate | pass |
|---|---|
| schema_valid_18_of_20 | yes |
| zero_hard_constraint_violations | yes |
| mean_tool_calls_under_8 | yes |
| tp_evidence_citation | yes |
| trace_logged | yes |

## Safety notes

- 3 of 7 true-positive cases were predicted as another label. 3 of those were flagged for human review and 0 were auto-closed.
- 14 of 20 decisions set `needs_human`.
- 0 cases were auto-closed in total. Auto-close requires false-positive probability at least 0.90, true-positive probability at most 0.05, and no malicious, suspicious, or MITRE signal.

## Cases

| case | incident | expected | predicted | route | human | confidence | calls | valid | citations |
|---|---|---|---|---|---|---:|---:|---|---:|
| case_01 | `0:809` | true_positive | true_positive | auto_escalate | no | 0.938 | 5 | yes | 3 |
| case_02 | `36:1064` | true_positive | false_positive | agent | yes | 0.937 | 5 | yes | 3 |
| case_03 | `236:5773` | true_positive | true_positive | auto_escalate | no | 0.863 | 5 | yes | 3 |
| case_04 | `14:219` | true_positive | false_positive | agent | yes | 0.600 | 5 | yes | 3 |
| case_05 | `24:11168` | true_positive | true_positive | auto_escalate | no | 0.780 | 5 | yes | 3 |
| case_06 | `122:29549` | true_positive | false_positive | agent | yes | 0.676 | 5 | yes | 3 |
| case_07 | `426:202664` | true_positive | true_positive | auto_escalate | no | 0.797 | 5 | yes | 3 |
| case_08 | `790:3189` | benign_positive | benign_positive | agent | yes | 0.627 | 5 | yes | 3 |
| case_09 | `96:5006` | benign_positive | benign_positive | agent | no | 0.905 | 5 | yes | 3 |
| case_10 | `26:20940` | benign_positive | benign_positive | agent | no | 0.976 | 5 | yes | 3 |
| case_11 | `151:12115` | benign_positive | benign_positive | agent | yes | 0.652 | 5 | yes | 3 |
| case_12 | `26:14320` | benign_positive | benign_positive | agent | yes | 0.846 | 5 | yes | 3 |
| case_13 | `27:1050` | benign_positive | benign_positive | agent | yes | 0.999 | 5 | yes | 3 |
| case_14 | `361:43155` | benign_positive | benign_positive | agent | yes | 0.997 | 5 | yes | 3 |
| case_15 | `146:400` | false_positive | false_positive | agent | yes | 0.872 | 5 | yes | 3 |
| case_16 | `55:1197` | false_positive | false_positive | agent | yes | 0.686 | 5 | yes | 3 |
| case_17 | `104:316` | false_positive | false_positive | agent | yes | 0.734 | 5 | yes | 3 |
| case_18 | `274:17681` | false_positive | false_positive | agent | yes | 0.976 | 5 | yes | 3 |
| case_19 | `355:15836` | false_positive | benign_positive | agent | yes | 0.840 | 5 | yes | 3 |
| case_20 | `87:3190` | false_positive | benign_positive | agent | yes | 0.506 | 5 | yes | 3 |

## Tool use

| tool | calls |
|---|---:|
| `get_incident` | 20 |
| `map_attack` | 20 |
| `propose_action` | 20 |
| `retrieve_playbook` | 20 |
| `search_similar_incidents` | 20 |

## Decision schema

`TriageDecision` is validated before it is written. Hard constraints include enum membership, confidence range, mandatory citations for true positives and remediation, containment actions only for true positives, no URLs or executable payloads in remediation, and `needs_human` for low-confidence human/agent routes.

## Artifacts

| artifact | path |
|---|---|
| traces | `reports/w3_traces.json` |
| report | `reports/w3_agent.md` |
| metrics | `reports/w3_agent_metrics.json` |
| index | `indexes/w3_retrieval` |
| model_dir | `models/classifier_v1` |

## Limitations

- The agent is a deterministic policy over the calibrated classifier and retrieved evidence. It is not an LLM agent and does not measure LLM cost or latency.
- The twenty cases are hand-picked exception cases, not a random sample. Exact label agreement is descriptive only.
- Retrieval precedents are train incidents with labels. Playbooks are synthetic and are not an operational policy.
- Tool outputs are truncated in traces. Full prompts are not logged; only their SHA-256 hash and length are recorded.
- No production SOC readiness is claimed.

## Reproduce

```bash
python -m triage.agent --case case_01
make w3-agent
```
