## Incident
{{INCIDENT_JSON}}

## Calibrated classifier
{{CLASSIFIER_JSON}}

## Tool results
{{TOOL_RESULTS_JSON}}

Produce a TriageDecision JSON object with these fields:
- incident_id: string
- verdict: true_positive | benign_positive | false_positive | undetermined
- priority: critical | high | medium | low
- remediation: list of {action, target, rationale}; use only the action taxonomy, and cite an evidence id in each rationale
- evidence: non-empty list of {evidence_id, quote, source}; quote must come from the cited incident, train precedent, or playbook passage
- confidence: number in [0, 1]
- needs_human: boolean
- route: auto_close | auto_escalate | agent | human
- classifier_version: string
- prompt_version: string
- tool_calls: integer
- latency_ms: integer
- cost_usd: number

Use `undetermined` and route `human` when the evidence is contradictory or too weak. Do not fill gaps with invented facts.
