# Week 5 demo script

This is a local demo of the review console. There is no hosted URL yet.

## Setup

```bash
uv run python -m triage.web seed --if-empty
uv run python -m triage.web serve
```

Open `http://127.0.0.1:8000`. The demo reviewer token is `demo-review-token`.
It is shown in the token dialog and is not a secret.

## Scenario 1: review a high-confidence true positive

1. Filter the queue to `true_positive`, or search for `0:809`.
2. Open `0:809`.
3. Point out the verdict, priority, confidence, evidence, and four remediation
   actions.
4. Approve it with a short note.

Expected: the status changes to `approved`, and a new `review.approve` event
appears in the audit timeline.

## Scenario 2: edit a decision

1. Open `236:5773`.
2. Choose `Edit`.
3. Change the verdict or priority, add a note, and submit.

Expected: the incident status becomes `edited`, the decision shows the edited
values, and the audit timeline records `review.edit` with the old and new
values.

## Scenario 3: inspect audit and health

1. Open `API and audit` in the top bar, or call `/api/audit`.
2. Show the append-only event list.
3. Call `/health` and `/api/metrics`.

Expected: `/health` returns `ok`, the database backend, and demo mode. Metrics
show incident and review counts by status.

## Timing

Each scenario takes under 30 seconds once the page is loaded. The three
scenarios together fit in a three-minute demo, including setup and a short
explanation of the selective-risk result.

## What the demo does not claim

- The console is a local demo, not a production SOC.
- The review token is a demo gate, not an identity system.
- Decisions are precomputed from the 20 tracked Week 3 traces.
- No live Vercel, Neon, or Render deployment is claimed yet.
- Citation usefulness has not been judged by a human reviewer.
