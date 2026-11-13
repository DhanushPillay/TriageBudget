# Deployment notes

The review console is local-first. Deployment is deferred until the local demo
and Week 6 report are complete. This document records the intended hosted path so
the code does not need a rewrite later.

## Local

```bash
uv run python -m triage.web seed --if-empty
uv run python -m triage.web serve
```

Open `http://127.0.0.1:8000`. The default database is SQLite at
`data/triage.db`. The demo seed contains 20 tracked Week 3 decisions. It does not
need raw GUIDE data.

The demo token is `demo-review-token`. Set `TRIAGE_REVIEW_TOKEN` to change it.
Set `TRIAGE_DEMO_MODE=0` to require a configured token; the app refuses review
writes with 503 when demo mode is off and no token is set.

## Docker Compose

```bash
docker compose up --build
```

Compose starts Postgres 16 and the app. The app waits for the database health
check, seeds the demo data if the table is empty, then serves on port 8000.
The Postgres volume is named `triage-db`.

Stop and remove the volume:

```bash
docker compose down -v
```

## Vercel plus Neon

Vercel can host the FastAPI app and static files. Neon provides Postgres because
Vercel's filesystem is ephemeral.

Planned settings:

- `DATABASE_URL`: Neon pooled Postgres connection string.
- `TRIAGE_REVIEW_TOKEN`: a random review token, not the demo value.
- `TRIAGE_DEMO_MODE=0`.
- Function `maxDuration`: 60 seconds.
- Static files served from `public/`.
- Exclude `data/`, `indexes/`, `models/`, `results/`, and tests from the bundle.

The Vercel Python bundle limit is 500 MB uncompressed. The app only needs the
seed trace file and code, not the GUIDE parquet files or the retrieval index.
The decisions are precomputed.

Before a public deployment:

- Replace the demo token with a real secret.
- Add rate limiting at the edge or in the app.
- Add reviewer identity beyond a display name.
- Restrict CORS if a separate frontend origin is used.
- Run the Postgres schema migration against a disposable database.
- Confirm the audit log survives a redeploy.
- Add a health check to the platform.

## Render fallback

Render can run the same Docker image with a managed Postgres instance. It is a
fallback if Vercel's Python runtime or bundle limits block the demo. The
environment variables are the same.

## Database

Tables:

- `incidents`: the precomputed decision and current review status.
- `reviews`: reviewer action, note, edits, and idempotency key.
- `audit_events`: append-only reviewer and system actions.

Every review write is a transaction: insert review, update incident status,
insert audit event. A repeated idempotency key returns the existing review
instead of writing a duplicate.

SQLite is for local development and tests. Postgres is the hosted target.

## Known gaps

- No live URL is claimed yet.
- The review token is a demo gate, not a full auth system.
- The seed is 20 hand-picked traces, not a production queue.
- No human citation-support review has been run.
- Deployment credentials are not in the repository.
