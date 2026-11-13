from __future__ import annotations

import argparse
import os
from pathlib import Path

from triage.web.db import Database, default_database_url
from triage.web.seed import DEFAULT_TRACES, seed_database


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TriageBudget review console.")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the FastAPI review console.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")

    seed = sub.add_parser("seed", help="Load the 20 tracked demo decisions.")
    seed.add_argument("--db", default=default_database_url())
    seed.add_argument("--traces", default=str(DEFAULT_TRACES))
    seed.add_argument("--reset", action="store_true")
    seed.add_argument("--if-empty", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "seed":
        inserted = seed_database(
            Database(args.db),
            Path(args.traces),
            reset=args.reset,
            if_empty=args.if_empty,
        )
        print(f"seeded {inserted} demo incidents")
        return 0

    os.environ.setdefault("TRIAGE_DEMO_MODE", "1")
    import uvicorn

    uvicorn.run(
        "triage.web.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_config=None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
