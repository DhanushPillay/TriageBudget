"""Vercel entrypoint.

Vercel imports this module and serves the ASGI `app` object. The application
lives in `src/triage/web/app.py`, so this shim only puts `src/` on the import
path before re-exporting it.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from triage.web.app import app  # noqa: E402

__all__ = ["app"]
