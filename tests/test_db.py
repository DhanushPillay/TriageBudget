from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from triage.web.db import Database


class _Cursor:
    rowcount = 3


class _Connection:
    def execute(self, statement: str, params: Any) -> _Cursor:
        return _Cursor()


def test_execute_uses_rowcount_on_postgres(monkeypatch) -> None:
    db = Database("postgresql://user:pass@localhost/triage")

    @contextmanager
    def fake_connect() -> Iterator[_Connection]:
        yield _Connection()

    monkeypatch.setattr(db, "connect", fake_connect)
    assert db.execute("DELETE FROM incidents") == 3
