"""Round-3 P1 fix #1: ``_execute_forced_stop`` MUST route through the
``transactional_db_write`` atomic primitive instead of opening an
independent ``aiosqlite.connect()``.

Per CLAUDE.md keystone invariant #8 (atomic persistence -- four primitives
only), every canonical write to the sidecar's SQLite database MUST go
through one of:

    - ``transactional_db_write``
    - ``object_put_with_digest``
    - ``queue_publish_with_idempotency``
    - ``local_atomic_file_write``
    (+ ``local_two_layer_locked_write`` / ``acquire_or_attach`` for the
     local OSS profile.)

The original ``_execute_forced_stop`` opened ``aiosqlite.connect()`` on a
fresh connection and emitted a BEGIN IMMEDIATE / INSERT / COMMIT directly.
This guard test asserts that the function's source body no longer mentions
``aiosqlite.connect(``; the forced_stop event_log row is now routed through
``transactional_db_write``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import inspect
import re

import pytest


@pytest.mark.plumbing
def test_execute_forced_stop_does_not_open_independent_connection() -> None:
    """Source guard: ``_execute_forced_stop`` body MUST NOT call
    ``aiosqlite.connect(``.

    The forensic forced_stop row goes through ``transactional_db_write``
    (atomic primitive #2). Direct ``aiosqlite.connect(`` outside the
    primitive is a banned pattern per CLAUDE.md keystone #8.
    """
    from relay_sidecar.runtime import _execute_forced_stop

    src = inspect.getsource(_execute_forced_stop)
    # The regex matches ``aiosqlite.connect(`` (with the open-paren) so
    # imports and comments containing the bare name do not false-positive.
    pattern = re.compile(r"\baiosqlite\.connect\s*\(")
    assert not pattern.search(src), (
        "_execute_forced_stop must not open independent aiosqlite "
        "connections; route the forensic event_log row through "
        "transactional_db_write (atomic primitive #2)."
    )


@pytest.mark.plumbing
def test_execute_forced_stop_uses_transactional_db_write() -> None:
    """Source guard: ``_execute_forced_stop`` body MUST reference the
    ``transactional_db_write`` primitive.

    The forensic row is preserved -- we just route it through the sanctioned
    write path.
    """
    from relay_sidecar.runtime import _execute_forced_stop

    src = inspect.getsource(_execute_forced_stop)
    assert "transactional_db_write" in src, (
        "_execute_forced_stop must call transactional_db_write so the "
        "forensic event_log row is written through the atomic primitive."
    )
