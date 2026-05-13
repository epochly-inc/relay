"""VAL-W2-022: BEGIN IMMEDIATE is the first statement of every txn.

All ``transactional_db_write`` calls MUST open the transaction with
``BEGIN IMMEDIATE`` (not ``BEGIN`` / ``BEGIN DEFERRED``). Verified by
enabling the SidecarDatabase's writer statement trace and asserting the
first non-PRAGMA / non-SELECT-idempotency-precheck statement following
any caller submission is ``BEGIN IMMEDIATE``.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import re
import uuid

import pytest
from relay_sidecar.db import SidecarDatabase, build_event_log_row

_BEGIN_IMMEDIATE_RE = re.compile(r"^\s*BEGIN\s+IMMEDIATE\b", re.IGNORECASE)
_BEGIN_DEFERRED_RE = re.compile(r"^\s*BEGIN(?!\s+IMMEDIATE)\b", re.IGNORECASE)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-022")
@pytest.mark.asyncio
async def test_begin_immediate_is_used_for_writes(tmp_path) -> None:
    """A transactional write logs BEGIN IMMEDIATE; no plain BEGIN appears."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        # Clear the trace buffer (migrations + open-time pragmas
        # accumulated entries we don't care about) and enable capture.
        db.writer_trace.clear()
        db.writer_trace.enabled = True

        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        row = build_event_log_row(
            event_type="test.begin_immediate",
            scope_id=scope_id,
            project_id=project_id,
        )
        result = await db.transactional_db_write(
            table="event_log_entries",
            row=row,
            scope_id=scope_id,
        )
        assert result.ok

        db.writer_trace.enabled = False
        statements = list(db.writer_trace.statements)
        # At least one BEGIN IMMEDIATE in the trace.
        immediates = [s for s in statements if _BEGIN_IMMEDIATE_RE.match(s)]
        assert immediates, (
            f"no BEGIN IMMEDIATE captured; trace was {statements!r}"
        )
        # Zero plain BEGIN / BEGIN DEFERRED in the trace.
        plain_begins = [
            s
            for s in statements
            if _BEGIN_DEFERRED_RE.match(s) and not _BEGIN_IMMEDIATE_RE.match(s)
        ]
        assert not plain_begins, (
            f"plain BEGIN or BEGIN DEFERRED captured; trace was {statements!r}"
        )
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-022")
@pytest.mark.asyncio
async def test_begin_immediate_precedes_insert(tmp_path) -> None:
    """BEGIN IMMEDIATE statement index < INSERT statement index in the trace."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        db.writer_trace.clear()
        db.writer_trace.enabled = True

        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        row = build_event_log_row(
            event_type="test.begin_before_insert",
            scope_id=scope_id,
            project_id=project_id,
        )
        await db.transactional_db_write(
            table="event_log_entries",
            row=row,
            scope_id=scope_id,
        )

        db.writer_trace.enabled = False
        statements = list(db.writer_trace.statements)
        begin_idx = next(
            (i for i, s in enumerate(statements) if _BEGIN_IMMEDIATE_RE.match(s)),
            -1,
        )
        insert_idx = next(
            (
                i
                for i, s in enumerate(statements)
                if re.match(r"^\s*INSERT\s+INTO\s+event_log_entries\b", s, re.IGNORECASE)
            ),
            -1,
        )
        assert begin_idx >= 0, statements
        assert insert_idx >= 0, statements
        assert begin_idx < insert_idx, (
            f"BEGIN IMMEDIATE at index {begin_idx} did not precede INSERT "
            f"at index {insert_idx}: {statements!r}"
        )
    finally:
        await db.close()
