"""Shared fixtures for packages/evals/tests/.

Provides:

- ``eval_db``: an in-memory SQLite connection with the W9.1 migration
  applied. Per-test fresh; no cross-test bleed.
- ``deterministic_ids``: a closure returning sequential
  ``eval-test-<n>`` identifiers, used by VAL-W9-004 byte-equality tests
  that need ``eval_run_id`` and ``eval_result_id`` values to be
  deterministic across two invocations.
- ``fixed_manifest_hash``: a stable sha256-form string accepted by the
  CHECK constraint on ``eval_runs.manifest_commit_hash``.
- ``valid_evidence``: an EvidenceBinding factory the tests use to build
  a "complete" binding by default; tests that want to exercise the
  invalid path strip specific anchors.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator

import pytest
from relay_evals import (
    EvidenceBinding,
    apply_migrations,
    connect_memory,
)

# Stable sha256-<hex> strings used by tests. The first 8 chars are
# 'deadbeef' / 'cafebabe' / 'feedface' so a grep over a failing test
# log makes the source obvious.
FIXED_MANIFEST_HASH = "sha256-" + ("dead" * 16)
FIXED_ARTIFACT_HASH = "sha256-" + ("beef" * 16)


@pytest.fixture
def eval_db() -> Iterator[sqlite3.Connection]:
    """In-memory SQLite connection with the W9.1 schema applied."""
    conn = connect_memory()
    try:
        apply_migrations(conn)
        yield conn
    finally:
        conn.close()


@pytest.fixture
def deterministic_ids() -> Callable[[], str]:
    """Return a closure that emits ``eval-test-1``, ``eval-test-2``, ..."""
    counter = {"n": 0}

    def supplier() -> str:
        counter["n"] += 1
        return f"eval-test-{counter['n']:08d}"

    return supplier


@pytest.fixture
def fixed_manifest_hash() -> str:
    return FIXED_MANIFEST_HASH


@pytest.fixture
def valid_evidence() -> Callable[..., EvidenceBinding]:
    """Factory that builds a complete EvidenceBinding by default.

    Override individual anchors via kwargs to exercise the invalid
    path. Example::

        binding = valid_evidence(span_ids=[])  # forces 'missing:span_ids'
    """

    def make(
        *,
        artifact_hash: str | None = FIXED_ARTIFACT_HASH,
        command_id: str | None = "cmd-test-1",
        exit_code: int | None = 0,
        span_ids: list[str] | None = None,
        manifest_commit_hash: str | None = FIXED_MANIFEST_HASH,
        assertion_id: str | None = "VAL-W9-001",
    ) -> EvidenceBinding:
        if span_ids is None:
            span_ids = ["span-1", "span-2"]
        return EvidenceBinding(
            artifact_hash=artifact_hash,
            command_id=command_id,
            exit_code=exit_code,
            span_ids=list(span_ids),
            manifest_commit_hash=manifest_commit_hash,
            assertion_id=assertion_id,
        )

    return make
