"""Shared helpers + provider implementations for the W8.1 tests.

Pure helpers (no pytest fixture decorators); imported by every
``test_w8_1_*`` module. Kept in a uniquely-named module
(``_w8_1_helpers``) rather than ``conftest.py`` to avoid the
across-package ``conftest`` module-name collision pytest's prepend
import mode otherwise produces (sibling test directories at
``apps/replay-proxy/tests/conftest.py`` and ``apps/local-sidecar/tests/
conftest.py`` ALSO declare a top-level ``conftest`` module that
shadows ours under sys.path). The fixture surface lives in
``conftest.py`` next to this file.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from relay_gate_engine import (
    GateAssertion,
    GateDecisionDraft,
    GateEvaluator,
    GatePipeline,
    GatePolicy,
)

# ----------------------------------------------------------------------------
# Provider implementations.
# ----------------------------------------------------------------------------


class InMemoryEvidenceProvider:
    """Dict-backed evidence_bundle resolver."""

    def __init__(self, bundles: Mapping[str, Mapping[str, Any]] | None = None) -> None:
        self._bundles: dict[str, Mapping[str, Any]] = dict(bundles or {})

    def add(self, bundle_id: str, body: Mapping[str, Any]) -> None:
        self._bundles[bundle_id] = body

    def get(self, bundle_id: str) -> Mapping[str, Any]:
        return self._bundles[bundle_id]


class InMemoryManifestResolver:
    """Dict-backed manifest command_hash -> command_line resolver."""

    def __init__(self, commands: Mapping[str, str] | None = None) -> None:
        self._commands: dict[str, str] = dict(commands or {})

    def add(self, command_hash: str, command_line: str) -> None:
        self._commands[command_hash] = command_line

    def resolve(self, command_hash: str) -> str:
        return self._commands[command_hash]


# ----------------------------------------------------------------------------
# Constants used across tests.
# ----------------------------------------------------------------------------


SCOPE_TYPE = "run"
SCOPE_ID = uuid4()
ROUND = 1
GATE_ID_SCRUTINY = uuid4()
GATE_ID_STRUCTURAL = uuid4()
GATE_ID_TESTING = uuid4()
WORKER_ID = uuid4()
ACTOR_HASH = "sha256-" + ("a" * 64)
MANIFEST_HASH = "sha256-" + ("b" * 64)
COMMAND_HASH_CLEAN = "sha256-clean"


# ----------------------------------------------------------------------------
# Builders.
# ----------------------------------------------------------------------------


def make_draft(
    *,
    gate_id: Any = None,
    draft_id: Any = None,
    scope_type: str = SCOPE_TYPE,
    scope_id: Any = SCOPE_ID,
    round_: int = ROUND,
    worker_id: Any = WORKER_ID,
    actor_identity_hash: str = ACTOR_HASH,
    manifest_commit_hash: str = MANIFEST_HASH,
    command_hash: str = COMMAND_HASH_CLEAN,
    submitted_at: datetime | None = None,
    evidence_refs: tuple[Any, ...] = (),
) -> GateDecisionDraft:
    return GateDecisionDraft(
        draft_id=draft_id or uuid4(),
        gate_id=gate_id or GATE_ID_SCRUTINY,
        scope_type=scope_type,
        scope_id=scope_id,
        round=round_,
        worker_id=worker_id,
        actor_identity_hash=actor_identity_hash,
        manifest_commit_hash=manifest_commit_hash,
        command_hash=command_hash,
        submitted_at=submitted_at or datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC),
        evidence_refs=evidence_refs,
    )


def make_gate(
    *,
    gate_id: Any = GATE_ID_SCRUTINY,
    gate_name: str = "scrutiny",
    assertions: tuple[GateAssertion, ...] = (),
    conditions: tuple[str, ...] = (),
    cascade_on_block: bool = True,
    draft_ttl_seconds: int = 900,
) -> GatePolicy:
    return GatePolicy(
        gate_id=str(gate_id),
        gate_name=gate_name,
        assertions=assertions,
        conditions=conditions,
        cascade_on_block=cascade_on_block,
        draft_ttl_seconds=draft_ttl_seconds,
    )


def make_pipeline(
    evaluator: GateEvaluator,
    *,
    scope_type: str = SCOPE_TYPE,
    scope_id: Any = SCOPE_ID,
    round_: int = ROUND,
) -> GatePipeline:
    return GatePipeline(
        scope_type=scope_type,
        scope_id=scope_id,
        round=round_,
        evaluator=evaluator,
    )


__all__ = [
    "ACTOR_HASH",
    "COMMAND_HASH_CLEAN",
    "GATE_ID_SCRUTINY",
    "GATE_ID_STRUCTURAL",
    "GATE_ID_TESTING",
    "InMemoryEvidenceProvider",
    "InMemoryManifestResolver",
    "MANIFEST_HASH",
    "ROUND",
    "SCOPE_ID",
    "SCOPE_TYPE",
    "WORKER_ID",
    "make_draft",
    "make_gate",
    "make_pipeline",
]
