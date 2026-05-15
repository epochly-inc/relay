"""Shared helpers for the W8.2 gate-decision-writer plumbing tests.

Builds an in-process SidecarDatabase with the W8.2 migration applied,
seeds the actors + manifest_versions tables with valid handoff anchors,
and yields a configured ``GateDecisionWriter`` instance plus the
factory helpers tests use to mint inputs.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite
from cryptography.hazmat.primitives.asymmetric import ed25519
from relay_gate_engine import (
    EvidenceBundleInputs,
    GateDecisionInputs,
    GateDecisionWriter,
    SigningKey,
)
from relay_sidecar.db import SidecarDatabase


def _ts(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


async def seed_actor(
    db: SidecarDatabase,
    *,
    identity_hash: str,
    kind: str = "gate_engine",
    revoked: bool = False,
) -> None:
    """Insert one actors row via raw aiosqlite connection (test setup)."""
    async with aiosqlite.connect(str(db.db_path)) as conn:
        await conn.execute(
            "INSERT INTO actors (identity_hash, kind, registered_at, revoked_at) "
            "VALUES (?, ?, ?, ?)",
            (
                identity_hash,
                kind,
                _ts(datetime.now(UTC)),
                _ts(datetime.now(UTC)) if revoked else None,
            ),
        )
        await conn.commit()


async def seed_manifest(
    db: SidecarDatabase,
    *,
    commit_hash: str,
    project_id: str = "00000000-0000-0000-0000-000000000000",
    effective_at: datetime | None = None,
    effective_until: datetime | None = None,
    grace_window_seconds: int = 86400,
) -> None:
    """Insert one manifest_versions row via raw aiosqlite connection."""
    async with aiosqlite.connect(str(db.db_path)) as conn:
        await conn.execute(
            "INSERT INTO manifest_versions "
            "(manifest_version_id, manifest_id, project_id, commit_hash, "
            " effective_at, effective_until, grace_window_seconds) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                str(uuid.uuid4()),
                project_id,
                commit_hash,
                _ts(effective_at or datetime.now(UTC)),
                _ts(effective_until) if effective_until is not None else None,
                grace_window_seconds,
            ),
        )
        await conn.commit()


async def seed_draft(
    db: SidecarDatabase,
    *,
    draft_id: str,
    gate_id: str,
    scope_type: str,
    scope_id: str,
    round_: int,
    worker_id: str,
    actor_identity_hash: str,
    manifest_commit_hash: str,
) -> None:
    """Insert one gate_decision_drafts row in 'pending' state."""
    async with aiosqlite.connect(str(db.db_path)) as conn:
        await conn.execute(
            "INSERT INTO gate_decision_drafts "
            "(draft_id, gate_id, scope_type, scope_id, round, worker_id, "
            " manifest_commit_hash, actor_identity_hash, submitted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                draft_id,
                gate_id,
                scope_type,
                scope_id,
                int(round_),
                worker_id,
                manifest_commit_hash,
                actor_identity_hash,
                _ts(datetime.now(UTC)),
            ),
        )
        await conn.commit()


def make_bundle_inputs(
    *,
    manifest_commit_hash: str,
    artifact_digest: str = "sha256-" + "f" * 64,
    command: str = "uv run pytest -m plumbing",
    exit_code: int = 0,
    span_ids: tuple[str, ...] = ("span-A", "span-B"),
    contract_assertion_ids: tuple[str, ...] = ("VAL-W8-010",),
    agent_worker_id: str = "worker-test-001",
    timestamp: datetime | None = None,
    environment: str = "local",
    redaction_policy_version: str = "v1",
) -> EvidenceBundleInputs:
    """Build a fully-populated EvidenceBundleInputs for a fixture write."""
    if timestamp is None:
        timestamp = datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)
    return EvidenceBundleInputs(
        artifact_digest=artifact_digest,
        command=command,
        exit_code=exit_code,
        span_ids=span_ids,
        contract_assertion_ids=contract_assertion_ids,
        agent_worker_id=agent_worker_id,
        manifest_commit_hash=manifest_commit_hash,
        timestamp=_ts(timestamp),
        environment=environment,
        redaction_policy_version=redaction_policy_version,
    )


def make_decision_inputs(
    *,
    gate_id: str,
    scope_type: str,
    scope_id: str,
    round_: int,
    actor_identity_hash: str,
    manifest_commit_hash: str,
    action: str = "accept",
    strict_pass: bool = True,
    failed_assertion_ids: tuple[str, ...] = (),
    unmet_conditions: tuple[Mapping[str, Any], ...] = (),
    cascade_on_block: bool = True,
    bundle_overrides: Mapping[str, Any] | None = None,
) -> GateDecisionInputs:
    bundle_kwargs: dict[str, Any] = {"manifest_commit_hash": manifest_commit_hash}
    if bundle_overrides:
        bundle_kwargs.update(bundle_overrides)
    bundle = make_bundle_inputs(**bundle_kwargs)
    return GateDecisionInputs(
        gate_id=gate_id,
        scope_type=scope_type,
        scope_id=scope_id,
        round_=round_,
        action=action,
        strict_pass=strict_pass,
        failed_assertion_ids=failed_assertion_ids,
        unmet_conditions=unmet_conditions,
        cascade_on_block=cascade_on_block,
        manifest_commit_hash=manifest_commit_hash,
        actor_identity_hash=actor_identity_hash,
        evidence_bundle=bundle,
    )


def make_ephemeral_signing_key(kid: str = "test-w8-2-kid") -> SigningKey:
    return SigningKey(
        private_key=ed25519.Ed25519PrivateKey.generate(),
        key_id=kid,
    )


@dataclass(frozen=True)
class WriterFixture:
    """Bundle of (database, writer, anchors, seeded ids) for tests."""

    database: SidecarDatabase
    writer: GateDecisionWriter
    actor_hash: str
    manifest_hash: str
    scope_id: str
    gate_id: str
    draft_id: str
    round_: int
    worker_id: str


async def setup_writer_fixture(
    tmp_path: Path,
    *,
    seed: bool = True,
) -> WriterFixture:
    """Build a SidecarDatabase + GateDecisionWriter and seed anchors.

    When ``seed=False`` the actors + manifest_versions tables are LEFT
    EMPTY so the handoff-mismatch tests can drive each anchor failure
    independently.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=2)
    await db.open()

    actor_hash = "sha256-" + "a" * 64
    manifest_hash = "sha256-" + "b" * 64
    scope_id = str(uuid.uuid4())
    gate_id = str(uuid.uuid4())
    draft_id = str(uuid.uuid4())
    worker_id = str(uuid.uuid4())
    round_ = 1

    if seed:
        await seed_actor(db, identity_hash=actor_hash, kind="gate_engine")
        await seed_manifest(db, commit_hash=manifest_hash)
        await seed_draft(
            db,
            draft_id=draft_id,
            gate_id=gate_id,
            scope_type="run",
            scope_id=scope_id,
            round_=round_,
            worker_id=worker_id,
            actor_identity_hash=actor_hash,
            manifest_commit_hash=manifest_hash,
        )

    writer = GateDecisionWriter(
        database=db,
        signing_key=make_ephemeral_signing_key(),
    )

    return WriterFixture(
        database=db,
        writer=writer,
        actor_hash=actor_hash,
        manifest_hash=manifest_hash,
        scope_id=scope_id,
        gate_id=gate_id,
        draft_id=draft_id,
        round_=round_,
        worker_id=worker_id,
    )


async def fetch_one(
    db: SidecarDatabase,
    sql: str,
    params: tuple[Any, ...] = (),
) -> tuple[Any, ...] | None:
    """Run a single-row SELECT against a fresh reader and return the row."""
    async with (
        aiosqlite.connect(str(db.db_path)) as conn,
        conn.execute(sql, params) as cur,
    ):
        return await cur.fetchone()


async def fetch_count(
    db: SidecarDatabase,
    table: str,
    where: str = "",
    params: tuple[Any, ...] = (),
) -> int:
    """Return ``SELECT count(*) FROM table [WHERE where]``."""
    sql = f"SELECT count(*) FROM {table}"
    if where:
        sql += f" WHERE {where}"
    row = await fetch_one(db, sql, params)
    return int(row[0]) if row is not None else 0


__all__ = [
    "WriterFixture",
    "fetch_count",
    "fetch_one",
    "make_bundle_inputs",
    "make_decision_inputs",
    "make_ephemeral_signing_key",
    "seed_actor",
    "seed_draft",
    "seed_manifest",
    "setup_writer_fixture",
]
