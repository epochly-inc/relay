"""Audit fix: sidecar ``idempotency_records`` table must mirror the
canonical Postgres shape declared at
``packages/schemas/sql/0002_control_plane.sql`` lines 107-126.

The 2026-05-17 whole-codebase audit surfaced this as a P0 because a
sidecar row CANNOT round-trip to canonical Postgres without these
constraints in place:

  - PK on ``idempotency_key`` alone (canonical Postgres declares
    ``idempotency_key text PRIMARY KEY``; the legacy sidecar PK was
    ``(key, surface)`` which is semantically incompatible).
  - ``idempotency_key`` carries the Crockford-base32 ULID grammar CHECK
    ``^[0-9A-HJKMNP-TV-Z]{26}$``.
  - ``request_digest`` carries the canonical ``sha256-<64 lowercase hex>``
    CHECK matching the spec B.2 wire format.
  - ``project_id`` is present (canonical declares it ``NOT NULL``; sidecar
    permits a sentinel project_id when the originating request did not
    resolve a tenant, but the column must exist).
  - ``schema_version`` is pinned to ``relay.idempotency_record.v1``
    (CLAUDE.md keystone invariant #10).

These tests assert the new shape directly against the sidecar SQLite
schema and against an INSERT into the table. Pre-fix the migration
introduced by 0021 does not exist; the schema CHECK assertions below
will fail until that migration lands.

Spec anchors:
  - sectionA.12 / VAL-W1-013, VAL-W1-014, VAL-W1-050 (canonical envelope)
  - sectionB.2 lines 3517-3520 (ULID + sha256-<hex> wire forms)
  - sectionB.7 (schema_version pin discipline)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import aiosqlite
import pytest

MIGRATIONS_DIR = (
    Path(__file__).resolve().parents[1] / "migrations"
)


async def _bootstrap(db_path: Path) -> None:
    """Apply every migration in lex order against a fresh SQLite db.

    Audit-R3 (2026-05-18): mirror __schema_migrations tracker so any
    subsequent _run_migrations call skips already-applied non-idempotent
    migrations.
    """
    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.executescript(
            "CREATE TABLE IF NOT EXISTS __schema_migrations ("
            "  filename   TEXT PRIMARY KEY,"
            "  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
            ");"
        )
        for sql in sorted(MIGRATIONS_DIR.glob("*.sql")):
            filename = sql.name
            async with conn.execute(
                "SELECT 1 FROM __schema_migrations WHERE filename = ?",
                (filename,),
            ) as cur:
                if await cur.fetchone() is not None:
                    continue
            await conn.executescript(sql.read_text(encoding="utf-8"))
            await conn.execute(
                "INSERT INTO __schema_migrations (filename) VALUES (?)",
                (filename,),
            )
        await conn.commit()


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idempotency_records_has_canonical_columns(
    tmp_path: Path,
) -> None:
    """The new schema MUST expose canonical column names."""
    db_path = tmp_path / "sidecar.db"
    await _bootstrap(db_path)
    async with (
        aiosqlite.connect(str(db_path)) as conn,
        conn.execute("PRAGMA table_info(idempotency_records)") as cur,
    ):
        rows = await cur.fetchall()
    columns = {row[1] for row in rows}
    # Canonical columns (envelopes.yaml IdempotencyRecord).
    must_have = {
        "idempotency_key",
        "schema_version",
        "project_id",
        "request_digest",
        "response_status",
        "first_seen_at",
        "expires_at",
    }
    missing = must_have - columns
    assert not missing, f"missing canonical columns: {missing}"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idempotency_records_primary_key_on_idempotency_key_alone(
    tmp_path: Path,
) -> None:
    """PK must be ``idempotency_key`` alone, not a composite."""
    db_path = tmp_path / "sidecar.db"
    await _bootstrap(db_path)
    async with (
        aiosqlite.connect(str(db_path)) as conn,
        conn.execute("PRAGMA table_info(idempotency_records)") as cur,
    ):
        rows = await cur.fetchall()
    # PRAGMA table_info row layout: (cid, name, type, notnull, dflt, pk).
    pk_cols = [row[1] for row in rows if row[5] > 0]
    assert pk_cols == ["idempotency_key"], (
        f"expected PRIMARY KEY (idempotency_key) only, got {pk_cols!r}"
    )


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idempotency_records_rejects_non_ulid_key(tmp_path: Path) -> None:
    """ULID grammar CHECK ``^[0-9A-HJKMNP-TV-Z]{26}$`` must reject
    non-Crockford-base32 keys.
    """
    db_path = tmp_path / "sidecar.db"
    await _bootstrap(db_path)
    bad_key = "not-a-ulid-key"
    async with aiosqlite.connect(str(db_path)) as conn:
        with pytest.raises(aiosqlite.IntegrityError):
            await conn.execute(
                "INSERT INTO idempotency_records "
                "(idempotency_key, schema_version, project_id, "
                " request_digest, response_status, first_seen_at, "
                " expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    bad_key,
                    "relay.idempotency_record.v1",
                    "00000000-0000-0000-0000-000000000000",
                    "sha256-" + ("a" * 64),
                    200,
                    "2026-05-17T00:00:00Z",
                    "2026-05-18T00:00:00Z",
                ),
            )


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idempotency_records_rejects_non_canonical_request_digest(
    tmp_path: Path,
) -> None:
    """request_digest CHECK ``^sha256-[0-9a-f]{64}$`` rejects the legacy
    ``sha256:<hex>`` colon form.
    """
    db_path = tmp_path / "sidecar.db"
    await _bootstrap(db_path)
    good_key = "01ARZ3NDEKTSV4RRFFQ69G5FAV"  # canonical Crockford ULID
    assert re.fullmatch(r"^[0-9A-HJKMNP-TV-Z]{26}$", good_key)
    async with aiosqlite.connect(str(db_path)) as conn:
        with pytest.raises(aiosqlite.IntegrityError):
            await conn.execute(
                "INSERT INTO idempotency_records "
                "(idempotency_key, schema_version, project_id, "
                " request_digest, response_status, first_seen_at, "
                " expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    good_key,
                    "relay.idempotency_record.v1",
                    "00000000-0000-0000-0000-000000000000",
                    "sha256:" + ("a" * 64),  # colon form, must be rejected
                    200,
                    "2026-05-17T00:00:00Z",
                    "2026-05-18T00:00:00Z",
                ),
            )


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idempotency_records_rejects_wrong_schema_version(
    tmp_path: Path,
) -> None:
    """schema_version CHECK pins to ``relay.idempotency_record.v1``."""
    db_path = tmp_path / "sidecar.db"
    await _bootstrap(db_path)
    good_key = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    async with aiosqlite.connect(str(db_path)) as conn:
        with pytest.raises(aiosqlite.IntegrityError):
            await conn.execute(
                "INSERT INTO idempotency_records "
                "(idempotency_key, schema_version, project_id, "
                " request_digest, response_status, first_seen_at, "
                " expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    good_key,
                    "relay.idempotency_record.v2",  # wrong pin
                    "00000000-0000-0000-0000-000000000000",
                    "sha256-" + ("a" * 64),
                    200,
                    "2026-05-17T00:00:00Z",
                    "2026-05-18T00:00:00Z",
                ),
            )


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idempotency_records_accepts_canonical_row(tmp_path: Path) -> None:
    """Round-trip: a canonical-shape row inserts successfully."""
    db_path = tmp_path / "sidecar.db"
    await _bootstrap(db_path)
    good_key = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.execute(
            "INSERT INTO idempotency_records "
            "(idempotency_key, schema_version, project_id, "
            " request_digest, response_status, first_seen_at, "
            " expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                good_key,
                "relay.idempotency_record.v1",
                "00000000-0000-0000-0000-000000000000",
                "sha256-" + ("a" * 64),
                201,
                "2026-05-17T00:00:00Z",
                "2026-05-18T00:00:00Z",
            ),
        )
        await conn.commit()
        async with conn.execute(
            "SELECT idempotency_key, schema_version, request_digest "
            "FROM idempotency_records WHERE idempotency_key = ?",
            (good_key,),
        ) as cur:
            row = await cur.fetchone()
    assert row is not None
    assert row[0] == good_key
    assert row[1] == "relay.idempotency_record.v1"
    assert row[2] == "sha256-" + ("a" * 64)
