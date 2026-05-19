"""V3M1-F03 plumbing tests: sidecar ``audit_log_entries`` renamed to
``admin_override_audit`` (frees the canonical §V hosted name).

Covers VAL-V3M1-005 (rename exists, old name absent) and VAL-V3M1-006
(callers updated; production code carries zero ``audit_log_entries``
references in sidecar / gate / cli source paths).

Per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import aiosqlite
import pytest
from relay_sidecar.db import SidecarDatabase

REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------------------
# VAL-V3M1-005: new name present, old name absent in fresh-DB schema.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-005")
@pytest.mark.asyncio
async def test_admin_override_audit_table_exists_after_migrations(
    tmp_path: Path,
) -> None:
    """A fresh sidecar DB, after applying all migrations through 0026,
    has ``admin_override_audit`` and NOT ``audit_log_entries``."""
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path)
    await db.open()
    try:
        async with aiosqlite.connect(str(db_path)) as conn:
            async with conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name = 'admin_override_audit'"
            ) as cur:
                new = await cur.fetchone()
            async with conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name = 'audit_log_entries'"
            ) as cur:
                old = await cur.fetchone()
        assert new is not None, (
            "admin_override_audit table must exist after 0026 applies"
        )
        assert old is None, (
            "audit_log_entries table must NOT exist after 0026 applies "
            "(rename collision with §V hosted canonical name)"
        )
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-005")
@pytest.mark.asyncio
async def test_admin_override_audit_preserves_columns_and_constraints(
    tmp_path: Path,
) -> None:
    """All 16 columns from the original 0011 ``audit_log_entries`` shape
    are preserved on ``admin_override_audit`` (after audit-R3 dropped
    ``schema_version`` in 0023, leaving 15 columns)."""
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path)
    await db.open()
    try:
        async with (
            aiosqlite.connect(str(db_path)) as conn,
            conn.execute(
                "PRAGMA table_info(admin_override_audit)"
            ) as cur,
        ):
            cols = await cur.fetchall()
        col_names = {row[1] for row in cols}
        expected = {
            "audit_id",
            "project_id",
            "scope_type",
            "scope_id",
            "gate_id",
            "action",
            "actor_kind",
            "actor_identity_hash",
            "actor_role",
            "reason",
            "prior_round_id",
            "new_round_id",
            "manifest_commit_hash",
            "payload",
            "occurred_at",
        }
        missing = expected - col_names
        assert not missing, (
            f"admin_override_audit missing columns: {sorted(missing)}"
        )
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-005")
@pytest.mark.asyncio
async def test_admin_override_audit_reopen_reason_check_constraint(
    tmp_path: Path,
) -> None:
    """The ``admin_override_audit_reopen_reason_required`` CHECK is
    preserved from 0011: admin.reopen with empty reason is rejected at
    the SQL layer."""
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path)
    await db.open()
    try:
        async with aiosqlite.connect(str(db_path)) as conn:
            with pytest.raises(aiosqlite.IntegrityError):
                await conn.execute(
                    "INSERT INTO admin_override_audit ("
                    "  audit_id, scope_type, scope_id, gate_id, "
                    "  action, actor_kind, actor_identity_hash, "
                    "  actor_role, reason, manifest_commit_hash, "
                    "  occurred_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "11111111-1111-1111-1111-111111111111",
                        "run",
                        "22222222-2222-2222-2222-222222222222",
                        "33333333-3333-3333-3333-333333333333",
                        "admin.reopen",
                        "user",
                        "sha256-" + "0" * 64,
                        "org_admin",
                        "",
                        "sha256-" + "a" * 64,
                        "2026-05-18T12:00:00.000000Z",
                    ),
                )
                await conn.commit()
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# VAL-V3M1-006: grep guard -- zero production references to the old name.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M1-006")
def test_no_audit_log_entries_references_in_production_code() -> None:
    """Programmatic grep guard: no ``audit_log_entries`` matches in
    sidecar runtime source, gate engine source, or cli source.

    Test docstrings and contract assertions inside the renamed test
    files still cite the old name (that is documented in the contract
    as acceptable); only production code paths are checked here.
    """
    targets = [
        REPO_ROOT / "apps" / "local-sidecar" / "relay_sidecar",
        REPO_ROOT / "packages" / "gate" / "src",
        REPO_ROOT / "packages" / "cli" / "src",
    ]
    for target in targets:
        if not target.is_dir():
            continue
        result = subprocess.run(  # noqa: S603
            ["grep", "-rn", "audit_log_entries", str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        # grep exit 1 = zero matches, exit 0 = matches. We want exit 1.
        assert result.returncode == 1, (
            f"audit_log_entries references remain in {target}:\n"
            f"{result.stdout}"
        )
