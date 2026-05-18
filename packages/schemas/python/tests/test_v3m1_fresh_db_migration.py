"""V3M1-F04 (2026-05-18): §Y FK chain repair across the 6 OSS FK refs
that target the undefined ``orgs`` and ``users`` identity tables.

The §V identity tables (``orgs``, ``users``, ``org_memberships``,
``project_keys``, ``ci_tokens``, ``api_tokens``, ``auditor_tokens``,
``token_revocations``) are deliberately deferred to private
``relay-platform/`` per ``boundaries.md`` (DEFERRED #1). The OSS
``relay/`` schema therefore CANNOT carry inline ``REFERENCES orgs(...)``
or ``REFERENCES users(...)`` -- a fresh Postgres database that applies
``packages/schemas/sql/*.sql`` in order will fail with
``relation "orgs" does not exist`` (or the equivalent for ``users``)
the moment the offending CREATE TABLE runs.

V3M1-F04 resolves this by adding a new migration
``0013_v3_fk_chain_repair.sql`` that:

  * DROPs the inline FK constraint from each of the 6 columns.
  * DROPs the NOT NULL marker on the two columns that currently carry it
    (``evidence_legal_holds.org_id``, ``evidence_legal_holds.imposed_by_user_id``)
    because their referenced row cannot exist in OSS.
  * RETAINS the ``uuid`` column type so private ``relay-platform`` can
    re-attach the FK to its own ``users``/``orgs`` tables in a follow-up
    migration without a destructive column rewrite.

This test locks in:

  VAL-V3M1-007  Catalog of all 6 FK refs in the new migration header.
  VAL-V3M1-008  Migration drops the FK constraint from every one of the 6
                ref sites and drops NOT NULL on the two that carry it.
  VAL-V3M1-009  Fresh-DB migration helper script exists and is executable.
  VAL-V3M1-010  ``0005_legal_holds.sql`` doc comment at the old FK
                description (lines 37-43 in the pre-fix tree) no longer
                claims the FKs are added conditionally via DO $$ blocks;
                the rewritten comment matches the post-fix DDL reality.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SQL_DIR = _REPO_ROOT / "packages" / "schemas" / "sql"
_FK_REPAIR_MIGRATION = _SQL_DIR / "0013_v3_fk_chain_repair.sql"
_LEGAL_HOLDS_MIGRATION = _SQL_DIR / "0005_legal_holds.sql"
_HUMAN_OVERSIGHT_MIGRATION = _SQL_DIR / "0006_human_oversight.sql"
_CLI_INVOCATIONS_MIGRATION = _SQL_DIR / "0011_cli_invocations.sql"
_FRESH_DB_SCRIPT = _REPO_ROOT / "scripts" / "fresh-db-migrate.sh"


# Canonical catalog of the 6 OSS FK references to undefined identity
# tables. Each entry: (sql file, table, column, NOT-NULL pre-fix?, target
# identity table). Kept in test data so assertions are checked, not just
# documented in a comment.
_FK_CATALOG: tuple[tuple[Path, str, str, bool, str], ...] = (
    (_LEGAL_HOLDS_MIGRATION, "evidence_legal_holds", "org_id", True, "orgs"),
    (
        _LEGAL_HOLDS_MIGRATION,
        "evidence_legal_holds",
        "imposed_by_user_id",
        True,
        "users",
    ),
    (
        _LEGAL_HOLDS_MIGRATION,
        "evidence_legal_holds",
        "released_by_user_id",
        False,
        "users",
    ),
    (
        _HUMAN_OVERSIGHT_MIGRATION,
        "human_oversight_events",
        "actor_user_id",
        False,
        "users",
    ),
    (
        _HUMAN_OVERSIGHT_MIGRATION,
        "data_provenance_records",
        "acquired_by_user_id",
        False,
        "users",
    ),
    (
        _CLI_INVOCATIONS_MIGRATION,
        "cli_invocations",
        "invoker_user_id",
        False,
        "users",
    ),
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# VAL-V3M1-007: catalog of all 6 FK refs documented in the new migration
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_val_v3m1_007_fk_repair_migration_exists() -> None:
    """The new migration must exist at the slot pinned in boundaries.md."""
    assert _FK_REPAIR_MIGRATION.exists(), (
        "VAL-V3M1-007: packages/schemas/sql/0013_v3_fk_chain_repair.sql "
        "missing -- slot pinned for m1-f04 per boundaries.md"
    )


@pytest.mark.plumbing
def test_val_v3m1_007_catalog_documents_all_6_sites() -> None:
    """The migration's header must enumerate all 6 catalog entries by
    table.column form so a future reader can audit coverage without
    cross-referencing the rest of the tree.
    """
    header = _read(_FK_REPAIR_MIGRATION)
    for _path, table, column, _not_null, _target in _FK_CATALOG:
        assert f"{table}.{column}" in header, (
            f"VAL-V3M1-007: catalog entry '{table}.{column}' missing "
            f"from 0013_v3_fk_chain_repair.sql header"
        )
    # Both identity table names must appear so the reader knows why we
    # are dropping the FKs (no orgs/users tables in OSS).
    assert "orgs" in header, "VAL-V3M1-007: header must mention 'orgs'"
    assert "users" in header, "VAL-V3M1-007: header must mention 'users'"


# ---------------------------------------------------------------------------
# VAL-V3M1-008: drop FK + drop NOT NULL (column stays uuid for forward
# compatibility with §V when relay-platform attaches its own FK)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_val_v3m1_008_drops_fk_constraint_for_every_site() -> None:
    """For each of the 6 catalog entries the migration must DROP the
    Postgres-auto-named ``{table}_{column}_fkey`` constraint.
    """
    text = _read(_FK_REPAIR_MIGRATION).lower()
    for _path, table, column, _not_null, _target in _FK_CATALOG:
        constraint = f"{table}_{column}_fkey"
        pattern = (
            rf"alter\s+table\s+{re.escape(table)}\s+drop\s+constraint"
            rf"\s+if\s+exists\s+{re.escape(constraint)}\b"
        )
        assert re.search(pattern, text), (
            f"VAL-V3M1-008: missing 'ALTER TABLE {table} DROP CONSTRAINT "
            f"IF EXISTS {constraint}' in 0013_v3_fk_chain_repair.sql"
        )


@pytest.mark.plumbing
def test_val_v3m1_008_drops_not_null_on_currently_required_columns() -> None:
    """The two columns currently NOT NULL (``evidence_legal_holds.org_id``
    and ``evidence_legal_holds.imposed_by_user_id``) MUST be dropped to
    NULLABLE because their target rows cannot exist in OSS.
    """
    text = _read(_FK_REPAIR_MIGRATION).lower()
    for _path, table, column, not_null, _target in _FK_CATALOG:
        if not not_null:
            continue
        pattern = (
            rf"alter\s+table\s+{re.escape(table)}\s+alter\s+column"
            rf"\s+{re.escape(column)}\s+drop\s+not\s+null\b"
        )
        assert re.search(pattern, text), (
            f"VAL-V3M1-008: missing 'ALTER TABLE {table} ALTER COLUMN "
            f"{column} DROP NOT NULL' in 0013_v3_fk_chain_repair.sql"
        )


@pytest.mark.plumbing
def test_val_v3m1_008_does_not_recreate_orgs_or_users_tables() -> None:
    """Boundary check -- the §V identity tables are explicitly deferred
    to relay-platform. The repair migration must NOT create them.
    """
    text = _read(_FK_REPAIR_MIGRATION).lower()
    # Strip comment lines (-- ...) before scanning so the header's
    # narrative mention of "orgs"/"users" does not trigger a false match.
    body = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("--")
    )
    assert not re.search(r"create\s+table\s+(if\s+not\s+exists\s+)?orgs\b", body), (
        "VAL-V3M1-008: boundary violation -- 0013_v3_fk_chain_repair.sql "
        "must not CREATE TABLE orgs (deferred to relay-platform)"
    )
    assert not re.search(r"create\s+table\s+(if\s+not\s+exists\s+)?users\b", body), (
        "VAL-V3M1-008: boundary violation -- 0013_v3_fk_chain_repair.sql "
        "must not CREATE TABLE users (deferred to relay-platform)"
    )


# ---------------------------------------------------------------------------
# VAL-V3M1-009: fresh-DB migration helper script exists + is runnable
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_val_v3m1_009_fresh_db_script_exists_and_is_executable() -> None:
    """``scripts/fresh-db-migrate.sh`` must exist, be executable, and
    have a clear shell shebang. The script applies every
    ``packages/schemas/sql/*.sql`` migration in lexicographic order
    against a temp database and exits 0 on success.
    """
    assert _FRESH_DB_SCRIPT.exists(), (
        "VAL-V3M1-009: scripts/fresh-db-migrate.sh missing"
    )
    text = _read(_FRESH_DB_SCRIPT)
    assert text.startswith("#!"), (
        "VAL-V3M1-009: scripts/fresh-db-migrate.sh missing shebang"
    )
    mode = _FRESH_DB_SCRIPT.stat().st_mode
    assert mode & stat.S_IXUSR, (
        "VAL-V3M1-009: scripts/fresh-db-migrate.sh not executable by owner"
    )
    # Sanity-check the script references the migrations directory it is
    # meant to walk.
    assert "packages/schemas/sql" in text, (
        "VAL-V3M1-009: script does not reference packages/schemas/sql"
    )


# ---------------------------------------------------------------------------
# VAL-V3M1-010: 0005_legal_holds.sql doc comment aligned with post-fix DDL
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_val_v3m1_010_legal_holds_doc_comment_no_longer_claims_conditional() -> None:
    """The pre-fix doc comment at ``0005_legal_holds.sql`` lines 37-43
    claimed the FKs are added conditionally via DO $$ blocks. The actual
    DDL at lines 52/58/65 uses inline REFERENCES. The post-fix comment
    must NOT continue to claim the conditional-DO-block treatment.
    """
    text = _read(_LEGAL_HOLDS_MIGRATION)
    # The pre-fix marker phrase that must be removed/rewritten.
    forbidden = "added conditionally via DO $$ blocks"
    assert forbidden not in text, (
        "VAL-V3M1-010: 0005_legal_holds.sql still claims FKs are added "
        f"conditionally via DO $$ blocks (forbidden phrase: {forbidden!r}). "
        "Rewrite the comment to describe the post-fix reality where FKs "
        "are dropped by 0013_v3_fk_chain_repair.sql."
    )


@pytest.mark.plumbing
def test_val_v3m1_010_legal_holds_doc_comment_cites_repair_migration() -> None:
    """The rewritten comment in ``0005_legal_holds.sql`` must point at
    ``0013_v3_fk_chain_repair.sql`` so a future reader following the
    chain finds the rationale for the dropped constraints.
    """
    text = _read(_LEGAL_HOLDS_MIGRATION)
    assert "0013_v3_fk_chain_repair.sql" in text, (
        "VAL-V3M1-010: 0005_legal_holds.sql doc comment must reference "
        "0013_v3_fk_chain_repair.sql so the FK rationale chain is "
        "discoverable from the parent migration"
    )
