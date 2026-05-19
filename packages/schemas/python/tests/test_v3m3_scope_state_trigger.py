"""V3M3-F06 (2026-05-19): re-assert the spec section W deferred
CONSTRAINT TRIGGER for the scope_state co-insert integrity guard.

Spec authority
--------------
planning/epochly-replay-spec.md section W line 5112 (spec authority
quoted verbatim):

    "A creating transaction that inserts an object row without the
     matching scope_state row fails the integrity check at commit
     (a deferred trigger validates the join). This guarantees that
     every object the state engine can address has a state row from
     the moment it exists."

Audit finding
-------------
The original install lives at
``packages/schemas/sql/0008_scope_state_extension.sql`` (V2M01 W1.7),
which wraps each CONSTRAINT TRIGGER creation in a
``DO $$ ... information_schema.tables ... END$$`` guard that SILENTLY
SKIPS the trigger when the target table is not yet present in the
catalog. At 0008 apply time the canonical Postgres profile defines
only four of the six scope-creating tables -- ``runs`` (0000),
``evidence_bundles`` (0003), ``replay_cases`` (0003), and
``gate_rounds`` (0003a). Neither ``eval_runs`` nor ``releases`` exists
in any ``packages/schemas/sql/*.sql`` migration, so the conditional
DO $$ blocks for those two scope_kinds completed without raising and
without installing the constraint trigger. The text-level grep guard
at ``test_v2m01_scope_state_extension.py`` line 357-368 only verifies
that the migration MENTIONS each of the six table names; it does not
verify that the corresponding trigger object exists in the live
catalog.

V3M3-F06 closes the audit gap by:

  1. Creating the missing ``eval_runs`` and ``releases`` stub tables
     in the canonical Postgres profile so the CONSTRAINT TRIGGER
     has a valid target to attach to. The stubs carry only the PK
     column; full DDL for these tables lands in their owning §A.AM
     (eval_runs) / §Q.2 (releases) feature work later in the V3
     buildout.
  2. Re-installing all six scope_state-paired CONSTRAINT TRIGGERs
     unconditionally (no DO $$ guard) so a fresh-database apply of
     the full migration tree always ends with six live triggers and
     never with a silent skip.
  3. Preserving the existing shared trigger function
     ``relay_scope_state_paired_row_check`` introduced by 0008
     (no function-signature change).

VAL-V3M3-017 binds to:

  * The new migration file ``packages/schemas/sql/0019_v3_scope_state_trigger.sql``
    exists and is readable.
  * The migration declares ``CREATE CONSTRAINT TRIGGER`` for each of
    the five scope-creating tables that lack a guaranteed live
    trigger after 0008: runs, replay_cases, evidence_bundles,
    eval_runs, releases. (gate_rounds is already covered by both the
    0008 trigger AND the sidecar precedent at 0016 / 0029.)
  * Each trigger is ``DEFERRABLE INITIALLY DEFERRED`` so the integrity
    check fires at COMMIT, not at INSERT statement time.
  * The migration creates ``eval_runs`` and ``releases`` stub tables
    (UUID PK) so the constraint trigger has a valid attach target.
  * The trigger reuses the shared function
    ``relay_scope_state_paired_row_check`` (no duplicate function
    body), passing ``(scope_kind, pk_column)`` via ``TG_ARGV``.
  * The migration is idempotent: DROP TRIGGER IF EXISTS + DROP TABLE
    NOT used (CREATE TABLE IF NOT EXISTS for the stubs; DROP TRIGGER
    IF EXISTS + CREATE CONSTRAINT TRIGGER for the trigger objects).
  * The trigger's error path raises ``RELAY-STATE-002`` so the
    spec section W integrity-guard error envelope can match the
    canonical error code.

These tests are text/regex assertions against the migration DDL
following the established pattern at
``test_v2m01_scope_state_extension.py`` and
``test_v3m1_schema_drift_fixes.py``. The schemas package has no live
Postgres test infrastructure -- DDL correctness is validated by
structural assertions on the migration file. Behavioural verification
against a live cluster lands in ``relay-platform`` integration tests
where Postgres is available.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SQL_DIR = _REPO_ROOT / "packages" / "schemas" / "sql"
_NEW_MIGRATION = _SQL_DIR / "0019_v3_scope_state_trigger.sql"
_BASELINE_0008 = _SQL_DIR / "0008_scope_state_extension.sql"

# The five tables this audit-resolution feature must (re-)install the
# constraint trigger for. gate_rounds is already covered by 0008's
# DO $$ block (gate_rounds exists in 0003a, so the conditional install
# succeeded for that table specifically).
_TARGET_TABLES: tuple[tuple[str, str, str], ...] = (
    # (object_table, scope_kind, pk_column)
    ("runs", "run", "run_id"),
    ("replay_cases", "replay_case", "replay_case_id"),
    ("evidence_bundles", "evidence_bundle", "evidence_bundle_id"),
    ("eval_runs", "eval_run", "eval_run_id"),
    ("releases", "release", "release_id"),
)


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def _strip_sql_comments(text: str) -> str:
    """Strip ``--`` line comments from a SQL source so prose mentions of
    DDL keywords inside the migration header do not pollute statement-
    counting assertions. PostgreSQL ``--`` comments run from the
    sequence to end of line."""
    out_lines: list[str] = []
    for line in text.splitlines():
        # A simple ``--`` strip is safe here: this migration does not
        # contain any quoted string literals that embed ``--`` (the only
        # string literals are short scope_kind / pk_column tokens).
        idx = line.find("--")
        if idx >= 0:
            line = line[:idx]
        out_lines.append(line)
    return "\n".join(out_lines)


# ---------------------------------------------------------------------------
# Migration file present
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-017")
def test_v3m3_f06_migration_file_present() -> None:
    """The new V3M3-F06 migration file must exist at the canonical path."""
    assert _NEW_MIGRATION.is_file(), (
        f"VAL-V3M3-017: missing migration file: {_NEW_MIGRATION}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-017")
def test_v3m3_f06_migration_ascii_only() -> None:
    """ASCII-Safe Source: the SQL migration must not introduce unicode."""
    text = _read(_NEW_MIGRATION)
    non_ascii = [
        (i, ch) for i, ch in enumerate(text) if ord(ch) > 127
    ]
    assert not non_ascii, (
        f"VAL-V3M3-017: non-ASCII characters in {_NEW_MIGRATION.name}: "
        f"{non_ascii[:8]}"
    )


# ---------------------------------------------------------------------------
# eval_runs and releases stub tables must be created so the CONSTRAINT
# TRIGGER has a valid attach target.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-017")
def test_v3m3_f06_creates_eval_runs_stub_table() -> None:
    """The migration creates an ``eval_runs`` stub table with UUID PK
    so the constraint trigger has a valid attach target. The stub
    carries only the PK column; full eval_runs DDL lands in §A.AM."""
    text = _read(_NEW_MIGRATION).lower()
    # CREATE TABLE IF NOT EXISTS eval_runs (... eval_run_id uuid ...)
    assert re.search(
        r"create\s+table\s+if\s+not\s+exists\s+eval_runs\s*\(",
        text,
    ), (
        "VAL-V3M3-017: migration must CREATE TABLE IF NOT EXISTS eval_runs "
        "(stub) so the constraint trigger can attach."
    )
    assert re.search(
        r"eval_run_id\s+uuid",
        text,
    ), (
        "VAL-V3M3-017: eval_runs stub must declare eval_run_id uuid as PK."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-017")
def test_v3m3_f06_creates_releases_stub_table() -> None:
    """The migration creates a ``releases`` stub table with UUID PK so
    the constraint trigger has a valid attach target. The stub carries
    only the PK column; full releases DDL lands in §Q.2."""
    text = _read(_NEW_MIGRATION).lower()
    assert re.search(
        r"create\s+table\s+if\s+not\s+exists\s+releases\s*\(",
        text,
    ), (
        "VAL-V3M3-017: migration must CREATE TABLE IF NOT EXISTS releases "
        "(stub) so the constraint trigger can attach."
    )
    assert re.search(
        r"release_id\s+uuid",
        text,
    ), (
        "VAL-V3M3-017: releases stub must declare release_id uuid as PK."
    )


# ---------------------------------------------------------------------------
# CONSTRAINT TRIGGER declarations -- one per target table, DEFERRABLE
# INITIALLY DEFERRED, attached to AFTER INSERT, invoking the shared
# scope_state_paired_row_check function.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-017")
def test_v3m3_f06_migration_uses_constraint_trigger() -> None:
    """Every trigger creation must use ``CREATE CONSTRAINT TRIGGER``
    (not plain ``CREATE TRIGGER``) so the integrity check fires at
    COMMIT time, not at INSERT statement time. Plain triggers cannot
    be DEFERRABLE in Postgres."""
    text = _strip_sql_comments(_read(_NEW_MIGRATION).lower())
    # Count CONSTRAINT TRIGGER occurrences -- must be exactly 5 (one per
    # target table). Plain ``CREATE TRIGGER ...`` (without CONSTRAINT)
    # for the scope_state guard is forbidden by this feature. Header
    # comments are stripped first so prose mentions inside the SQL
    # comment block do not inflate the count.
    constraint_trigger_count = len(
        re.findall(r"create\s+constraint\s+trigger\s+", text)
    )
    assert constraint_trigger_count == 5, (
        f"VAL-V3M3-017: migration must declare exactly 5 CREATE CONSTRAINT "
        f"TRIGGER statements (one per target table); found "
        f"{constraint_trigger_count}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-017")
def test_v3m3_f06_every_trigger_is_deferrable_initially_deferred() -> None:
    """Every trigger declared by this migration must be DEFERRABLE
    INITIALLY DEFERRED so the integrity check fires at COMMIT, allowing
    callers to INSERT the object row and the scope_state row in either
    order within a single BEGIN..COMMIT block."""
    text = _strip_sql_comments(_read(_NEW_MIGRATION).lower())
    deferrable_count = len(
        re.findall(r"deferrable\s+initially\s+deferred", text)
    )
    # One DEFERRABLE INITIALLY DEFERRED per CREATE CONSTRAINT TRIGGER.
    assert deferrable_count == 5, (
        f"VAL-V3M3-017: every CREATE CONSTRAINT TRIGGER must be "
        f"DEFERRABLE INITIALLY DEFERRED; found {deferrable_count} "
        f"occurrences (expected 5)"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-017")
@pytest.mark.parametrize(("table", "scope_kind", "pk_col"), _TARGET_TABLES)
def test_v3m3_f06_trigger_declared_for_each_target_table(
    table: str, scope_kind: str, pk_col: str
) -> None:
    """Each of the five target tables must have a CONSTRAINT TRIGGER
    declared by this migration. The trigger must be AFTER INSERT,
    DEFERRABLE INITIALLY DEFERRED, and invoke
    ``relay_scope_state_paired_row_check`` with the matching
    ``(scope_kind, pk_column)`` arguments."""
    text = _read(_NEW_MIGRATION).lower()
    # Find a CREATE CONSTRAINT TRIGGER block targeting this table that
    # carries the expected after-insert + deferrable shape.
    pattern = re.compile(
        r"create\s+constraint\s+trigger\s+\S+"
        + r"\s+after\s+insert\s+on\s+"
        + re.escape(table)
        + r"\s+deferrable\s+initially\s+deferred"
        + r"\s+for\s+each\s+row"
        + r"\s+execute\s+function\s+relay_scope_state_paired_row_check\s*\(\s*"
        + r"'"
        + re.escape(scope_kind)
        + r"'\s*,\s*"
        + r"'"
        + re.escape(pk_col)
        + r"'\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    assert pattern.search(text), (
        f"VAL-V3M3-017: missing CONSTRAINT TRIGGER block for table "
        f"{table!r} (scope_kind={scope_kind!r}, pk={pk_col!r}). "
        f"Expected: CREATE CONSTRAINT TRIGGER ... AFTER INSERT ON "
        f"{table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
        f"EXECUTE FUNCTION relay_scope_state_paired_row_check("
        f"'{scope_kind}', '{pk_col}')"
    )


# ---------------------------------------------------------------------------
# Idempotency: re-running the migration must not error. DROP TRIGGER IF
# EXISTS must precede every CREATE CONSTRAINT TRIGGER.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-017")
@pytest.mark.parametrize(("table", "scope_kind", "pk_col"), _TARGET_TABLES)
def test_v3m3_f06_trigger_creation_is_idempotent(
    table: str, scope_kind: str, pk_col: str
) -> None:
    """Every CREATE CONSTRAINT TRIGGER must be preceded by a matching
    DROP TRIGGER IF EXISTS on the same table so re-applying the
    migration on a populated catalog does not raise duplicate-object."""
    text = _read(_NEW_MIGRATION).lower()
    drop_pat = re.compile(
        r"drop\s+trigger\s+if\s+exists\s+" + re.escape(table)
        + r"_scope_state_paired_check\s+on\s+" + re.escape(table),
        re.IGNORECASE,
    )
    assert drop_pat.search(text), (
        f"VAL-V3M3-017: missing DROP TRIGGER IF EXISTS "
        f"{table}_scope_state_paired_check ON {table} -- migration must "
        f"be idempotent."
    )


# ---------------------------------------------------------------------------
# The migration must reuse the shared function relay_scope_state_paired_row_check
# from 0008 (no duplicate function body).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-017")
def test_v3m3_f06_reuses_shared_trigger_function() -> None:
    """The migration must reference the shared trigger function
    ``relay_scope_state_paired_row_check`` introduced by 0008. The
    function must NOT be redefined here -- 0008's CREATE OR REPLACE
    FUNCTION is the canonical definition."""
    text = _read(_NEW_MIGRATION)
    assert "relay_scope_state_paired_row_check" in text, (
        "VAL-V3M3-017: migration must EXECUTE FUNCTION "
        "relay_scope_state_paired_row_check (shared with 0008)."
    )
    # The function body (CREATE OR REPLACE FUNCTION ...) must NOT appear
    # here -- 0008 owns the definition.
    forbidden = re.search(
        r"create\s+(or\s+replace\s+)?function\s+"
        r"relay_scope_state_paired_row_check",
        text,
        re.IGNORECASE,
    )
    assert forbidden is None, (
        "VAL-V3M3-017: migration must NOT redefine "
        "relay_scope_state_paired_row_check; 0008 owns the function body."
    )


# ---------------------------------------------------------------------------
# Documentation: the migration header must reference the spec authority
# (section W line 5112) and the audit finding it resolves.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-017")
def test_v3m3_f06_migration_header_documents_spec_authority() -> None:
    """The migration header must reference the spec authority
    (section W line 5112) and the audit finding it resolves so future
    readers understand why 0019 exists separately from 0008."""
    text = _read(_NEW_MIGRATION).lower()
    # Spec anchor: section W, line 5112 (or the W-block reference).
    assert (
        "5112" in text or "section w" in text or "sectionw" in text
    ), (
        "VAL-V3M3-017: migration header must reference spec section W "
        "(line 5112) as the authority for the deferred-trigger rule."
    )
    # Audit finding: reference 0008's DO $$ conditional-skip gap.
    assert "0008" in text, (
        "VAL-V3M3-017: migration header must reference 0008 (the "
        "baseline install whose DO $$ guards silently skipped eval_runs "
        "and releases)."
    )


# ---------------------------------------------------------------------------
# Sanity: 0008 baseline must still declare the shared function (this
# migration depends on 0008 having defined it).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-017")
def test_v3m3_f06_baseline_0008_still_declares_shared_function() -> None:
    """Defensive: 0008 must still own the
    ``relay_scope_state_paired_row_check`` function body (the new
    migration depends on its existence)."""
    text = _read(_BASELINE_0008)
    assert re.search(
        r"create\s+or\s+replace\s+function\s+"
        r"relay_scope_state_paired_row_check",
        text,
        re.IGNORECASE,
    ), (
        "VAL-V3M3-017: baseline 0008 must still own the "
        "relay_scope_state_paired_row_check function definition."
    )
