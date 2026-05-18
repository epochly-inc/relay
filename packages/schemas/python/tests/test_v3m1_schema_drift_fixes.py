"""V3M1-F08 (2026-05-18): schema-drift fixes.

Per spec authority three drifts are corrected by this feature:

  VAL-V3M1-023  ``failed_assertion_ids`` aligned to ``text[]`` in the
                canonical Postgres DDL (spec line 2958 -- the spec types
                this column as ``text[] not null default '{}'``; the
                pre-fix Postgres DDL at
                ``packages/schemas/sql/0003a_canonical_run_results_and_gates.sql:98``
                used ``jsonb``). The sidecar SQLite mirror has no native
                array type and therefore stays TEXT (comma-separated)
                with documented mapping in the new sidecar migration
                header.

  VAL-V3M1-024  ``gate_rounds.initiated_by`` restricted to the spec
                4-value enum {control_plane, cron, user, remediation}
                (spec §A.4 line 3035). The pre-fix Postgres DDL widened
                this to a 6-value enum
                {..., submission, admin_override} -- those two values
                are dropped and pre-existing rows that carry either are
                data-migrated to ``control_plane`` (the closest spec
                value for first-round / forced-restart initiation).

  VAL-V3M1-025  ``apps/local-sidecar/migrations/0017_explain.sql``
                header carries a supersession annotation pointing at
                ``0023_audit_r3_schema_alignment.sql`` so future readers
                of the 0017 file understand that its narrow
                ``reviewer_decision`` CHECK at lines 64-66 was widened
                by 0023 to include ``pending``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]
_PG_MIGRATION = (
    _REPO_ROOT / "packages" / "schemas" / "sql" / "0016_v3_schema_drift_fixes.sql"
)
_SIDECAR_MIGRATION = (
    _REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "migrations"
    / "0029_v3_schema_drift_fixes.sql"
)
_SIDECAR_0017_MIGRATION = (
    _REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "migrations"
    / "0017_explain.sql"
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# VAL-V3M1-023: failed_assertion_ids aligned to text[] (spec authority)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_val_v3m1_023_pg_failed_assertion_ids_altered_to_text_array() -> None:
    """The Postgres migration ALTERs gate_decisions.failed_assertion_ids
    from jsonb (the historical 0003a shape at line 98) to ``text[]``
    (the spec-mandated shape at spec line 2958). The migration must
    carry a USING clause that unwraps the existing jsonb array elements
    into the new text[] column so existing rows survive the type change.
    """
    text = _read(_PG_MIGRATION).lower()
    # ALTER COLUMN statement to text[]
    assert re.search(
        r"alter\s+table\s+gate_decisions\s+"
        r"alter\s+column\s+failed_assertion_ids\s+"
        r"(set\s+data\s+)?type\s+text\[\]",
        text,
    ), (
        "VAL-V3M1-023: ALTER TABLE gate_decisions ALTER COLUMN "
        "failed_assertion_ids TYPE text[] missing from "
        "packages/schemas/sql/0016_v3_schema_drift_fixes.sql"
    )
    # USING clause to convert jsonb -> text[]; we need any pattern that
    # unwraps the jsonb array into a text[] (typically array(select
    # jsonb_array_elements_text(...))).
    assert "using" in text, (
        "VAL-V3M1-023: ALTER ... TYPE text[] must include a USING clause "
        "to convert the existing jsonb array data into text[]"
    )
    assert (
        "jsonb_array_elements_text" in text
        or "jsonb_to_text_array" in text
    ), (
        "VAL-V3M1-023: USING clause must reference "
        "jsonb_array_elements_text (or equivalent unwrapper) to convert "
        "the existing jsonb array into text[]"
    )


@pytest.mark.plumbing
def test_val_v3m1_023_sidecar_failed_assertion_ids_mapping_documented() -> None:
    """The sidecar SQLite mirror cannot use a native array type. The
    sidecar migration must explicitly document that
    ``failed_assertion_ids`` stays TEXT (comma-separated) on the OSS
    SQLite profile so the Pydantic layer (list[str]) bridges the two
    tiers consistently. The mapping rationale must appear in the
    sidecar migration header.
    """
    text = _read(_SIDECAR_MIGRATION).lower()
    assert "failed_assertion_ids" in text, (
        "VAL-V3M1-023: sidecar migration must mention "
        "failed_assertion_ids to document the cross-tier mapping"
    )
    # The mapping note must explain SQLite has no native array type.
    assert "comma" in text or "text" in text, (
        "VAL-V3M1-023: sidecar migration must document the "
        "comma-separated TEXT mapping"
    )
    # Reference the cross-tier counterpart so readers can find both.
    assert "0016_v3_schema_drift_fixes.sql" in text or "text[]" in text, (
        "VAL-V3M1-023: sidecar migration must cross-reference the "
        "Postgres counterpart (0016_v3_schema_drift_fixes.sql) or the "
        "canonical text[] type"
    )


# ---------------------------------------------------------------------------
# VAL-V3M1-024: gate_rounds.initiated_by restricted to spec 4-value enum
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_val_v3m1_024_pg_initiated_by_check_restricted_to_four_values() -> None:
    """The Postgres migration must DROP the pre-existing
    gate_rounds_initiated_by CHECK constraint (which currently widens
    to 6 values per 0003a:209-213) and ADD a new CHECK that restricts
    initiated_by to exactly the spec 4-value enum
    {control_plane, cron, user, remediation}.
    """
    text = _read(_PG_MIGRATION)
    lower = text.lower()
    # DROP the widened constraint
    assert (
        "drop constraint" in lower
        and "gate_rounds" in lower
        and "initiated_by" in lower
    ), (
        "VAL-V3M1-024: migration must DROP the widened "
        "gate_rounds_initiated_by_check constraint"
    )
    # ADD a new CHECK with exactly the 4 spec values
    assert re.search(
        r"check\s*\(\s*initiated_by\s+in\s*\(\s*"
        r"'control_plane'\s*,\s*'cron'\s*,\s*'user'\s*,\s*'remediation'\s*\)\s*\)",
        lower,
    ), (
        "VAL-V3M1-024: ADDed CHECK must restrict initiated_by to the "
        "exact 4-value spec enum {control_plane, cron, user, "
        "remediation}"
    )
    # Forbid the widened values from appearing in the new CHECK.
    # Use an exclusion search across the lines that introduce the new
    # CHECK to avoid false-positives on the data-migration UPDATE.
    add_check_match = re.search(
        r"add\s+constraint[^;]*check\s*\([^;]*initiated_by[^;]*\)",
        lower,
        flags=re.DOTALL,
    )
    assert add_check_match is not None, (
        "VAL-V3M1-024: could not locate the ADD CONSTRAINT ... CHECK "
        "block for initiated_by"
    )
    add_check = add_check_match.group(0)
    assert "'submission'" not in add_check, (
        "VAL-V3M1-024: ADDed CHECK must NOT include 'submission' "
        "(widened value being removed)"
    )
    assert "'admin_override'" not in add_check, (
        "VAL-V3M1-024: ADDed CHECK must NOT include 'admin_override' "
        "(widened value being removed)"
    )


@pytest.mark.plumbing
def test_val_v3m1_024_pg_data_migrates_widened_values_to_control_plane() -> None:
    """The Postgres migration must data-migrate any existing rows
    carrying ``submission`` or ``admin_override`` to ``control_plane``
    BEFORE adding the restrictive CHECK -- otherwise the ADD CONSTRAINT
    will fail on pre-existing rows.
    """
    text = _read(_PG_MIGRATION).lower()
    assert re.search(
        r"update\s+gate_rounds\s+set\s+initiated_by\s*=\s*'control_plane'",
        text,
    ), (
        "VAL-V3M1-024: migration must contain "
        "UPDATE gate_rounds SET initiated_by = 'control_plane' ..."
    )
    assert "'submission'" in text and "'admin_override'" in text, (
        "VAL-V3M1-024: data migration WHERE clause must enumerate "
        "both 'submission' and 'admin_override' for translation"
    )


@pytest.mark.plumbing
def test_val_v3m1_024_sidecar_initiated_by_check_restricted_to_four_values() -> None:
    """The sidecar SQLite mirror must perform the equivalent CHECK
    restriction. SQLite cannot ALTER an existing CHECK in place; the
    migration uses the canonical recreate-via-rename idiom (rename
    old table, CREATE new, INSERT SELECT with data-migrated values,
    DROP old).
    """
    text = _read(_SIDECAR_MIGRATION).lower()
    # Data migration: UPDATE old rows OR an INSERT SELECT with CASE
    # that maps submission/admin_override -> control_plane.
    assert (
        re.search(
            r"update\s+gate_rounds\s+set\s+initiated_by\s*=\s*'control_plane'",
            text,
        )
        or (
            "case" in text
            and "'submission'" in text
            and "'admin_override'" in text
            and "'control_plane'" in text
        )
    ), (
        "VAL-V3M1-024: sidecar migration must data-migrate rows where "
        "initiated_by IN ('submission','admin_override') to "
        "'control_plane' (either via UPDATE or INSERT SELECT CASE "
        "during table-rebuild)"
    )
    # Final shape carries the 4-value CHECK.
    assert re.search(
        r"check\s*\(\s*initiated_by\s+in\s*\(\s*"
        r"'control_plane'\s*,\s*'cron'\s*,\s*'user'\s*,\s*'remediation'\s*\)\s*\)",
        text,
    ), (
        "VAL-V3M1-024: sidecar migration final CHECK must enumerate "
        "exactly the 4 spec values"
    )


# ---------------------------------------------------------------------------
# VAL-V3M1-025: 0017_explain.sql carries supersession annotation
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_val_v3m1_025_sidecar_0017_explain_header_annotated_as_superseded() -> None:
    """The header of apps/local-sidecar/migrations/0017_explain.sql
    must include a supersession annotation pointing at
    0023_audit_r3_schema_alignment.sql so future readers know its
    narrow reviewer_decision CHECK at lines 64-66 was widened by 0023.
    """
    text = _read(_SIDECAR_0017_MIGRATION)
    # Look at the header block (top 30 lines) so the annotation is
    # discoverable WITHOUT scrolling to the body.
    header = "\n".join(text.splitlines()[:30])
    assert "SUPERSEDED BY 0023_audit_r3_schema_alignment.sql" in header, (
        "VAL-V3M1-025: 0017_explain.sql header must contain the "
        "exact marker 'SUPERSEDED BY 0023_audit_r3_schema_alignment.sql'"
    )
    # And the rationale -- it must mention reviewer_decision (the
    # specific CHECK that was widened).
    assert "reviewer_decision" in header, (
        "VAL-V3M1-025: 0017_explain.sql supersession annotation must "
        "explain that the reviewer_decision CHECK was widened by 0023"
    )
