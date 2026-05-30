"""ISO-036 regression: gate-engine-invariants must verify trigger BODY.

Reproduces VAL-ISO-036. The gate-engine-invariants checker
(``relay_cli.invariants.gate_engine_invariants.run``) asserts that the
W8.2 migration declares six enforcement triggers, but it only greps for
the literal ``CREATE TRIGGER <name>`` header. It never verifies the
trigger BODY enforces the invariant. A trigger whose header is intact
but whose body has been neutered (no ``RAISE(ABORT, ...)``) still passes
the check -- the invariant guard is vacuous.

RED at base commit (neutered trigger passes); GREEN after the check
asserts each required trigger's body contains the enforcement primitive.

The check reads a fixed canonical migration path
(``apps/local-sidecar/migrations/0009_gate_decision_writer.sql``) under
the repo root, so the test builds a synthetic repo tree with that exact
layout and writes a tampered migration into it.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path

import pytest
from relay_cli.invariants import gate_engine_invariants
from verify_self.finding_codes import (
    RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
_MIGRATION_REL = "apps/local-sidecar/migrations/0009_gate_decision_writer.sql"


def _read_canonical_migration() -> str:
    """Return the real committed W8.2 migration text."""
    return (REPO_ROOT / _MIGRATION_REL).read_text(encoding="utf-8")


def _write_migration(repo_root: Path, text: str) -> None:
    """Write ``text`` to the canonical migration path under ``repo_root``."""
    mig = repo_root / _MIGRATION_REL
    mig.parent.mkdir(parents=True, exist_ok=True)
    mig.write_text(text, encoding="utf-8")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-036")
def test_intact_migration_passes(tmp_path: Path) -> None:
    """The real, intact migration MUST pass (no findings).

    Guards against the fix becoming over-broad: the genuine migration
    keeps every trigger body intact and must not be flagged.
    """
    _write_migration(tmp_path, _read_canonical_migration())
    _name, findings = gate_engine_invariants.run(tmp_path)
    assert findings == [], (
        "intact migration must produce no findings; got " + repr(findings)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-036")
def test_neutered_trigger_body_is_detected(tmp_path: Path) -> None:
    """A trigger whose header is intact but whose body is a no-op fails.

    This is the load-bearing regression: prior to the fix the grep
    finds ``CREATE TRIGGER gate_decisions_role_check`` and reports no
    finding even though the trigger no longer RAISE(ABORT)s on an
    unauthorized writer.
    """
    text = _read_canonical_migration()
    # Replace the role-check trigger's enforcement body with a no-op
    # (SELECT 1) while keeping the CREATE TRIGGER header and the trigger
    # structure intact. The header-only grep still matches the name.
    original_body = (
        "SELECT RAISE(ABORT, 'gate_decisions_role_check: only "
        "relay_gate_engine role may INSERT into gate_decisions');"
    )
    assert original_body in text, "fixture precondition: role-check body present"
    neutered = text.replace(original_body, "SELECT 1;")
    assert "CREATE TRIGGER gate_decisions_role_check" in neutered, (
        "neutered fixture must keep the trigger header"
    )
    assert "RAISE(ABORT" not in neutered.split(
        "CREATE TRIGGER gate_decisions_role_check"
    )[1].split("END;")[0], "neutered role-check body must have no RAISE(ABORT)"

    _write_migration(tmp_path, neutered)
    _name, findings = gate_engine_invariants.run(tmp_path)

    assert any(
        f.code == RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING
        and "gate_decisions_role_check" in f.pattern
        for f in findings
    ), (
        "expected a finding for the neutered gate_decisions_role_check "
        "body; got " + repr(findings)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-036")
def test_missing_trigger_still_detected(tmp_path: Path) -> None:
    """An entirely missing trigger declaration is still a finding.

    Guards against the fix regressing the original name-presence check.
    """
    text = _read_canonical_migration()
    # Remove the no_delete trigger declaration entirely.
    marker = "DROP TRIGGER IF EXISTS gate_decisions_no_delete;"
    assert marker in text, "fixture precondition: no_delete trigger present"
    head, tail = text.split(marker, 1)
    # Drop everything from the marker through the terminating END; of
    # that trigger so the trigger name no longer appears.
    rest = tail.split("END;", 1)[1]
    mutated = head + rest
    assert "gate_decisions_no_delete" not in mutated, (
        "mutated fixture must not mention the removed trigger"
    )

    _write_migration(tmp_path, mutated)
    _name, findings = gate_engine_invariants.run(tmp_path)

    assert any(
        f.code == RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING
        and "gate_decisions_no_delete" in f.pattern
        for f in findings
    ), (
        "expected a finding for the missing gate_decisions_no_delete "
        "trigger; got " + repr(findings)
    )
