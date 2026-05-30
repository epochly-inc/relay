"""W8.2 gate-engine invariants checker (VAL-W8-040).

Per VAL-W8-040 the ``rly verify-self`` runner asserts that the W8.2
canonical write path is wired correctly. Concretely: the SQLite
migration that creates the gate_decisions writer enforcement triggers
(role gate, immutability, evidence-bundle FK, signature non-empty,
bundle-manifest-match) MUST be present at
``apps/local-sidecar/migrations/0009_gate_decision_writer.sql``. Every
required trigger declaration is asserted BOTH by name AND by body: a
missing trigger declaration is one finding; a trigger whose header is
present but whose body no longer enforces the invariant (no
``RAISE(ABORT, ...)``) is ALSO one finding. A name-only grep is vacuous
(VAL-ISO-036) -- a neutered trigger body would silently pass -- so the
check parses each trigger block from its ``CREATE TRIGGER`` header to
its terminating ``END;`` and asserts the enforcement primitive is
present.

The check is text-only against the migration file. No sidecar needs to
be running. A missing migration file produces one finding naming the
absent path. Per VAL-W5-031 deterministic output, findings sort by
``(file, line, code)``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from verify_self.finding_codes import (
    RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING,
)

from .util import Finding, suggested_fix_for

CHECK_NAME: Final[str] = "gate-engine-invariants"

# Path to the W8.2 migration, relative to the repo root.
_MIGRATION_REL_PATH: Final[str] = (
    "apps/local-sidecar/migrations/0009_gate_decision_writer.sql"
)

# Parent directory of the migration. When the directory itself is
# absent the check treats the repo as "not the relay tree" and emits
# zero findings (synthetic test trees do not need to mirror the
# canonical sidecar migration layout to exercise other verify-self
# checkers). When the directory IS present but the W8.2 migration
# file is absent, that IS a finding because the tree has the
# canonical sidecar structure and SHOULD include the W8.2 migration.
_MIGRATION_DIR_REL_PATH: Final[str] = "apps/local-sidecar/migrations"

# Required trigger declarations the migration MUST contain. Each
# trigger is asserted both by its canonical name AND by the presence of
# the enforcement primitive in its body. The migration source uses
# ``CREATE TRIGGER <name> ... BEGIN <body> END;`` and every enforcement
# trigger aborts an unauthorized write via ``RAISE(ABORT, ...)``. A
# name-only grep is vacuous (VAL-ISO-036): a trigger whose header is
# intact but whose body no longer aborts would silently pass. So the
# check parses each trigger block and asserts the body contains the
# enforcement primitive.
_REQUIRED_TRIGGERS: Final[tuple[str, ...]] = (
    "gate_decisions_role_check",
    "gate_decisions_no_update",
    "gate_decisions_no_delete",
    "gate_decisions_evidence_fk",
    "gate_decisions_signature_required",
    "gate_decisions_bundle_manifest_match",
)

# The enforcement primitive every gate-decisions guard trigger uses to
# reject an unauthorized / invalid write. SQLite raises and rolls back
# the statement via ``RAISE(ABORT, '<message>')``. Whitespace between
# ``RAISE`` and ``(`` is tolerated so a reformatted-but-equivalent body
# is not a false positive. ASCII case-insensitive (SQL keywords are not
# case sensitive).
_ENFORCEMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"RAISE\s*\(\s*ABORT", re.IGNORECASE
)


def _grep_trigger_line(text: str, trigger_name: str) -> int | None:
    """Return the 1-based line number of ``CREATE TRIGGER <name>``.

    Matches the canonical declaration form used by the migration:
    ``CREATE TRIGGER <trigger_name>`` (whitespace-tolerant). Returns
    None when the declaration is absent.
    """
    needle = f"CREATE TRIGGER {trigger_name}"
    for idx, line in enumerate(text.splitlines()):
        if needle in line:
            return idx + 1
    return None


def _trigger_body_enforces(text: str, trigger_name: str) -> bool:
    """Return True iff ``trigger_name``'s body contains the enforcement primitive.

    Extracts the trigger block from its ``CREATE TRIGGER <name>`` header
    through the first terminating ``END;`` and checks that the body
    issues ``RAISE(ABORT, ...)``. A trigger declared by name but with a
    neutered / no-op body (VAL-ISO-036) returns False. Returns False
    when the header is absent (the caller treats absence as a finding
    via :func:`_grep_trigger_line`).
    """
    header = f"CREATE TRIGGER {trigger_name}"
    start = text.find(header)
    if start == -1:
        return False
    # The trigger block ends at the first ``END;`` following the header.
    # SQLite trigger bodies are ``BEGIN ... END;`` so the first ``END;``
    # after the header terminates this trigger. (No nested BEGIN/END in
    # the gate-decisions guard triggers.)
    end = text.find("END;", start)
    if end == -1:
        # Malformed / truncated block -- treat as non-enforcing.
        return False
    block = text[start:end]
    return _ENFORCEMENT_RE.search(block) is not None


def run(repo_root: Path) -> tuple[str, list[Finding]]:
    """Run the gate-engine-invariants check.

    Returns ``(check_name, findings)`` sorted by ``(file, line, code)``.
    """
    findings: list[Finding] = []
    migration_dir = repo_root / _MIGRATION_DIR_REL_PATH
    if not migration_dir.is_dir():
        # The synthetic test trees the verify-self plumbing suite
        # constructs don't mirror the canonical sidecar layout. When
        # the migration directory itself is absent treat the repo as
        # "not the relay tree" and emit zero findings; the W8.2 guard
        # is moot until the canonical sidecar tree exists.
        return CHECK_NAME, findings
    migration_path = repo_root / _MIGRATION_REL_PATH
    if not migration_path.is_file():
        findings.append(
            Finding(
                file=_MIGRATION_REL_PATH,
                line=1,
                code=RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING,
                suggested_fix=suggested_fix_for(
                    RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING
                ),
                pattern="<migration file absent>",
            )
        )
    else:
        try:
            text = migration_path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        for trigger_name in _REQUIRED_TRIGGERS:
            line = _grep_trigger_line(text, trigger_name)
            if line is None:
                # The trigger declaration is entirely absent.
                findings.append(
                    Finding(
                        file=_MIGRATION_REL_PATH,
                        line=1,
                        code=RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING,
                        suggested_fix=suggested_fix_for(
                            RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING
                        ),
                        pattern=f"CREATE TRIGGER {trigger_name}",
                    )
                )
            elif not _trigger_body_enforces(text, trigger_name):
                # The trigger header is present but its body no longer
                # issues RAISE(ABORT, ...) -- the invariant is declared
                # but not enforced (VAL-ISO-036). Report on the header
                # line so the finding points at the neutered trigger.
                findings.append(
                    Finding(
                        file=_MIGRATION_REL_PATH,
                        line=line,
                        code=RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING,
                        suggested_fix=suggested_fix_for(
                            RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING
                        ),
                        pattern=(
                            f"CREATE TRIGGER {trigger_name} "
                            "(body does not RAISE(ABORT) - invariant not "
                            "enforced)"
                        ),
                    )
                )
    findings.sort(key=lambda f: (f.file, f.line, f.code))
    return CHECK_NAME, findings


__all__ = ["CHECK_NAME", "run"]
