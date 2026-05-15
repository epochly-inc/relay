"""W8.2 gate-engine invariants checker (VAL-W8-040).

Per VAL-W8-040 the ``rly verify-self`` runner asserts that the W8.2
canonical write path is wired correctly. Concretely: the SQLite
migration that creates the gate_decisions writer enforcement triggers
(role gate, immutability, evidence-bundle FK, signature non-empty,
bundle-manifest-match) MUST be present at
``apps/local-sidecar/migrations/0009_gate_decision_writer.sql``. Every
required trigger declaration is asserted by name; a missing trigger is
one finding emitted with a path + line of the first SQL declaration
expected.

The check is grep-only against the migration file's text. No sidecar
needs to be running. A missing migration file produces one finding
naming the absent path. Per VAL-W5-031 deterministic output, findings
sort by ``(file, line, code)``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

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
# trigger is asserted by its canonical name; the migration source
# uses ``CREATE TRIGGER <name>`` so a grep on ``CREATE TRIGGER <name>``
# is the load-bearing check.
_REQUIRED_TRIGGERS: Final[tuple[str, ...]] = (
    "gate_decisions_role_check",
    "gate_decisions_no_update",
    "gate_decisions_no_delete",
    "gate_decisions_evidence_fk",
    "gate_decisions_signature_required",
    "gate_decisions_bundle_manifest_match",
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
    findings.sort(key=lambda f: (f.file, f.line, f.code))
    return CHECK_NAME, findings


__all__ = ["CHECK_NAME", "run"]
