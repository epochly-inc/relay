"""Per-case evidence binding for the eval runner.

Encodes CLAUDE.md keystone invariant #2 + VAL-W9-007 (contract.md
line 4132-4146): a per-case ``eval_results`` row whose evidence binding
is incomplete is written with ``status='invalid'``, NOT ``'passed'`` or
``'failed'``. The five anchors:

    (a) artifact_hash       SHA-256 of the input fixture
    (b) command_id          stable id of the evaluator invocation
        + exit_code         exit code returned by that invocation
    (c) span_ids            non-empty list of trace span ids
    (d) manifest_commit_hash  the manifest commit in force
    (e) assertion_id        which assertion this case evaluates

The runner consumes ``EvidenceBinding`` instances and calls
``validate_binding()`` before persisting. The returned
``EvidenceValidation`` carries the missing-field token used as
``eval_results.invalid_reason`` so the audit log can attribute the
``invalid`` outcome (per VAL-W9-007 "log entry citing the missing
binding").

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# sha256-<64 lowercase hex>. Mirrors the SQL CHECK in 0001_eval_runs.sql
# and packages/schemas/sql/0003_evidence_replay.sql line 46.
_SHA256_RE = re.compile(r"^sha256-[0-9a-f]{64}$")


class EvidenceFieldMissing(str):
    """Singleton-style sentinel set used as ``invalid_reason`` tokens.

    Implemented as a ``str`` subclass so the value is JSON-serialisable
    without bespoke encoder support and the assertion log lines stay
    grep-friendly.
    """


# Stable tokens. Tests assert these exact strings appear in the
# eval_results.invalid_reason column.
MISSING_ARTIFACT_HASH = EvidenceFieldMissing("missing:artifact_hash")
MISSING_COMMAND_ID = EvidenceFieldMissing("missing:command_id")
MISSING_EXIT_CODE = EvidenceFieldMissing("missing:exit_code")
MISSING_SPAN_IDS = EvidenceFieldMissing("missing:span_ids")
MISSING_MANIFEST_COMMIT_HASH = EvidenceFieldMissing("missing:manifest_commit_hash")
MISSING_ASSERTION_ID = EvidenceFieldMissing("missing:assertion_id")
MALFORMED_ARTIFACT_HASH = EvidenceFieldMissing("malformed:artifact_hash")
MALFORMED_MANIFEST_COMMIT_HASH = EvidenceFieldMissing(
    "malformed:manifest_commit_hash"
)


@dataclass(frozen=True, slots=True)
class EvidenceBinding:
    """Five-anchor evidence binding required by VAL-W9-007.

    A ``span_ids`` list of length zero counts as missing; an
    ``exit_code`` of ``0`` does NOT (zero is a valid exit code).
    """

    artifact_hash: str | None
    command_id: str | None
    exit_code: int | None
    span_ids: list[str] = field(default_factory=list)
    manifest_commit_hash: str | None = None
    assertion_id: str | None = None


@dataclass(frozen=True, slots=True)
class EvidenceValidation:
    """Result of ``validate_binding(binding)``.

    ``is_complete`` is True iff every anchor is present and well-formed.
    ``missing`` is a sorted list of stable tokens (empty when complete).
    """

    is_complete: bool
    missing: tuple[str, ...]


def validate_binding(binding: EvidenceBinding) -> EvidenceValidation:
    """Return the completeness + structured missing-field tokens.

    The ordering of ``missing`` is the canonical declaration order
    (artifact_hash, command_id, exit_code, span_ids,
    manifest_commit_hash, assertion_id). Tests bind to this order.
    """
    missing: list[str] = []

    if binding.artifact_hash is None:
        missing.append(MISSING_ARTIFACT_HASH)
    elif not _SHA256_RE.match(binding.artifact_hash):
        missing.append(MALFORMED_ARTIFACT_HASH)

    if binding.command_id is None or binding.command_id == "":
        missing.append(MISSING_COMMAND_ID)

    if binding.exit_code is None:
        missing.append(MISSING_EXIT_CODE)

    if not binding.span_ids:
        missing.append(MISSING_SPAN_IDS)

    if binding.manifest_commit_hash is None:
        missing.append(MISSING_MANIFEST_COMMIT_HASH)
    elif not _SHA256_RE.match(binding.manifest_commit_hash):
        missing.append(MALFORMED_MANIFEST_COMMIT_HASH)

    if binding.assertion_id is None or binding.assertion_id == "":
        missing.append(MISSING_ASSERTION_ID)

    return EvidenceValidation(
        is_complete=len(missing) == 0,
        missing=tuple(missing),
    )


def render_invalid_reason(validation: EvidenceValidation) -> str:
    """Render the structured ``invalid_reason`` payload for a row.

    Form: ``EVIDENCE_INCOMPLETE|<comma-separated missing tokens>``.
    Stable across versions so audit-log greps remain valid.
    """
    if validation.is_complete:
        return ""
    return "EVIDENCE_INCOMPLETE|" + ",".join(validation.missing)
