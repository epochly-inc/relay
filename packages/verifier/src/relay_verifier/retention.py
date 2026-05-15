"""Subject-resolution check for the W10.4 bundle validator.

Per spec section K lines 4435 (tombstoned) and 4438 (redacted-after-
signing) an evidence bundle's referenced subject (run / replay /
eval_run) MAY no longer exist or MAY have been redacted by a superseding
bundle. The verifier reports the resolution state without rejecting the
bundle: internal consistency (subject id + digest) is preserved either
way, and the original signature binding remains valid.

Per VAL-W10-037 a tombstoned subject -> ``subject_resolution: "tombstoned"``.
Per VAL-W10-038 a subject redacted after signing -> ``subject_resolution:
"redacted_after_signing"``. Per VAL-W10-021 a live subject (or no
subject store consulted) -> ``subject_resolution: "live"`` /
``"unknown"``.

The verifier accepts an optional ``subject_store`` -- a dict-like map
from ``subject_id`` to ``SubjectRecord`` -- and resolves the bundle's
referenced subject through it. When no store is supplied (the default
offline configuration) the resolution is ``"unknown"`` because the
verifier cannot prove or disprove the subject's status.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Protocol

# Sentinel constant for the offline default.
SUBJECT_RESOLUTION_LIVE: Final[str] = "live"
SUBJECT_RESOLUTION_TOMBSTONED: Final[str] = "tombstoned"
SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING: Final[str] = "redacted_after_signing"
SUBJECT_RESOLUTION_UNKNOWN: Final[str] = "unknown"


# -----------------------------------------------------------------------------
# Subject store protocol
# -----------------------------------------------------------------------------


class SubjectStore(Protocol):
    """Minimal protocol for resolving a subject id.

    Production stores back this with a sidecar SQLite query; tests
    supply an in-memory dict that implements ``lookup(subject_id) ->
    SubjectRecord | None``.
    """

    def lookup(self, subject_id: str) -> SubjectRecord | None: ...


@dataclass(frozen=True)
class SubjectRecord:
    """Subject lookup return value.

    `state` is one of: "live", "tombstoned", "redacted_after_signing".
    `original_digest_hex` is the digest the subject carried at the time
    the bundle was signed (preserved across tombstone/redaction so the
    integrity binding remains intact).
    """

    state: str
    original_digest_hex: str


# -----------------------------------------------------------------------------
# Resolution
# -----------------------------------------------------------------------------


@dataclass
class SubjectResolutionResult:
    """Verdict for a subject-resolution check."""

    resolution: str = SUBJECT_RESOLUTION_UNKNOWN
    reason: str = ""
    original_digest_preserved: bool = True


def resolve_subject(
    *,
    subject_id: str | None,
    subject_digest_hex: str | None,
    subject_store: SubjectStore | None,
) -> SubjectResolutionResult:
    """Resolve a bundle's subject reference through an optional store.

    Inputs:
      * `subject_id` -- the subject reference declared in the bundle
        (e.g., ``run_id`` / ``replay_case_id``). May be None for
        bundles that do not reference an external subject (uncommon
        but valid for self-contained bundles).
      * `subject_digest_hex` -- the subject digest the bundle bound at
        sign time. Compared to the store's record to prove the
        original binding is preserved across tombstone/redaction.
      * `subject_store` -- optional store. When None the resolution is
        ``"unknown"``; the verifier reports this as ``"unknown"`` in
        its output (NOT a reject).

    Returns a :class:`SubjectResolutionResult`. Never raises; failure
    modes are encoded in the result fields.
    """
    result = SubjectResolutionResult()

    if subject_store is None:
        result.resolution = SUBJECT_RESOLUTION_UNKNOWN
        result.reason = (
            "no subject_store supplied; verifier cannot determine subject "
            "state (offline mode)"
        )
        return result

    if subject_id is None or subject_id == "":
        # Bundle with no subject reference: treat as live by definition
        # (nothing to look up).
        result.resolution = SUBJECT_RESOLUTION_LIVE
        result.reason = "bundle declares no subject_id; trivially live"
        return result

    record = subject_store.lookup(subject_id)
    if record is None:
        # Not found -> tombstoned per spec K line 4435 (the subject was
        # deleted under retention but the bundle's signature binding
        # is still valid).
        result.resolution = SUBJECT_RESOLUTION_TOMBSTONED
        result.reason = (
            f"subject {subject_id!r} not found in store (deleted under "
            "retention)"
        )
        return result

    if record.state not in {
        SUBJECT_RESOLUTION_LIVE,
        SUBJECT_RESOLUTION_TOMBSTONED,
        SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING,
    }:
        result.resolution = SUBJECT_RESOLUTION_UNKNOWN
        result.reason = (
            f"subject {subject_id!r} record carries unknown state "
            f"{record.state!r}"
        )
        return result

    # Preservation check: the bundle's recorded digest must equal the
    # store's recorded original_digest_hex regardless of subject state.
    if (
        subject_digest_hex is not None
        and record.original_digest_hex != ""
        and subject_digest_hex != record.original_digest_hex
    ):
        result.original_digest_preserved = False
        result.reason = (
            f"subject {subject_id!r} original_digest_hex "
            f"{record.original_digest_hex!r} does not match bundle's "
            f"subject_digest_hex {subject_digest_hex!r}"
        )

    result.resolution = record.state
    return result


# -----------------------------------------------------------------------------
# In-memory store (test fixtures only)
# -----------------------------------------------------------------------------


class InMemorySubjectStore:
    """Trivial dict-backed subject store; for tests/fixtures.

    Production callers wire a sidecar-backed implementation; this class
    keeps the verifier package self-contained for the W10.4 plumbing
    tests.
    """

    def __init__(self, records: dict[str, SubjectRecord] | None = None) -> None:
        self._records: dict[str, SubjectRecord] = dict(records or {})

    def lookup(self, subject_id: str) -> SubjectRecord | None:
        return self._records.get(subject_id)

    def set(self, subject_id: str, record: SubjectRecord) -> None:
        self._records[subject_id] = record


__all__ = [
    "InMemorySubjectStore",
    "SUBJECT_RESOLUTION_LIVE",
    "SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING",
    "SUBJECT_RESOLUTION_TOMBSTONED",
    "SUBJECT_RESOLUTION_UNKNOWN",
    "SubjectRecord",
    "SubjectResolutionResult",
    "SubjectStore",
    "resolve_subject",
]
