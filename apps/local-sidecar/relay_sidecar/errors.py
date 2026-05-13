"""Sidecar error codes (W2.1).

Maps the descriptive error tokens from contract.md (VAL-W2-002, -003, -004,
-007, -008, -011) onto the W1-pattern-compliant numeric codes registered
in ``packages/schemas/raw/relay-error-codes.yaml``.

Per VAL-W1-029, every wire-format error code MUST match
``^RELAY-[A-Z]+-[0-9]{3}$``. The contract's prose uses semantic suffixes
(``RELAY-SIDECAR-LOCKFILE-MALFORMED``, ``-INSECURE``, ``-WINDOWS-ACL``,
``-AUTH-MISMATCH``, ``-NONCE-EXPIRED``, ``-NONLOCAL-FS``). We surface BOTH:
the numeric ``code`` field (W1-compliant) AND the semantic ``error_class``
(human-readable token from the contract). Tests can match either.

The numeric allocation is locked here:

    RELAY-SIDECAR-001 -> LOCKFILE-MALFORMED  (VAL-W2-002)
    RELAY-SIDECAR-002 -> LOCKFILE-INSECURE   (VAL-W2-003)
    RELAY-SIDECAR-003 -> LOCKFILE-WINDOWS-ACL (VAL-W2-004)
    RELAY-SIDECAR-004 -> AUTH-MISMATCH        (VAL-W2-007)
    RELAY-SIDECAR-005 -> NONCE-EXPIRED        (VAL-W2-008)
    RELAY-SIDECAR-006 -> NONLOCAL-FS          (VAL-W2-011)
    RELAY-SIDECAR-007 -> DRAINING             (VAL-W2-015)
    RELAY-SIDECAR-008 -> CONTEXT-NOT-REHYDRATED (VAL-W2-056)
    RELAY-SIDECAR-009 -> BYPASS-MARKER-DETECTED (VAL-W2-057)
    RELAY-SQLITE-001  -> SQLITE-BUSY-EXHAUSTED (VAL-W2-020)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

# Numeric W1-compliant tokens (registered in relay-error-codes.yaml).
RELAY_SIDECAR_LOCKFILE_MALFORMED_CODE: Final[str] = "RELAY-SIDECAR-001"
RELAY_SIDECAR_LOCKFILE_INSECURE_CODE: Final[str] = "RELAY-SIDECAR-002"
RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL_CODE: Final[str] = "RELAY-SIDECAR-003"
RELAY_SIDECAR_AUTH_MISMATCH_CODE: Final[str] = "RELAY-SIDECAR-004"
RELAY_SIDECAR_NONCE_EXPIRED_CODE: Final[str] = "RELAY-SIDECAR-005"
RELAY_SIDECAR_NONLOCAL_FS_CODE: Final[str] = "RELAY-SIDECAR-006"
# W2.2 numeric code for sidecar drain mode (VAL-W2-015). The drain
# middleware in runtime.py emits this on new requests during shutdown.
RELAY_SIDECAR_DRAINING_CODE: Final[str] = "RELAY-SIDECAR-007"
# W2.4 numeric code for context-reinjection guard failure (VAL-W2-056).
# Emitted when a resumed worker submits a state transition with a stale
# manifest/contract/procedure hash relative to the on-disk active version.
RELAY_SIDECAR_CONTEXT_NOT_REHYDRATED_CODE: Final[str] = "RELAY-SIDECAR-008"
# W2.3 numeric code for SQLITE BUSY exhaustion (VAL-W2-020).
RELAY_SQLITE_BUSY_EXHAUSTED_CODE: Final[str] = "RELAY-SQLITE-001"

# Descriptive tokens (from contract.md prose). Surfaced as ``error_class``
# in the structured error so VAL-W2-* tests can match the contract text.
RELAY_SIDECAR_LOCKFILE_MALFORMED: Final[str] = "RELAY-SIDECAR-LOCKFILE-MALFORMED"
RELAY_SIDECAR_LOCKFILE_INSECURE: Final[str] = "RELAY-SIDECAR-LOCKFILE-INSECURE"
RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL: Final[str] = "RELAY-SIDECAR-LOCKFILE-WINDOWS-ACL"
RELAY_SIDECAR_AUTH_MISMATCH: Final[str] = "RELAY-SIDECAR-AUTH-MISMATCH"
RELAY_SIDECAR_NONCE_EXPIRED: Final[str] = "RELAY-SIDECAR-NONCE-EXPIRED"
RELAY_SIDECAR_NONLOCAL_FS: Final[str] = "RELAY-SIDECAR-NONLOCAL-FS"
# W2.2 descriptive token for sidecar drain (matches runtime.py literal).
RELAY_SIDECAR_DRAINING: Final[str] = "RELAY-SIDECAR-DRAINING"
# W2.4 descriptive token for context-reinjection guard (VAL-W2-056 prose).
RELAY_SIDECAR_CONTEXT_NOT_REHYDRATED: Final[str] = "RELAY-SIDECAR-CONTEXT-NOT-REHYDRATED"
# Contract-text descriptive token used in VAL-W2-020 prose.
RELAY_SQLITE_BUSY_EXHAUSTED: Final[str] = "RELAY-SQLITE-BUSY-EXHAUSTED"

# Bidirectional map for callers that have one form and need the other.
_CODE_TO_CLASS: Final[dict[str, str]] = {
    RELAY_SIDECAR_LOCKFILE_MALFORMED_CODE: RELAY_SIDECAR_LOCKFILE_MALFORMED,
    RELAY_SIDECAR_LOCKFILE_INSECURE_CODE: RELAY_SIDECAR_LOCKFILE_INSECURE,
    RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL_CODE: RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL,
    RELAY_SIDECAR_AUTH_MISMATCH_CODE: RELAY_SIDECAR_AUTH_MISMATCH,
    RELAY_SIDECAR_NONCE_EXPIRED_CODE: RELAY_SIDECAR_NONCE_EXPIRED,
    RELAY_SIDECAR_NONLOCAL_FS_CODE: RELAY_SIDECAR_NONLOCAL_FS,
    RELAY_SIDECAR_DRAINING_CODE: RELAY_SIDECAR_DRAINING,
    RELAY_SIDECAR_CONTEXT_NOT_REHYDRATED_CODE: RELAY_SIDECAR_CONTEXT_NOT_REHYDRATED,
    RELAY_SQLITE_BUSY_EXHAUSTED_CODE: RELAY_SQLITE_BUSY_EXHAUSTED,
}
_CLASS_TO_CODE: Final[dict[str, str]] = {v: k for k, v in _CODE_TO_CLASS.items()}


@dataclass(frozen=True)
class SidecarError(Exception):
    """Structured sidecar error.

    Carries both the numeric ``code`` (W1-compliant, ready to populate the
    wire-format error envelope's ``code`` field) and the descriptive
    ``error_class`` (the contract.md prose token, populated into the
    envelope's ``error_class`` field).

    Attributes:
        code: ``RELAY-SIDECAR-NNN`` numeric form.
        error_class: ``RELAY-SIDECAR-{KIND}`` descriptive form.
        message: Human-readable explanation.
        details: Optional structured payload (file paths, observed values).
    """

    code: str
    error_class: str
    message: str
    details: dict[str, object] | None = None

    def __post_init__(self) -> None:  # noqa: D401
        # Validate the pair: refuse to construct with mismatched code/class.
        expected_class = _CODE_TO_CLASS.get(self.code)
        if expected_class is None or expected_class != self.error_class:
            raise ValueError(
                "SidecarError code/error_class mismatch: "
                f"code={self.code!r} error_class={self.error_class!r} "
                f"(expected error_class={expected_class!r})"
            )

    def __str__(self) -> str:  # noqa: D401
        return f"[{self.code}/{self.error_class}] {self.message}"


def make_error(
    error_class: str,
    message: str,
    *,
    details: dict[str, object] | None = None,
) -> SidecarError:
    """Construct a SidecarError from the descriptive token.

    Resolves the numeric code from ``error_class`` so callers don't repeat
    the mapping at every error site. Raises ``KeyError`` (programmer error)
    if ``error_class`` is not registered.
    """
    code = _CLASS_TO_CODE[error_class]
    return SidecarError(
        code=code,
        error_class=error_class,
        message=message,
        details=details,
    )


class RelaySQLiteBusyExhausted(Exception):
    """SQLITE_BUSY retry/backoff budget exhausted (VAL-W2-020).

    Raised by ``transactional_db_write`` when the busy_timeout window
    (5000ms by default) plus application-level exponential backoff has
    elapsed without acquiring the SQLite write lock. The HTTP layer maps
    this exception to a structured 503 response carrying:

        code         = RELAY-SQLITE-001
        error_class  = RELAY-SQLITE-BUSY-EXHAUSTED
        http_status  = 503
        retry_advice = after_retry_after

    Not a ``SidecarError`` subclass because SidecarError is dataclass-
    frozen with a strict ``(code, error_class)`` pair check; this
    exception additionally carries ``attempts`` and
    ``sql_statement_digest`` for the observability surface.
    """

    code: Final[str] = RELAY_SQLITE_BUSY_EXHAUSTED_CODE
    error_class: Final[str] = RELAY_SQLITE_BUSY_EXHAUSTED
    http_status: Final[int] = 503

    def __init__(
        self,
        *,
        message: str,
        attempts: int,
        sql_statement_digest: str,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.attempts = attempts
        self.sql_statement_digest = sql_statement_digest

    def to_envelope(self) -> dict[str, object]:
        """Return a JSON-serialisable error envelope payload."""
        return {
            "code": self.code,
            "error_class": self.error_class,
            "http_status": self.http_status,
            "message": self.message,
            "details": {
                "attempts": self.attempts,
                "sql_statement_digest": self.sql_statement_digest,
            },
        }


__all__ = [
    "RELAY_SIDECAR_AUTH_MISMATCH",
    "RELAY_SIDECAR_AUTH_MISMATCH_CODE",
    "RELAY_SIDECAR_CONTEXT_NOT_REHYDRATED",
    "RELAY_SIDECAR_CONTEXT_NOT_REHYDRATED_CODE",
    "RELAY_SIDECAR_DRAINING",
    "RELAY_SIDECAR_DRAINING_CODE",
    "RELAY_SIDECAR_LOCKFILE_INSECURE",
    "RELAY_SIDECAR_LOCKFILE_INSECURE_CODE",
    "RELAY_SIDECAR_LOCKFILE_MALFORMED",
    "RELAY_SIDECAR_LOCKFILE_MALFORMED_CODE",
    "RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL",
    "RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL_CODE",
    "RELAY_SIDECAR_NONCE_EXPIRED",
    "RELAY_SIDECAR_NONCE_EXPIRED_CODE",
    "RELAY_SIDECAR_NONLOCAL_FS",
    "RELAY_SIDECAR_NONLOCAL_FS_CODE",
    "RELAY_SQLITE_BUSY_EXHAUSTED",
    "RELAY_SQLITE_BUSY_EXHAUSTED_CODE",
    "RelaySQLiteBusyExhausted",
    "SidecarError",
    "make_error",
]
