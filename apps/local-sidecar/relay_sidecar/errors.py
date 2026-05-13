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

# Descriptive tokens (from contract.md prose). Surfaced as ``error_class``
# in the structured error so VAL-W2-* tests can match the contract text.
RELAY_SIDECAR_LOCKFILE_MALFORMED: Final[str] = "RELAY-SIDECAR-LOCKFILE-MALFORMED"
RELAY_SIDECAR_LOCKFILE_INSECURE: Final[str] = "RELAY-SIDECAR-LOCKFILE-INSECURE"
RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL: Final[str] = "RELAY-SIDECAR-LOCKFILE-WINDOWS-ACL"
RELAY_SIDECAR_AUTH_MISMATCH: Final[str] = "RELAY-SIDECAR-AUTH-MISMATCH"
RELAY_SIDECAR_NONCE_EXPIRED: Final[str] = "RELAY-SIDECAR-NONCE-EXPIRED"
RELAY_SIDECAR_NONLOCAL_FS: Final[str] = "RELAY-SIDECAR-NONLOCAL-FS"

# Bidirectional map for callers that have one form and need the other.
_CODE_TO_CLASS: Final[dict[str, str]] = {
    RELAY_SIDECAR_LOCKFILE_MALFORMED_CODE: RELAY_SIDECAR_LOCKFILE_MALFORMED,
    RELAY_SIDECAR_LOCKFILE_INSECURE_CODE: RELAY_SIDECAR_LOCKFILE_INSECURE,
    RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL_CODE: RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL,
    RELAY_SIDECAR_AUTH_MISMATCH_CODE: RELAY_SIDECAR_AUTH_MISMATCH,
    RELAY_SIDECAR_NONCE_EXPIRED_CODE: RELAY_SIDECAR_NONCE_EXPIRED,
    RELAY_SIDECAR_NONLOCAL_FS_CODE: RELAY_SIDECAR_NONLOCAL_FS,
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


__all__ = [
    "RELAY_SIDECAR_AUTH_MISMATCH",
    "RELAY_SIDECAR_AUTH_MISMATCH_CODE",
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
    "SidecarError",
    "make_error",
]
