"""Structured error envelope for the Relay CEL evaluator.

Every Relay-CEL error carries a canonical ``RELAY-CEL-NNN`` code (from the
generated :class:`RelayErrorCode` registry) plus a stable ``subtype`` token.
The cel-js mirror (W6.2) emits the identical token set. The pair
(`code`, `subtype`) is the cross-runtime byte-equality key that VAL-W6-006
and VAL-W6-007 enforce.

Code-to-subtype map (W6.1 scope; mirror in cel-js TS module on W6.2):

    RELAY-CEL-002  RELAY-CEL-PROFILE-DYN-DISABLED
    RELAY-CEL-002  RELAY-CEL-PROFILE-TS-DISABLED
    RELAY-CEL-002  RELAY-CEL-PROFILE-DUR-DISABLED
    RELAY-CEL-003  RELAY-CEL-TIMEOUT-001
    RELAY-CEL-004  RELAY-CEL-UDF-IMPURE
    RELAY-CEL-006  RELAY-CEL-NUMERIC-OOB
    RELAY-CEL-007  RELAY-CEL-PROFILE-REGEX-BACKREF

Spec anchors: D, B.4 (closed error envelope).
Eng plan anchors: CQ1 lines 145-157, X4 line 216.
CLAUDE.md anchors: keystone invariant 6, banned pattern #16.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from relay_schemas.error_codes import RelayErrorCode

# --- Stable subtype tokens (cross-runtime byte equality with cel-js) -------

SUBTYPE_PROFILE_DYN_DISABLED: Final[str] = "RELAY-CEL-PROFILE-DYN-DISABLED"
SUBTYPE_PROFILE_TS_DISABLED: Final[str] = "RELAY-CEL-PROFILE-TS-DISABLED"
SUBTYPE_PROFILE_DUR_DISABLED: Final[str] = "RELAY-CEL-PROFILE-DUR-DISABLED"
SUBTYPE_PROFILE_REGEX_BACKREF: Final[str] = "RELAY-CEL-PROFILE-REGEX-BACKREF"
SUBTYPE_TIMEOUT: Final[str] = "RELAY-CEL-TIMEOUT-001"
SUBTYPE_UDF_IMPURE: Final[str] = "RELAY-CEL-UDF-IMPURE"
SUBTYPE_NUMERIC_OOB: Final[str] = "RELAY-CEL-NUMERIC-OOB"


@dataclass(frozen=True)
class RelayCelErrorEnvelope:
    """Stable JSON-serializable envelope.

    The key set (``code``, ``subtype``, ``message``) is the cross-runtime
    contract: cel-js (W6.2) MUST emit the same three keys in the same
    spelling for a given fixture. ``message`` is human prose and NOT part
    of the byte-equality contract; tests compare ``code`` + ``subtype``.
    """

    code: str
    subtype: str
    message: str

    def to_dict(self) -> dict[str, str]:
        # Stable key order matches the cel-js mirror.
        return {"code": self.code, "subtype": self.subtype, "message": self.message}


class RelayCelError(Exception):
    """Base class for every structured Relay CEL error.

    All subclasses set ``self.code`` (a ``RELAY-CEL-NNN`` token from the
    generated registry) and ``self.subtype`` (a stable cross-runtime
    subtype token). Direct instantiation is permitted but discouraged --
    prefer one of the specific subclasses below.
    """

    code: str = ""
    subtype: str = ""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    @property
    def envelope(self) -> RelayCelErrorEnvelope:
        return RelayCelErrorEnvelope(
            code=self.code, subtype=self.subtype, message=self.message
        )


class RelayCelProfileError(RelayCelError):
    """Profile violation: dyn / timestamp / duration / RE2-incompatible regex."""

    code = RelayErrorCode.RELAY_CEL_002

    def __init__(self, message: str, *, subtype: str) -> None:
        super().__init__(message)
        # Subtype distinguishes profile sub-violations (dyn vs timestamp
        # vs duration vs regex backref) while sharing the canonical code.
        self.subtype = subtype


class RelayCelTimeoutError(RelayCelError):
    """Wall-clock timeout exceeded during evaluation (VAL-W6-003)."""

    code = RelayErrorCode.RELAY_CEL_003
    subtype = SUBTYPE_TIMEOUT


class RelayUdfPurityError(RelayCelError):
    """UDF registered with ``pure=False`` (VAL-W6-004; CLAUDE.md banned #16)."""

    code = RelayErrorCode.RELAY_CEL_004
    subtype = SUBTYPE_UDF_IMPURE


class RelayCelNumericOutOfBoundsError(RelayCelError):
    """Evaluation produced NaN / +Inf / -Inf (VAL-W6-006).

    JCS (RFC 8785 section 3.2.2) cannot canonicalise NaN/Inf, so the
    evaluator MUST reject before canonicalisation is attempted.
    """

    code = RelayErrorCode.RELAY_CEL_006
    subtype = SUBTYPE_NUMERIC_OOB


class RelayCelRegexBackreferenceError(RelayCelProfileError):
    """Regex literal contains a backreference (RE2 forbids; VAL-W6-007)."""

    code = RelayErrorCode.RELAY_CEL_007

    def __init__(self, message: str) -> None:
        super().__init__(message, subtype=SUBTYPE_PROFILE_REGEX_BACKREF)
