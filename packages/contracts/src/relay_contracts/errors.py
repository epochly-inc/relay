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
    RELAY-CEL-004  RELAY-CEL-UDF-UNREGISTERED
    RELAY-CEL-006  RELAY-CEL-NUMERIC-OOB
    RELAY-CEL-007  RELAY-CEL-PROFILE-REGEX-BACKREF
    RELAY-CEL-008  RELAY-CEL-RESOURCE-EXHAUSTED
    RELAY-CEL-009  RELAY-CEL-ENGINE-COMPILE   (wasm engine compile failure)
    RELAY-CEL-009  RELAY-CEL-ENGINE-EXEC      (wasm engine runtime failure)
    RELAY-CEL-009  RELAY-CEL-ENGINE-REQUEST   (wasm engine request/marshaling bug)
    RELAY-CEL-009  RELAY-CEL-ENGINE-PANIC     (wasm reactor trap, re-instantiated)

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
SUBTYPE_RESOURCE_EXHAUSTED: Final[str] = "RELAY-CEL-RESOURCE-EXHAUSTED"
# A caller passed an extra UDF the wasm engine has no registration slot for
# (the engine exposes only the 3 hardcoded relay.* UDFs). Shares the UDF code
# (004) with the purity error -- both are UDF-registration failures.
SUBTYPE_UDF_UNREGISTERED: Final[str] = "RELAY-CEL-UDF-UNREGISTERED"
# Engine-error subtypes (RELAY-CEL-009): the wasm engine reported a failure
# that is NOT one of the classified host conditions. Distinct from 004/006 so a
# wasm exec/request failure is never confused with a host UDF-impurity (004) /
# numeric-out-of-bounds (006) classification (which would poison the gate's
# signed per-condition error_code).
SUBTYPE_ENGINE_COMPILE: Final[str] = "RELAY-CEL-ENGINE-COMPILE"
SUBTYPE_ENGINE_EXEC: Final[str] = "RELAY-CEL-ENGINE-EXEC"
SUBTYPE_ENGINE_REQUEST: Final[str] = "RELAY-CEL-ENGINE-REQUEST"
SUBTYPE_ENGINE_PANIC: Final[str] = "RELAY-CEL-ENGINE-PANIC"


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


class RelayCelResourceExhaustedError(RelayCelError):
    """Evaluator orphan-thread cap reached (Round-3 P1 fix #4).

    Cel-python evaluation is not interruptible from another thread, so a
    wall-clock timeout leaves the worker thread alive until cel-python
    finishes computing. Under adversarial inputs (loop of pathological
    evaluations) orphans accumulate without bound -- a trivial DoS
    vector. The evaluator bounds the live orphan count at
    ``MAX_ORPHAN_THREADS``; once reached, new evaluations raise this
    error instead of spawning yet another orphan.

    The bound exists because cel-python lacks cancellation support; if
    cel-python ever exposes a cancel handle the bound can be lifted.
    """

    code = RelayErrorCode.RELAY_CEL_008
    subtype = SUBTYPE_RESOURCE_EXHAUSTED


class RelayCelUnsupportedUdfError(RelayCelError):
    """A caller passed an extra UDF the wasm engine cannot host.

    The single-engine (wasm) evaluator exposes only the 3 hardcoded Relay UDFs
    (relay.coverage / relay.tool_arg / relay.schema_match) and has no
    registration mechanism, so any caller-supplied extra UDF is rejected
    fail-closed BEFORE evaluation. Shares the UDF code (004) with the purity
    error; the subtype distinguishes "unregistered" from "impure".
    """

    code = RelayErrorCode.RELAY_CEL_004
    subtype = SUBTYPE_UDF_UNREGISTERED


# Map a wasm engine envelope code -> the RELAY-CEL-009 engine subtype. The wasm
# emits its OWN RELAY-CEL-NNN namespace (packages/cel-wasm crate `codes`):
# 001 = compile, 004 = exec, 006 = request; plus the host loader's
# RELAY-CEL-PANIC trap marker. Their NUMBERS overlap the host's classified
# codes (004 = UDF-impure, 006 = numeric-OOB) but their MEANINGS differ, so the
# wasm-backed adapter translates them into the distinct 009 code with a
# per-cause subtype. (The wasm's 002 profile envelope is handled separately ->
# RelayCelProfileError, carrying the wasm's own subtype.)
_WASM_CODE_TO_ENGINE_SUBTYPE: Final[dict[str, str]] = {
    "RELAY-CEL-001": SUBTYPE_ENGINE_COMPILE,
    "RELAY-CEL-004": SUBTYPE_ENGINE_EXEC,
    "RELAY-CEL-006": SUBTYPE_ENGINE_REQUEST,
    "RELAY-CEL-PANIC": SUBTYPE_ENGINE_PANIC,
}


class RelayCelEngineError(RelayCelError):
    """The CEL engine reported a non-classified internal failure (RELAY-CEL-009).

    Distinct from the host's classified codes so a wasm compile/exec/request/
    panic failure is never confused with a host UDF-impurity (004) or
    numeric-out-of-bounds (006) classification -- a confusion that would poison
    the gate's signed per-condition ``error_code`` (cross-runtime byte equality).
    """

    code = RelayErrorCode.RELAY_CEL_009

    def __init__(self, message: str, *, subtype: str = SUBTYPE_ENGINE_EXEC) -> None:
        super().__init__(message)
        self.subtype = subtype

    @classmethod
    def from_wasm_envelope(cls, wasm_code: str, message: str) -> RelayCelEngineError:
        """Translate a wasm engine ``{"ok": false}`` envelope into a 009 error.

        ``wasm_code`` is the engine's OWN ``RELAY-CEL-NNN`` code (or
        ``RELAY-CEL-PANIC``); unknown codes default to ENGINE-EXEC. The original
        wasm code is preserved in the message for diagnosis.
        """
        subtype = _WASM_CODE_TO_ENGINE_SUBTYPE.get(wasm_code, SUBTYPE_ENGINE_EXEC)
        return cls(f"[{wasm_code}] {message}", subtype=subtype)
