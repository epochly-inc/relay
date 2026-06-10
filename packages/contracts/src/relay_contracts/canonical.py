"""RFC 8785 JSON Canonicalization Scheme (JCS) serializer.

Used by the Relay CEL evaluator to canonicalise structured evaluation
results before hashing or cross-runtime comparison (VAL-W6-005). Output
bytes MUST be byte-equal to those produced by the cyberphone/json-
canonicalization Java reference and to the cel-js mirror that ships in
W6.2.

Why not the stdlib JSON sorter (key-sorted ``json.dumps`` with compact
separators)? Because key ordering alone is insufficient. RFC 8785 also pins:

  - Number representation (ECMA-262 7.1.12.1 ToString applied to IEEE-754
    doubles; the JCS spec mandates the I-JSON / ES6 Number string form).
  - String escaping (only ``"``, ``\\``, and U+0000..U+001F are escaped;
    all higher code points are emitted literally as UTF-8).
  - Rejection of NaN / +Inf / -Inf at serialisation time -- caller MUST
    have rejected these at the evaluation-result boundary
    (:class:`RelayCelNumericOutOfBoundsError`).

Spec anchors: D, RFC 8785.
Eng plan anchors: line 306 ("RFC 8785 JCS ... conformance suites").

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import math
import unicodedata
from typing import Any, Final

from .errors import RelayCelNumericOutOfBoundsError

# Round-3 P1 fix #5: wire-stable code for the BMP-only key screen.
# Python str sorts by codepoint; JS strings sort by UTF-16 code unit.
# For Basic Multilingual Plane keys (< U+10000) these match. For
# supplementary-plane keys (>= U+10000) the orderings diverge, which
# silently produces DIFFERENT JCS bytes between the Python and TS
# encoders for the same input -- breaking cross-runtime signature verification
# (CLAUDE.md keystone invariant #11: trust anchor / cross-runtime byte
# equality). Until both encoders implement the full UTF-16-code-unit
# sort, we fail-closed on supplementary-plane KEYS. Values may still
# contain supplementary-plane chars; only object keys are sorted.
CANONICAL_NON_BMP_KEY_CODE: Final[str] = "RELAY-CANON-NON-BMP-KEY"


class CanonicalEncodingError(Exception):
    """Raised when the JCS encoder cannot produce cross-runtime-stable bytes.

    Currently raised for non-BMP object keys (Round-3 P1 fix #5). Future
    encoder hardening may add additional reasons; ``code`` discriminates.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = CANONICAL_NON_BMP_KEY_CODE,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code

# RFC 8785 section 3.2.2.1: control characters U+0000..U+001F MUST be
# escaped using the short forms or \\u00xx; quote and backslash also.
_ESCAPE_MAP = {
    0x00: "\\u0000", 0x01: "\\u0001", 0x02: "\\u0002", 0x03: "\\u0003",
    0x04: "\\u0004", 0x05: "\\u0005", 0x06: "\\u0006", 0x07: "\\u0007",
    0x08: "\\b",     0x09: "\\t",     0x0A: "\\n",     0x0B: "\\u000b",
    0x0C: "\\f",     0x0D: "\\r",     0x0E: "\\u000e", 0x0F: "\\u000f",
    0x10: "\\u0010", 0x11: "\\u0011", 0x12: "\\u0012", 0x13: "\\u0013",
    0x14: "\\u0014", 0x15: "\\u0015", 0x16: "\\u0016", 0x17: "\\u0017",
    0x18: "\\u0018", 0x19: "\\u0019", 0x1A: "\\u001a", 0x1B: "\\u001b",
    0x1C: "\\u001c", 0x1D: "\\u001d", 0x1E: "\\u001e", 0x1F: "\\u001f",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _encode_string(s: str) -> str:
    # RFC 8785 + spec line 5696 + VAL-W17-003: all canonicalized JSON for
    # digest uses UTF-8 NFC. NFC is idempotent and ASCII-identity, so
    # this is a no-op on existing W6/W10 corpora (verified) and enforces
    # the invariant when inputs contain compatibility codepoints or
    # decomposed sequences.
    s = unicodedata.normalize("NFC", s)
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _ESCAPE_MAP.get(cp)
        if esc is not None:
            out.append(esc)
        else:
            # All other code points (including non-ASCII) emitted literally.
            # The final UTF-8 encoding happens at bytes() conversion below.
            out.append(ch)
    out.append('"')
    return "".join(out)


def _es6_to_string_positive(n: float) -> str:
    """ECMA-262 7.1.12.1 Number.toString for a strictly positive finite
    double; mirrors JS ``String(n)`` byte-for-byte. See the verifier's
    ``relay_verifier.canonical._es6_to_string_positive`` for the algorithm
    derivation -- this is an intentional duplicate to keep the contracts
    package self-contained and to allow the cross-package parity test in
    ``test_w10_3_jcs_corpus.py`` to detect drift between the two
    implementations.
    """
    s = repr(n)
    if "e" in s:
        mantissa, exp_str = s.split("e")
        exp = int(exp_str)
    else:
        mantissa, exp = s, 0
    if "." in mantissa:
        int_part, frac_part = mantissa.split(".")
    else:
        int_part, frac_part = mantissa, ""
    raw_digits = int_part + frac_part
    stripped_lead = raw_digits.lstrip("0")
    leading_zero_count = len(raw_digits) - len(stripped_lead)
    if not stripped_lead:
        return "0"
    stripped = stripped_lead.rstrip("0")
    n_dec = len(int_part) - leading_zero_count + exp
    k = len(stripped)
    if k <= n_dec <= 21:
        return stripped + ("0" * (n_dec - k))
    if 0 < n_dec <= 21:
        return stripped[:n_dec] + "." + stripped[n_dec:]
    if -6 < n_dec <= 0:
        return "0." + ("0" * (-n_dec)) + stripped
    sign = "+" if n_dec - 1 >= 0 else "-"
    abs_exp = str(abs(n_dec - 1))
    if k == 1:
        return stripped + "e" + sign + abs_exp
    return stripped[0] + "." + stripped[1:] + "e" + sign + abs_exp


def _encode_number(n: int | float) -> str:
    # Booleans subclass int in Python; route them out at the caller.
    if isinstance(n, bool):  # pragma: no cover -- caller dispatches first
        raise TypeError("bool is not a number for JCS encoding")
    if isinstance(n, int):
        # Integers within the IEEE-754 safe range are emitted as plain
        # decimal integers per ECMA-262 ToString. Outside the safe range
        # JCS still applies, but Relay rejects: contract evaluation
        # results outside [-2^53, 2^53] are an out-of-band signal.
        return str(n)
    # Float path: must be finite (caller has rejected NaN/Inf).
    if math.isnan(n) or math.isinf(n):
        # Defensive: callers are expected to reject before reaching here.
        raise RelayCelNumericOutOfBoundsError(
            f"JCS cannot encode non-finite number: {n!r}"
        )
    # Negative zero collapses to "0" per ECMA-262 ToString.
    if n == 0.0:
        return "0"
    if n < 0:
        return "-" + _es6_to_string_positive(-n)
    return _es6_to_string_positive(n)


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return _encode_number(value)
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, list | tuple):
        parts = [_encode(item) for item in value]
        return "[" + ",".join(parts) + "]"
    if isinstance(value, dict):
        # RFC 8785 section 3.2.3: keys sorted by their UTF-16 code-unit
        # sequence. Python str compares by code point; for the BMP these
        # match. For supplementary-plane characters (>= U+10000) the
        # orderings diverge silently -- a Python encoder and a JS
        # encoder produce DIFFERENT canonical bytes for the same input,
        # which breaks cross-runtime signature verification (CLAUDE.md
        # keystone invariant #11). Round-3 P1 fix #5: fail-closed on
        # supplementary-plane object KEYS. Values may contain
        # supplementary-plane characters -- only keys are sorted.
        items_raw = [(str(k), v) for k, v in value.items()]
        for k, _v in items_raw:
            for ch in k:
                if ord(ch) >= 0x10000:
                    raise CanonicalEncodingError(
                        f"JCS: non-BMP codepoint U+{ord(ch):04X} in object "
                        f"key {k!r}; supplementary-plane keys produce "
                        f"runtime-divergent canonical bytes and are "
                        f"refused. Re-key the object with BMP-only "
                        f"strings."
                    )
        items = sorted(items_raw, key=lambda kv: kv[0])
        parts = [_encode_string(k) + ":" + _encode(v) for k, v in items]
        return "{" + ",".join(parts) + "}"
    raise TypeError(
        f"JCS: unsupported type {type(value).__name__} for value {value!r}"
    )


def jcs_canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 JCS canonical-bytes form of ``value``.

    Output is UTF-8 bytes (no BOM). Caller is responsible for hashing or
    cross-runtime comparison. NaN / +Inf / -Inf raise
    :class:`RelayCelNumericOutOfBoundsError` defensively; well-formed
    callers reject these at the evaluation-result boundary.
    """

    return _encode(value).encode("utf-8")
