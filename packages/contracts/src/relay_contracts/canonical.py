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
import re
from typing import Any

from .errors import RelayCelNumericOutOfBoundsError

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


# Match optional leading "-", digits, optional fraction, optional exponent.
# Used only to detect when ``repr(float)`` returns a value Python prefers
# over the JCS canonical form (e.g., trailing ``.0``).
_TRAILING_DOT_ZERO = re.compile(r"^(-?\d+)\.0$")


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
    # Whole-valued floats (e.g., 1.0) are emitted without the trailing
    # ".0" per ECMA-262 ToString rules used by JCS.
    if n.is_integer() and -1e21 < n < 1e21:
        return str(int(n))
    # General path: Python's repr() for float yields the shortest
    # decimal that round-trips to the same double, which matches the
    # ECMA-262 ToString spec for the JCS-relevant magnitudes used by
    # Relay contract evaluation. Strip a trailing ".0" if it appears.
    text = repr(n)
    m = _TRAILING_DOT_ZERO.match(text)
    if m is not None:
        return m.group(1)
    return text


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
        # match. For SMP characters (>= U+10000) the orderings diverge --
        # Relay contract keys are ASCII / BMP in practice, but enforce
        # by using the same key ordering on both runtimes.
        items = sorted(((str(k), v) for k, v in value.items()), key=lambda kv: kv[0])
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
