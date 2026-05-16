"""RFC 8785 JCS canonicalization for the OSS evidence verifier (W10.3).

Mirror of :mod:`relay_contracts.canonical` (W6.1), reproduced inside
``relay_verifier`` so the verifier package stays import-boundary clean
(it MUST NOT depend on ``relay_contracts`` to remain installable as a
standalone evidence-verification wheel; auditors verifying bundles do
not need the contract DSL stack).

Why a second copy instead of a shared dependency? The verifier package's
import boundary (per spec section AO.4 and CLAUDE.md) requires that the
offline verifier wheel pulls only ``cryptography`` + stdlib + the
schemas package; routing through ``relay_contracts`` would drag in CEL,
the UDF registry, and the parser. Cross-language and cross-package
parity is enforced by the W10.3 conformance corpus
(``tests/conformance/jcs/rfc8785_corpus.json``), which BOTH this module
and ``relay_contracts.canonical`` consume; any divergence is caught by
golden-byte comparison in CI.

What this module pins (RFC 8785):

  * Section 3.2.2: number representation per ECMA-262 7.1.12.1
    (Number.toString) -- whole-valued doubles emit without trailing
    ``.0``; negative zero collapses to ``0``; NaN/Inf rejected at
    serialisation.
  * Section 3.2.2.1: only ``"``, ``\\``, and U+0000..U+001F are escaped;
    higher code points emitted literally as UTF-8.
  * Section 3.2.3: object keys sorted by their UTF-16 code-unit
    sequence. Python's ``str`` compares by code point; for the BMP these
    match. SMP code points (>= U+10000) -- where the orderings would
    diverge -- are not used in Relay evidence bundle keys (asserted by
    the corpus).

Bundle-digest helper (VAL-W10-020):

  :func:`bundle_digest` returns ``SHA-256(JCS(claim_payload))`` for a
  single evidence claim, with the ``signatures`` field stripped if
  present (signatures are over the canonical bytes of the
  signature-free payload, per section L.5 cross-signing model).

Spec anchors: section K (line 4390 ``SHA-256 over RFC 8785 (JCS)
canonical JSON``), section AO.4. RFC 8785 sections 3.2.2 / 3.2.2.1 /
3.2.3.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import math
import unicodedata
from typing import Any

# RFC 8785 section 3.2.2.1: control characters U+0000..U+001F MUST be
# escaped using the short forms (\b, \t, \n, \f, \r) or \u00xx; the
# quote and backslash MUST be escaped as \" and \\. All other code
# points are emitted literally (the final UTF-8 bytes are produced by
# ``str.encode("utf-8")`` at the bottom of the encode pipeline).
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


class JCSEncodeError(ValueError):
    """Raised when an input cannot be encoded as RFC 8785 canonical JSON.

    Distinct from a generic :class:`ValueError` so callers verifying
    bundles can catch it explicitly and emit a structured error code
    (``RELAY-EVID-014`` is the wire code for canonical-payload
    mismatches; this class signals ``unencodable input``).
    """


def _encode_string(s: str) -> str:
    # RFC 8785 + spec line 5696: All canonicalized JSON for digest uses
    # UTF-8 NFC. NFC is idempotent and ASCII-identity, so this is a
    # no-op on the existing W6/W10 corpora (verified) and enforces the
    # invariant on any future input that contains compatibility
    # codepoints or decomposed sequences (VAL-W17-003).
    s = unicodedata.normalize("NFC", s)
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _ESCAPE_MAP.get(cp)
        if esc is not None:
            out.append(esc)
        else:
            # Higher code points (incl. non-ASCII BMP and SMP code
            # points) emit literally; final UTF-8 conversion happens
            # at bytes() time.
            out.append(ch)
    out.append('"')
    return "".join(out)


def _es6_to_string_positive(n: float) -> str:
    """ECMA-262 7.1.12.1 Number.toString for a strictly positive finite
    double. Mirrors JS ``String(n)`` byte-for-byte. Caller has handled
    NaN/Inf/zero/negative dispatch.

    Algorithm summary (see ECMA-262 7.1.12.1 + ECMA-402 Note):

      1. Derive the shortest decimal digit sequence ``s`` of length
         ``k`` that round-trips to the input double under IEEE-754
         double-precision (Grisu3/Dragon4). Let ``n_dec`` be the
         decimal-point position from the left of ``s`` (i.e., value
         equals ``int(s) * 10**(n_dec - k)``).
      2. Choose decimal vs exponential form by ``(k, n_dec)``:
           * ``k <= n_dec <= 21``  -> integer form, pad with zeros.
           * ``0 < n_dec <= 21``   -> decimal with fraction.
           * ``-6 < n_dec <= 0``   -> ``0.`` + leading zeros + digits.
           * otherwise             -> exponential ``d.ddde+NN``.

    Why this is necessary for VAL-W17-004: Python's ``repr(float)``
    yields a shortest round-trip form, but its formatter chooses
    different exponent thresholds than ECMA-262 (e.g., repr(1e-6) is
    ``'1e-06'`` while ``String(1e-6)`` is ``'0.000001'``), and prints
    exponents with zero-padding (``e-07`` vs ``e-7``) and trailing
    ``.0`` on whole-valued floats. This helper produces the exact
    bytes JS String(n) does, restoring cross-runtime byte parity for
    the W17.1 corpus.
    """
    # Shortest round-trip digits via Python repr.
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
    # Booleans are routed at the caller (Python's bool subclasses int).
    if isinstance(n, bool):
        raise TypeError("bool is not a number for JCS encoding")
    if isinstance(n, int):
        # Python int has arbitrary precision; the JCS spec encodes via
        # ECMA-262 ToString which is defined over IEEE-754 doubles.
        # Relay does not place arbitrary-precision integers inside
        # signed payloads (counts, indices, byte sizes all fit in 53
        # bits). The encoder accepts arbitrary integers byte-for-byte
        # (decimal form) for parity with the contract canonicaliser
        # which has the same behaviour.
        return str(n)
    # Float path: caller responsible for rejecting NaN/Inf upstream;
    # the defensive check below ensures we never silently emit a
    # non-canonical token if the caller forgot.
    if math.isnan(n) or math.isinf(n):
        raise JCSEncodeError(
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
        # RFC 8785 section 3.2.3: keys sorted by UTF-16 code-unit
        # sequence. For BMP-only keys (the Relay evidence-bundle
        # contract), str-by-code-point and UTF-16-by-code-unit produce
        # the same ordering. The corpus pins BMP-only keys to keep
        # this guarantee load-bearing.
        items = sorted(((str(k), v) for k, v in value.items()), key=lambda kv: kv[0])
        parts = [_encode_string(k) + ":" + _encode(v) for k, v in items]
        return "{" + ",".join(parts) + "}"
    raise JCSEncodeError(
        f"JCS: unsupported type {type(value).__name__} for value {value!r}"
    )


def jcs_canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 JCS canonical bytes for ``value``.

    Output is UTF-8 bytes (no BOM). Caller hashes or compares.
    NaN / +Inf / -Inf raise :class:`JCSEncodeError` defensively;
    well-formed callers reject these at the evaluation-result boundary.

    Spec anchors: RFC 8785 sections 3.2.2 / 3.2.2.1 / 3.2.3.
    """
    return _encode(value).encode("utf-8")


# ---------------------------------------------------------------------------
# Bundle-digest helper (VAL-W10-020)
# ---------------------------------------------------------------------------


def bundle_digest(value: Any, *, strip_signatures: bool = True) -> str:
    """Return ``sha256(jcs_canonicalize(value)).hexdigest()`` for ``value``.

    By default the helper strips a top-level ``signatures`` field if
    present, matching the bundle-signing convention (see
    :func:`relay_verifier.verifier._payload_for_signing`): the signer
    signs the canonical bytes of the signature-free payload, then
    appends the ``signatures`` block to the bundle. The same convention
    applies to per-claim digests when a claim wraps its own signatures.

    Pass ``strip_signatures=False`` to compute the digest over the
    object exactly as supplied (the corpus uses this for cases where
    the claim has no ``signatures`` envelope).
    """
    if strip_signatures and isinstance(value, dict) and "signatures" in value:
        payload = {k: v for k, v in value.items() if k != "signatures"}
    else:
        payload = value
    return hashlib.sha256(jcs_canonicalize(payload)).hexdigest()


__all__ = [
    "JCSEncodeError",
    "bundle_digest",
    "jcs_canonicalize",
]
