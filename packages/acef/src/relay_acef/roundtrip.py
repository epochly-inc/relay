"""ACEF bundle emit/parse roundtrip helpers (W11.3).

This module provides the round-trip surface for Relay-emitted ACEF
bundles: ``emit(bundle) -> bytes`` produces RFC 8785 (JCS) canonical
UTF-8 bytes for the bundle, and ``parse(canonical_bytes) -> dict``
loads canonical bytes into a dict and re-validates the W11.2 emission
contract (root-key audit, schema_version pins, control-plane bindings).

Why a separate W11.3 module rather than methods on
``relay_extensions.EmissionWriter``? The W11.2 writer is intentionally
pure: it validates an in-memory dict and returns it unchanged so the
emission-service caller can decide on persistence. The W11.3 surface
adds the *byte-level* canonicalisation contract (roundtrip determinism,
NFC normalisation, decimal preservation, Merkle binding) on top of that
validated dict. Keeping the byte-level surface in this module preserves
the W11.2 boundary (writer = validation only; this module = bytes +
content addressing).

Public surface:

  * :func:`emit_bundle(bundle)`   -- write_bundle(bundle), then JCS
                                     canonicalize, return bytes.
  * :func:`parse_bundle(data)`    -- json.loads under Decimal scope,
                                     write_bundle for re-validation,
                                     return validated dict.
  * :func:`roundtrip(bundle)`     -- emit_bundle(parse_bundle(emit_bundle(b))).
                                     Convenience used by the corpus
                                     determinism tests.
  * :func:`bundle_merkle_root(b)` -- SHA-256 Merkle root over the
                                     bundle's claims (per spec K line
                                     4390 "binds claims into a Merkle
                                     tree"); RFC 6962 leaf+internal
                                     domain separation.
  * :func:`bundle_digest(b)`      -- SHA-256(JCS(bundle)) hex.

The Merkle leaves are the SHA-256(JCS(claim)) digests of each claim in
the canonical claim order (lexicographic on
``evidence_claim_id`` -- per ACEF Core's canonical claim order, mirrored
in VAL-W11-019). When ``claims`` is absent or empty the Merkle root is
defined as SHA-256 of the empty string (deterministic empty-tree
convention; matches the verifier's empty-bundle behaviour).

NFC normalisation (RFC 8785 section 3.2.3 + unicodedata.normalize):
JSON object keys are key-sorted by raw code-unit sequence AFTER NFC
normalisation. String VALUES are also NFC-normalised on emit so that an
input arriving in NFD (e.g. ``"cafe" + U+0301``) and the same input in
NFC (``"cafe-acute"``) produce identical canonical bytes on the very
first emit (VAL-W11-020). The parse path also NFC-normalises so a
malformed inbound bundle (NFD on the wire) re-emits as NFC bytes.

Decimal precision (RFC 8785 section 3.2.2 numbers via ECMA-262
Number.toString): numeric values that arrive as :class:`decimal.Decimal`
are routed through a JCS encoder branch that preserves the textual
representation. This avoids the float-drift trap on values like
``0.1 + 0.2``; callers SHOULD use ``Decimal`` for any value where ULP
preservation matters.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from decimal import Decimal
from typing import Any, Final

from relay_extensions.emission import EmissionWriter

# -----------------------------------------------------------------------------
# RFC 8785 JCS encoder (W11.3-local, decimal-aware).
# -----------------------------------------------------------------------------
#
# Mirrors the verifier's relay_verifier.canonical encoder semantics for
# bool/None/list/dict/str/int/float, with two W11.3-specific extensions
# required by VAL-W11-020 and VAL-W11-021:
#
#   1. unicodedata.normalize("NFC", k) is applied to every dict KEY
#      before sorting. RFC 8785 section 3.2.3 mandates UTF-16 code-unit
#      sort order; for the BMP this matches Python's str compare. NFC
#      normalisation is required because keys arriving in different
#      normal forms (e.g., NFD with combining marks) would otherwise
#      sort differently from the same key in NFC.
#
#   2. decimal.Decimal values bypass the float path entirely and are
#      emitted via str(Decimal) with the "+" exponent prefix stripped.
#      This preserves every digit; no value differs by even one ULP
#      after roundtrip.
#
# String VALUES are emitted literally (UTF-8). RFC 8785 leaves string-
# value normalisation to the application; W11.3 normalises strings to
# NFC ON PARSE so the second emit is canonical.

_ESCAPE_MAP: Final[dict[int, str]] = {
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
    """The bundle contains a value that cannot be RFC 8785 JCS-encoded.

    Distinct from the W11.2 ``SchemaVersionError`` so callers can
    distinguish "bundle structure rejected" (W11.2) from "bundle bytes
    cannot be derived" (W11.3 numeric/encoding floor).
    """


def _encode_string(s: str) -> str:
    """Emit a JSON string literal with RFC 8785 minimal escaping.

    String values are NFC-normalised before escaping so that an input
    arriving in NFD (e.g. ``"cafe" + U+0301``) and the same input in NFC
    (``"cafe-acute"``) produce identical canonical bytes. This satisfies
    VAL-W11-020 (unicode normalisation is NFC and roundtrips losslessly).
    """
    s = unicodedata.normalize("NFC", s)
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _ESCAPE_MAP.get(cp)
        if esc is not None:
            out.append(esc)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


_ECMA_262_DECIMAL_RANGE_LOW = Decimal("1E-6")
_ECMA_262_DECIMAL_RANGE_HIGH = Decimal("1E+21")


def _encode_decimal(d: Decimal) -> str:
    """Emit a Decimal per RFC 8785 / ECMA-262 NumberToString.

    A Decimal value arrives with explicit precision (e.g.,
    ``Decimal("0.1234567890123456789")``). ECMA-262 NumberToString emits
    decimal form when ``1e-6 <= |n| < 1e21`` and exponential form
    otherwise. ``str(Decimal)`` is NOT RFC 8785 compliant -- it preserves
    the parsed exponent form (e.g., ``Decimal("1E+5")`` stringifies to
    ``"1E+5"``), which JS / RFC 8785 verifiers would re-encode to
    ``"100000"``. We implement the spec explicitly so Python emits the
    same canonical bytes a JS verifier would.

    NaN / Inf are rejected (no canonical text form per JCS 3.2.2).
    Negative zero collapses to ``"0"`` per ECMA-262.
    """
    if not d.is_finite():
        raise JCSEncodeError(f"JCS cannot encode non-finite Decimal: {d!r}")
    if d.is_zero():
        return "0"
    abs_d = abs(d)
    if _ECMA_262_DECIMAL_RANGE_LOW <= abs_d < _ECMA_262_DECIMAL_RANGE_HIGH:
        # Decimal form. ``format(d, 'f')`` expands exponent notation to
        # full positional form while preserving every parsed digit.
        text = format(d, "f")
        if "." in text:
            text = text.rstrip("0").rstrip(".")
        if text.startswith("+"):
            text = text[1:]
        return text or "0"
    # Exponential form. Reconstruct mantissa + exponent from the
    # canonical decimal tuple so the shortest round-tripping
    # representation is emitted (e.g., ``1.0E+22`` -> ``1e+22``).
    sign, digits, exp = d.as_tuple()
    digits_str = "".join(str(c) for c in digits).rstrip("0")
    if not digits_str:
        return "0"
    mantissa = (
        digits_str if len(digits_str) == 1 else digits_str[0] + "." + digits_str[1:]
    )
    # Effective exponent: parsed exponent + (number of trailing zeros
    # we stripped) + (digits left of decimal point - 1).
    stripped_trailing = len("".join(str(c) for c in digits)) - len(digits_str)
    true_exp = exp + stripped_trailing + (len(digits_str) - 1)
    sign_str = "-" if sign else ""
    sign_exp = "+" if true_exp >= 0 else ""
    return f"{sign_str}{mantissa}e{sign_exp}{true_exp}"


def _es6_to_string_positive(n: float) -> str:
    """ECMA-262 7.1.12.1 Number.toString for a strictly positive finite
    double; mirrors JS ``String(n)`` byte-for-byte.

    Replicated from ``relay_contracts.canonical._es6_to_string_positive``
    (the authoritative implementation; the contracts package owns the JCS
    encoder for CEL evaluation) and from
    ``relay.redaction._es6_to_string_positive`` (the SDK redaction mirror).
    ``relay_acef`` does NOT depend on ``relay_contracts`` (see
    ``pyproject.toml``), so the algorithm is duplicated here rather than
    imported, and kept byte-identical by the cross-package parity test in
    ``tests/test_w11_3_acef_roundtrip.py``
    (``test_acef_encode_number_is_byte_identical_to_canonical``).

    Why this instead of ``repr(n)``? Python's ``repr`` uses zero-padded
    two-digit exponents (``repr(1e-7) == '1e-07'``) and never emits the
    ECMA-262 decimal form for small-magnitude values (``1e-6`` must
    canonicalise to ``'0.000001'``, not ``'1e-06'``). Routing floats
    through ``repr`` therefore produced JCS bytes that diverged from the
    Decimal path the parse side takes (``parse_float=Decimal``), breaking
    emit -> parse -> emit byte-determinism (VAL-CANON-003).
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
    """Emit an int or float per RFC 8785 (ECMA-262 Number.toString).

    Integers are emitted exact (no float coercion, so values past 2**53
    stay precise). Finite non-zero floats route through
    :func:`_es6_to_string_positive` so the bytes match the Decimal path
    (:func:`_encode_decimal`) and the authoritative
    ``relay_contracts.canonical`` encoder byte-for-byte. ``-0.0`` collapses
    to ``"0"``; NaN / Inf raise (no canonical JCS form, JCS 3.2.2).
    """
    if isinstance(n, bool):  # bool is a subclass of int; route at caller
        raise TypeError("bool is not a number for JCS encoding")
    if isinstance(n, int):
        return str(n)
    if math.isnan(n) or math.isinf(n):
        raise JCSEncodeError(f"JCS cannot encode non-finite number: {n!r}")
    if n == 0.0:
        # Collapses -0.0 to "0" per ECMA-262 ToString.
        return "0"
    if n < 0:
        return "-" + _es6_to_string_positive(-n)
    return _es6_to_string_positive(n)


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Decimal):
        return _encode_decimal(value)
    if isinstance(value, int | float):
        return _encode_number(value)
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, list | tuple):
        parts = [_encode(item) for item in value]
        return "[" + ",".join(parts) + "]"
    if isinstance(value, dict):
        # NFC-normalise keys before sorting (RFC 8785 section 3.2.3 +
        # Unicode Standard Annex #15). For BMP-only keys NFC is a
        # no-op, but the normalisation step ensures keys arriving as
        # NFD (e.g., "café" vs "café") collapse to the same
        # canonical key BEFORE the sort.
        items = sorted(
            (
                (unicodedata.normalize("NFC", str(k)), v)
                for k, v in value.items()
            ),
            key=lambda kv: kv[0],
        )
        parts = [_encode_string(k) + ":" + _encode(v) for k, v in items]
        return "{" + ",".join(parts) + "}"
    raise JCSEncodeError(
        f"JCS: unsupported type {type(value).__name__} for value {value!r}"
    )


def jcs_canonicalize(value: Any) -> bytes:
    """Return RFC 8785 canonical UTF-8 bytes for ``value``.

    See :class:`JCSEncodeError` for the rejection contract on non-finite
    numbers and unsupported types.
    """
    return _encode(value).encode("utf-8")


# -----------------------------------------------------------------------------
# Emit / parse roundtrip
# -----------------------------------------------------------------------------


def emit_bundle(bundle: dict[str, Any]) -> bytes:
    """Validate ``bundle`` (W11.2 contract) and return JCS canonical bytes.

    Raises:
        SchemaVersionError / ControlPlaneBindingError: any W11.2 contract
            violation (root-key, unknown namespace, schema_version pin,
            missing/wrong control-plane binding).
        JCSEncodeError: the bundle holds a non-finite number or a value
            type the encoder cannot serialise.
    """
    # W11.2 validation chokepoint. Returns the same dict on success.
    validated = EmissionWriter().write_bundle(bundle)
    return jcs_canonicalize(validated)


def parse_bundle(data: bytes) -> dict[str, Any]:
    """Parse JCS canonical bytes into a dict and re-validate W11.2.

    The parse path:

      1. ``json.loads(data, parse_float=Decimal)`` so numeric values
         that were emitted with full Decimal precision parse back as
         Decimal (no ULP drift on the second emit).
      2. Recursively NFC-normalise every string value so the parse path
         is idempotent against inputs that arrived in NFC-equivalent
         but byte-different form. Object keys are likewise NFC-collapsed
         (handled by the encoder's key-sort, but we do it here too so
         downstream callers see canonical keys).
      3. Re-validate via the W11.2 EmissionWriter so a bundle that
         arrives missing required control-plane bindings (VAL-W11-023)
         or with an unknown schema_version (VAL-W11-017/018) is
         rejected on parse with the same structured errors.

    Raises:
        json.JSONDecodeError: malformed JSON.
        SchemaVersionError(RELAY-SCHEMA-023): missing required
            control-plane binding (VAL-W11-023).
        SchemaVersionError: any other W11.2 contract violation.
    """
    if not isinstance(data, bytes | bytearray):
        raise TypeError(f"parse_bundle expects bytes; got {type(data).__name__}")
    parsed = json.loads(data, parse_float=Decimal)
    normalised = _nfc_walk(parsed)
    EmissionWriter().write_bundle(normalised)
    return normalised


def roundtrip(bundle: dict[str, Any]) -> bytes:
    """Return ``emit(parse(emit(bundle)))``; second emit MUST equal first.

    The byte equality between this return value and ``emit_bundle(bundle)``
    is the load-bearing assertion for VAL-W11-016 / VAL-W11-022.
    """
    first = emit_bundle(bundle)
    parsed = parse_bundle(first)
    return emit_bundle(parsed)


def _nfc_walk(value: Any) -> Any:
    """Recursively NFC-normalise every str inside a parsed JSON tree.

    Dict keys and string values are normalised. Numeric/None/bool values
    pass through. Decimals pass through (already canonical text). The
    walker preserves dict/list identity-types (returns new dict/list).
    """
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_nfc_walk(item) for item in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            kk = unicodedata.normalize("NFC", str(k))
            out[kk] = _nfc_walk(v)
        return out
    # Decimal, int, float, bool, None: return as-is.
    return value


# -----------------------------------------------------------------------------
# Bundle digest + Merkle root (VAL-W11-019)
# -----------------------------------------------------------------------------


def bundle_digest(bundle: dict[str, Any]) -> str:
    """Return ``sha256(emit_bundle(bundle))`` as lowercase hex.

    Convenience over ``hashlib.sha256(emit_bundle(b)).hexdigest()``.
    The bundle is validated as a side effect of emit_bundle; a malformed
    bundle raises before the digest is computed.
    """
    return hashlib.sha256(emit_bundle(bundle)).hexdigest()


def _claim_canonical_id(claim: dict[str, Any]) -> str:
    """Return the canonical sort key for a claim.

    ACEF Core's canonical claim order (per VAL-W11-019) is lexicographic
    on ``evidence_claim_id``. If a claim is missing ``evidence_claim_id``
    we fall back to the SHA-256 digest of its canonical bytes so the
    sort is still total and deterministic; this matches the verifier's
    "no-id claim" handling and keeps the Merkle root computable even
    when a fixture omits the optional id field.
    """
    cid = claim.get("evidence_claim_id")
    if isinstance(cid, str) and cid:
        return cid
    return hashlib.sha256(jcs_canonicalize(claim)).hexdigest()


def bundle_merkle_root(bundle: dict[str, Any]) -> str:
    """Return the Merkle root over ``bundle["claims"]`` as lowercase hex.

    Tree shape (RFC 6962 sec 2; mirror of relay_verifier.merkle):

      - Leaves: SHA-256(0x00 || sha256(JCS(claim))) over each claim, in
        canonical claim order (sorted by evidence_claim_id).
      - Internal: SHA-256(0x01 || left || right).
      - Odd levels: promote the last unpaired node verbatim
        (lonely-leaf convention).
      - Empty bundle: SHA-256(b"") -> the canonical empty-bundle root,
        matching the verifier's empty-bundle behaviour.

    Determinism guarantee: for the same set of claims (regardless of
    insertion order in the input dict), this function returns the same
    root. VAL-W11-019 binds the equality:
    ``bundle_merkle_root(parse(emit(b))) == bundle_merkle_root(b)``.
    """
    claims = bundle.get("claims") or []
    if not claims:
        return hashlib.sha256(b"").hexdigest()

    sorted_claims = sorted(claims, key=_claim_canonical_id)
    leaves: list[bytes] = []
    for claim in sorted_claims:
        claim_digest = hashlib.sha256(jcs_canonicalize(claim)).digest()
        leaves.append(hashlib.sha256(b"\x00" + claim_digest).digest())

    level = leaves
    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            if i + 1 < len(level):
                right = level[i + 1]
                next_level.append(hashlib.sha256(b"\x01" + left + right).digest())
            else:
                # Lonely-leaf: promote the unpaired node verbatim.
                next_level.append(left)
        level = next_level
    return level[0].hex()


__all__ = [
    "JCSEncodeError",
    "bundle_digest",
    "bundle_merkle_root",
    "emit_bundle",
    "jcs_canonicalize",
    "parse_bundle",
    "roundtrip",
]
