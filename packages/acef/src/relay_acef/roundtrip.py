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
import re
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

_TRAILING_DOT_ZERO: Final[re.Pattern[str]] = re.compile(r"^(-?\d+)\.0$")


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


def _encode_decimal(d: Decimal) -> str:
    """Emit a Decimal with every digit preserved; no ULP drift.

    A Decimal value arrives with explicit precision (e.g.,
    ``Decimal("0.1234567890123456789")``). We emit via ``str(Decimal)``,
    strip a leading ``+`` if present, and reject NaN/Inf defensively
    (no canonical text form for non-finite per JCS section 3.2.2).
    """
    if not d.is_finite():
        raise JCSEncodeError(f"JCS cannot encode non-finite Decimal: {d!r}")
    # ECMA-262 NumberToString collapses negative zero to "0". Without this
    # the second emit drifts (parse loses the sign on JSON's numeric -0).
    if d.is_zero():
        return "0"
    text = str(d)
    if text.startswith("+"):
        text = text[1:]
    return text


def _encode_number(n: int | float) -> str:
    """Emit an int or float per RFC 8785 (ECMA-262 Number.toString)."""
    if isinstance(n, bool):  # bool is a subclass of int; route at caller
        raise TypeError("bool is not a number for JCS encoding")
    if isinstance(n, int):
        return str(n)
    if math.isnan(n) or math.isinf(n):
        raise JCSEncodeError(f"JCS cannot encode non-finite number: {n!r}")
    if n == 0.0:
        return "0"
    if n.is_integer() and -1e21 < n < 1e21:
        return str(int(n))
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
