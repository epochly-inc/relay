"""Crockford base32 ULID generator for the Relay Python SDK (W3.2).

ULIDs are the canonical Relay idempotency key encoding (VAL-W3-017). The
26-character output matches the ULID spec:

  - 10 chars (48-bit) timestamp: milliseconds since Unix epoch.
  - 16 chars (80-bit) randomness from ``secrets.token_bytes``.

Encoding is Crockford base32 (RFC 4648 alphabet with the I/L/O/U dropped to
avoid ambiguity):

    ``0123456789ABCDEFGHJKMNPQRSTVWXYZ``

This matches the ``python-ulid`` library's default encoding and produces a
byte-identical 26-character string for the same input bytes -- the SDK
tests pin the canonical regex
``^[0-7][0-9A-HJKMNP-TV-Z]{25}$``.

A first-character constraint follows from the spec: the highest 3 bits of
a 128-bit ULID are zero until year 10889 AD (the 48-bit ms timestamp
fits in 6 octets, and base32 5-bit groups put the leftover 2 bits at the
top of the first character). The first char is in ``{0,1,2,3,4,5,6,7}``.

This module is import-side-effect-free.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import secrets
import time

# Crockford base32 alphabet (excludes I, L, O, U for human-readability).
# This is the canonical ULID alphabet; the ``python-ulid`` library uses
# the identical table.
_CROCKFORD_ALPHABET: str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# ULID encoding sizes per the spec.
_TIMESTAMP_BYTES: int = 6   # 48 bits
_RANDOMNESS_BYTES: int = 10  # 80 bits
_TOTAL_BYTES: int = _TIMESTAMP_BYTES + _RANDOMNESS_BYTES  # 16 bytes

# Encoded character lengths.
_TIMESTAMP_CHARS: int = 10
_RANDOMNESS_CHARS: int = 16
_ULID_CHARS: int = _TIMESTAMP_CHARS + _RANDOMNESS_CHARS  # 26


def _encode_crockford(b: bytes, *, char_count: int) -> str:
    """Encode ``b`` as Crockford base32 zero-padded to ``char_count`` chars.

    ``b`` is interpreted as a big-endian unsigned integer; the integer is
    converted to a base-32 string and zero-padded on the left to exactly
    ``char_count`` characters. The number of input bits MUST be
    ``char_count * 5`` (so the output is byte-stream lossless).
    """
    n = int.from_bytes(b, byteorder="big", signed=False)
    out = [""] * char_count
    for i in range(char_count - 1, -1, -1):
        out[i] = _CROCKFORD_ALPHABET[n & 0x1F]
        n >>= 5
    return "".join(out)


def new_ulid(*, now_ms: int | None = None, randomness: bytes | None = None) -> str:
    """Return a fresh 26-character Crockford base32 ULID.

    Args:
        now_ms: Optional Unix epoch milliseconds (for deterministic tests).
            Defaults to ``int(time.time() * 1000)``.
        randomness: Optional 10-byte randomness payload (for deterministic
            tests / cross-language fixture comparison). Defaults to
            ``secrets.token_bytes(10)``.

    The encoding is byte-for-byte compatible with ``python-ulid`` and the
    ``ulid`` npm package: same alphabet, same timestamp layout, same
    randomness layout, same total length. Cross-language parity
    (VAL-W3-017 cross-language fixture) requires identical input bytes.
    """
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    if now_ms < 0:
        raise ValueError("now_ms must be non-negative")
    # The 48-bit timestamp packs into 6 big-endian bytes.
    ts_bytes = now_ms.to_bytes(_TIMESTAMP_BYTES, byteorder="big", signed=False)
    if randomness is None:
        randomness = secrets.token_bytes(_RANDOMNESS_BYTES)
    if len(randomness) != _RANDOMNESS_BYTES:
        raise ValueError(
            f"randomness must be exactly {_RANDOMNESS_BYTES} bytes; "
            f"received {len(randomness)}"
        )
    return _encode_crockford(ts_bytes, char_count=_TIMESTAMP_CHARS) + _encode_crockford(
        randomness, char_count=_RANDOMNESS_CHARS
    )


__all__ = ["new_ulid"]
