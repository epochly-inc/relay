/**
 * Crockford base32 ULID generator for the Relay TypeScript SDK (W4.2).
 *
 * Parity with the Python SDK ``relay._ulid`` module. ULIDs are the
 * canonical Relay idempotency-key encoding (VAL-W4-014). The 26-character
 * output matches the ULID spec:
 *
 *   - 10 chars (48-bit) timestamp: milliseconds since Unix epoch.
 *   - 16 chars (80-bit) randomness from ``crypto.randomBytes``.
 *
 * Encoding is Crockford base32 (RFC 4648 alphabet with the I/L/O/U dropped
 * to avoid ambiguity):
 *
 *     ``0123456789ABCDEFGHJKMNPQRSTVWXYZ``
 *
 * This matches the ``ulid`` npm package's default encoding and produces a
 * byte-identical 26-character string for the same input bytes -- the SDK
 * tests pin the canonical regex ``^[0-7][0-9A-HJKMNP-TV-Z]{25}$``.
 *
 * Cross-language parity (VAL-W4-014): given identical seed bytes, this
 * generator MUST produce the same 26-character ULID as the Python
 * ``relay._ulid.new_ulid`` and the canonical ``ulid`` npm package. The
 * test corpus pins this with shared seeds.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";

// Crockford base32 alphabet (excludes I, L, O, U for human-readability).
// This is the canonical ULID alphabet; the ``ulid`` npm package uses the
// identical table.
const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

// ULID encoding sizes per the spec.
const TIMESTAMP_BYTES = 6; // 48 bits
const RANDOMNESS_BYTES = 10; // 80 bits

// Encoded character lengths.
const TIMESTAMP_CHARS = 10;
const RANDOMNESS_CHARS = 16;
const ULID_CHARS = TIMESTAMP_CHARS + RANDOMNESS_CHARS; // 26

/** The canonical Crockford base32 ULID regex (VAL-W4-014). */
export const ULID_REGEX = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

/**
 * Encode ``buf`` as Crockford base32 zero-padded to ``charCount`` chars.
 *
 * ``buf`` is interpreted as a big-endian unsigned integer; the integer is
 * converted to a base-32 string and zero-padded on the left to exactly
 * ``charCount`` characters. The number of input bits MUST be
 * ``charCount * 5`` (so the output is byte-stream lossless).
 */
function encodeCrockford(buf: Buffer, charCount: number): string {
  // Build a big-endian integer from bytes. We avoid BigInt where possible
  // by using a per-character running modulus over the byte stream, but
  // BigInt is the only safe path for >= 32 bits because Number loses
  // precision past 2^53 and the timestamp+randomness halves are 48 bits
  // and 80 bits respectively.
  let n = BigInt(0);
  for (const byte of buf) {
    n = (n << BigInt(8)) | BigInt(byte);
  }
  const out: string[] = new Array(charCount).fill("0");
  for (let i = charCount - 1; i >= 0; i--) {
    const idx = Number(n & BigInt(0x1f));
    out[i] = CROCKFORD_ALPHABET.charAt(idx);
    n >>= BigInt(5);
  }
  return out.join("");
}

export interface NewUlidOptions {
  /** Optional Unix epoch milliseconds (for deterministic tests). */
  nowMs?: number;
  /** Optional 10-byte randomness payload (for deterministic tests). */
  randomness?: Buffer;
}

/**
 * Return a fresh 26-character Crockford base32 ULID.
 *
 * Cross-language parity (VAL-W4-014) requires identical input bytes
 * produce identical output strings vs Python ``relay._ulid.new_ulid``
 * and the canonical ``ulid`` npm package.
 */
export function newUlid(options: NewUlidOptions = {}): string {
  const nowMs = options.nowMs ?? Date.now();
  if (!Number.isInteger(nowMs) || nowMs < 0) {
    throw new Error(`now_ms must be a non-negative integer; received ${nowMs}`);
  }
  // Pack 48-bit timestamp into 6 big-endian bytes.
  const tsBuf = Buffer.alloc(TIMESTAMP_BYTES);
  // Use BigInt to avoid Number precision loss past 2^32.
  let ts = BigInt(nowMs);
  for (let i = TIMESTAMP_BYTES - 1; i >= 0; i--) {
    tsBuf[i] = Number(ts & BigInt(0xff));
    ts >>= BigInt(8);
  }
  let randBuf: Buffer;
  if (options.randomness !== undefined) {
    if (!Buffer.isBuffer(options.randomness) || options.randomness.length !== RANDOMNESS_BYTES) {
      throw new Error(
        `randomness must be exactly ${RANDOMNESS_BYTES} bytes; received ${options.randomness?.length ?? "non-buffer"}`,
      );
    }
    randBuf = options.randomness;
  } else {
    randBuf = crypto.randomBytes(RANDOMNESS_BYTES);
  }
  return encodeCrockford(tsBuf, TIMESTAMP_CHARS) + encodeCrockford(randBuf, RANDOMNESS_CHARS);
}

/** Total length of a canonical ULID string (26). */
export const ULID_LENGTH = ULID_CHARS;
