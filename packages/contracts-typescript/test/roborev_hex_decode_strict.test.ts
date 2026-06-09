// roborev finding 9: typedToNative bytes hex decode used Number.parseInt(pair,16)
// which accepts PARTIAL hex -- e.g. parseInt('0g', 16) === 0 -- silently
// dropping the invalid nibble instead of rejecting malformed hex.
//
// The fix validates each hex character (full string /^[0-9a-f]*$/, lowercase per
// the wasm emitter at lib.rs:1143) and rejects invalid hex with a clear error.
//
// Tool: vitest. Evidence: vitest exit code + the rejection on malformed hex and
// the round-trip of valid lowercase hex.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import { typedToNative, type TypedValue } from "../src/wasm-evaluator.js";

describe("roborev finding 9: bytes hex decode rejects malformed hex", () => {
  // Valid lowercase hex round-trips to the right bytes.
  test("valid lowercase hex decodes to the correct bytes", () => {
    const typed: TypedValue = { t: "bytes", v: "00ff10" };
    const decoded = typedToNative(typed) as Uint8Array;
    expect(decoded).toBeInstanceOf(Uint8Array);
    expect(Array.from(decoded)).toEqual([0x00, 0xff, 0x10]);
  });

  // An even-length string containing a non-hex char ('g') is malformed: the old
  // parseInt path returned 0 for '0g' and silently corrupted the decode. It must
  // throw.
  test("malformed hex '0g' (non-hex nibble) is rejected, not silently truncated", () => {
    const typed: TypedValue = { t: "bytes", v: "0g" };
    expect(() => typedToNative(typed)).toThrow();
  });

  test("malformed hex 'zz' is rejected", () => {
    const typed: TypedValue = { t: "bytes", v: "zz" };
    expect(() => typedToNative(typed)).toThrow();
  });

  // Uppercase hex is NOT what the wasm emits (lib.rs:1143 emits lowercase); the
  // strict matcher rejects it so a non-canonical encoding cannot slip through.
  test("uppercase hex 'FF' is rejected (the wasm emits lowercase)", () => {
    const typed: TypedValue = { t: "bytes", v: "FF" };
    expect(() => typedToNative(typed)).toThrow();
  });

  // The empty byte string is valid (zero-length bytes).
  test("empty hex decodes to an empty Uint8Array", () => {
    const typed: TypedValue = { t: "bytes", v: "" };
    const decoded = typedToNative(typed) as Uint8Array;
    expect(decoded).toBeInstanceOf(Uint8Array);
    expect(decoded.length).toBe(0);
  });
});
