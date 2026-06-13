// Engine-agnostic host-side guards for the Relay CEL profile (TypeScript).
//
// M6 WS-I (locked decision #4): the regex-backreference pre-screen
// (`checkRegexBackref`) and the finiteness / safe-integer guard
// (`checkFinite`) are HOST-SIDE invariants that survive the legacy engine's
// removal. They are NOT delegated to the wasm engine -- they run in the TS
// host on every engine path -- so they live in this small shared module that
// the wasm-backed evaluator (wasm-evaluator.ts WasmCelBackend) imports and
// applies. Single-sourcing them here keeps the guards from drifting and keeps
// them independent of any particular CEL backend.
//
// Mirrors the host-guard surface of
// packages/contracts/src/relay_contracts/evaluator.py (the engine-agnostic
// host-guards module after the cel-python removal): regex-backref pre-screen,
// _check_finite, and the timeout bounds.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import {
  RelayCelNumericOutOfBoundsError,
  RelayCelRegexBackreferenceError,
} from "./errors.js";

// CQ1 line 153 ("timeout-bounded"): default per-evaluation wall-clock
// budget is 50 ms; the per-tenant override caps at 250 ms.
export const DEFAULT_TIMEOUT_MS = 50;
export const MAX_TIMEOUT_MS = 250;

// VAL-PARITY-001: integral evaluation results whose absolute value EXCEEDS
// Number.MAX_SAFE_INTEGER (2**53 - 1) are rejected at the result boundary,
// mirroring packages/contracts/src/relay_contracts/evaluator.py
// SAFE_INTEGER_BOUND. cel-python keeps such an integer exact (arbitrary
// precision) while a JS double silently rounds it, so the same logical
// result would canonicalise to DIFFERENT JCS bytes in each runtime -- a
// cross-runtime digest break (CLAUDE.md keystone invariant #11). Both
// runtimes apply the SAME numeric threshold (abs > MAX_SAFE_INTEGER,
// equivalently magnitude >= 2**53) so they fail-closed identically.
//
// The threshold is MAX_SAFE_INTEGER (2**53 - 1), NOT 2**53: 2**53 is itself
// NOT a safe integer -- it is indistinguishable from 2**53 + 1 after IEEE-754
// double rounding (both round to the same float64), so a JS-double result of
// exactly 2**53 may be a ROUNDED integer overflow (e.g. 9007199254740992 + 1
// -> exact int 9007199254740993 in cel-python, rounded to 9007199254740992
// in a JS double). Accepting exactly 2**53 is precisely what would let a
// rounded integer overflow pass (fail-open vs cel-python). Key identity: for
// any integer V, float64(V) > MAX_SAFE_INTEGER  <=>  V >= 2**53, so this bound
// gives the SAME verdict in cel-python (exact int) and in the JS host (float64)
// for every integer including arithmetic overflow. (Found by `codex review`:
// CEL +-2^53 Py<->TS parity P1; CONFIRMED empirically.)
export const SAFE_INTEGER_BOUND = 2 ** 53 - 1; // 9007199254740991 === Number.MAX_SAFE_INTEGER

// Regex feature detection: backreference (\1, \2, ...) -- RE2 forbids
// these so we pre-screen them in the raw expression text. We screen the
// entire expression text rather than walking a parsed AST because the
// cross-runtime contract requires the backref-bearing expression to produce
// RELAY-CEL-007 in BOTH runtimes BEFORE the engine sees it.
//
// The pattern matches `\<digit>` inside a string literal in the raw
// expression text. Single-quoted and double-quoted CEL strings both
// parse the backslash literally; an inner `\1` in the source text
// becomes the regex backref `\1` after CEL string parsing.
const STRING_LITERAL_PATTERN = /(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')/g;
const REGEX_BACKREF_PATTERN = /\\\d/;

// Pre-screen the raw expression text for string literals containing
// regex backreferences. Mirrors packages/contracts/src/relay_contracts/
// evaluator.py:151-167. Only the first string-literal hit matters --
// any backref triggers the same envelope.
//
// Reused by the wasm-backed evaluator (wasm-evaluator.ts WasmCelBackend) so
// the host-side guard is single-sourced -- the regex-backref pre-screen runs
// in the TS host on every engine path.
export function checkRegexBackref(expression: string): void {
  let match: RegExpExecArray | null;
  // Reset lastIndex by reconstructing via fresh regex execution loop.
  const re = new RegExp(STRING_LITERAL_PATTERN.source, STRING_LITERAL_PATTERN.flags);
  while ((match = re.exec(expression)) !== null) {
    // match[1] = double-quoted body, match[2] = single-quoted body.
    const body = match[1] ?? match[2];
    if (typeof body === "string" && REGEX_BACKREF_PATTERN.test(body)) {
      throw new RelayCelRegexBackreferenceError(
        "Relay CEL profile pins regex to the RE2 subset; " +
          "backreferences (e.g., \\1) are not supported.",
      );
    }
  }
}

// Recursive finite-number check on a result tree. Lists and plain
// objects recurse; numeric leaves throw on non-finite OR on an integral
// value outside the IEEE-754 safe range. Mirrors
// packages/contracts/src/relay_contracts/evaluator.py _check_finite.
//
// Reused by the wasm-backed evaluator (wasm-evaluator.ts WasmCelBackend) so the
// IDENTICAL host-side finiteness / safe-range guard runs on the
// typedToNative-converted wasm result (the host guard stays host-side, not
// delegated to the wasm).
export function checkFinite(value: unknown): unknown {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new RelayCelNumericOutOfBoundsError(
        `Relay CEL evaluator rejects non-finite number: ${String(value)}`,
      );
    }
    // VAL-PARITY-001: an integral result whose magnitude exceeds
    // MAX_SAFE_INTEGER (2**53 - 1) is an out-of-band signal -- cel-python
    // preserves it exactly while a JS double rounds it, diverging the
    // cross-runtime digest. Fail-closed here so the JS host refuses the same
    // result cel-python refuses. 2**53 itself is NOT safe (it cannot be
    // distinguished from 2**53 + 1 after rounding) so it is rejected; only
    // magnitude <= MAX_SAFE_INTEGER is accepted. Non-integral numbers (e.g.
    // 1.5) are not subject to this bound.
    if (Number.isInteger(value) && Math.abs(value) > SAFE_INTEGER_BOUND) {
      throw new RelayCelNumericOutOfBoundsError(
        "Relay CEL evaluator rejects integer outside the IEEE-754 safe " +
          "range [-(2**53 - 1), 2**53 - 1]: a JS double would lose " +
          `precision and diverge the cross-runtime digest: ${String(value)}`,
      );
    }
    return value;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      checkFinite(item);
    }
    return value;
  }
  if (value instanceof Map) {
    // A wasm map with non-string keys (bool/int/uint) decodes to a JS Map
    // (typedToNative). Its values are NOT own-enumerable properties, so the
    // Object.keys() branch below would skip them; iterate the Map's values
    // explicitly so the finiteness / safe-integer guard still covers them
    // (keys are scalar CEL keys, never collections, so they need no recursion).
    for (const item of value.values()) {
      checkFinite(item);
    }
    return value;
  }
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    for (const k of Object.keys(obj)) {
      checkFinite(obj[k]);
    }
    return value;
  }
  return value;
}
