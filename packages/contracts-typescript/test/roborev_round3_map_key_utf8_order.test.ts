// ROBOREV round-3 findings A + B on the round-2 nativeToTyped Map re-encode path.
//
// Finding A (MED, KEYSTONE #16): the Map-branch / object-branch key sort used JS
// `<` / `>`, which compares UTF-16 CODE UNITS. Rust `str` Ord (the pinned wasm
// crate, lib.rs:1270 `a.0.cmp(&b.0)`) compares UTF-8 BYTES, and Python's
// `_key_sort_string` is sorted by `str` code-point order (wasm_codec.py:311
// `entries.sort(key=lambda e: e[0])`). UTF-8 byte order == code-point order, and
// BOTH differ from UTF-16 code-unit order for supplementary-plane (non-BMP,
// >= U+10000) characters (a surrogate pair's lead unit 0xD800..0xDBFF sorts
// BELOW a BMP char in [0xE000, 0xFFFF] under UTF-16, but ABOVE it under
// code-point / UTF-8 order). So a map with a non-BMP string key could be
// re-ordered by TS and break byte-identical round-trip (a P0 keystone break).
//
// Finding B (MED, fail-closed): the nativeToTyped Map branch could emit multiple
// typed map pairs whose keys COLLIDE on the same CEL key (same keySortString);
// the wasm decoder inserts into a Rust HashMap (lib.rs:1437 `hm.insert`) so one
// value is silently overwritten (data loss). The Map branch must fail closed on
// a duplicate -- byte-symmetric with the typedToNative DECODE path, which already
// rejects a colliding key (round-2 finding D).
//
// Tool: vitest. Evidence: vitest exit code + the re-encoded typed ordering and the
// duplicate-key rejection.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import { RelayCelEngineError } from "../src/errors.js";
import {
  keySortString,
  nativeToTyped,
  type TypedValue,
} from "../src/wasm-evaluator.js";

// A non-BMP (supplementary-plane) string and a BMP string chosen so the two
// orderings DISAGREE:
//   - BMP key  : U+FFFD REPLACEMENT CHARACTER (code point 0xFFFD, one UTF-16 unit)
//   - non-BMP  : U+1F600 GRINNING FACE (code point 0x1F600, surrogate pair
//                0xD83D 0xDE00 in UTF-16)
// Code-point / UTF-8 order: 0xFFFD < 0x1F600  -> BMP key sorts FIRST.
// UTF-16 code-unit order:  lead 0xD83D < 0xFFFD -> non-BMP key sorts FIRST.
// The crate + Python sort by code-point/UTF-8, so the BMP key MUST come first.
const BMP_KEY = "\uFFFD"; // U+FFFD REPLACEMENT CHARACTER (ASCII-escaped source)
const NON_BMP_KEY = "\u{1F600}"; // U+1F600 GRINNING FACE (ASCII-escaped source)

describe("roborev round-3 finding A: map-key sort matches Rust UTF-8 / Python code-point order, NOT UTF-16", () => {
  test("a non-BMP and a BMP string key re-encode in code-point order (BMP first)", () => {
    // Build a JS Map whose keys are TypedValue string keys (the shape
    // typedToNative emits for a non-string-keyed map; here we force a
    // mixed-with-non-string map by including a non-string key so nativeToTyped
    // takes the Map branch and exercises keySortString ordering).
    const m = new Map<TypedValue, unknown>([
      // Insertion order deliberately puts the non-BMP key FIRST so a stable sort
      // would keep it first unless the comparator actively reorders.
      [{ t: "string", v: NON_BMP_KEY }, "emoji"],
      [{ t: "string", v: BMP_KEY }, "replacement"],
    ]);
    const encoded = nativeToTyped(m) as { t: "map"; v: [TypedValue, TypedValue][] };
    expect(encoded.t).toBe("map");
    const keyStrings = encoded.v.map(([k]) => (k as { v: string }).v);
    // Code-point / UTF-8 order: the BMP key (U+FFFD) MUST sort BEFORE the non-BMP
    // key (U+1F600). UTF-16 code-unit order would (wrongly) put the emoji first.
    expect(keyStrings).toEqual([BMP_KEY, NON_BMP_KEY]);
  });

  test("the keySortString comparator orders code-point order, not UTF-16 (direct)", () => {
    // keySortString returns "3:string:<raw>"; the discriminating order is the raw
    // key. The TS comparator MUST agree with code-point order for the non-BMP vs
    // BMP pair (the JS `<` UTF-16 comparison gets this WRONG).
    const sBmp = keySortString({ t: "string", v: BMP_KEY });
    const sNonBmp = keySortString({ t: "string", v: NON_BMP_KEY });
    // Under code-point / UTF-8 order, BMP (U+FFFD) sorts before non-BMP (U+1F600).
    // A correct comparator returns sBmp < sNonBmp; this is what the Map branch
    // and object branch must use (a UTF-8-byte comparison), NOT JS `<`.
    expect(codePointLess(sBmp, sNonBmp)).toBe(true);
    // And the UTF-16 `<` gives the OPPOSITE (proving the two orders diverge for
    // this pair -- the whole point of the finding).
    expect(sBmp < sNonBmp).toBe(false);
  });

  test("a plain-object (string-key) map also re-encodes in code-point order", () => {
    // The object branch (string-only keys) must use the SAME UTF-8 comparator.
    const obj: Record<string, unknown> = {};
    obj[NON_BMP_KEY] = "emoji";
    obj[BMP_KEY] = "replacement";
    const encoded = nativeToTyped(obj) as { t: "map"; v: [TypedValue, TypedValue][] };
    const keyStrings = encoded.v.map(([k]) => (k as { v: string }).v);
    expect(keyStrings).toEqual([BMP_KEY, NON_BMP_KEY]);
  });
});

describe("roborev round-3 finding B: nativeToTyped Map branch fails closed on a duplicate CEL key", () => {
  test("a JS Map with two keys colliding on the SAME CEL key raises (no silent overwrite)", () => {
    // Two distinct TypedValue key OBJECTS that map to the SAME keySortString
    // ({"t":"int","v":"5"} twice). The wasm decoder would silently overwrite one
    // (Rust HashMap insert); the encode path must reject before emitting.
    const m = new Map<TypedValue, unknown>([
      [{ t: "int", v: "5" }, "first"],
      [{ t: "int", v: "5" }, "second"],
    ]);
    expect(() => nativeToTyped(m)).toThrow(RelayCelEngineError);
  });

  test("a string-key collision (two equal string keys) also raises", () => {
    const m = new Map<TypedValue, unknown>([
      [{ t: "string", v: "dup" }, "a"],
      [{ t: "string", v: "dup" }, "b"],
    ]);
    expect(() => nativeToTyped(m)).toThrow(RelayCelEngineError);
  });

  test("distinct keys (int 5 and uint 5) do NOT collide (no false positive)", () => {
    const m = new Map<TypedValue, unknown>([
      [{ t: "int", v: "5" }, "as_int"],
      [{ t: "uint", v: "5" }, "as_uint"],
    ]);
    expect(() => nativeToTyped(m)).not.toThrow();
  });
});

// Reference code-point comparison: compare two strings by Unicode code point
// (the order Rust `str` Ord / Python `str` sort produce). Iterating a JS string
// with for..of yields code points (not UTF-16 units), so comparing the code
// point sequences gives the code-point order independent of the implementation
// under test.
function codePointLess(a: string, b: string): boolean {
  const ca = [...a].map((ch) => ch.codePointAt(0)!);
  const cb = [...b].map((ch) => ch.codePointAt(0)!);
  const n = Math.min(ca.length, cb.length);
  for (let i = 0; i < n; i++) {
    if (ca[i]! !== cb[i]!) {
      return ca[i]! < cb[i]!;
    }
  }
  return ca.length < cb.length;
}

// ---------------------------------------------------------------------------
// Cross-host byte parity: the TS nativeToTyped typed form for a map with a
// non-BMP string key MUST be byte-identical to the Python py_to_typed typed form
// (the bytes the wasm consumes on each host). This is the keystone #16 guard for
// finding A: if the TS sort diverged from Python's code-point sort, the ordered
// [[k,v],...] pairs -- and thus the serialized wire bytes -- would differ.
// ---------------------------------------------------------------------------
describe("roborev round-3 finding A: Py-wasm typed bytes == TS round-trip bytes for a non-BMP map key", () => {
  test("a map keyed by U+1F600 (non-BMP) and U+FFFD (BMP) serializes byte-identically on both hosts", () => {
    // The same logical map on both hosts: two string keys (one non-BMP, one BMP)
    // and a third pure-ASCII key, deliberately given out of sorted order so the
    // sort -- the thing under test -- is exercised on both sides.
    const KEYS: Array<[string, string]> = [
      [NON_BMP_KEY, "emoji"],
      ["z", "ascii_z"],
      [BMP_KEY, "replacement"],
    ];

    // TS side: build a JS Map of TypedValue string keys -> values, encode via
    // nativeToTyped (the Map branch + the UTF-8 comparator under test), and
    // serialize to the wire JSON the wasm consumes.
    const tsMap = new Map<TypedValue, unknown>(
      KEYS.map(([k, v]) => [{ t: "string", v: k } as TypedValue, v]),
    );
    const tsTyped = nativeToTyped(tsMap);
    const tsBytes = JSON.stringify(tsTyped);

    // Python side: build the EXACT same map (a plain dict of str -> str), encode
    // via py_to_typed (the parity reference, byte-faithful to the Rust crate),
    // and serialize with the same compact JSON separators so the byte comparison
    // is meaningful.
    const pyBytes = pythonPyToTypedMap(KEYS);

    // Byte-identical: the ordered [[k,v],...] pairs match, so the wasm sees the
    // same input bytes on both hosts (finding A, keystone #16).
    expect(tsBytes).toBe(pyBytes);

    // And the order is code-point order (BMP < non-BMP < 'z'? no: 'z' is 0x7A <
    // both): assert the actual sorted key order explicitly. Code points:
    // 'z'=0x7A, U+FFFD=0xFFFD, U+1F600=0x1F600 -> z < BMP < non-BMP.
    const parsed = tsTyped as { t: "map"; v: [TypedValue, TypedValue][] };
    const order = parsed.v.map(([k]) => (k as { v: string }).v);
    expect(order).toEqual(["z", BMP_KEY, NON_BMP_KEY]);
  });
});

// Encode a list of [strKey, strVal] pairs as a Python dict through the parity
// REFERENCE py_to_typed (loaded by file location so the package __init__ -- which
// pulls relay_schemas -- is bypassed; wasm_codec.py needs only celpy + stdlib),
// then json.dumps with the SAME compact separators JS JSON.stringify uses
// (",", ":"). Returns the wire JSON string. Fails loud (no skip) if the venv
// python is missing -- a silent skip would mask a byte-parity divergence
// (keystone #16).
function pythonPyToTypedMap(pairs: Array<[string, string]>): string {
  const root = repoRoot();
  const codecPath = resolve(
    root,
    "packages",
    "contracts",
    "src",
    "relay_contracts",
    "wasm_codec.py",
  );
  // Pass the pairs as a JSON argument so non-ASCII (non-BMP) keys cross the
  // process boundary losslessly (json.loads reconstructs the exact code points).
  const pairsJson = JSON.stringify(pairs);
  const script = [
    "import sys, json, importlib.util",
    `spec = importlib.util.spec_from_file_location('wcodec', ${JSON.stringify(codecPath)})`,
    "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    "pairs = json.loads(sys.argv[1])",
    "d = {k: v for k, v in pairs}",
    "typed = m.py_to_typed(d)",
    // Compact separators to match JS JSON.stringify (no spaces); ensure_ascii
    // False so the raw UTF-8 bytes of the keys are emitted (JS JSON.stringify
    // also emits raw chars for printable non-ASCII), making the byte comparison
    // apples-to-apples.
    "sys.stdout.write(json.dumps(typed, separators=(',', ':'), ensure_ascii=False))",
  ].join("\n");
  return execFileSync(pythonExecutable(root), ["-c", script, pairsJson], {
    cwd: root,
    encoding: "utf-8",
  });
}

// The relay/ package root (where .venv lives). test/ is
// packages/contracts-typescript/test/ -> the relay root is three directories up.
function repoRoot(): string {
  const here = fileURLToPath(new URL(".", import.meta.url));
  return resolve(here, "..", "..", "..");
}

// The repo venv python (which has celpy installed); fall back to ambient python3.
// Fail loud if neither resolves rather than skip -- a silent skip would hide a
// byte-parity divergence (keystone #16).
function pythonExecutable(root: string): string {
  const venvPy = resolve(root, ".venv", "bin", "python3");
  if (existsSync(venvPy)) {
    return venvPy;
  }
  return "python3";
}
