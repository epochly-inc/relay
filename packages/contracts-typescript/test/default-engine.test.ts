// VAL-CWC-P2TSGATE-013 (TS half): the default CEL engine stays cel-js at M2 --
// no premature flip to wasm.
//
// This is the TypeScript mirror of the Python default_engine guard
// (packages/contracts/tests/test_engine_factory.py
// test_default_engine_is_celpy_when_env_unset), which asserts
// make_cel_evaluator() with RELAY_CEL_ENGINE unset returns the cel-python
// RelayCelEvaluator. On the TS side the package exposes NO env-var engine
// factory at M2 (by design / boundaries.md: engine selection is read ONLY in
// the packages/contracts Python factory; the TS wasm backend is an opt-in class,
// not the default). So "the TS default" is the package's primary evaluator
// export -- the cel-js-backed RelayCelEvaluator -- NOT the opt-in wasm
// WasmCelBackend.
//
// The flip to a wasm default is WS-H / M5, NOT M2. This suite is the structural
// fence: it FAILS (bites) if anyone makes the default the wasm engine before
// M5 -- by aliasing the default export to WasmCelBackend, by making
// RelayCelEvaluator a wasm subclass, by re-pointing RelayCelEvaluator at the
// wasm loader, or by introducing a TS engine factory that returns wasm with the
// engine selector unset.
//
// boundaries.md: "Do NOT flip the RELAY_CEL_ENGINE default to wasm before
// milestone M5." and "Do NOT remove cel-js before milestone M6."
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import {
  readdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, test } from "vitest";

import * as contracts from "../src/index.js";
import { RelayCelEvaluator } from "../src/evaluator.js";
import { WasmCelBackend } from "../src/wasm-evaluator.js";
import { RELAY_UDFS } from "../src/udfs/registry.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC_DIR = resolve(HERE, "..", "src");
const EVALUATOR_SRC = resolve(SRC_DIR, "evaluator.ts");

describe("VAL-CWC-P2TSGATE-013: default TS CEL engine stays cel-js (no premature wasm flip)", () => {
  test("the primary evaluator export is RelayCelEvaluator, not WasmCelBackend", () => {
    // index.ts re-exports RelayCelEvaluator as the package's primary CEL
    // evaluator (mirroring make_cel_evaluator()'s celpy default). WasmCelBackend
    // is an opt-in named export, never the default. If the primary export were
    // re-pointed at the wasm backend, this fails.
    expect(contracts.RelayCelEvaluator).toBe(RelayCelEvaluator);
    expect(contracts.RelayCelEvaluator).not.toBe(WasmCelBackend);
    expect(RelayCelEvaluator).not.toBe(WasmCelBackend);
    expect(RelayCelEvaluator.name).toBe("RelayCelEvaluator");
  });

  test("the default evaluator is NOT the wasm backend (no class identity / subclass flip)", () => {
    // A flip-to-wasm could be smuggled in by aliasing the default to the wasm
    // class or making the default a subclass of WasmCelBackend. Either would
    // route the unset-default through the wasm engine -- both are M5 work, not
    // M2.
    const ev = new RelayCelEvaluator();
    expect(ev).not.toBeInstanceOf(WasmCelBackend);
    // The default class does not derive from the wasm backend.
    expect(
      RelayCelEvaluator.prototype instanceof WasmCelBackend,
    ).toBe(false);
    expect(
      WasmCelBackend.prototype.isPrototypeOf(RelayCelEvaluator.prototype),
    ).toBe(false);
  });

  test("constructing the unset-default evaluator does not load the wasm engine", () => {
    // The default evaluator is the cel-js-backed RelayCelEvaluator. It binds
    // cel-js at module import (evaluator.ts: `import { parse } from "cel-js"`)
    // and spawns a cel-js worker lazily; it never loads the wasm engine. The
    // wasm-loading surface is the `.mjs` RelayCel loader (relay-cel-wasm /
    // RelayCel.load), which lives ONLY in wasm-evaluator.ts (WasmCelBackend).
    // We prove the default's source carries NO wasm-loading surface; an
    // incidental WasmCelBackend mention in a doc comment is not such a surface,
    // so we assert on the load-bearing loader symbols, not the class name.
    const evaluatorSrc = readFileSync(EVALUATOR_SRC, "utf8");
    expect(evaluatorSrc).toContain('from "cel-js"');
    expect(evaluatorSrc).not.toContain("relay-cel-wasm");
    expect(evaluatorSrc).not.toContain("RelayCel.load");

    // Constructing the default with the production UDFs succeeds and yields a
    // cel-js RelayCelEvaluator (not a wasm backend). This is the TS analogue of
    // the Python `type(make_cel_evaluator(udfs=...)).__name__ ==
    // 'RelayCelEvaluator'` assertion.
    const defaultEvaluator = new RelayCelEvaluator({ udfs: RELAY_UDFS });
    try {
      expect(defaultEvaluator.constructor).toBe(RelayCelEvaluator);
      expect(defaultEvaluator.constructor.name).toBe("RelayCelEvaluator");
      expect(defaultEvaluator).not.toBeInstanceOf(WasmCelBackend);

      // Identity/prototype checks alone could be satisfied by a composition
      // wrapper that delegates to wasm at runtime. Prove the default actually
      // ROUTES through cel-js by evaluating an expression: RelayCelEvaluator.
      // evaluate() is the SYNCHRONOUS cel-js worker path (it returns the value
      // directly, not a Promise). The wasm backend's evaluate() returns a
      // Promise (worker_threads async loader). So a synchronous numeric result
      // here is positive evidence the cel-js engine evaluated it -- a wasm-backed
      // default would return a thenable, failing the `not Promise` assertion.
      const sum = defaultEvaluator.evaluate("1 + 1");
      expect(sum).not.toBeInstanceOf(Promise);
      expect(sum).toBe(2);
      // A second expression touching string concat exercises the cel-js parse +
      // eval path, not just integer fast-math.
      expect(defaultEvaluator.evaluate('"a" + "b"')).toBe("ab");
    } finally {
      defaultEvaluator.dispose();
    }
  });

  test("there is no TS env-var engine factory that flips the default to wasm at M2", () => {
    // Engine selection (RELAY_CEL_ENGINE) is read ONLY in the Python
    // packages/contracts factory (boundaries.md). The TS package must NOT carry
    // its own RELAY_CEL_ENGINE read that could resolve the unset-env default to
    // the wasm backend. If a future change adds such a factory, it MUST keep the
    // unset default cel-js (M5 is where the default flips). This guard asserts
    // the package does not currently expose a default-engine factory that
    // returns the wasm backend -- the only exported evaluator constructors are
    // RelayCelEvaluator (default, cel-js) and WasmCelBackend (opt-in, wasm), and
    // the primary one is cel-js.
    const exportedNames = Object.keys(contracts);
    expect(exportedNames).toContain("RelayCelEvaluator");
    expect(exportedNames).toContain("WasmCelBackend");

    // Dynamic guard (NOT a hardcoded factory-name allowlist): a hardcoded list
    // of candidate factory names (makeCelEvaluator/defaultCelEvaluator/...)
    // would miss a differently-named factory that reads RELAY_CEL_ENGINE. The
    // load-bearing boundary is "RELAY_CEL_ENGINE is read ONLY in the Python
    // factory" -- so we scan the ENTIRE TS src/ tree for ANY read of
    // process.env.RELAY_CEL_ENGINE (or a bracket-form env access). Any such read
    // in the TS package, under ANY function name, trips this guard. This is the
    // grep-based structural check that a renamed/composed factory cannot evade.
    const srcFiles = listSourceFiles(SRC_DIR);
    expect(srcFiles.length).toBeGreaterThan(0);
    const offenders: string[] = [];
    for (const file of srcFiles) {
      const raw = readFileSync(file, "utf8");
      // ROBOREV round-2 finding I: strip comments AND string literals FIRST so a
      // doc comment / message string that merely NAMES the env var (without a
      // real read) does not false-positive, and so the broadened forms below
      // cannot be smuggled inside a string. Then scan the executable code for ANY
      // form of a RELAY_CEL_ENGINE env read -- the prior guard matched only the
      // direct dot / bracket access, so a destructuring read, an optional chain,
      // or an alias (const e = process.env; e.RELAY_CEL_ENGINE) would EVADE it
      // (false confidence). The four patterns below close those evasions.
      const code = stripCommentsAndStrings(raw);
      if (readsRelayCelEngineEnv(code)) {
        offenders.push(file);
      }
    }
    expect(offenders, (
      "engine selection (RELAY_CEL_ENGINE) must be read ONLY in the Python " +
      "packages/contracts factory (boundaries.md); found a process.env." +
      `RELAY_CEL_ENGINE read in TS src/: ${offenders.join(", ")}`
    )).toEqual([]);
  });
});

/**
 * True if `code` (already comment- and string-stripped) contains ANY form of a
 * RELAY_CEL_ENGINE read off process.env. ROBOREV round-2 finding I: covers the
 * direct/bracket access (with optional chaining), the destructuring read, and an
 * aliased process.env access -- so a renamed/composed/destructured read of the
 * engine selector cannot evade the structural guard.
 */
export function readsRelayCelEngineEnv(code: string): boolean {
  // 1. Direct or bracket access, with optional chaining at either step:
  //    process.env.RELAY_CEL_ENGINE / process.env?.RELAY_CEL_ENGINE /
  //    process.env["RELAY_CEL_ENGINE"] / process?.env?.["RELAY_CEL_ENGINE"].
  // The dot form allows an optional `?.`; the bracket form allows an optional
  // `?.` BEFORE the `[` (the `process?.env?.["..."]` optional-chained bracket).
  const directOrBracket =
    /process\s*\??\.\s*env\s*(?:\??\.\s*RELAY_CEL_ENGINE\b|\??\.?\s*\[\s*["']RELAY_CEL_ENGINE["']\s*\])/;
  // 2. Destructuring directly off process.env:
  //    const { RELAY_CEL_ENGINE } = process.env
  //    const { RELAY_CEL_ENGINE: alias } = process.env  (renamed bind)
  const destructureFromEnv =
    /\{[^}]*\bRELAY_CEL_ENGINE\b[^}]*\}\s*=\s*process\s*\??\.\s*env\b/;
  if (directOrBracket.test(code) || destructureFromEnv.test(code)) {
    return true;
  }
  // 3. Alias the env object, then read RELAY_CEL_ENGINE off the alias:
  //    const env = process.env;            ... env.RELAY_CEL_ENGINE
  //    const env = process.env;            ... env["RELAY_CEL_ENGINE"]
  //    const { RELAY_CEL_ENGINE } = env     (destructure off the alias)
  // Collect identifiers bound directly to process.env, then look for a read of
  // RELAY_CEL_ENGINE off any such alias (dot / bracket / destructure).
  const aliasDecl =
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*process\s*\??\.\s*env\b/g;
  const aliases = new Set<string>();
  for (const m of code.matchAll(aliasDecl)) {
    aliases.add(m[1]!);
  }
  for (const alias of aliases) {
    const a = alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const aliasRead = new RegExp(
      `\\b${a}\\s*\\??\\s*(?:\\.\\s*RELAY_CEL_ENGINE\\b|\\[\\s*["']RELAY_CEL_ENGINE["']\\s*\\])`,
    );
    const aliasDestructure = new RegExp(
      `\\{[^}]*\\bRELAY_CEL_ENGINE\\b[^}]*\\}\\s*=\\s*${a}\\b`,
    );
    if (aliasRead.test(code) || aliasDestructure.test(code)) {
      return true;
    }
  }
  return false;
}

/**
 * Remove `//` line comments, block comments, and string/template literals from
 * TS source so the env-read scan sees executable code only (a comment or message
 * string naming RELAY_CEL_ENGINE is not a read). This is a lightweight scrubber
 * (NOT a full parser): it is conservative -- it blanks comment/string spans to
 * spaces so positions are preserved and an env read can never hide inside one.
 */
export function stripCommentsAndStrings(src: string): string {
  let out = "";
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    // Line comment.
    if (c === "/" && c2 === "/") {
      while (i < n && src[i] !== "\n") {
        i += 1;
      }
      continue;
    }
    // Block comment.
    if (c === "/" && c2 === "*") {
      i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) {
        i += 1;
      }
      i += 2;
      continue;
    }
    // Plain string ('/"). Blank the contents so a doc/message string that merely
    // NAMES the env var cannot false-positive -- EXCEPT a string that is a
    // computed-member-access KEY (preceded, skipping whitespace, by `[`), which is
    // a genuine `obj["KEY"]` access that the bracket-form scan must still see.
    if (c === '"' || c === "'") {
      // Look back (skipping whitespace) for a `[` => this string is a bracket key.
      let j = out.length - 1;
      while (j >= 0 && /\s/.test(out[j]!)) {
        j -= 1;
      }
      const isBracketKey = j >= 0 && out[j] === "[";
      const quote = c;
      let literal = quote;
      i += 1;
      while (i < n && src[i] !== quote) {
        if (src[i] === "\\") {
          literal += src[i]! + (src[i + 1] ?? "");
          i += 2;
          continue;
        }
        literal += src[i];
        i += 1;
      }
      literal += quote;
      i += 1; // skip the closing quote
      // Preserve a bracket-access key verbatim; blank any other string literal.
      out += isBracketKey ? literal : "";
      continue;
    }
    // Template literal. ROBOREV round-3 finding C: blank only the literal TEXT
    // portions, but PRESERVE and recursively scrub the ${...} interpolation
    // BODIES -- those are executable code where a RELAY_CEL_ENGINE read can hide,
    // and blanking the WHOLE template (the prior behavior) let such a read evade
    // the scan. The recursion handles nested templates / strings inside the
    // interpolation.
    if (c === "`") {
      i += 1; // skip the opening backtick
      while (i < n && src[i] !== "`") {
        if (src[i] === "\\") {
          // Escaped char in the literal text: skip both (blanked, not emitted).
          i += 2;
          continue;
        }
        if (src[i] === "$" && src[i + 1] === "{") {
          // Interpolation: capture the balanced ${...} body and recursively
          // scrub it so an env read inside it survives the scan.
          const end = findInterpolationEnd(src, i + 2, n);
          const body = src.slice(i + 2, end);
          out += stripCommentsAndStrings(body);
          // Advance past the closing `}` (end points AT it, or AT n if
          // unterminated -- then the outer loop ends).
          i = end < n ? end + 1 : n;
          continue;
        }
        // Ordinary literal text: blanked (not emitted), positions not preserved
        // across the template but a text mention can never be a read.
        i += 1;
      }
      i += 1; // skip the closing backtick (or past n if unterminated)
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
}

/**
 * Index of the `}` that closes a template-literal interpolation that opened at
 * `start` (the first char AFTER the `${`). Balances nested `{`/`}` and SKIPS
 * over nested strings, template literals, and their own interpolations so a `}`
 * inside a nested string/template does not prematurely close this one. Returns
 * the index OF the closing `}`, or `n` if the interpolation is unterminated.
 *
 * ROBOREV round-3 finding C: the template-literal scrubber needs the exact
 * interpolation body so it can recursively scan executable code (where a
 * RELAY_CEL_ENGINE read can hide) while still blanking the literal text around it.
 */
function findInterpolationEnd(src: string, start: number, n: number): number {
  let depth = 0; // nesting of plain `{`...`}` inside the interpolation body
  let i = start;
  while (i < n) {
    const c = src[i];
    // Skip a nested plain string: its braces/backticks are inert text.
    if (c === '"' || c === "'") {
      i += 1;
      while (i < n && src[i] !== c) {
        i += src[i] === "\\" ? 2 : 1;
      }
      i += 1;
      continue;
    }
    // Skip a nested template literal, recursing through its own interpolations
    // so a `}` inside the nested template does not close THIS interpolation.
    if (c === "`") {
      i += 1;
      while (i < n && src[i] !== "`") {
        if (src[i] === "\\") {
          i += 2;
          continue;
        }
        if (src[i] === "$" && src[i + 1] === "{") {
          const inner = findInterpolationEnd(src, i + 2, n);
          i = inner < n ? inner + 1 : n;
          continue;
        }
        i += 1;
      }
      i += 1; // past the closing backtick
      continue;
    }
    if (c === "{") {
      depth += 1;
      i += 1;
      continue;
    }
    if (c === "}") {
      if (depth === 0) {
        return i;
      }
      depth -= 1;
      i += 1;
      continue;
    }
    i += 1;
  }
  return n;
}

/**
 * Recursively list every .ts / .mts / .mjs / .js source file under `dir`,
 * skipping nothing (the whole src/ tree is in scope for the env-read scan).
 */
function listSourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...listSourceFiles(full));
    } else if (/\.(?:ts|mts|cts|mjs|cjs|js)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// ROBOREV round-2 finding I: NON-VACUITY of the broadened env-read guard.
// ---------------------------------------------------------------------------
describe("roborev round-2 finding I: the env-read guard catches evasive RELAY_CEL_ENGINE reads", () => {
  test("the predicate FLAGS every evasion form (direct/bracket/optional-chain/destructure/alias)", () => {
    const flagged = [
      "const v = process.env.RELAY_CEL_ENGINE;",
      "const v = process.env?.RELAY_CEL_ENGINE;",
      'const v = process.env["RELAY_CEL_ENGINE"];',
      "const v = process?.env?.[\"RELAY_CEL_ENGINE\"];",
      "const { RELAY_CEL_ENGINE } = process.env;",
      "const { RELAY_CEL_ENGINE: sel } = process.env;",
      "const e = process.env; const v = e.RELAY_CEL_ENGINE;",
      'const e = process.env; const v = e["RELAY_CEL_ENGINE"];',
      "const e = process.env; const { RELAY_CEL_ENGINE } = e;",
    ];
    for (const snippet of flagged) {
      expect(
        readsRelayCelEngineEnv(stripCommentsAndStrings(snippet)),
        `should FLAG: ${snippet}`,
      ).toBe(true);
    }
  });

  test("the predicate does NOT flag mere mentions in comments or strings, or unrelated env vars", () => {
    const clean = [
      "// reads RELAY_CEL_ENGINE in the Python factory only",
      "/* RELAY_CEL_ENGINE = process.env.RELAY_CEL_ENGINE */",
      'const msg = "process.env.RELAY_CEL_ENGINE is read in Python";',
      "const v = process.env.CEL_WASM;",
      "const { CEL_WASM } = process.env;",
      "const RELAY_CEL_ENGINE = 'wasm';", // a local var, not an env read
    ];
    for (const snippet of clean) {
      expect(
        readsRelayCelEngineEnv(stripCommentsAndStrings(snippet)),
        `should NOT flag: ${snippet}`,
      ).toBe(false);
    }
  });

  // End-to-end non-vacuity: drop a temp src file that destructures the engine
  // selector and prove the REAL guard scan flags it, then remove it. This proves
  // the file-tree scan (not just the predicate in isolation) bites the evasion.
  describe("end-to-end: a temp src file with a destructured read makes the guard FAIL", () => {
    const TEMP = resolve(SRC_DIR, "__roborev_i_nonvacuity_probe__.ts");

    afterEach(() => {
      try {
        unlinkSync(TEMP);
      } catch {
        // already removed
      }
    });

    test("the guard's file scan flags a destructuring read in src/", () => {
      writeFileSync(
        TEMP,
        "export function evade() {\n" +
          "  const { RELAY_CEL_ENGINE } = process.env;\n" +
          "  return RELAY_CEL_ENGINE;\n" +
          "}\n",
        "utf8",
      );
      const offenders: string[] = [];
      for (const file of listSourceFiles(SRC_DIR)) {
        const code = stripCommentsAndStrings(readFileSync(file, "utf8"));
        if (readsRelayCelEngineEnv(code)) {
          offenders.push(file);
        }
      }
      // The probe MUST be flagged (the old direct/bracket-only pattern missed
      // the destructuring form), and no OTHER src file should trip (so the guard
      // stays clean once the probe is removed).
      expect(offenders).toContain(TEMP);
      expect(offenders.filter((f) => f !== TEMP)).toEqual([]);
    });
  });
});

// ---------------------------------------------------------------------------
// ROBOREV round-3 finding C: the scrubber must NOT swallow a RELAY_CEL_ENGINE
// read hidden inside a TEMPLATE-LITERAL INTERPOLATION ${...}.
//
// stripCommentsAndStrings blanked the ENTIRE backtick template literal, including
// the executable ${...} expressions. A genuine env read placed inside a ${...}
// interpolation was therefore stripped BEFORE the scan, evading the guard. The
// fix must preserve (and recursively scrub) the ${...} interpolation BODIES while
// still blanking the literal text portions (so a mere MENTION of the env var in
// the literal text stays a non-read).
// ---------------------------------------------------------------------------
describe("roborev round-3 finding C: the env-read guard sees inside template-literal interpolations", () => {
  test("a RELAY_CEL_ENGINE read inside a ${...} interpolation is NOT stripped (it is FLAGGED)", () => {
    const evasions = [
      "const v = `${process.env.RELAY_CEL_ENGINE}`;",
      "const v = `engine=${process.env.RELAY_CEL_ENGINE} suffix`;",
      'const v = `${process.env["RELAY_CEL_ENGINE"]}`;',
      "const v = `${(() => { const { RELAY_CEL_ENGINE } = process.env; return RELAY_CEL_ENGINE; })()}`;",
      // Nested template inside the interpolation: the inner read must still surface.
      "const v = `outer ${`inner ${process.env.RELAY_CEL_ENGINE}`}`;",
    ];
    for (const snippet of evasions) {
      expect(
        readsRelayCelEngineEnv(stripCommentsAndStrings(snippet)),
        `should FLAG (interpolation read): ${snippet}`,
      ).toBe(true);
    }
  });

  test("a mere MENTION in the template-literal TEXT (not an interpolation) is NOT flagged", () => {
    const clean = [
      "const msg = `process.env.RELAY_CEL_ENGINE is read in Python`;",
      "const msg = `the ${'x'} env var RELAY_CEL_ENGINE lives in the Python factory`;",
    ];
    for (const snippet of clean) {
      expect(
        readsRelayCelEngineEnv(stripCommentsAndStrings(snippet)),
        `should NOT flag (literal-text mention): ${snippet}`,
      ).toBe(false);
    }
  });

  // End-to-end non-vacuity: a temp src file with an interpolation read must make
  // the REAL file-tree scan FAIL, then be removed.
  describe("end-to-end: a temp src file with an interpolation read makes the guard FAIL", () => {
    const TEMP = resolve(SRC_DIR, "__roborev_c_interp_probe__.ts");

    afterEach(() => {
      try {
        unlinkSync(TEMP);
      } catch {
        // already removed
      }
    });

    test("the guard's file scan flags a ${...}-interpolation read in src/", () => {
      writeFileSync(
        TEMP,
        "export function evade(): string {\n" +
          "  return `selected:${process.env.RELAY_CEL_ENGINE}`;\n" +
          "}\n",
        "utf8",
      );
      const offenders: string[] = [];
      for (const file of listSourceFiles(SRC_DIR)) {
        const code = stripCommentsAndStrings(readFileSync(file, "utf8"));
        if (readsRelayCelEngineEnv(code)) {
          offenders.push(file);
        }
      }
      expect(offenders).toContain(TEMP);
      expect(offenders.filter((f) => f !== TEMP)).toEqual([]);
    });
  });
});
