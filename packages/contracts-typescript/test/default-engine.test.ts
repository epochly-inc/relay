// VAL-CWC-P5FLIP-011 (M5 / WS-H): the TS contracts factory defaults to the
// WASM CEL engine; cel-js is returned ONLY on explicit selection.
//
// This suite is the TRANSITIONED successor of the M2 fence
// (VAL-CWC-P2TSGATE-013), which asserted the default STAYED cel-js while the
// wasm backend was an opt-in class. M5 is exactly the milestone that flips the
// default (boundaries.md: "Do NOT flip the RELAY_CEL_ENGINE default to wasm
// before milestone M5" -- this IS M5). The canonical selection factory
// `makeCelEvaluator` (src/engine.ts, the TS mirror of the Python
// make_cel_evaluator in packages/contracts/src/relay_contracts/engine.py) now
// constructs the wasm-backed `WasmCelBackend` when the engine selection is
// UNSET (or blank), and the legacy cel-js `RelayCelEvaluator` ONLY when the
// caller explicitly selects "celjs" / "cel-js" (the rollback escape hatch
// through the one-release bake; cel-js is removed at M6, per boundaries.md
// "Do NOT remove cel-js before milestone M6").
//
// Pre-flip non-vacuity: at the pre-flip baseline (workerStartCommit 7a2bc04)
// this file's predecessor PROVED the unset default routed through cel-js
// synchronously (the "constructing the unset-default evaluator does not load
// the wasm engine" case, green in the baseline run), and NO factory existed
// (the package exported only the two classes). The default-equals-wasm
// assertions below therefore encode a REAL behavior flip, not a vacuous truth.
//
// Determinism boundary, UNCHANGED by the flip: the TS selection is
// CONFIG/PARAM-based, NOT environment-based. The engine-selector ENV VAR is
// read ONLY in the Python packages/contracts factory; the AST presence scan
// below (unchanged from M2) still FAILS the suite if any production TS src/
// file ever names that selector.
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

import ts from "typescript";
import { afterEach, describe, expect, test } from "vitest";

import * as contracts from "../src/index.js";
import { makeCelEvaluator } from "../src/engine.js";
import { RelayCelUnsupportedUdfError } from "../src/errors.js";
import {
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  RelayCelEvaluator,
} from "../src/evaluator.js";
import { registerUdf } from "../src/udf.js";
import { RELAY_UDFS } from "../src/udfs/registry.js";
import {
  resolvePackagedLoaderPath,
  resolvePackagedWasmPath,
} from "../src/wasm-artifact.js";
import { WasmCelBackend } from "../src/wasm-evaluator.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC_DIR = resolve(HERE, "..", "src");
const EVALUATOR_SRC = resolve(SRC_DIR, "evaluator.ts");

describe("VAL-CWC-P5FLIP-011: TS factory default engine is wasm; cel-js only on explicit selection", () => {
  test("default engine is wasm: makeCelEvaluator() with the engine selection unset constructs WasmCelBackend", async () => {
    // The TS analogue of the Python `type(make_cel_evaluator(udfs=...)).__name__
    // == 'WasmCelEvaluator'` assertion (VAL-CWC-P5FLIP-009): no `engine` option
    // -> the wasm backend. Pre-flip (M2-M4) the package's default evaluator was
    // the cel-js RelayCelEvaluator and no factory existed; this is the flip.
    const unsetDefault = makeCelEvaluator({ udfs: RELAY_UDFS });
    try {
      expect(unsetDefault).toBeInstanceOf(WasmCelBackend);
      expect(unsetDefault.constructor).toBe(WasmCelBackend);
      expect(unsetDefault.constructor.name).toBe("WasmCelBackend");
      expect(unsetDefault).not.toBeInstanceOf(RelayCelEvaluator);
    } finally {
      await unsetDefault.dispose();
    }

    // A bare zero-argument call and an explicit `engine: undefined` are the
    // SAME "no selection" signal -- both resolve to the wasm default.
    const bare = makeCelEvaluator();
    try {
      expect(bare).toBeInstanceOf(WasmCelBackend);
      expect(bare.timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    } finally {
      await bare.dispose();
    }
    const explicitUndefined = makeCelEvaluator({ engine: undefined });
    try {
      expect(explicitUndefined).toBeInstanceOf(WasmCelBackend);
    } finally {
      await explicitUndefined.dispose();
    }
  });

  test("default engine is wasm: a blank/whitespace engine token is 'no selection' and resolves to wasm", async () => {
    // Mirrors the Python factory's blank handling (engine.py:113-119): a
    // set-but-blank selector cannot pin the legacy engine -- only an explicit
    // "celjs"/"cel-js" selects the rollback.
    for (const blank of ["", "   ", "\t\n"]) {
      const ev = makeCelEvaluator({ engine: blank });
      try {
        expect(ev).toBeInstanceOf(WasmCelBackend);
      } finally {
        await (ev as WasmCelBackend).dispose();
      }
    }
  });

  test("default engine is wasm AND it evaluates: a smoke eval through the unset-default path returns the right verdict", async () => {
    // Loader-wiring proof (the flip is only real if the default backend LOADS):
    // the unset default resolves the PACKAGED wasm + `.mjs` loader (WS-G package
    // data; precedence explicit > CEL_WASM > packaged, wasm-evaluator.ts:1087,
    // defaultLoaderPath). With CEL_WASM unset, both packaged artifacts must
    // resolve and the default backend must actually EVALUATE through them.
    const savedCelWasm = process.env.CEL_WASM;
    delete process.env.CEL_WASM;
    try {
      expect(resolvePackagedWasmPath()).not.toBeNull();
      expect(resolvePackagedLoaderPath()).not.toBeNull();

      // ENGINE stays unset (that is the assertion under test); timeoutMs is
      // MAX_TIMEOUT_MS (the 250ms Relay cap) because the budget covers Worker
      // COLD START (spawn + .mjs import + wasm compile) and a 50ms budget
      // spuriously times out under concurrent full-suite load -- the SAME
      // jitter class the Python side swept in commit 7a2bc04. The result
      // assertions are unchanged; only the budget grows.
      const ev = makeCelEvaluator({
        udfs: RELAY_UDFS,
        timeoutMs: MAX_TIMEOUT_MS,
      });
      expect(ev).toBeInstanceOf(WasmCelBackend);
      try {
        // The wasm default's evaluate() is the ASYNC worker path (a Promise) --
        // the exact inverse of the M2 fence's synchronous cel-js evidence.
        const pending = ev.evaluate("1 + 1");
        expect(pending).toBeInstanceOf(Promise);
        expect(await pending).toBe(2);
        // String concat + a comprehension exercise the wasm parse/eval path,
        // not just integer fast-math.
        expect(await ev.evaluate('"a" + "b"')).toBe("ab");
        expect(await ev.evaluate("[1, 2, 3].exists(x, x == 2)")).toBe(true);
      } finally {
        await ev.dispose();
      }
    } finally {
      if (savedCelWasm !== undefined) {
        process.env.CEL_WASM = savedCelWasm;
      }
    }
  });

  test("explicit cel-js selection returns the legacy RelayCelEvaluator (rollback escape hatch)", () => {
    // Both spellings of the legacy token select the cel-js evaluator, mirroring
    // the Python factory's explicit `celpy` rollback (VAL-CWC-P5FLIP-010).
    for (const token of ["celjs", "cel-js"] as const) {
      const ev = makeCelEvaluator({ engine: token, udfs: RELAY_UDFS });
      try {
        expect(ev).toBeInstanceOf(RelayCelEvaluator);
        expect(ev.constructor).toBe(RelayCelEvaluator);
        expect(ev).not.toBeInstanceOf(WasmCelBackend);
      } finally {
        ev.dispose();
      }
    }
  });

  test("the rollback cel-js evaluator still ROUTES through cel-js (sync evaluate, no wasm-loading surface)", () => {
    // cel-js stays intact as the rollback until M6: evaluator.ts still binds
    // cel-js at module import and carries NO wasm-loading surface (the loader
    // symbols live only in wasm-evaluator.ts).
    const evaluatorSrc = readFileSync(EVALUATOR_SRC, "utf8");
    expect(evaluatorSrc).toContain('from "cel-js"');
    expect(evaluatorSrc).not.toContain("relay-cel-wasm");
    expect(evaluatorSrc).not.toContain("RelayCel.load");

    // Class identity alone could be satisfied by a composition wrapper that
    // delegates to wasm at runtime. Prove the rollback actually ROUTES through
    // cel-js by evaluating: RelayCelEvaluator.evaluate() is the SYNCHRONOUS
    // cel-js path (it returns the value directly, not a Promise); the wasm
    // backend's evaluate() returns a Promise. A synchronous numeric result here
    // is positive evidence the cel-js engine evaluated it.
    const rollback = makeCelEvaluator({ engine: "cel-js", udfs: RELAY_UDFS });
    expect(rollback).toBeInstanceOf(RelayCelEvaluator);
    try {
      const sum = rollback.evaluate("1 + 1");
      expect(sum).not.toBeInstanceOf(Promise);
      expect(sum).toBe(2);
      expect(rollback.evaluate('"a" + "b"')).toBe("ab");
    } finally {
      rollback.dispose();
    }
  });

  test("explicit wasm selection returns WasmCelBackend (same engine as the default)", async () => {
    const ev = makeCelEvaluator({ engine: "wasm", udfs: RELAY_UDFS });
    try {
      expect(ev).toBeInstanceOf(WasmCelBackend);
    } finally {
      await ev.dispose();
    }
  });

  test("an unknown engine token is rejected fail-closed (never a silent fallback)", () => {
    // Mirrors the Python ValueError contract (engine.py:120-127): name the bad
    // value AND the allowed set; matching is case-sensitive. "celpy" is the
    // PYTHON rollback token -- it is NOT a TS engine and must not silently
    // select anything here.
    for (const bad of ["celpy", "WASM", "Cel-JS", "wasm2", "cel_js"]) {
      expect(() => makeCelEvaluator({ engine: bad })).toThrow(
        /not a recognized CEL engine/,
      );
      expect(() => makeCelEvaluator({ engine: bad })).toThrow(bad);
      expect(() => makeCelEvaluator({ engine: bad })).toThrow(/case-sensitive/);
    }
    // A non-string runtime value (a JS caller bypassing the types) is a
    // category error, rejected with a clear TypeError -- never coerced.
    expect(() =>
      makeCelEvaluator({ engine: 42 as unknown as string }),
    ).toThrow(TypeError);
  });

  test("timeoutMs and udfs forward to the selected evaluator with identical semantics", async () => {
    // An explicit (within-cap; MAX_TIMEOUT_MS is 250) timeout reaches
    // whichever engine is selected.
    const wasmEv = makeCelEvaluator({ timeoutMs: 100 });
    try {
      expect(wasmEv.timeoutMs).toBe(100);
    } finally {
      await wasmEv.dispose();
    }
    const celjsEv = makeCelEvaluator({ engine: "celjs", timeoutMs: 100 });
    try {
      expect(celjsEv.timeoutMs).toBe(100);
    } finally {
      celjsEv.dispose();
    }
    // An unspecified timeout defers to the evaluator's own DEFAULT_TIMEOUT_MS
    // (identical to direct construction with no timeoutMs argument).
    const defaulted = makeCelEvaluator({ engine: "celjs" });
    try {
      expect(defaulted.timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    } finally {
      defaulted.dispose();
    }
    // Out-of-bounds timeouts are rejected by the underlying constructor; the
    // factory forwards, never masks. Zero/negative trips the positive-integer
    // bound; an over-cap value trips the MAX_TIMEOUT_MS (250 ms) Relay cap.
    expect(() => makeCelEvaluator({ timeoutMs: 0 })).toThrow(
      /positive integer/,
    );
    expect(() => makeCelEvaluator({ engine: "celjs", timeoutMs: 0 })).toThrow(
      /positive integer/,
    );
    expect(() => makeCelEvaluator({ timeoutMs: 1234 })).toThrow(
      /exceeds Relay cap/,
    );
    expect(() =>
      makeCelEvaluator({ engine: "celjs", timeoutMs: 1234 }),
    ).toThrow(/exceeds Relay cap/);
  });

  test("a non-allowlist UDF through the unset-default (wasm) path is rejected fail-closed", () => {
    // The TS half of the Python VAL-CWC-P5FLIP-014 contract: the now-default
    // wasm engine exposes only the 3 native relay.* UDFs; a caller-supplied
    // extra UDF is a structured RelayCelUnsupportedUdfError at construction,
    // not a silent acceptance.
    const extra = registerUdf({
      name: "my_check",
      fn: () => true,
      pure: true,
      arity: 0,
    });
    expect(() => makeCelEvaluator({ udfs: [extra] })).toThrow(
      RelayCelUnsupportedUdfError,
    );
    // The SAME extra UDF is accepted by the explicit cel-js rollback (the
    // legacy registry path), so the rejection above is engine-specific, not a
    // registry regression.
    const rollback = makeCelEvaluator({ engine: "celjs", udfs: [extra] });
    try {
      expect(rollback).toBeInstanceOf(RelayCelEvaluator);
    } finally {
      rollback.dispose();
    }
  });

  test("the factory is the package's canonical evaluator entry (exported from index)", () => {
    expect(contracts.makeCelEvaluator).toBe(makeCelEvaluator);
    const exportedNames = Object.keys(contracts);
    expect(exportedNames).toContain("makeCelEvaluator");
    // Both engine classes stay exported: WasmCelBackend (the default engine)
    // and RelayCelEvaluator (the rollback class, removed at M6).
    expect(exportedNames).toContain("RelayCelEvaluator");
    expect(exportedNames).toContain("WasmCelBackend");
    expect(contracts.RelayCelEvaluator).toBe(RelayCelEvaluator);
    expect(contracts.WasmCelBackend).toBe(WasmCelBackend);
  });

  test("engine selection stays config/param-based: no production TS src/ file names the engine-selector env var", () => {
    // The flip did NOT introduce an environment read into production TS. The
    // engine-selector env var is read ONLY in the Python packages/contracts
    // factory (boundaries.md); the TS factory takes the engine as a CONFIG
    // PARAMETER. This is the SAME presence scan the M2 fence ran -- kept verbatim
    // so the flip cannot smuggle in an env-token read. See the threat model on
    // `sourceNamesRelayCelEngine` below: a presence scan is SOUND for the real
    // threat (an accidental production read), because every naturally written
    // read of the selector ULTIMATELY names it as an identifier or string
    // literal in the parsed program.
    const srcFiles = listSourceFiles(SRC_DIR);
    expect(srcFiles.length).toBeGreaterThan(0);
    const offenders: string[] = [];
    for (const file of srcFiles) {
      const raw = readFileSync(file, "utf8");
      if (sourceNamesRelayCelEngine(raw, file)) {
        offenders.push(file);
      }
    }
    expect(offenders, (
      "engine selection (RELAY_CEL_ENGINE) must be read ONLY in the Python " +
      "packages/contracts factory (boundaries.md); found a production TS src/ " +
      `file that NAMES RELAY_CEL_ENGINE: ${offenders.join(", ")}`
    )).toEqual([]);
  });
});

// The engine-selector env var whose appearance in TS src/ this guard forbids.
const ENGINE_ENV_VAR = "RELAY_CEL_ENGINE";

/**
 * True if `source` NAMES `RELAY_CEL_ENGINE` anywhere in the parsed program,
 * determined by a TypeScript COMPILER AST walk.
 *
 * THREAT MODEL (read carefully). The guard's purpose is defense-in-depth: the
 * cel-js / default TS path is engine-selector-INDEPENDENT (only the Python
 * factory reads RELAY_CEL_ENGINE, never the TS engine). The threat we defend
 * against is a developer ACCIDENTALLY making production TS branch on
 * RELAY_CEL_ENGINE. It is NOT an adversary deliberately obfuscating the read.
 * Concretely:
 *   - IN SCOPE: every naturally written read, in ANY of these forms --
 *       process.env.RELAY_CEL_ENGINE              (direct member access)
 *       process.env["RELAY_CEL_ENGINE"]           (bracket access)
 *       process.env?.RELAY_CEL_ENGINE             (optional chaining)
 *       const { RELAY_CEL_ENGINE } = process.env  (destructure)
 *       const { RELAY_CEL_ENGINE: x } = process.env  (aliased destructure)
 *       (process.env as any).RELAY_CEL_ENGINE     (cast/paren/non-null wrappers)
 *       const e = process.env; e.RELAY_CEL_ENGINE (any var/let/const alias)
 *       env = process.env; env.RELAY_CEL_ENGINE   (outer-scope reassignment)
 *       if (x) { var env = process.env; } env.RELAY_CEL_ENGINE  (var hoisting)
 *     ...and closures and ANY lexical scope. EVERY one of these forms
 *     ULTIMATELY names the property RELAY_CEL_ENGINE as an Identifier or a
 *     string literal in the AST, so a single presence scan catches them ALL --
 *     with NO model of JS scope resolution. That soundness is the whole point
 *     of this redesign: prior versions re-implemented per-lexical-scope alias
 *     tracking inside the guard (frame stack, shadowing, reassignment, var
 *     hoisting) and kept producing scope/var edge cases the tracker missed
 *     (outer-scope reassignment updated only the innermost frame; var was
 *     stored in the block frame though var is function-scoped). A presence scan
 *     has no such tail because it never models scope.
 *   - OUT OF SCOPE (by design): adversarial string-splitting such as
 *       process.env["RELAY_" + "CEL_ENGINE"]
 *     The two halves are separate string-literal nodes; neither equals the
 *     full selector, so the scan does not flag it. This is acceptable: the
 *     guard is defense-in-depth against ACCIDENTS, not a defense against a
 *     developer deliberately evading it.
 *
 * WHY AN AST WALK (not a regex / not a string scan). COMMENTS and the TEXT of
 * unrelated string literals are not the concern -- a production file that
 * MENTIONS RELAY_CEL_ENGINE only in a `//` comment (the wasm-artifact.ts /
 * wasm-evaluator.ts CEL_WASM-vs-RELAY_CEL_ENGINE explanatory comments) must NOT
 * be flagged. The TS compiler AST does NOT expose comments as nodes, so a name
 * appearing only in a comment is invisible to the walk by construction, and the
 * guard stays green for those files. We DO flag a string literal whose TEXT is
 * exactly RELAY_CEL_ENGINE, because a bracket access (`["RELAY_CEL_ENGINE"]`)
 * or an aliased destructure key carries the selector as a string-literal node;
 * that is a real read form, not a comment.
 *
 * The scan FLAGS the file if ANY node is:
 *   - an Identifier whose text is exactly RELAY_CEL_ENGINE, OR
 *   - a StringLiteral / NoSubstitutionTemplateLiteral whose text is exactly
 *     RELAY_CEL_ENGINE.
 *
 * `filePath` only labels the synthetic SourceFile (diagnostics); the scan does
 * not type-check, so no tsconfig / program is needed. The file extension drives
 * the scriptKind so `.mjs`/`.cts`/`.tsx` parse correctly.
 */
export function sourceNamesRelayCelEngine(
  source: string,
  filePath: string,
): boolean {
  const sf = ts.createSourceFile(
    filePath,
    source,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    scriptKindFor(filePath),
  );

  let found = false;
  const visit = (node: ts.Node): void => {
    if (found) {
      return;
    }
    // An identifier or a property name (e.g. the `.RELAY_CEL_ENGINE` in a
    // member access, the bound name in a destructure) whose text matches.
    if (ts.isIdentifier(node) && node.text === ENGINE_ENV_VAR) {
      found = true;
      return;
    }
    // A string-literal selector: the bracket-access key (`["RELAY_CEL_ENGINE"]`)
    // or a string property name in a destructure pattern. Template literals with
    // NO substitutions are plain string literals too; a literal WITH a `${...}`
    // substitution is a TemplateExpression whose interpolated reads are ordinary
    // nodes the walk already visits.
    if (
      (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) &&
      node.text === ENGINE_ENV_VAR
    ) {
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/** Map a file extension to the TS scriptKind so each source parses correctly. */
function scriptKindFor(filePath: string): ts.ScriptKind {
  if (filePath.endsWith(".tsx")) {
    return ts.ScriptKind.TSX;
  }
  if (filePath.endsWith(".jsx")) {
    return ts.ScriptKind.JSX;
  }
  if (
    filePath.endsWith(".js") ||
    filePath.endsWith(".mjs") ||
    filePath.endsWith(".cjs")
  ) {
    return ts.ScriptKind.JS;
  }
  // .ts / .mts / .cts
  return ts.ScriptKind.TS;
}

/**
 * Recursively list every .ts / .mts / .mjs / .js source file under `dir`,
 * skipping nothing (the whole src/ tree is in scope for the env-name scan).
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
// NON-VACUITY of the presence-scan guard.
//
// The predicate (sourceNamesRelayCelEngine) replaces the prior per-lexical-scope
// alias-tracking engine (frame stack, shadowing, reassignment, var hoisting,
// expression-wrapper unwrapping, process.env-receiver matching) with a SOUND AST
// presence scan: flag the file iff any Identifier or string-literal node names
// RELAY_CEL_ENGINE. The predicate-level cases below confirm the scan FLAGS every
// read form (including the two round-6 cases the scope engine missed -- outer-
// scope reassignment and var hoisting) and does NOT flag mere comment mentions
// or an unrelated same-named local. The end-to-end cases prove the REAL src/-tree
// scan (the exact loop the guard runs) bites each form when a probe file is
// present, and does NOT false-positive on an unrelated `env` local.
// ---------------------------------------------------------------------------
describe("the presence-scan env-name guard catches every RELAY_CEL_ENGINE read form", () => {
  // The predicate is fed a synthetic file name only to drive its scriptKind; the
  // scan is purely structural (no type-checking, no tsconfig).
  const SCAN = "__probe__.ts";

  test("the predicate FLAGS every read form, incl. the round-6 outer-reassign and var cases", () => {
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
      // Aliased read declared AFTER its use (forward reference) -- a presence
      // scan does not care about declaration order at all.
      "function f() { return e.RELAY_CEL_ENGINE; } const e = process.env;",
      // Read inside a template ${...} interpolation.
      "const v = `${process.env.RELAY_CEL_ENGINE}`;",
      "const v = `engine=${process.env.RELAY_CEL_ENGINE} suffix`;",
      "const v = `outer ${`inner ${process.env.RELAY_CEL_ENGINE}`}`;",
      // A `}` inside an interpolation COMMENT: invisible to the AST entirely; the
      // real read is still an ordinary identifier node.
      "const v = `${/* } */ process.env.RELAY_CEL_ENGINE}`;",
      "const v = `${ // } trailing\n  process.env.RELAY_CEL_ENGINE}`;",
      // Common TS expression wrappers around the receiver -- the property name
      // RELAY_CEL_ENGINE is still an identifier node regardless of the wrapper.
      "const v = (process.env).RELAY_CEL_ENGINE;", // parenthesized
      "const v = process.env!.RELAY_CEL_ENGINE;", // non-null assertion
      'const v = (process.env as NodeJS.ProcessEnv)["RELAY_CEL_ENGINE"];', // as-assertion
      "const v = (process.env satisfies NodeJS.ProcessEnv).RELAY_CEL_ENGINE;", // satisfies
      "const v = (<NodeJS.ProcessEnv>process.env).RELAY_CEL_ENGINE;", // angle assertion
      "const e = (process.env as any); const v = e.RELAY_CEL_ENGINE;",
      "const e = (process.env)!; const v = e.RELAY_CEL_ENGINE;",
      "const v = ((process.env as any)!).RELAY_CEL_ENGINE;",
      // ROUND-6 finding 1: outer-scope reassignment. The scope engine updated
      // only the innermost frame and missed this; the presence scan names
      // RELAY_CEL_ENGINE regardless of where the alias was assigned.
      "let env; function f(){ env = process.env; return env.RELAY_CEL_ENGINE; }",
      // ROUND-6 finding 2: var hoisted out of a block (var is function/source
      // scoped, not block scoped). The scope engine stored it in the block frame
      // and missed the later read; the presence scan does not model scope.
      "if (true) { var env = process.env; } export const z = env.RELAY_CEL_ENGINE;",
    ];
    for (const snippet of flagged) {
      expect(
        sourceNamesRelayCelEngine(snippet, SCAN),
        `should FLAG: ${snippet}`,
      ).toBe(true);
    }
  });

  test("the predicate does NOT flag comment/string-text mentions, unrelated env vars, or an unrelated local", () => {
    const clean = [
      // Mentions only in comments are invisible to the AST -- exactly the
      // wasm-artifact.ts / wasm-evaluator.ts production case (CEL_WASM-vs-
      // RELAY_CEL_ENGINE explanatory comments).
      "// reads RELAY_CEL_ENGINE in the Python factory only",
      "/* RELAY_CEL_ENGINE = process.env.RELAY_CEL_ENGINE */",
      "const v = process.env.CEL_WASM; // not RELAY_CEL_ENGINE",
      // Unrelated env vars never name the selector.
      "const v = process.env.CEL_WASM;",
      "const { CEL_WASM } = process.env;",
      // The inverse no-false-positive case from the task: an unrelated `env`
      // local reading a DIFFERENT property. No RELAY_CEL_ENGINE token anywhere.
      "function g(env){ return env.SOMETHING_ELSE; }",
      // Adversarial string-splitting is explicitly OUT OF SCOPE: neither half
      // equals the full selector, so the scan does not flag it. Documented as a
      // deliberate non-goal in the threat model.
      'const v = process.env["RELAY_" + "CEL_ENGINE"];',
    ];
    for (const snippet of clean) {
      expect(
        sourceNamesRelayCelEngine(snippet, SCAN),
        `should NOT flag: ${snippet}`,
      ).toBe(false);
    }
  });

  // End-to-end non-vacuity: drop a temp src file carrying a real read, prove the
  // REAL file-tree scan (the exact loop the guard runs) flags it, then remove it.
  // One probe per read FORM the task enumerates, INCLUDING the two round-6 scope
  // cases. Each probe MUST trip the scan, and NO other src file may (so the guard
  // stays clean once the probe is gone). A final inverse probe proves an
  // unrelated `env` local does NOT false-positive.
  describe("end-to-end: a temp src file naming RELAY_CEL_ENGINE makes the src/-tree scan FAIL", () => {
    const TEMP = resolve(SRC_DIR, "__roborev_presence_probe__.ts");

    afterEach(() => {
      try {
        unlinkSync(TEMP);
      } catch {
        // already removed
      }
    });

    const scanSrcTree = (): string[] => {
      const offenders: string[] = [];
      for (const file of listSourceFiles(SRC_DIR)) {
        if (sourceNamesRelayCelEngine(readFileSync(file, "utf8"), file)) {
          offenders.push(file);
        }
      }
      return offenders;
    };

    const probes: Array<{ label: string; body: string }> = [
      {
        label: "direct member-access read",
        body:
          "export function evade(): string | undefined {\n" +
          "  return process.env.RELAY_CEL_ENGINE;\n" +
          "}\n",
      },
      {
        label: "bracket-access read",
        body:
          "export function evade(): string | undefined {\n" +
          '  return process.env["RELAY_CEL_ENGINE"];\n' +
          "}\n",
      },
      {
        label: "destructuring read",
        body:
          "export function evade(): string | undefined {\n" +
          "  const { RELAY_CEL_ENGINE } = process.env;\n" +
          "  return RELAY_CEL_ENGINE;\n" +
          "}\n",
      },
      {
        label: "aliased destructuring read",
        body:
          "export function evade(): string | undefined {\n" +
          "  const { RELAY_CEL_ENGINE: x } = process.env;\n" +
          "  return x;\n" +
          "}\n",
      },
      {
        label: "optional-chaining read",
        body:
          "export function evade(): string | undefined {\n" +
          "  return process.env?.RELAY_CEL_ENGINE;\n" +
          "}\n",
      },
      {
        label: "as-assertion (cast) read",
        body:
          "export function evade(): string | undefined {\n" +
          "  return (process.env as any).RELAY_CEL_ENGINE;\n" +
          "}\n",
      },
      {
        label: "round-6: outer-scope reassignment read",
        body:
          "let env: NodeJS.ProcessEnv | undefined;\n" +
          "export function f(): string | undefined {\n" +
          "  env = process.env;\n" +
          "  return env.RELAY_CEL_ENGINE;\n" +
          "}\n",
      },
      {
        label: "round-6: var hoisted out of a block read",
        body:
          "if (true) {\n" +
          "  var env = process.env;\n" +
          "}\n" +
          "export const z = env.RELAY_CEL_ENGINE;\n",
      },
    ];

    for (const { label, body } of probes) {
      test(`the src/-tree scan flags a ${label} in src/`, () => {
        writeFileSync(TEMP, body, "utf8");
        const offenders = scanSrcTree();
        // The probe MUST be flagged, and no OTHER src file should trip.
        expect(offenders).toContain(TEMP);
        expect(offenders.filter((f) => f !== TEMP)).toEqual([]);
      });
    }

    test("an unrelated `env` local naming a DIFFERENT property does NOT false-positive", () => {
      // The task's inverse case: a same-named `env` local that reads
      // SOMETHING_ELSE off itself names no RELAY_CEL_ENGINE token, so the
      // src/-tree scan must stay clean (no offender from this file).
      const body =
        "export function g(env: Record<string, string>): string {\n" +
        "  return env.SOMETHING_ELSE;\n" +
        "}\n";
      writeFileSync(TEMP, body, "utf8");
      const offenders = scanSrcTree();
      expect(offenders).not.toContain(TEMP);
      expect(offenders).toEqual([]);
    });
  });

  // The REAL src/ tree must be CLEAN today: no production file NAMES
  // RELAY_CEL_ENGINE (the only mentions are in `//` comments, which the AST does
  // not expose). This is the standing assertion the suite's main guard makes; we
  // restate it here as a focused non-vacuity anchor so a future production read
  // (in any form above) trips it.
  test("the actual src/ tree names RELAY_CEL_ENGINE nowhere (guard is green today)", () => {
    const offenders: string[] = [];
    for (const file of listSourceFiles(SRC_DIR)) {
      if (sourceNamesRelayCelEngine(readFileSync(file, "utf8"), file)) {
        offenders.push(file);
      }
    }
    expect(offenders).toEqual([]);
  });
});
