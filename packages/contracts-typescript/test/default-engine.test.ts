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

import ts from "typescript";
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
    // factory" -- so we scan the ENTIRE TS src/ tree for ANY appearance of the
    // engine-selector name and fail if a production source NAMES it. See the
    // threat model on `sourceNamesRelayCelEngine` below: a presence scan is
    // SOUND for the real threat (an accidental production read), because every
    // naturally written read of the selector ULTIMATELY names RELAY_CEL_ENGINE
    // as an identifier or string literal in the parsed program.
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
