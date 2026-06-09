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
    // factory" -- so we scan the ENTIRE TS src/ tree for ANY read of
    // process.env.RELAY_CEL_ENGINE (or a bracket-form env access). Any such read
    // in the TS package, under ANY function name, trips this guard. This is the
    // grep-based structural check that a renamed/composed factory cannot evade.
    const srcFiles = listSourceFiles(SRC_DIR);
    expect(srcFiles.length).toBeGreaterThan(0);
    // ROBOREV round-4 finding A: the prior comment/string SCRUBBER + regex scan
    // kept producing evasion cases (round-3: a read inside a ${...} interpolation;
    // round-4: a `}` inside an interpolation COMMENT like `${/* } */ ...}`
    // prematurely terminated the captured body, dropping the real read). Those are
    // all artifacts of approximating the language with regex. We now scan with the
    // TypeScript COMPILER (an AST walk), which parses the source EXACTLY: comments
    // and string-literal TEXT are not part of the AST, so a read can never hide in
    // one, and a read inside a template `${...}` interpolation is an ordinary
    // expression node the walk visits. The whole comment/string-evasion class is
    // eliminated by construction.
    const offenders: string[] = [];
    for (const file of srcFiles) {
      const raw = readFileSync(file, "utf8");
      if (sourceReadsRelayCelEngineEnv(raw, file)) {
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

// The env var whose read from process.env this guard forbids in TS src/.
const ENGINE_ENV_VAR = "RELAY_CEL_ENGINE";

/**
 * True if `source` contains ANY read of `RELAY_CEL_ENGINE` off `process.env`,
 * determined by a TypeScript COMPILER AST walk (ROBOREV round-4 finding A).
 *
 * The prior implementation approximated the language with a comment/string
 * SCRUBBER plus regexes; that approach kept producing evasion cases (round-3: a
 * read hidden inside a `${...}` template interpolation; round-4: a `}` inside an
 * interpolation COMMENT, `${/* } *​/ process.env.RELAY_CEL_ENGINE}`, prematurely
 * terminated the captured body and dropped the read). Those are all artifacts of
 * regex-approximating a real grammar. A genuine parse eliminates the entire
 * class: `ts.createSourceFile` builds the AST, in which COMMENTS and
 * string-literal TEXT are NOT nodes (so a read can never hide in one), and a read
 * inside a template `${...}` interpolation is an ordinary expression node the
 * walk visits like any other. We detect:
 *
 *   1. member access of RELAY_CEL_ENGINE off `process.env` (and off any local
 *      identifier bound to `process.env`):
 *        process.env.RELAY_CEL_ENGINE          (PropertyAccessExpression)
 *        process.env?.RELAY_CEL_ENGINE          (optional chaining: same node)
 *        process.env["RELAY_CEL_ENGINE"]        (ElementAccessExpression, string arg)
 *        process?.env?.["RELAY_CEL_ENGINE"]      (optional-chained bracket)
 *        const e = process.env; e.RELAY_CEL_ENGINE / e["RELAY_CEL_ENGINE"]
 *   2. destructuring RELAY_CEL_ENGINE off `process.env` (or an alias of it),
 *      incl. an aliased bind { RELAY_CEL_ENGINE: x }:
 *        const { RELAY_CEL_ENGINE } = process.env
 *        const { RELAY_CEL_ENGINE: sel } = process.env
 *        const e = process.env; const { RELAY_CEL_ENGINE } = e
 *
 * `filePath` only labels the synthetic SourceFile (diagnostics); the scan does
 * not type-check, so no tsconfig / program is needed. The file extension drives
 * the scriptKind so `.mjs`/`.cts`/`.tsx` parse correctly.
 */
export function sourceReadsRelayCelEngineEnv(
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

  // Identifiers locally bound DIRECTLY to `process.env` (const e = process.env).
  // A read of RELAY_CEL_ENGINE off any such alias is equivalent to reading it off
  // process.env. Collected in a first pass so a `const e = process.env` that
  // textually FOLLOWS the alias read is still caught.
  const envAliases = collectProcessEnvAliases(sf);

  let found = false;
  const visit = (node: ts.Node): void => {
    if (found) {
      return;
    }
    // (1) Member access: <envExpr>.RELAY_CEL_ENGINE or <envExpr>["RELAY_CEL_ENGINE"].
    if (ts.isPropertyAccessExpression(node)) {
      if (
        node.name.text === ENGINE_ENV_VAR &&
        isProcessEnvExpression(node.expression, envAliases)
      ) {
        found = true;
        return;
      }
    } else if (ts.isElementAccessExpression(node)) {
      const arg = node.argumentExpression;
      if (
        ts.isStringLiteralLike(arg) &&
        arg.text === ENGINE_ENV_VAR &&
        isProcessEnvExpression(node.expression, envAliases)
      ) {
        found = true;
        return;
      }
    } else if (
      ts.isVariableDeclaration(node) &&
      node.initializer !== undefined &&
      ts.isObjectBindingPattern(node.name) &&
      isProcessEnvExpression(node.initializer, envAliases) &&
      objectBindingPullsEngineVar(node.name)
    ) {
      // (2) Destructuring read: const { RELAY_CEL_ENGINE [: alias] } = process.env
      // (or = an alias of process.env).
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/**
 * True if `expr` denotes `process.env` -- either the literal member access
 * `process.env` / `process?.env`, or an identifier in `envAliases` (a local
 * binding `const e = process.env`). Used as the receiver test for both the
 * member-access and the destructuring detectors.
 */
function isProcessEnvExpression(
  expr: ts.Expression,
  envAliases: ReadonlySet<string>,
): boolean {
  if (ts.isIdentifier(expr)) {
    return envAliases.has(expr.text);
  }
  // process.env (PropertyAccess) or process?.env -- a `.env` off an identifier
  // named `process`. Bracket form process["env"] also denotes process.env.
  if (ts.isPropertyAccessExpression(expr)) {
    return expr.name.text === "env" && isProcessIdentifier(expr.expression);
  }
  if (ts.isElementAccessExpression(expr)) {
    const arg = expr.argumentExpression;
    return (
      ts.isStringLiteralLike(arg) &&
      arg.text === "env" &&
      isProcessIdentifier(expr.expression)
    );
  }
  return false;
}

/** True if `expr` is the bare identifier `process`. */
function isProcessIdentifier(expr: ts.Expression): boolean {
  return ts.isIdentifier(expr) && expr.text === "process";
}

/**
 * Collect every local identifier bound DIRECTLY to `process.env` via a variable
 * declaration `const|let|var e = process.env`. A subsequent read of
 * RELAY_CEL_ENGINE off such an alias is a process.env read. (We deliberately do
 * NOT chase deeper aliasing-of-aliases: the production boundary is "no
 * RELAY_CEL_ENGINE read in TS src/ at all", so the one-hop alias closes the
 * realistic evasion while staying a precise, false-positive-free structural
 * check.)
 */
function collectProcessEnvAliases(sf: ts.SourceFile): ReadonlySet<string> {
  const aliases = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer !== undefined &&
      isLiteralProcessEnv(node.initializer)
    ) {
      aliases.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return aliases;
}

/** True if `expr` is the literal `process.env` / `process?.env` / process["env"]. */
function isLiteralProcessEnv(expr: ts.Expression): boolean {
  if (ts.isPropertyAccessExpression(expr)) {
    return expr.name.text === "env" && isProcessIdentifier(expr.expression);
  }
  if (ts.isElementAccessExpression(expr)) {
    const arg = expr.argumentExpression;
    return (
      ts.isStringLiteralLike(arg) &&
      arg.text === "env" &&
      isProcessIdentifier(expr.expression)
    );
  }
  return false;
}

/**
 * True if an object binding pattern `{ ... }` pulls RELAY_CEL_ENGINE, whether
 * bound under its own name (`{ RELAY_CEL_ENGINE }`) or aliased
 * (`{ RELAY_CEL_ENGINE: sel }`). The PROPERTY name (not the local bind name) is
 * the env-var read, so we inspect `element.propertyName ?? element.name`.
 */
function objectBindingPullsEngineVar(pattern: ts.ObjectBindingPattern): boolean {
  for (const element of pattern.elements) {
    // `{ a: b }` -> propertyName = a (the read), name = b (the local bind).
    // `{ a }`    -> propertyName undefined, name = a (both read and bind).
    const keyNode = element.propertyName ?? element.name;
    if (ts.isIdentifier(keyNode) && keyNode.text === ENGINE_ENV_VAR) {
      return true;
    }
    // A computed property key { ["RELAY_CEL_ENGINE"]: x } carries the name in a
    // string/numeric literal node.
    if (
      element.propertyName !== undefined &&
      ts.isStringLiteralLike(element.propertyName) &&
      element.propertyName.text === ENGINE_ENV_VAR
    ) {
      return true;
    }
  }
  return false;
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
// ROBOREV round-4 finding A: NON-VACUITY of the AST-based env-read guard.
//
// The predicate (sourceReadsRelayCelEngineEnv) replaces the regex/scrubber scan
// with a TypeScript COMPILER AST walk. The whole comment/string-evasion class is
// gone by construction (comments and string-literal TEXT are not AST nodes). The
// predicate-level cases below confirm the AST detector FLAGS every read form and
// does NOT flag mere mentions; the end-to-end cases prove the REAL src/-tree scan
// (the guard the suite runs) bites each evasion when a probe file is present.
// ---------------------------------------------------------------------------
describe("roborev round-4 finding A: the AST env-read guard catches evasive RELAY_CEL_ENGINE reads", () => {
  // The predicate is fed a synthetic file name only to drive its scriptKind; the
  // scan is purely structural (no type-checking, no tsconfig).
  const SCAN = "__probe__.ts";

  test("the AST predicate FLAGS every read form (direct/optional-chain/bracket/destructure/alias/interpolation)", () => {
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
      // The alias declared AFTER its use is still resolved (two-pass collection).
      "function f() { return e.RELAY_CEL_ENGINE; } const e = process.env;",
      // Read inside a template ${...} interpolation (round-3 class).
      "const v = `${process.env.RELAY_CEL_ENGINE}`;",
      "const v = `engine=${process.env.RELAY_CEL_ENGINE} suffix`;",
      "const v = `outer ${`inner ${process.env.RELAY_CEL_ENGINE}`}`;",
      // The EXACT round-4 evasion: a `}` inside an interpolation COMMENT. The
      // regex/scrubber prematurely terminated the body at the `}` in `/* } */`
      // and dropped the real read; the AST never sees the comment at all.
      "const v = `${/* } */ process.env.RELAY_CEL_ENGINE}`;",
      // A line comment with a brace inside the interpolation, same class.
      "const v = `${ // } trailing\n  process.env.RELAY_CEL_ENGINE}`;",
    ];
    for (const snippet of flagged) {
      expect(
        sourceReadsRelayCelEngineEnv(snippet, SCAN),
        `should FLAG: ${snippet}`,
      ).toBe(true);
    }
  });

  test("the AST predicate does NOT flag mere mentions in comments/strings/template-text or unrelated env vars", () => {
    const clean = [
      "// reads RELAY_CEL_ENGINE in the Python factory only",
      "/* RELAY_CEL_ENGINE = process.env.RELAY_CEL_ENGINE */",
      'const msg = "process.env.RELAY_CEL_ENGINE is read in Python";',
      "const msg = `process.env.RELAY_CEL_ENGINE is read in Python`;",
      "const v = process.env.CEL_WASM;",
      "const { CEL_WASM } = process.env;",
      "const RELAY_CEL_ENGINE = 'wasm';", // a local var, not an env read
      // A read off an unrelated object that merely shares the property name.
      "const cfg = { RELAY_CEL_ENGINE: 'x' }; const v = cfg.RELAY_CEL_ENGINE;",
    ];
    for (const snippet of clean) {
      expect(
        sourceReadsRelayCelEngineEnv(snippet, SCAN),
        `should NOT flag: ${snippet}`,
      ).toBe(false);
    }
  });

  // End-to-end non-vacuity: drop a temp src file carrying a real read, prove the
  // REAL file-tree scan (the exact loop the guard runs) flags it, then remove it.
  // One probe per evasion FORM the regex approach historically missed, INCLUDING
  // the round-4 `}`-in-interpolation-comment case. Each probe MUST trip the scan,
  // and NO other src file may (so the guard stays clean once the probe is gone).
  describe("end-to-end: a temp src file with a real read makes the src/-tree scan FAIL", () => {
    const TEMP = resolve(SRC_DIR, "__roborev_a_ast_probe__.ts");

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
        if (sourceReadsRelayCelEngineEnv(readFileSync(file, "utf8"), file)) {
          offenders.push(file);
        }
      }
      return offenders;
    };

    const probes: Array<{ label: string; body: string }> = [
      {
        label: "destructuring read",
        body:
          "export function evade() {\n" +
          "  const { RELAY_CEL_ENGINE } = process.env;\n" +
          "  return RELAY_CEL_ENGINE;\n" +
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
        label: "template-${...}-interpolation read",
        body:
          "export function evade(): string {\n" +
          "  return `selected:${process.env.RELAY_CEL_ENGINE}`;\n" +
          "}\n",
      },
      {
        label: "round-4: read behind a `}` in an interpolation COMMENT",
        body:
          "export function evade(): string {\n" +
          "  return `${/* } */ process.env.RELAY_CEL_ENGINE}`;\n" +
          "}\n",
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
  });
});
