// CEL engine-selection factory -- the canonical TS evaluator entry point.
//
// `makeCelEvaluator()` is the TypeScript mirror of the Python factory
// packages/contracts/src/relay_contracts/engine.py (make_cel_evaluator). It
// selects between the two TS CEL evaluators that share the host facade
// (`compile`, `evaluate`, `timeoutMs`):
//
//   - "wasm" (the DEFAULT as of milestone M5, and the selection when `engine`
//     is unset or blank): :class WasmCelBackend (wasm-evaluator.ts), the
//     single wasm CEL engine behind the host facade. This is now the engine
//     EVERY consumer that does not explicitly opt out runs on. The default
//     backend resolves the PACKAGED wasm artifact + `.mjs` loader (WS-G
//     package data) with the explicit precedence explicit > CEL_WASM >
//     packaged data (wasm-artifact.ts resolveWasmPathForLoader /
//     wasm-evaluator.ts defaultLoaderPath), so a fresh install loads the
//     engine with no configuration.
//   - "celjs" / "cel-js" (explicit selection ONLY): :class RelayCelEvaluator
//     (evaluator.ts), the legacy cel-js-backed evaluator. It is retained ONLY
//     as the rollback escape hatch during the one-release bake window (cel-js
//     is removed at M6); a deployment that hits a wasm regression can select
//     "celjs" to fall back to the legacy path while the regression is
//     diagnosed. Both spellings are accepted because the package metadata and
//     docs name the engine "cel-js" while the Python rollback token style is
//     a bare word ("celpy") -- accepting both removes a foot-gun without
//     loosening matching (which stays exact and case-sensitive).
//
// An unknown engine name is rejected with a clear error naming the bad value
// AND the allowed set -- never a silent fallback to a default.
//
// DETERMINISM BOUNDARY (load-bearing; differs from Python BY DESIGN): the TS
// selection is CONFIG/PARAM-based, NOT environment-based. The engine-selector
// environment variable (RELAY_CEL_ENGINE) is read ONLY in the Python
// packages/contracts factory (boundaries.md); production TS src/ MUST NOT
// name it -- the AST presence scan in test/default-engine.test.ts FAILS the
// build if any src/ file carries that token as an identifier or string
// literal. A TS consumer that wants env-driven selection performs the env
// read itself (outside this package) and passes the resolved token as
// `engine`. (This comment may name the selector: comments are invisible to
// the AST scan, exactly like the wasm-artifact.ts explanatory comments.)
//
// The M5 flip (this factory's default): an unset / blank `engine` now selects
// "wasm". Through M1-M4 the TS default was cel-js (the package's primary
// evaluator export; no factory existed) and the wasm backend was an opt-in
// class (boundaries.md: "Do NOT flip the RELAY_CEL_ENGINE default to wasm
// before milestone M5"); M5 (WS-H) is exactly the milestone that flips it.
// The M1-M4 dual-run byte-parity work PROVED the wasm engine agrees with the
// legacy hosts on every in-corpus expression, so the flip is
// behavior-preserving for the contract workload; explicit "celjs"/"cel-js"
// remains the deliberate rollback override until M6.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { RelayCelEvaluator } from "./evaluator.js";
import type { PureUdf } from "./udf.js";
import { WasmCelBackend } from "./wasm-evaluator.js";

// Canonical engine tokens. "wasm" is the default as of M5 (the flip landed in
// WS-H / M5); "celjs" / "cel-js" are the explicit rollback override spellings
// (removed at M6). Matching is exact (case-sensitive) after surrounding-
// whitespace trim -- no locale-dependent case-folding, so selection is
// deterministic. Mirrors engine.py _ENGINE_CELPY / _ENGINE_WASM.
const ENGINE_WASM = "wasm";
const ENGINE_CELJS = "celjs";
const ENGINE_CELJS_HYPHEN = "cel-js";

// The default engine when `engine` is unset or blank. FLIPPED to wasm at M5
// (WS-H) -- the cutover's most consequential TS change: every consumer that
// constructs an evaluator through this factory without selecting an engine now
// runs on the single wasm CEL engine. Mirrors engine.py _DEFAULT_ENGINE.
const DEFAULT_ENGINE = ENGINE_WASM;

const ALLOWED_ENGINE_TOKENS: readonly string[] = [
  ENGINE_CELJS,
  ENGINE_CELJS_HYPHEN,
  ENGINE_WASM,
];

/**
 * The canonical engine tokens a TypeScript caller may select. `"wasm"` is the
 * M5 default; `"celjs"` / `"cel-js"` are the two accepted spellings of the
 * legacy rollback engine (removed at M6).
 */
export type CelEngineName = "wasm" | "celjs" | "cel-js";

/**
 * The shared host-side CEL evaluator facade the factory returns: either the
 * wasm-backed default or the legacy cel-js rollback. The TS analogue of the
 * Python CelEvaluatorProtocol (engine.py). Narrow with `instanceof` when an
 * engine-specific surface (e.g. the wasm backend's async `evaluate`) is
 * needed.
 */
export type CelEvaluator = RelayCelEvaluator | WasmCelBackend;

export interface MakeCelEvaluatorOptions {
  /**
   * Engine selection token. Unset / blank selects the default (wasm as of
   * M5). `"celjs"` / `"cel-js"` select the legacy cel-js rollback. Typed as
   * `string` (not the literal union) deliberately: this mirrors the Python
   * factory's env-string contract -- arbitrary runtime strings are accepted
   * at the type level and validated fail-closed at runtime, so a JS caller
   * threading an externally-resolved token gets the structured rejection, not
   * a type hole.
   */
  engine?: string;
  /**
   * Per-evaluation wall-clock budget (ms). Forwarded to the selected
   * evaluator's constructor with IDENTICAL semantics (positive integer,
   * <= MAX_TIMEOUT_MS); when omitted the evaluator's own DEFAULT_TIMEOUT_MS
   * governs, exactly as if the class had been constructed directly.
   */
  timeoutMs?: number;
  /**
   * Pure UDFs to register. Forwarded verbatim. The wasm engine accepts ONLY
   * the 3 native relay.* UDFs and rejects any other fail-closed
   * (RelayCelUnsupportedUdfError / RELAY-CEL-004); the legacy cel-js path
   * registers them in its host registry.
   */
  udfs?: readonly PureUdf[];
}

/**
 * Resolve the engine token from the factory options (the TS counterpart of
 * engine.py _select_engine_name, minus the env read -- see the determinism
 * boundary in the module docstring).
 *
 * An absent or blank value resolves to the default (wasm as of M5). A
 * non-blank value is trimmed of surrounding whitespace (a common
 * config-plumbing accident) and matched case-sensitively against the allowed
 * tokens. A non-string runtime value is a category error (TypeError); an
 * unknown token raises a clear Error naming the value and the allowed set.
 */
function selectEngineToken(
  engine: string | undefined,
): typeof ENGINE_WASM | typeof ENGINE_CELJS {
  if (engine === undefined) {
    return DEFAULT_ENGINE;
  }
  if (typeof engine !== "string") {
    // A JS caller bypassing the types. Reject the category error loudly
    // rather than coercing (String(engine) could silently select an engine).
    throw new TypeError(
      `makeCelEvaluator: 'engine' must be a string when provided; ` +
        `got ${typeof engine}`,
    );
  }
  const value = engine.trim();
  if (value === "") {
    // A blank selection (e.g. an empty config field) is the standard "no
    // selection" signal; fall back to the default. As of M5 that default is
    // wasm (the flip); a blank value cannot pin the legacy cel-js engine --
    // only an explicit "celjs"/"cel-js" selects the rollback.
    return DEFAULT_ENGINE;
  }
  if (value === ENGINE_CELJS || value === ENGINE_CELJS_HYPHEN) {
    return ENGINE_CELJS;
  }
  if (value === ENGINE_WASM) {
    return ENGINE_WASM;
  }
  const allowed = ALLOWED_ENGINE_TOKENS.map((token) =>
    JSON.stringify(token),
  ).join(", ");
  throw new Error(
    `makeCelEvaluator: engine ${JSON.stringify(engine)} is not a recognized ` +
      `CEL engine; allowed values are ${allowed} (unset or blank -> ` +
      `${JSON.stringify(DEFAULT_ENGINE)}). Engine names are case-sensitive.`,
  );
}

/**
 * Construct the CEL evaluator for the selected engine -- the package's
 * canonical evaluator entry point (VAL-CWC-P5FLIP-011).
 *
 * `engine` unset / blank -> the wasm default (`WasmCelBackend`, the M5 flip);
 * `"celjs"` / `"cel-js"` -> the legacy `RelayCelEvaluator` (the explicit
 * rollback override until M6); `"wasm"` -> the wasm backend explicitly.
 * `timeoutMs` and `udfs` are forwarded to the selected evaluator's
 * constructor with IDENTICAL semantics, so the factory is a transparent
 * substitute for constructing either class directly.
 *
 * NOTE the engines' `evaluate()` calling conventions differ: the wasm
 * backend's `evaluate()` is async (returns a Promise; the worker_threads
 * hard-kill timeout path), while the legacy cel-js `evaluate()` is
 * synchronous. A caller that may receive either engine must `await` the
 * result (awaiting a non-Promise is a no-op) or narrow with `instanceof`.
 *
 * @throws TypeError `engine` is a non-string runtime value.
 * @throws Error `engine` holds an unrecognized token, OR the forwarded
 *   `timeoutMs` is out of bounds (re-raised from the evaluator constructor).
 * @throws RelayCelUnsupportedUdfError a non-allowlist UDF was forwarded to
 *   the wasm engine (fail-closed at construction).
 */
export function makeCelEvaluator(
  options?: MakeCelEvaluatorOptions & { engine?: typeof ENGINE_WASM },
): WasmCelBackend;
export function makeCelEvaluator(
  options: MakeCelEvaluatorOptions & {
    engine: typeof ENGINE_CELJS | typeof ENGINE_CELJS_HYPHEN;
  },
): RelayCelEvaluator;
export function makeCelEvaluator(
  options?: MakeCelEvaluatorOptions,
): CelEvaluator;
export function makeCelEvaluator(
  options?: MakeCelEvaluatorOptions,
): CelEvaluator {
  // `?? {}` (not a parameter default) so a JS caller passing an explicit
  // `null` gets the default-construction path rather than a bare property
  // read on null.
  const opts = options ?? {};
  const engine = selectEngineToken(opts.engine);

  // Forward only the options the caller actually supplied, so the selected
  // evaluator's own defaults govern the unspecified ones (identical to direct
  // construction). Mirrors engine.py's conditional kwargs build.
  const forwarded: { timeoutMs?: number; udfs?: readonly PureUdf[] } = {};
  if (opts.timeoutMs !== undefined) {
    forwarded.timeoutMs = opts.timeoutMs;
  }
  if (opts.udfs !== undefined) {
    forwarded.udfs = opts.udfs;
  }

  if (engine === ENGINE_CELJS) {
    return new RelayCelEvaluator(forwarded);
  }
  // selectEngineToken returns only the two allowed tokens; the remaining one
  // is the wasm default.
  return new WasmCelBackend(forwarded);
}
