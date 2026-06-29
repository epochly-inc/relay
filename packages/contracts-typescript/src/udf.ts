// Pure-only UDF registry for the Relay CEL profile (TypeScript).
//
// CLAUDE.md banned pattern #16: every Relay UDF MUST be `pure`: no wall
// clock, no network, no filesystem reads outside the inputs, no
// locale-dependent comparisons, no mutable process globals, no random
// sources. This module provides the single registration entry point
// that the rest of `packages/contracts-typescript/` consumes; passing
// `pure: false` raises `RelayUdfPurityError` at registration time so
// the non-determinism cannot reach evaluation.
//
// VAL-W6-013 binds: a guard test attempts to register `pure: false`
// and asserts the registration call throws before the UDF can be
// invoked.
//
// Mirrors packages/contracts/src/relay_contracts/udf.py byte-for-byte
// in semantics: identical class shape, identical kwarg-mandatory
// purity flag, identical rejection rules.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { RelayUdfPurityError } from "./errors.js";

export interface RegisterUdfOptions {
  /**
   * Name the CEL expression invokes (e.g., `relay.coverage`). The wasm CEL
   * engine hosts the 3 native relay.* UDFs by their dotted names; this
   * registry holds the names by exact string. Cross-language parity is pinned
   * by the Relay-CEL conformance corpus.
   */
  name: string;
  /** Pure callable. */
  fn: (...args: unknown[]) => unknown;
  /**
   * Purity flag. MUST be the literal boolean `true`. Anything else
   * (false, truthy non-bool, omitted) raises `RelayUdfPurityError`.
   */
  pure: boolean;
  /** Fixed positional-argument count; variadic UDFs not supported in v0.1. */
  arity: number;
}

/**
 * Frozen, registered, pure-only UDF. Construct via `registerUdf`; the
 * constructor is private-by-convention -- callers that bypass
 * `registerUdf` and assemble a `PureUdf` directly defeat the purity
 * guard.
 */
export interface PureUdf {
  readonly name: string;
  readonly fn: (...args: unknown[]) => unknown;
  readonly arity: number;
}

/**
 * Register a UDF for the Relay CEL evaluator.
 *
 * `pure` MUST be the literal boolean `true`. Passing `pure: false`
 * raises `RelayUdfPurityError` immediately -- the UDF is never
 * constructed and never reaches evaluation. This enforces CLAUDE.md
 * banned pattern #16 structurally rather than via review.
 *
 * The options-bag form is mandatory; positional purity flags are easy
 * to flip by accident in a refactor and would silently regress the
 * invariant.
 */
export function registerUdf(options: RegisterUdfOptions): PureUdf {
  const { name, fn, pure, arity } = options;
  // typeof check rejects truthy non-bool ("yes", 1, [true]) -- those
  // are a category error, not a purity claim. Mirrors Python check at
  // packages/contracts/src/relay_contracts/udf.py:61-66.
  if (typeof pure !== "boolean") {
    throw new RelayUdfPurityError(
      `registerUdf(${JSON.stringify(name)}): 'pure' MUST be a boolean; got ${typeof pure}`,
    );
  }
  if (pure !== true) {
    throw new RelayUdfPurityError(
      `registerUdf(${JSON.stringify(name)}): 'pure' MUST be true; got ${String(pure)}. ` +
        "CLAUDE.md banned pattern #16: non-deterministic UDFs are forbidden.",
    );
  }
  if (typeof name !== "string" || name.length === 0) {
    throw new RelayUdfPurityError(
      `registerUdf: 'name' MUST be a non-empty string; got ${JSON.stringify(name)}`,
    );
  }
  if (typeof fn !== "function") {
    throw new RelayUdfPurityError(
      `registerUdf(${JSON.stringify(name)}): 'fn' MUST be a function; got ${typeof fn}`,
    );
  }
  if (
    typeof arity !== "number" ||
    !Number.isInteger(arity) ||
    arity < 0
  ) {
    throw new RelayUdfPurityError(
      `registerUdf(${JSON.stringify(name)}): 'arity' MUST be a non-negative integer; got ${String(arity)}`,
    );
  }
  // Object.freeze enforces immutability at runtime; readonly enforces
  // it at compile time. Both belt and suspenders.
  return Object.freeze({ name, fn, arity });
}
