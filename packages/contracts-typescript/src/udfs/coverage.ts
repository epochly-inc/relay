// `relay.coverage(trace, step_name)` UDF (TypeScript).
//
// Returns `true` when `trace` is a plain object carrying a `steps`
// array containing at least one element whose `name` field equals
// `step_name`. Returns `false` otherwise. Never throws on shape
// variance.
//
// Mirrors packages/contracts/src/relay_contracts/udfs/coverage.py
// byte-for-byte in semantics. Cross-language byte-equality is enforced
// by the parity corpus at tests/conformance/cel/relay_udfs_parity.json.
//
// Purity contract (CLAUDE.md banned pattern #16):
//   - no wall clock (no Date.now / performance.now)
//   - no network (no fetch / Socket / http)
//   - no filesystem reads outside the inputs (no fs.readFile / openSync)
//   - no locale-dependent comparisons (only `===` on strings; no
//     toLowerCase / toLocaleLowerCase / Intl.Collator)
//   - no mutable process globals (no process.env, no module-level
//     mutable singletons; the constant RELAY_COVERAGE_NAME is a frozen
//     literal)
//   - no random sources (no Math.random, no crypto.randomBytes)
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

export const RELAY_COVERAGE_NAME = "relay.coverage" as const;
export const RELAY_COVERAGE_ARITY = 2 as const;

// Plain-object guard that excludes arrays, null, and class instances
// (Object.getPrototypeOf(x) === Object.prototype). The Python side
// uses isinstance(Mapping); the closest TS analog for cross-runtime
// parity is "JSON-shaped object literal".
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    return false;
  }
  if (Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Return `true` iff `trace.steps` contains an entry named `step_name`.
 *
 * Reject non-plain-object `trace` -> false.
 * Reject non-string `step_name` -> false.
 * Reject non-array `trace.steps` -> false.
 * Skip step entries that are not plain objects.
 * Use strict `===` on string `name` (codepoint equality, no case
 * folding).
 */
export function relayCoverage(
  trace: unknown,
  stepName: unknown,
): boolean {
  if (!isPlainObject(trace)) {
    return false;
  }
  if (typeof stepName !== "string") {
    return false;
  }
  const steps = trace["steps"];
  if (!Array.isArray(steps)) {
    return false;
  }
  for (const entry of steps) {
    if (!isPlainObject(entry)) {
      continue;
    }
    const name = entry["name"];
    if (typeof name === "string" && name === stepName) {
      return true;
    }
  }
  return false;
}
