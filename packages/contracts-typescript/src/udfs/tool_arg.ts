// `relay.tool_arg(call, key)` UDF (TypeScript).
//
// Returns `call.args[key]` when `call` is a plain object with a plain
// object `args` field that contains `key`. Returns `null` on any
// shape mismatch. Never throws.
//
// Mirrors packages/contracts/src/relay_contracts/udfs/tool_arg.py
// byte-for-byte in semantics. Cross-language parity corpus pinned at
// tests/conformance/cel/relay_udfs_parity.json.
//
// Purity contract (CLAUDE.md banned pattern #16):
//   - no wall clock
//   - no network
//   - no filesystem reads outside the inputs
//   - no locale-dependent comparisons (only `in` / `[]` on plain
//     objects with string keys; no Intl.Collator, no toLowerCase)
//   - no mutable process globals
//   - no random sources
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

export const RELAY_TOOL_ARG_NAME = "relay.tool_arg" as const;
export const RELAY_TOOL_ARG_ARITY = 2 as const;

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
 * Return `call.args[key]` when present; otherwise `null`.
 *
 * The returned value is whatever the args mapping holds for that key
 * (string, number, boolean, null, array, object). Callers compare it
 * with CEL operators; we do not coerce.
 *
 * Note: a key whose value is JSON `null` is indistinguishable from a
 * missing key in v0.1; both yield `null`. This matches the Python
 * mirror exactly (Python returns None in both cases).
 */
export function relayToolArg(call: unknown, key: unknown): unknown {
  if (!isPlainObject(call)) {
    return null;
  }
  if (typeof key !== "string") {
    return null;
  }
  const args = call["args"];
  if (!isPlainObject(args)) {
    return null;
  }
  // Object.prototype.hasOwnProperty.call avoids prototype-chain
  // pollution (`{}.toString` would otherwise spuriously match
  // `key="toString"`). Mirrors Python's `key in args` over plain
  // dicts.
  if (!Object.prototype.hasOwnProperty.call(args, key)) {
    return null;
  }
  return args[key];
}
