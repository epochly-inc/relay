// `relay.schema_match(payload, schema)` UDF (TypeScript).
//
// Returns `true` iff `payload` conforms to a minimal JSON-Schema
// subset (the same subset the Python mirror supports).
//
// Mirrors packages/contracts/src/relay_contracts/udfs/schema_match.py
// byte-for-byte in semantics. Cross-language parity corpus pinned at
// tests/conformance/cel/relay_udfs_parity.json.
//
// Supported schema keywords (v0.1):
//   - `type`: one of "string" | "number" | "integer" | "boolean" |
//     "object" | "array" | "null"
//   - `required`: array of property names that MUST be present
//   - `properties`: object mapping property name -> nested schema
//   - `items`: nested schema applied to every array element
//
// Returns `false` on any malformed schema. Returns `true` for empty
// schema {} (matches anything; mirrors JSON Schema's "always-pass").
//
// Purity contract (CLAUDE.md banned pattern #16):
//   - no wall clock
//   - no network
//   - no filesystem reads outside the inputs
//   - no locale-dependent comparisons (only `===` on strings; no
//     toLowerCase / Intl.Collator)
//   - no mutable process globals
//   - no random sources
//   - bounded recursion (depth-limited at MAX_DEPTH)
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

export const RELAY_SCHEMA_MATCH_NAME = "relay.schema_match" as const;
export const RELAY_SCHEMA_MATCH_ARITY = 2 as const;

// Defense-in-depth depth cap. The evaluator's wall-clock timeout
// (DEFAULT_TIMEOUT_MS = 50 ms) is the primary bound.
export const MAX_DEPTH = 64 as const;

const VALID_TYPES = new Set<string>([
  "string",
  "number",
  "integer",
  "boolean",
  "object",
  "array",
  "null",
]);

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

// JS distinguishes integer vs float by value, not by type. JSON
// parsers never produce a "float-shaped 1" -- so 1 and 1.0 round-trip
// to the same Number 1 in JS. The Python mirror's `isinstance(int)`
// vs `isinstance(float)` distinction collapses for whole-valued
// doubles in the JCS-roundtripped corpus, so v0.1's TS `integer`
// check is "Number.isInteger(payload) && typeof payload === 'number'"
// excluding NaN and booleans.
function isInteger(value: unknown): boolean {
  return typeof value === "number" && Number.isInteger(value);
}

function matchesType(payload: unknown, typeName: string): boolean {
  if (typeName === "boolean") {
    return typeof payload === "boolean";
  }
  if (typeName === "null") {
    return payload === null;
  }
  if (typeName === "string") {
    return typeof payload === "string";
  }
  if (typeName === "integer") {
    return isInteger(payload);
  }
  if (typeName === "number") {
    // JSON Schema "number" matches int or float; reject booleans
    // (they are not numbers in JSON Schema).
    if (typeof payload === "boolean") {
      return false;
    }
    return typeof payload === "number" && Number.isFinite(payload);
  }
  if (typeName === "object") {
    return isPlainObject(payload);
  }
  if (typeName === "array") {
    return Array.isArray(payload);
  }
  return false;
}

function validate(payload: unknown, schema: unknown, depth: number): boolean {
  if (depth > MAX_DEPTH) {
    return false;
  }
  if (!isPlainObject(schema)) {
    return false;
  }
  // Empty schema validates anything.
  if (Object.keys(schema).length === 0) {
    return true;
  }
  const typeName = schema["type"];
  if (typeName !== undefined) {
    if (typeof typeName !== "string") {
      return false;
    }
    if (!VALID_TYPES.has(typeName)) {
      return false;
    }
    if (!matchesType(payload, typeName)) {
      return false;
    }
  }
  if (isPlainObject(payload)) {
    const required = schema["required"];
    if (required !== undefined) {
      if (!Array.isArray(required)) {
        return false;
      }
      for (const name of required) {
        if (typeof name !== "string") {
          return false;
        }
        if (!Object.prototype.hasOwnProperty.call(payload, name)) {
          return false;
        }
      }
    }
    const properties = schema["properties"];
    if (properties !== undefined) {
      if (!isPlainObject(properties)) {
        return false;
      }
      for (const propName of Object.keys(properties)) {
        const propSchema = properties[propName];
        if (Object.prototype.hasOwnProperty.call(payload, propName)) {
          if (!validate(payload[propName], propSchema, depth + 1)) {
            return false;
          }
        }
      }
    }
  }
  if (Array.isArray(payload)) {
    const items = schema["items"];
    if (items !== undefined) {
      if (!isPlainObject(items)) {
        return false;
      }
      for (const element of payload) {
        if (!validate(element, items, depth + 1)) {
          return false;
        }
      }
    }
  }
  return true;
}

/**
 * Return `true` iff `payload` conforms to `schema`. Pure,
 * deterministic, depth-bounded. Returns `false` rather than throwing
 * on any malformed input.
 */
export function relaySchemaMatch(payload: unknown, schema: unknown): boolean {
  return validate(payload, schema, 0);
}
