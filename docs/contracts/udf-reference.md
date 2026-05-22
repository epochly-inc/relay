# Relay UDF Reference

## Overview

Relay user-defined functions (UDFs) are pure Python (and TypeScript mirror)
callables that contract authors invoke from CEL expressions inside
`BehavioralAssertion`, `SchemaContract`, and `ToolArgContract` definitions.
They live in `packages/contracts/src/relay_contracts/udfs/` and are
registered into the evaluator at import time via the `RELAY_UDFS` tuple in
`packages/contracts/src/relay_contracts/__init__.py`.

Every Relay UDF is registered with `pure=True`. The `register_udf` entry
point raises `RelayUdfPurityError` (`RELAY-CEL-004`) at registration time
when `pure=False`. Purity means: no wall clock, no network, no filesystem
reads outside the inputs, no locale-dependent comparisons, no mutable
process globals, no random sources. This constraint is load-bearing for
replay correctness — see `cel-primer.md` for the broader CEL profile
(`dyn` / `timestamp` / `duration` disabled, RE2-only regex,
wall-clock-bounded evaluation).

The v0.1 production set ships three UDFs: `relay.coverage`,
`relay.tool_arg`, and `relay.schema_match`.

## `relay.coverage`

### Signature

```python
def relay_coverage(trace: Any, step_name: Any) -> bool: ...
```

Registered name: `relay.coverage`. Arity: `2`. Source:
`packages/contracts/src/relay_contracts/udfs/coverage.py`.

### What it does

Returns `True` when `trace` is a mapping carrying a `steps` field that is
a list or tuple containing at least one entry whose `name` field equals
`step_name`. Returns `False` on any shape mismatch — the function never
raises, which keeps it safe to call against partial traces during
early-stage replay.

### Arguments

| Name | Type | Description |
|---|---|---|
| `trace` | mapping (`celtypes.MapType` or `dict`) | The trace value bound into the CEL evaluation environment. Must expose a `steps` field. |
| `step_name` | string (`celtypes.StringType` or `str`) | The exact step name to look for. Comparison is codepoint-wise `==`; no case folding, no locale-aware compare. |

### Returns

`bool`. `True` iff at least one mapping entry in `trace["steps"]` has a
`name` field equal to `step_name`.

### Example

```cel
relay.coverage(trace, "tool.search") && relay.coverage(trace, "model.respond")
```

This asserts that the trace contains both a step named `tool.search` and
a step named `model.respond`.

### Failure modes

- `trace` not a `Mapping` (`dict` / `celtypes.MapType`) -> `False`
- `step_name` not a `str` -> `False`
- `trace["steps"]` missing, not a `list` / `tuple`, or a bare string -> `False`
- Step entry not a `Mapping` -> skipped (does not match)
- Step entry `name` missing or not a `str` -> skipped

The UDF itself never raises. CEL evaluator errors that can surface around
its use include `RELAY-CEL-003` (`RELAY-CEL-TIMEOUT-001`) if the
surrounding expression exceeds the 50 ms wall-clock bound and
`RELAY-CEL-008` (`RELAY-CEL-RESOURCE-EXHAUSTED`) on bounded-resource
exhaustion.

## `relay.tool_arg`

### Signature

```python
def relay_tool_arg(call: Any, key: Any) -> Any: ...
```

Registered name: `relay.tool_arg`. Arity: `2`. Source:
`packages/contracts/src/relay_contracts/udfs/tool_arg.py`.

### What it does

Returns the value of `call["args"][key]` when `call` is a mapping with an
`args` mapping field that contains `key`. Returns `None` on any shape
mismatch. Never raises — contract authors write expressions like
`relay.tool_arg(call, "case_id") != null` and rely on a deterministic,
shape-tolerant probe.

### Arguments

| Name | Type | Description |
|---|---|---|
| `call` | mapping | A tool-call value bound into the CEL environment. Must expose an `args` mapping. |
| `key` | string | The exact argument name. Lookup uses `Mapping.__contains__`, which dispatches to codepoint-based `str.__hash__` / `__eq__`. |

### Returns

`Any`. The raw value stored under `call["args"][key]` (string, number,
bool, `None`, list, mapping). Returns `None` on any shape mismatch. Values
are not coerced; callers compare with CEL operators.

### Example

```cel
relay.tool_arg(call, "case_id") != null &&
relay.tool_arg(call, "severity") in ["low", "medium", "high"]
```

This asserts that the tool call has a non-null `case_id` and a `severity`
drawn from the allowed set.

### Failure modes

- `call` not a `Mapping` -> `None`
- `key` not a `str` -> `None`
- `call["args"]` missing or not a `Mapping` -> `None`
- `key` not present in `call["args"]` -> `None`

The UDF itself never raises.

## `relay.schema_match`

### Signature

```python
def relay_schema_match(payload: Any, schema: Any) -> bool: ...
```

Registered name: `relay.schema_match`. Arity: `2`. Source:
`packages/contracts/src/relay_contracts/udfs/schema_match.py`.

### What it does

Returns `True` iff `payload` conforms to a minimal JSON-Schema subset
declared by `schema`. Supports the keywords required by the contract DSL's
`SchemaContract` checks: `type`, `required`, `properties`, and `items`.
Returns `False` rather than raising on any malformed input.

### Arguments

| Name | Type | Description |
|---|---|---|
| `payload` | any | The value to validate. |
| `schema` | mapping | A JSON-Schema-subset mapping. An empty mapping matches anything (mirrors JSON Schema `{}` / `true`). |

Supported schema keywords:

| Keyword | Effect |
|---|---|
| `type` | One of `"string"`, `"number"`, `"integer"`, `"boolean"`, `"object"`, `"array"`, `"null"`. Single string only; array-of-types and `null` unions are not supported in v0.1. |
| `required` | List of property names that MUST be present (object payloads only). |
| `properties` | Mapping of property name to nested schema. Only declared properties are validated; unknown keys are permitted (JSON Schema default `additionalProperties: true`). |
| `items` | Nested schema applied to every element of an array. `items` as a list (tuple validation) is not supported in v0.1. |

Recursion is depth-bounded at `MAX_DEPTH = 64` as defense-in-depth on top
of the evaluator's 50 ms wall-clock timeout.

### Returns

`bool`. `True` iff `payload` conforms.

### Example

```cel
relay.schema_match(claim, {
  "type": "object",
  "required": ["case_id", "rationale"],
  "properties": {
    "case_id": {"type": "string"},
    "rationale": {"type": "string"},
    "confidence": {"type": "number"}
  }
})
```

### Failure modes

- `schema` not a `Mapping` -> `False`
- `type` value not a `str` or not in `{string, number, integer, boolean, object, array, null}` -> `False`
- Type mismatch (e.g., `type: "integer"` against a Python `bool` — booleans
  are explicitly routed out even though `bool` subclasses `int`) -> `False`
- `type: "number"` against `NaN` / `+Inf` / `-Inf` -> `False` (parity with
  the TypeScript mirror's `Number.isFinite` gate)
- `required` not a list / tuple of strings -> `False`
- Missing required property -> `False`
- Any nested `properties[k]` mismatch -> `False`
- Any nested `items` mismatch on an array element -> `False`
- Recursion depth exceeds `MAX_DEPTH` (64) -> `False`

The UDF itself never raises.

## Parity notes (cel-python vs cel-js)

Each Relay UDF has a TypeScript mirror at
`packages/contracts-typescript/src/udfs/` (`coverage.ts`,
`schema_match.ts`, `tool_arg.ts`). The contract is byte-identical
JCS-canonical output bytes for the same input across both runtimes.
Specific parity surfaces worth knowing:

- `relay.coverage`: Python `str` equality and `celtypes.StringType` (a
  `str` subclass) share the same codepoint-based hash and `==`. cel-js
  decodes JS strings to the same UTF-16 codepoint sequence; equality
  holds.
- `relay.tool_arg`: Mapping containment in Python uses `__hash__` /
  `__eq__` on `str`, which is codepoint-based and locale-independent.
  Parity with cel-js object property lookup holds.
- `relay.schema_match`: The `type: "number"` finiteness check is the
  pain point. Python rejects `NaN` / `+/- Inf` via `math.isfinite`;
  TypeScript rejects them via `Number.isFinite`. Booleans are explicitly
  excluded from `number` and `integer` in both runtimes because Python
  `bool` subclasses `int`.

The Relay Conformance Corpus
(`tests/conformance/cel/relay_udfs_parity.json`) enforces parity. Every
new UDF or UDF behavior change MUST add corpus cases and pass parity
between cel-python and cel-js before merge.

## Adding a custom UDF

Custom UDFs are registered with the same `register_udf(name=..., fn=...,
pure=True, arity=...)` entry point used by the production set. `pure=True`
is enforced structurally — `register_udf` raises `RelayUdfPurityError`
(`RELAY-CEL-004`) at registration time when `pure=False`, so an impure UDF
cannot reach the evaluator. Custom UDFs must satisfy the same purity
contract: no wall clock, no network, no filesystem reads outside the
inputs, no locale-dependent comparisons, no mutable process globals, no
random sources. For the full walkthrough (when to add a UDF, how to wire
parity tests, conformance corpus updates), see
`../how-to/add-custom-cel-udf.md`.

---

Spec: §D.1, §D.2, §D.4
