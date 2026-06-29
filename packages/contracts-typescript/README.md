# @epochly/relay-contracts

TypeScript mirror of the Python `relay_contracts` package. Evaluates CEL with
the single `relay_cel_wasm` wasm engine -- the same `relay_cel_wasm.wasm` the
Python host loads -- behind the Relay CEL profile (CQ1 line 146): native
`dyn(...)`, `timestamp(...)`, and `duration(...)` are rejected at parse time,
regex literals are pinned to the RE2 subset, every evaluation runs under a
wall-clock timeout (default 50 ms, capped at 250 ms), UDFs must be registered
with `pure: true`, and structured outputs are canonicalised with RFC 8785 JCS
so the byte form is identical to the cel-python output (VAL-W6-014).

ASCII-only per CLAUDE.md "ASCII-Safe Source".

## CEL engine: wasm only (M6 single-engine model)

As of milestone M6 WS-I the wasm CEL engine is the ONLY backend. The legacy
`cel-js` evaluator was removed; `makeCelEvaluator()` always constructs the
wasm `WasmCelBackend`. Byte-for-byte parity between the Python host and this
TypeScript host is guaranteed by construction because both load the same
pinned wasm artifact (the Py<->TS verdict + JCS byte-determinism keystone
invariant, CLAUDE.md invariant #16).

Engine selection now fails closed:

- `makeCelEvaluator()` with no `engine` (or `engine` unset / blank / `"wasm"`)
  returns the wasm engine.
- `makeCelEvaluator({ engine: "celjs" })` (or `"cel-js"`, or any other
  legacy/unknown token) **throws** a structured error naming the bad value and
  the allowed set. The legacy engine no longer exists; there is nothing to
  select. A non-string `engine` is a `TypeError`.

There is deliberately NO environment variable read in the TS factory --
engine selection is config-only so evaluation stays deterministic.

The earlier M5 bake window (when `cel-js` was still selectable for a single
release as a rollback) is closed. There is no rollback path: the wasm engine
is the sole CEL backend.
