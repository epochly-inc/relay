# @epochly/relay-contracts

TypeScript mirror of the Python `relay_contracts` package. Wraps `cel-js`
behind the Relay CEL profile (CQ1 line 146): native `dyn(...)`,
`timestamp(...)`, and `duration(...)` are rejected at parse time, regex
literals are pinned to the RE2 subset, every evaluation runs under a
wall-clock timeout (default 50 ms, capped at 250 ms), UDFs must be
registered with `pure: true`, and structured outputs are canonicalised
with RFC 8785 JCS so the byte form is identical to the cel-python
output (VAL-W6-014).

ASCII-only per CLAUDE.md "ASCII-Safe Source".

## CEL engine default: wasm (M5 bake window)

As of milestone M5 the default engine returned by `makeCelEvaluator()` is
the single wasm CEL engine (the same `relay_cel_wasm.wasm` the Python host
loads), flipped after the dual-run parity gates showed zero divergence.
The legacy cel-js path stays selectable for the one-release bake window
only, via the config parameter `makeCelEvaluator({ engine: "celjs" })`
(`"cel-js"` is also accepted). There is deliberately NO environment
variable read in the TS factory -- engine selection is config-only so
evaluation stays deterministic. The rollback is removed at M6 (cel-js
removal).

The canonical bake/rollback procedure (including what to verify after a
rollback and the requirement to report any rollback use) lives in
`packages/contracts/README.md` under "CEL engine default: wasm (M5 bake
window)".
