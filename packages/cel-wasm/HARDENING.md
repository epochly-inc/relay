# relay-cel-wasm hardening backlog (G1..G16 + WS2 newly-surfaced)

Maps every conformance gap from the
[WS1 report](../../../planning/adr/cel-wasm-single-engine-rearchitecture.md)
(gap register G1..G16) to its WS2 status:

- **DONE** -- landed in the WS2 wrapper (`crate/src/lib.rs`), verified by the
  conformance harness and/or `tests/test_profile_fence.py`.
- **WRAPPER-TODO** -- feasible in the wrapper (custom function / serializer /
  parser pre-pass) without touching cel internals; not yet done this increment.
- **NEEDS-FORK** -- requires a vendored `cel-rust-relay` fork (the equality
  core, the macro lowering, the type-value model, or the lexer); cannot be
  done by wrapping cel 0.13.

Severity is carried from the WS1 report. Counts are post-WS2 (after the dyn
shim made the cross-numeric forms visible).

| Gap | What | WS1 severity | WS2 status | Notes |
|-----|------|--------------|-----------|-------|
| **G1** | proto/message construction PANICS (wasm trap) | HARD (P0 safety) | **DONE (fenced)** | `find_profile_rejection` walks the AST and rejects `Expr::Struct`, map `StructField`, and `Unspecified` with a clean `RELAY-CEL-002` BEFORE `execute()` reaches `objects.rs` `todo!()`/`panic!`. 185 cases now error cleanly; **0 engine panics**. The Relay profile excludes proto messages, so producing a value is NOT the goal -- the goal is no-panic, which is met. |
| **G2** | missing `dyn()` builtin | EASY | **DONE** | `dyn(x) = x` registered as a custom identity function. Unblocked the dyn-gated comparisons. The cross-numeric equality these forms exercise underneath is G6. |
| **G3** | missing `type()` + type denotations | EASY-MED / HARD | **NEEDS-FORK** | cel 0.13 `Value` has no `Type` variant; `type(1)` must return a first-class type value (`{"t":"type","v":"int"}`). A custom function cannot synthesize a type value the engine + serializer agree on. 85 `missing_builtin_or_function` failures are mostly `type(...)`. Needs the fork's type-value model. |
| **G4** | macros2 two-variable comprehensions | HARD | **NEEDS-FORK** | `exists(i,v,..)`, `all(i,v,..)`, `existsOne(i,v,..)`, `transformList`, `transformMap`. New macro lowering in the parser/comprehension engine. 38 `macros2` cases. |
| **G5** | parser gaps (negative hex, etc.) | MED | **WRAPPER-TODO / NEEDS-FORK** | e.g. `-0x55555555` -> `invalid int literal`. The unary-minus-over-hex fold is a lexer/parser fix (NEEDS-FORK if it lives in cel's antlr grammar). A pre-normalization pass in the wrapper could handle some forms but is fragile -- prefer the fork. 47 `parse_compile_failure`. Also surfaced: `--------------------------------19` folds to `-19` instead of `19` (repeated-unary-minus parity bug) -- fork. |
| **G6** | no cross-numeric equality / mixed-type number comparison | MED-HARD | **NEEDS-FORK** | `1.0 == 1` -> `false` (should be `true`); `dyn(1) == 1u` -> `false`. **WS2 newly-visible count: 32** (`cross_numeric_equality_or_bool`), surfaced once the dyn shim let these forms reach the equality core. Load-bearing for Relay contract assertions. Lives in cel's equality implementation -> fork. |
| **G7** | triple-quoted string/bytes keep the quotes | MED | **WRAPPER-TODO / NEEDS-FORK** | `b'''hello'''` -> `2727...2727` (includes inner `''`). Lexer literal handling. ~16 `value_mismatch:bytes`. Best fixed in the fork's lexer; a wrapper pre-pass is brittle. |
| **G8** | string escape handling diverges | MED | **NEEDS-FORK** | `'\?'` keeps `\?`; `"\\'"` keeps the backslash. Escape-set + quote-context rules. ~12 `string_value_mismatch`. Lexer -> fork. |
| **G9** | double->string canonical format (large magnitudes) | EASY | **DONE** | Serializer-side: `format_double_g` reproduces Go `strconv.FormatFloat(f,'g',-1,64)` (the oracle's format). `double(1e12)` -> `1e+12`, `1e6` -> `1e+06`, boundary at exp 6 / -4. Verified across exp -6..23 + `tests`. |
| **G10** | missing range/overflow checks on conversions | MED | **DONE** | `int()`/`uint()` re-registered as custom functions (`relay_int`/`relay_uint`) that, for a DOUBLE arg, reproduce cel-go's exact-representability rule (common/types/overflow.go): `int` errors when `NaN/Inf or v <= float64(i64::MIN) or v >= float64(i64::MAX)`; `uint` errors when `NaN/Inf or v < 0 or v >= 2**64`. Because `i64::MAX as f64 == 2**63` and `u64::MAX as f64 == 2**64`, the boundary cases error: `int(9223372036854775807.0)` (f64 is 2**63), `int(-9223372036854775808.0)` (f64 is -2**63), `int(1e99)`, `int(18446744073709551615.0)`, `uint(6.022e23)` all now error cleanly (RELAY-CEL-004), while in-range conversions still produce values (`int(double(2**55))`, `int(1.9)->1`, `uint(25.5)->25`). Non-double arms (string parse, int/uint identity + checked cross-cast) preserve stock cel 0.13 behavior. `error_expected_got_value` dropped 8 -> 6; `conversions` file 64 -> 67. |
| **G11** | `size()` counts UTF-8 bytes, not code points | EASY-MED | **DONE** | `relay_size` uses `chars().count()` for strings (bytes/list/map keep their counts). Works as method and function (`This<Value>`). `size('ÿ')` -> 1. Verified in `tests`. |
| **G12** | conversion overloads reject already-typed args | EASY | **DONE** | `relay_bytes`/`relay_duration`/`relay_timestamp` accept an already-typed value idempotently. `bytes(b'abc')`, `duration(duration('100s'))`, `timestamp(timestamp(...))` now succeed. (`string`/`int`/`uint`/`double` already accepted multiple types.) Verified in `tests`. |
| **G13** | timestamp/duration arithmetic + `int(timestamp)` | MED | **PARTIAL: int(timestamp) DONE; arithmetic NEEDS-FORK** | `int(timestamp)` landed as an arm of the re-registered `relay_int` (G10): a `Value::Timestamp(t)` returns `Value::Int(t.timestamp())` (chrono Unix epoch SECONDS). Verified `int(timestamp('1970-01-01T00:00:01Z'))->1`, `int(timestamp('2004-09-16T23:59:59Z'))->1095379199`, pre-epoch `->-1`; `timestamps` file 57 -> 58. The remaining `duration('120s') + timestamp(...)` -> `UnsupportedBinaryOperator` binary-operator dispatch is in cel's arithmetic core and stays NEEDS-FORK. |
| **G14** | timestamp->string `+00:00` vs `Z` | EASY | **DONE** | Serializer-side: `rfc3339_utc_z` converts to UTC and emits `Z` with `SecondsFormat::AutoSi`. `timestamp('...Z')` round-trips with `Z`. Verified in `tests`. |
| **G15** | error short-circuit in macros | MED | **NEEDS-FORK** | `[1,2,3].all(e, 6/(2-e) == 6)` raises `DivisionByZero`; spec short-circuits `all` to `false`. Error-vs-value propagation order in the comprehension engine -> fork. 1 `div_mod_semantics` visible. |
| **G16** | namespace/container resolution | MED | **WRAPPER-TODO / NEEDS-FORK** | `y` with `container "x"` and `x.y` bound resolves to the wrong binding. 2 `type_mismatch:bool->string` (`y` -> string `"false"` instead of bool from `x.y`) + `namespace` file failures. Container-qualified name resolution is in cel's resolver -> likely fork; the wrapper could pre-resolve container prefixes for the binding path (WRAPPER-TODO, partial). |

## WS2 landed this increment (summary)

DONE (first WS2 pass): **G1** (the P0 safety fence), **G2**, **G9**, **G11**,
**G12**, **G14** -- moved **58.1% raw / 67.0% ex-proto** (WS1 baseline) to
**69.5% raw / 80.7% ex-proto**.

DONE (WS2 wrapper conformance pass 2): **G10** (int/uint exact-range errors),
**G13** `int(timestamp)` epoch-seconds overload. Moved
**69.5% raw / 80.7% ex-proto** -> **69.8% raw (921/1319) / 81.1% ex-proto
(896/1105)**: `conversions` 64 -> 67 (+3), `timestamps` 57 -> 58 (+1), net +4
with **zero per-file regressions**.

Both passes hold the keystone invariants: **0 engine panics** and byte-parity
(`diff` exit 0 across Python/Node, 1449 records).

## Deferred to the fork (`cel-rust-relay`), in rough priority

1. **G6** cross-numeric equality (load-bearing for Relay; the equality core).
2. **G3** the type-value model (unblocks the `type()` mass, ~85 cases).
3. **G4** macros2 two-variable comprehensions (38 cases).
4. **G7 / G8 / G5** lexer/parser: triple-quote literals, escape set,
   negative-hex + repeated-unary-minus folding.
5. **G15** comprehension error short-circuit ordering.
6. **G16** container resolution + **G13** timestamp/duration BINARY arithmetic
   (`duration + timestamp`) -- the cel arithmetic core. (The `int(timestamp)`
   half of G13 is DONE in the wrapper.)

## Wrapper-feasible TODO (could land before the fork, without cel internals)

- **G16** partial: pre-resolve container-qualified binding names on the host
  side of the binding protocol.

DONE this pass (were on this list): **G10** exact-representability range checks
on `int()`/`uint()`; **G13** `int(timestamp)` epoch-seconds overload.
