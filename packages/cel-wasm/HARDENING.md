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
| **G3** | missing `type()` + type denotations | EASY-MED / HARD | **DONE (fork increment 2)** | cel 0.13 `Value` had no `Type` variant; `type(1)` was `UndeclaredReference`. FIXED in the vendored fork: added `Value::Type(Arc<str>)` (`vendor/cel/src/objects.rs`) carrying the canonical cel-go runtime type NAME, a `dyn Val` type-value (`vendor/cel/src/common/types/type_value.rs` `CelTypeValue`, `get_type()==TYPE_TYPE`, name-based `equals`), both `Value`<->`dyn Val` conversion legs, name-based `PartialEq`, and qualified-name resolution in `Expr::Select` (so `google.protobuf.Timestamp` resolves). The wrapper (`crate/src/lib.rs`) registers `type(x)` (returns the type value of x's runtime type) and binds the ten type identifiers + `google.protobuf.{Timestamp,Duration}` as type values; `value_to_typed`/`typed_to_value` emit/accept `{"t":"type","v":"<name>"}`. All `Relay fork (G3)`. Verified vs the cel-go oracle: the 33 failing `type(...)`/denotation cases (30 `conversions`, 4 `timestamps`, incl. `type(type(1))==type`, `type(7)==type(7u)`->false, monomorphic list/map, dotted proto names) all pass with ZERO non-G3 regressions; `conversions` 67->96, `timestamps` 58->62. Conformance 71.9/83.5 -> 74.4/86.3; byte-parity held (1449). `tests/test_g3_type_values.py` (58 cases). |
| **G4** | macros2 two-variable comprehensions | HARD | **NEEDS-FORK** | `exists(i,v,..)`, `all(i,v,..)`, `existsOne(i,v,..)`, `transformList`, `transformMap`. New macro lowering in the parser/comprehension engine. 38 `macros2` cases. |
| **G5** | parser gaps (negative hex, etc.) | MED | **WRAPPER-TODO / NEEDS-FORK** | e.g. `-0x55555555` -> `invalid int literal`. The unary-minus-over-hex fold is a lexer/parser fix (NEEDS-FORK if it lives in cel's antlr grammar). A pre-normalization pass in the wrapper could handle some forms but is fragile -- prefer the fork. 47 `parse_compile_failure`. Also surfaced: `--------------------------------19` folds to `-19` instead of `19` (repeated-unary-minus parity bug) -- fork. |
| **G6** | no cross-numeric equality / mixed-type number comparison | MED-HARD | **DONE (fork increment 1)** | `1.0 == 1` -> now `true`. FIXED in the vendored fork: `Val::equals` for `int`/`uint`/`double` (`vendor/cel/src/common/types/{int,double,uint}.rs`, marked `Relay fork (G6)`) delegated to a same-type-only downcast; now delegates to the already-cross-numeric `Comparer::compare` (equal iff `Ordering::Equal`; non-numeric rhs / NaN -> false). Verified vs cel-go oracle + a 216-cell cross-numeric matrix + `tests/test_g6_cross_numeric.py` (30 cases incl. the int/uint boundary + NaN). Conformance 69.8/81.1 -> 71.9/83.5; byte-parity held. |
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

DONE (fork increment 1): **G6** cross-numeric equality (the equality core).
Moved **69.8% / 81.1%** -> **71.9% raw (948/1319) / 83.5% ex-proto (923/1105)**.

DONE (fork increment 2): **G3** the CEL type-value model (`Value::Type` +
`type()` + type identifiers + qualified-name resolution). Moved
**71.9% / 83.5%** -> **74.4% raw (981/1319) / 86.3% ex-proto (954/1105)**:
`conversions` 67 -> 96 (+29), `timestamps` 58 -> 62 (+4), net +33 with **zero
non-G3 regressions** (verified: non-G3 passing count unchanged at 947).

All passes hold the keystone invariants: **0 engine panics** and byte-parity
(`diff` exit 0 across Python/Node, 1449 records).

## Deferred to the fork (`cel-rust-relay`), in rough priority

DONE in the fork: **G6** cross-numeric equality (increment 1), **G3** the
type-value model (increment 2 -- `Value::Type` + `type()` + type identifiers +
qualified-name resolution).

Remaining:

1. **G4** macros2 two-variable comprehensions (38 cases).
2. **G7 / G8 / G5** lexer/parser: triple-quote literals, escape set,
   negative-hex + repeated-unary-minus folding.
3. **G15** comprehension error short-circuit ordering.
4. **G16** container resolution + **G13** timestamp/duration BINARY arithmetic
   (`duration + timestamp`) -- the cel arithmetic core. (The `int(timestamp)`
   half of G13 is DONE in the wrapper. The G3 qualified-name lookup resolves
   dotted TYPE denotations but not general container-relative bindings -- G16
   stays open.)

## Wrapper-feasible TODO (could land before the fork, without cel internals)

- **G16** partial: pre-resolve container-qualified binding names on the host
  side of the binding protocol.

DONE this pass (were on this list): **G10** exact-representability range checks
on `int()`/`uint()`; **G13** `int(timestamp)` epoch-seconds overload.
