# relay-cel-wasm hardening backlog (G1..G16 + WS2 newly-surfaced)

**Current state (after the fork-cleanup increment): 85.82% raw (1132/1319) /
100.0% ex-proto (1105/1105).** Every G1..G16 gap is DONE. The only RAW failures
left are proto-message construction/access (fenced to a clean `RELAY-CEL-002`,
excluded from the Relay CEL profile) and 2 checker-deduced-type assertions a
runtime evaluator cannot produce -- all out of scope (see "Honest residual
breakdown" at the bottom). Byte-parity holds (1449 records, Python <-> Node).

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
| **G4** | macros2 two-variable comprehensions | HARD | **DONE (fork increment G4)** | `e.all(i,v,p)`, `e.exists(i,v,p)`, `e.existsOne(i,v,p)` / `e.exists_one(...)`, `e.transformList(i,v[,f],t)`, `e.transformMap(i,v[,f],t)`. FIXED in the vendored fork (faithful port of cel-go v0.28 `ext/comprehensions.go`, all marked `Relay fork (G4)`). Three pieces: (1) parser lowering (`vendor/cel/src/parser/macros.rs`) -- `find_expander` now dispatches the arity-3 receiver forms (and arity-3/4 transforms) to two-variable expanders, distinguished from the one-var forms by arity at expansion time (one-var = 2 args, two-var = 3, filtered transform = 4); each emits a `ComprehensionExpr` with `iter_var` (index/key) AND `iter_var2: Some(value)`; `extract_iter_vars` enforces cel-go's duplicate-name / accumulator-shadow guards. (2) comprehension engine (`vendor/cel/src/objects.rs` `Expr::Comprehension`) -- when `iter_var2` is `Some`, switch on range type: `LIST_TYPE` binds `iter_var` to a 0-based `CelInt` index + `iter_var2` to the element; `MAP_TYPE` binds `iter_var` to the key + `iter_var2` to the indexer-looked-up value. One-var path (`iter_var2` None) left byte-for-byte unchanged. (3) `cel.@mapInsert` (`objects.rs` `Expr::Call` special-case + `DefaultMap::insert_entry` in `vendor/cel/src/common/types/map.rs`) -- the synthetic `transformMap` step; returns a new map = accumulator with `(key, value)` inserted; never in user source (re-exported as `crate::parser::MAP_INSERT`). Verified vs the cel-go oracle: `macros2` 8 -> 45 (+37; the 38th case is G15, see below). Conformance 80.0/93.0 -> 82.79/96.38; byte-parity held (1449). `tests/test_g4_two_var_macros.py` (56 cases) + 101 fork unit tests green; ZERO per-file regressions (basic/conversions/macros/parse/timestamps all delta=+0; total passed 1055 -> 1092 = exactly the macros2 gain). The single `macros2` residual (`all/list_elem_type_exhaustive`, `[0,'foo',3].all(i,v,v%2==i)` -> false) is **G15** (error-as-value short-circuit ordering), the same root cause as the one remaining `macros` file failure, and is out of G4 scope. `transformMapEntry` has no `macros2.textproto` cases and was not implemented. |
| **G5** | parser gaps (negative hex, repeated unary minus) | MED | **DONE (fork increment 3)** | `-0x55555555` -> now `-1431655765`; `--------19` (even) -> now `19`. FIXED in the vendored fork (`vendor/cel/src/parser/parser.rs`, marked `Relay fork (G5)`). `visit_Int`/`visit_Uint` now mirror cel-go VisitInt/VisitUint: take the NUM_INT/NUM_UINT **token** text (not `ctx.get_text()`, which prepends the MINUS sign), strip the `0x` radix prefix to select base 16, THEN prepend the sign and `from_str_radix`. The previous code ran `strip_prefix("0x")` on `-0x...` (text starts with `-`), the strip failed, and `"-0x...".parse::<i64>()` errored. `visit_Negate`/`visit_LogicalNot` now mirror cel-go: an even op count returns the member directly (no NEGATE/NOT wrap, no op id consumed) -- the previous code visited the member then ALWAYS wrapped once, folding even chains to a single negate. CEL has no `0o`/`0b` prefixes; leading-zero literals (`017`->17) are decimal (handled by base-10 `from_str_radix`). Verified vs the cel-go oracle: `-0x55555555`->-1431655765, `--------19`(32)->19, `---19`->-19, `0xFu`->15u, `017`->17, overflow forms still error. Closed both G5 cases (1 `parse_compile_failure`, 1 `value_mismatch:int`). `tests/test_g5_g7_g8_literals.py`. |
| **G6** | no cross-numeric equality / mixed-type number comparison | MED-HARD | **DONE (fork increment 1)** | `1.0 == 1` -> now `true`. FIXED in the vendored fork: `Val::equals` for `int`/`uint`/`double` (`vendor/cel/src/common/types/{int,double,uint}.rs`, marked `Relay fork (G6)`) delegated to a same-type-only downcast; now delegates to the already-cross-numeric `Comparer::compare` (equal iff `Ordering::Equal`; non-numeric rhs / NaN -> false). Verified vs cel-go oracle + a 216-cell cross-numeric matrix + `tests/test_g6_cross_numeric.py` (30 cases incl. the int/uint boundary + NaN). Conformance 69.8/81.1 -> 71.9/83.5; byte-parity held. |
| **G7** | triple-quoted string/bytes keep the quotes | MED | **DONE (fork increment 3)** | `b'''hello'''` -> now `68656c6c6f` (`hello`), not `2727...2727`. FIXED in the vendored fork (`vendor/cel/src/parser/parse.rs` rewritten as a faithful port of cel-go `parser/unescape.go`, marked `Relay fork (G7/G8)`; caller `parser.rs` `visit_Bytes`). The new `unescape(value, is_bytes)` strips the full `'''`/`"""` delimiter span (cel-go `value[3:n-3]`) for strings AND bytes (incl. raw `r'''`/`br'''`), then decodes the body. The byte caller previously did `string[2..len-1]` (strip `b'` + one trailing quote), which embedded the inner `''` delimiters; it now strips only the leading `b`/`B` designator (cel-go `GetText()[1:]`) and lets `unescape` strip the quotes. Closed all 16 `value_mismatch:bytes` cases plus the triple-quote `parse_compile_failure` cases. `tests/test_g5_g7_g8_literals.py`. |
| **G8** | string escape handling diverges | MED | **DONE (fork increment 3)** | `'\?'` -> now `?`; the escape set is quote-context independent. FIXED in the same `parse.rs` cel-go `unescapeChar` port (`Relay fork (G7/G8)`). The CEL escape set -- `\a \b \f \n \r \t \v`, `\\ \" \' \` \?`, `\xHH`/`\XHH`, `\uHHHH`, `\UHHHHHHHH`, octal `\NNN` -- decodes per CEL with the spec's quote-context independence (`\"`/`\'`/`\`` yield the bare char regardless of opening quote; the old code retained the backslash based on quote context) and the bytes-vs-string split (`\x`/`\X`/octal are raw byte values in bytes and unicode code points in strings; `\u`/`\U` are rejected in bytes). Added `\X` (upper-case hex), previously unsupported. Closed all 47 `parse_compile_failure` escape/triple cases shared with G7 and 9 of 12 `string_value_mismatch` (the remaining 3 are G13/G14 timestamp/duration string formatting, out of this increment's scope). `tests/test_g5_g7_g8_literals.py`. |
| **G9** | double->string canonical format (large magnitudes) | EASY | **DONE** | Serializer-side: `format_double_g` reproduces Go `strconv.FormatFloat(f,'g',-1,64)` (the oracle's format). `double(1e12)` -> `1e+12`, `1e6` -> `1e+06`, boundary at exp 6 / -4. Verified across exp -6..23 + `tests`. |
| **G10** | missing range/overflow checks on conversions | MED | **DONE** | `int()`/`uint()` re-registered as custom functions (`relay_int`/`relay_uint`) that, for a DOUBLE arg, reproduce cel-go's exact-representability rule (common/types/overflow.go): `int` errors when `NaN/Inf or v <= float64(i64::MIN) or v >= float64(i64::MAX)`; `uint` errors when `NaN/Inf or v < 0 or v >= 2**64`. Because `i64::MAX as f64 == 2**63` and `u64::MAX as f64 == 2**64`, the boundary cases error: `int(9223372036854775807.0)` (f64 is 2**63), `int(-9223372036854775808.0)` (f64 is -2**63), `int(1e99)`, `int(18446744073709551615.0)`, `uint(6.022e23)` all now error cleanly (RELAY-CEL-004), while in-range conversions still produce values (`int(double(2**55))`, `int(1.9)->1`, `uint(25.5)->25`). Non-double arms (string parse, int/uint identity + checked cross-cast) preserve stock cel 0.13 behavior. `error_expected_got_value` dropped 8 -> 6; `conversions` file 64 -> 67. |
| **G11** | `size()` counts UTF-8 bytes, not code points | EASY-MED | **DONE** | `relay_size` uses `chars().count()` for strings (bytes/list/map keep their counts). Works as method and function (`This<Value>`). `size('ÿ')` -> 1. Verified in `tests`. |
| **G12** | conversion overloads reject already-typed args | EASY | **DONE** | `relay_bytes`/`relay_duration`/`relay_timestamp` accept an already-typed value idempotently. `bytes(b'abc')`, `duration(duration('100s'))`, `timestamp(timestamp(...))` now succeed. (`string`/`int`/`uint`/`double` already accepted multiple types.) Verified in `tests`. |
| **G13** | timestamp/duration arithmetic + `int(timestamp)` | MED | **DONE (fork cleanup)** | `int(timestamp)` landed earlier (G10 arm: epoch seconds). The BINARY arithmetic is now complete in the fork (`Relay fork (G13)`, `vendor/cel/src/common/types/{timestamp,duration}.rs`): `timestamp + duration`, `duration + timestamp` (the commutative sibling, delegating to a shared range-checked `Timestamp::checked_add_duration`), `timestamp - duration`, `timestamp - timestamp -> duration` (with an int64-nanos overflow check so a 10000-year span errors), `duration +/- duration`. The wrapper added `timestamp(int)` (epoch seconds), `bool()`, a UTF-8-strict `string(bytes)` + Go-style `string(duration)`, and the cel-spec `[0001..9999]` timestamp range check. The timezone-aware getters (`getFullYear`/.../`getMilliseconds` with an optional IANA name or fixed-offset arg) landed in the fork via chrono-tz; `Duration.getMilliseconds` now returns the ms COMPONENT. `timestamps` file -> 76/76; `conversions` -> 109/109. `tests/test_g13_{conversions_tail,temporal_arith,timestamp_getters}.py`. |
| **G14** | timestamp->string `+00:00` vs `Z` | EASY | **DONE** | Serializer-side: `rfc3339_utc_z` converts to UTC and emits `Z` with `SecondsFormat::AutoSi`. `timestamp('...Z')` round-trips with `Z`. Verified in `tests`. |
| **G15** | error short-circuit in macros | MED | **DONE (fork cleanup)** | `[1,2,3].all(e, 6/(2-e)==6) -> false` and `[0,'foo',3].all(i,v,v%2==i) -> false`. FIXED in the fork comprehension engine (`Relay fork (G15)`, `objects.rs Expr::Comprehension`, both one-var and two-var paths). cel-go error-as-value: a predicate error is HELD in the accumulator and ABSORBED by a dominant operand (`error && false == false`, `error || true == true`), else it persists and surfaces. `loop_step_absorb_op` detects the `@result && predicate` / `@result || predicate` macro shape (all/exists only; map/filter/existsOne propagate); `comprehension_step` + `absorb_predicate` model the held error and the dominance rule. `tests/test_g15_comprehension_shortcircuit.py`. |
| **G16** | namespace/container resolution | MED | **DONE (fork cleanup)** | Full CEL name resolution in the fork (`Relay fork (G16)`). (1) Container: `Context::Root` carries a container (`set_container`); `get_variable_with_container` tries candidates most-qualified to least (`a.b.c.n` .. `n`) so a qualified binding beats the bare name. (2) Comprehension variables SHADOW the namespace: `get_local_variable` (Child scopes only) is checked before the container in `Expr::Ident`, and the `Expr::Select` qualified lookup skips when the base ident is a local var (so `y.z` inside `exists(y,...)` is field selection on the local `y`). (3) Leading-dot is ABSOLUTE: the parser marks `.y` with a `.` prefix; the resolver routes it to `get_root_variable` (no container, no local), for both bare `.y` and dotted `.y.z`. The container is now forwarded end-to-end (oracle `main.go` emits it; the harness + both parity dumps forward it; the wasm `eval` request accepts a `container` field). `namespace` file -> 14/14. `tests/test_g16_namespace.py`. |

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

DONE (fork increment 3): **G5 / G7 / G8** lexer literal parsing
(signed-radix int, repeated-unary-minus parity, triple-quote delimiter
stripping, the CEL escape set). `vendor/cel/src/parser/parse.rs` rewritten as a
faithful port of cel-go `parser/unescape.go`; `parser.rs` `visit_Int` /
`visit_Uint` / `visit_Negate` / `visit_LogicalNot` / `visit_Bytes` aligned to
cel-go. Moved **74.4% / 86.3%** -> **80.0% raw (1055/1319) / 93.0% ex-proto
(1028/1105)**: `parse` 121 -> 193 (+72), `basic` 41 -> 43 (+2), net **+74** with
**zero per-file regressions** (verified across all 16 files; G3/G6/conversions/
comparisons/timestamps/string all held). Closed every G5/G7/G8 corpus case:
`parse_compile_failure` 47 -> 0, `value_mismatch:bytes` 16 -> 0,
`string_value_mismatch` 12 -> 3 (the 3 residuals are G13/G14 timestamp/duration
string formatting), `value_mismatch:int` 8 -> 7 (the G5 `--------19` case
closed; the 7 residuals are G13/G14 timezone handling). `tests/test_g5_g7_g8_literals.py`
(50 cases) + `vendor/cel` `parser::parse` unit tests (9 cases).

DONE (fork increment G4): **G4** two-variable comprehension macros
(`ext.TwoVarComprehensions`: `all`/`exists`/`existsOne`/`exists_one`/
`transformList`/`transformMap`). New parser lowering
(`vendor/cel/src/parser/macros.rs`) + two-variable binding in the comprehension
engine (`vendor/cel/src/objects.rs`) + the synthetic `cel.@mapInsert` step
(`objects.rs` + `vendor/cel/src/common/types/map.rs`). Moved **80.0% / 93.0%**
-> **82.79% raw (1092/1319) / 96.38% ex-proto**: `macros2` 8 -> 45 (+37) with
**zero per-file regressions** (total passed 1055 -> 1092 = exactly the macros2
gain). The 38th `macros2` case (`[0,'foo',3].all(i,v,v%2==i)`) is G15
(error-as-value short-circuit), shared with the one-var path and out of scope.
`tests/test_g4_two_var_macros.py` (56 cases) + 101 fork unit tests.

All passes hold the keystone invariants: **0 engine panics** and byte-parity
(`diff` exit 0 across Python/Node, 1449 records).

DONE (fork cleanup -- the FIXABLE ex-proto tail): **G13** timestamp/duration
BINARY arithmetic + timezone-aware getters + the conversion tail (`bool()`,
`timestamp(int)`, UTF-8-strict `string(bytes)`, Go-style `string(duration)`),
**G16** container/comprehension-shadow/leading-dot namespace resolution,
**G15** comprehension error-as-value short-circuit, plus the
`integer_math`/`lists`/`comparisons` residuals: unary-minus type errors
(`-false`, `-(i64::MIN)`), integral-double list indices, and cross-numeric MAP
equality. Moved **82.79% raw / 96.38% ex-proto** -> **85.82% raw (1132/1319) /
100.0% ex-proto (1105/1105)**: `conversions` -> 109/109, `timestamps` -> 76/76,
`namespace` -> 14/14, `integer_math` -> 64/64, `lists` -> 39/39, `comparisons`
ex-proto residual closed, `macros`/`macros2` -> the last 2 closed. Byte-parity
held (1449); 101 fork unit tests + 361 wrapper tests green.

## Honest residual breakdown (RAW failures that remain -- all OUT OF SCOPE)

After the fork cleanup, **every ex-proto case passes (100.0%, 1105/1105)**. The
187 remaining RAW failures are structurally out of scope for a runtime CEL
evaluator and are NOT bugs:

1. **Proto-message construction / field access (179 cases:** `comparisons` 72,
   `dynamic` 98, `parse` 9). `Foo{...}` / `google.protobuf.X{...}` /
   `TestAllTypes{}.field` are fenced to a clean `RELAY-CEL-002`
   (PROFILE-STRUCT-DISABLED, the G1 keystone). The Relay CEL profile EXCLUDES
   proto messages, so producing a value is not the goal -- no-panic is, and that
   holds (0 engine panics). These are excluded from the ex-proto number by the
   harness `is_proto` classifier.
2. **`type_deduction` checker-deduced types (8 cases).** 6 are proto field
   access (fenced as above). 2 (`null_assignable_to_{duration,timestamp}_parameter_candidate`,
   `[msg.single_duration, null][0]`) assert a type DEDUCED BY THE CHECKER from
   an unbound proto-message variable -- a runtime evaluator cannot produce a
   checker's type judgement, so these are unmeasurable (the `msg` reference is
   also a proto message, fenced/undeclared at runtime).

The ex-proto figure (100.0%) is the achievable runtime-conformance ceiling for
the Relay CEL profile. The proto-message gap is a profile decision, not a defect.

## WS3 reproducible build + CI gate (DONE + VERIFIED)

A wasm that produces audit-grade Relay evidence must be byte-reproducible (a
signature could not be reproduced offline from a non-deterministic build).

- **Byte-deterministic.** Two clean builds via the recipe -> identical sha256
  `ba1cb86851e88aeb9d2970b07fcea399134043fa329e7f3ab32cb69ed9fcdedd`
  (`make repro`). Profile: `opt-level="z"`, `lto`, `codegen-units=1`,
  `panic="abort"`, `strip="symbols"` (crate/Cargo.toml).
- **Cross-machine path-independent.** The raw build embeds ~123 absolute
  `$HOME/.cargo` dependency panic-location paths, so a different machine would
  hash differently. Fixed by `--remap-path-prefix` in the build RECIPE
  (`conformance/build.sh` `det_rustflags`: CARGO_HOME->/cargo, repo-root->/build,
  sysroot->/rust) -- verified 123 -> 0 embedded paths. NOTE: the in-manifest
  `trim-paths` is NOT usable here -- it is a hard PARSE ERROR on cargo 1.93.1
  ("feature `trim-paths` is required ... not stabilized"), so it must stay out of
  Cargo.toml until the toolchain ships it stable.
- **Pinned toolchain.** `crate/rust-toolchain.toml` pins rustc 1.93.1 + wasm32
  (codegen determinism across machines). Deps pinned via the vendored Cargo.lock.
  Remaining for full hermeticity: a pinned CI container image.
- **Size.** raw 2.55M, gzip 660KB (63% of the Cloudflare Workers 1MB compressed
  budget), brotli 428KB -- UNDER budget, so the chrono-tz growth did not break
  the edge deploy. `make dist` (wasm-opt -Oz) is an OPTIONAL headroom widener.
- **CI gate.** `.github/workflows/cel-wasm-conformance.yml` -- a `conformance-gate`
  job (build + cel-go v0.28.1 oracle over cel-spec@f91dffca + ex-proto-100% floor
  + byte-parity) and a `reproducible-build` job (cmp-rebuild), aggregated into one
  required check. `make gate` is the local equivalent.

NOT in WS3: the **signed** half (sign + transparency-log the reproducible
artifact) lives in `relay-platform`/KMS -- trust-anchor key material is banned
from the public repo (CLAUDE.md #14). Deferred to that work-stream. The
production cutover (embed into `packages/contracts`, replace cel-python +
@bufbuild/cel) is WS4/WS5 and needs explicit go-ahead (keystone invariant #16).

## WS4 cutover step 1: Relay UDFs in the wasm (DONE + VERIFIED)

The 3 contract-DSL UDFs are ported from
`packages/contracts/src/relay_contracts/udfs/{coverage,tool_arg,schema_match}.py`
into `crate/src/lib.rs` as native Rust, registered under the dotted CEL name
(`relay.coverage` / `relay.tool_arg` / `relay.schema_match`) and reached via the
fork's qualified-name function resolution (`objects.rs` `Expr::Call` `Some(target)`
arm: `relay.<fn>(...)` -> `ctx.get_function("relay.<fn>")`). They are pure,
deterministic, and TOTAL (a shape mismatch yields false/null, never an error), so
the single wasm implementation is byte-identical across the Python and TS hosts BY
CONSTRUCTION -- retiring the per-runtime UDF parity grind.

- Authored against the DOCUMENTED, intended contract + VAL-PARITY-002 (an integral
  CEL double is an "integer"; booleans are NOT integers/numbers). The wasm is the
  single source of truth.
- **Discovered pre-existing bug:** cel-python driven THROUGH CEL violates that
  contract -- `celpy.MapType.get` RAISES `KeyError` on a missing key (so
  `relay.schema_match(x, {"required":[...]})` raises), and `celpy.BoolType`/
  `DoubleType` break the `isinstance` type screens (so `schema_match(true,
  {"type":"integer"})` wrongly returns True and `schema_match(1.0,
  {"type":"integer"})` raises TypeError). The wasm, operating on typed `cel::Value`,
  is CORRECT. The cutover REPLACES the broken behavior; the parity golden for the
  new CEL-eval UDF cases must come from the intended contract / direct-callable
  path, NOT cel-python-through-CEL.
- Verified: 55 new UDF tests (`tests/test_relay_udfs.py`), 416 wasm tests total;
  ex-proto conformance still 100.0%; cel-spec byte-parity diff exit 0; an
  adversarial cross-host UDF byte-parity sweep (17 exprs incl. every `tool_arg`
  typed-return path) diff exit 0 Py-wasmtime vs Node; `make repro` ->
  `7436ec8a300879ce84c080760ec65283e066e2be77a15867bc7b3ef56aaba111`; ascii-lint
  PASS.

## WS4 cutover step 2: profile call-fence + structured subtype (DONE + VERIFIED)

The wasm registers `dyn()`/`timestamp()`/`duration()` as working builtins for the
cel-spec conformance corpus, but the Relay PROFILE forbids those CALL forms (the
host rejects them at compile). Moved that fence INTO the wasm
(`find_profile_rejection`), FLAG-GATED on a `relay_profile` request field:

- **Flag off (default, conformance mode):** dyn/ts/dur calls evaluate -> ex-proto
  stays 100%. The cel-spec harness omits the flag.
- **Flag on (Relay host):** the GLOBAL call forms are rejected with `RELAY-CEL-002`
  + the matching subtype (`RELAY-CEL-PROFILE-{DYN,TS,DUR}-DISABLED`), mirroring the
  host's bare-call `_check_profile`. Py and TS reject the IDENTICAL set by
  construction (the loaders thread the same flag). Only the global call form is
  fenced -- timestamp/duration VALUE bindings stay valid under the profile.
- The **struct/Unspecified safety fence is ALWAYS on** (cel 0.13 panics on those),
  now carrying the `RELAY-CEL-PROFILE-STRUCT-DISABLED` subtype.
- The error envelope gained a structured **`subtype`** field (emitted only for
  profile rejections) so the host maps `(code, subtype)` -> the typed
  RelayCelError without parsing the message string.

Verified: 10 new fence tests + 426 wasm tests; ex-proto still 100.0% (flag off);
cel-spec byte-parity exit 0; an adversarial cross-host fence+subtype byte-parity
sweep (flag on) diff exit 0 Py vs Node; `make repro` ->
`1abfe06a027546f3a61365e104531d39a2a4086640e4307022ccea5322c10502`; ascii-lint PASS.

Remaining cutover steps: the per-eval `udf_trace` forensic-capture field (deferred
into step 4 where the host consumes it); step 3 add UDF-via-CEL corpus cases
(golden from the INTENDED contract, NOT cel-python-through-CEL which is broken);
steps 4-5 wire the Python + TS hosts behind `RELAY_CEL_ENGINE` (default celpy);
step 6 flip default; step 7 drop cel-python/cel-js. Steps 4+ touch production + a
public-API decision (caller-supplied extra UDFs) -- they need the open-question
answers first.

## WS-J edge timeout: the platform-CPU-only gap is CLOSED (DONE + VERIFIED)

**Status: CLOSED.** WS-C shipped the Node host's wall-clock timeout as a
`node:worker_threads` Worker hard-kill (`Worker.terminate()`): a hung or
budget-exceeding evaluation is aborted by terminating the Worker that owns the
wasm instance. That primitive does NOT exist on Cloudflare Workers (no
`worker_threads`, no `Worker.terminate`), so WS-C documented an honest residual
gap: the **Cloudflare-Workers-shaped edge path's timeout was the platform CPU
limit ONLY -- a documented gap until WS-J**. A platform CPU limit is host-defined,
not portable, and not byte-identical across hosts, so an edge evaluation could
not produce the SAME structured timeout an audited Relay bundle requires.

WS-J **closes** that gap with an **in-engine DETERMINISTIC FUEL BUDGET** rather
than a wall clock. The vendored cel fork (`vendor/cel/src/lib.rs`,
`vendor/cel/src/objects.rs`, marked `Relay fork (WS-J)`) charges one unit of a
per-evaluation step budget per evaluated AST node / comprehension iteration; the
wasm wrapper (`crate/src/lib.rs`) accepts an optional `fuel_budget` request field
and, when a POSITIVE budget is exhausted, returns the structured envelope
`{ok:false, code:"RELAY-CEL-003", subtype:"RELAY-CEL-TIMEOUT-001"}` instead of
running unbounded. Key properties that make this the portable edge timeout:

- **No new wasm import.** The fuel counter is an engine-internal in-wasm
  thread-local; the reactor still instantiates with an EMPTY import object (no
  host clock, no `Date.now`, no host callback). A Cloudflare-Workers-shaped path
  (no `worker_threads`, no `Worker.terminate`) therefore gets a structured
  timeout PURELY from the in-wasm counter -- it does not need any host-kill
  primitive the edge runtime lacks.
- **Same (code, subtype) envelope as WS-C.** The fuel-exhaustion timeout maps to
  the EXACT (`RELAY-CEL-003`, `RELAY-CEL-TIMEOUT-001`) pair the Node
  worker-thread wall-clock kill surfaces via `RelayCelTimeoutError`. No new
  `RELAY-CEL-NNN` timeout code, no divergent subtype: the edge fuel path and the
  Node worker-thread path are INDISTINGUISHABLE downstream
  (VAL-CWC-P7EDGE-007).
- **Byte-identical across Python + Node.** Because the budget and the exhaustion
  envelope live INSIDE the single wasm, the Python (wasmtime) host and the Node
  host loading the SAME `.wasm` produce a byte-identical fuel-exhaustion envelope
  -- byte-parity BY CONSTRUCTION, asserted by the cross-host parity gate
  (`tests/conformance/cel/test_fuel_exhaustion_cross_host_envelope_parity.py`,
  VAL-CWC-P7EDGE-004).
- **Fuel-off is byte-identical to the pre-WS-J engine.** An ABSENT / 0 / negative
  budget is the disabled sentinel: the request JSON is byte-identical to the
  no-fuel form and every cel-spec conformance record and every fuel-off eval
  stays byte-for-byte equal to the pre-WS-J engine (VAL-002). The fuel budget
  adds NO conformance regression: ex-proto stays 100.0% and the reproducible
  build hash is unchanged-by-recipe (`make repro` -> the pinned
  `49a6a6a2d3b3fcd50479dfae68ea6eace70a40cc30aa574e6584045c261b7c08`).
- **Loaders thread the budget identically + fail closed.** Both the TS/edge
  loader (`typescript/relay-cel-wasm.mjs`, `fuelBudget`/`fuel_budget` option) and
  the Python loader (`python/relay_cel_wasm.py`, `fuel_budget=`) add the field to
  the wasm request ONLY when it is a positive in-range integer, and FAIL CLOSED
  (raise/throw) on a positive value outside u64 / non-safe-integer rather than
  letting a "large finite" budget silently become the unbounded sentinel.

The TS `WasmCelBackend` (`packages/contracts-typescript/src/wasm-evaluator.ts`)
is the NODE worker-thread surface and KEEPS its `Worker.terminate()` wall-clock
hard-kill; its non-Node branch fails loud (it does not itself thread fuel). The
portable edge timeout for a Cloudflare-Workers-shaped caller is the loader's
`fuelBudget` option, wired straight to the in-wasm counter above. The decode of
the fuel envelope onto `RelayCelTimeoutError` lives at
`wasm-evaluator.ts` `decodeWasmEnvelope` (`code 003 -> RelayCelTimeoutError`).

Verified (WS-J acceptance commands, the cel-wasm CI workflow runs the first
two): `make -C packages/cel-wasm gate` exit 0 (ex-proto 100.0% + cross-host
byte-parity); `make -C packages/cel-wasm repro` exit 0 (byte-deterministic ==
pinned `49a6a6a2...`, 0 embedded machine paths); `make -C packages/cel-wasm
ascii-lint` exit 0. The WS-J Python loader fuel-timeout test
(`tests/test_wsj_fuel_timeout.py`), the TS edge-fuel-timeout vitest, and the
fuel-exhaustion cross-host envelope-parity plumbing test all green. The cel-wasm
CI workflow (`.github/workflows/cel-wasm-conformance.yml`) runs the
`conformance-gate` (`make gate`) and `reproducible-build` (`make repro`) jobs as
release-blocking required checks, plus the WS-J fuel-exhaustion cross-host parity
plumbing step in the discipline gate. NO new wasm import, NO trust-anchor key
material.

## Post-cutover audit remediation (DONE + VERIFIED)

A structural review + adversarial audit of the full cutover diff surfaced two
real crate-level correctness defects (plus three host-level fixes). Both crate
fixes rebuilt the wasm; the pinned sha moved
`431d966b... -> 49a6a6a2...` (re-vendored to both package-data copies, re-pinned
at every site, `make repro` byte-deterministic, `make gate` ex-proto 100.0% +
cross-host byte-parity 1449 records, verify-self `cel-engine-single-wasm` green).

- **crate-1 (P1): negative sub-second duration dropped its sign.**
  `value_to_typed`'s `Value::Duration` arm built `secs` from `num_seconds()`
  (truncates toward zero) and emitted `nanos.abs()`, so a duration in the open
  interval `(-1s, 0s)` (e.g. `timestamp - timestamp` yielding `-0.5s`) serialized
  as `"0.500000000"` -- a POSITIVE half-second. The deserializer
  `split_secs_nanos` had the mirror bug (it negated nanos only when `secs < 0`,
  but `"-0"` parses to `0`), so a `"-0.5"` BINDING decoded as `+0.5s`. Both now
  carry the sign from the whole value (serializer derives it from total
  nanoseconds like `format_duration_go`; deserializer keys on a leading `'-'`).
  Byte-identical for every duration OUTSIDE `(-1s, 0s)`, so conformance + the
  corpus golden are unchanged. `tests/test_g13_temporal_arith.py`.
- **vendor-1 (P1): `timestamp +/- duration` could TRAP the wasm.**
  `Timestamp::checked_add_duration` / `Subtractor::sub` used chrono's PANICKING
  `+`/`-` operators; a host duration BINDING with a chrono-representation-
  overflowing magnitude (~285M years -- the `duration()` builtin caps at ~292y
  but a typed binding does not) panicked -> `RELAY-CEL-PANIC` instead of the
  clean `RELAY-CEL-004` Overflow. Both legs now use `checked_add_signed` /
  `checked_sub_signed`, mapping a chrono `None` to the same Overflow as the
  cel-spec MIN/MAX range check. `tests/test_g13_temporal_arith.py`.
- **loaders-1 (P2): TS fuel loader failed OPEN on a non-number budget.** The
  `.mjs` loader's `typeof fuel === "number"` guard SILENTLY DROPPED a non-number
  truthy `fuelBudget` (a string / object / bool), leaving the eval UNBOUNDED -- a
  fail-OPEN divergence from the Python loader's `type(fuel_budget) is not int ->
  raise`. It now rejects any defined non-integer with a RangeError.
  `conformance/harness/wsj_edge_fuel_timeout.test.mjs`.
- **loaders-2 (P2) + ts-host-1 (doc):** the `.mjs` loader now omits an empty
  `bindings` object (request shape byte-identical to the Python loader); a stale
  `wasm-evaluator.ts` header comment ("`evaluator.ts`") corrected to
  `host-guards.ts`.
- **crate-2 (P2, second-pass audit): duration BINDING deserializer could TRAP
  the wasm.** The fix for vendor-1 hardened the timestamp-ARITHMETIC path but
  left `typed_to_value`'s `"duration"` arm reconstructing a binding via chrono's
  PANICKING `Duration::seconds(secs) + Duration::nanoseconds(nanos)`;
  `split_secs_nanos` does no range check, so a boundary wire string beyond the
  representable `TimeDelta` range (e.g. `"9223372036854775.900000000"`) panicked
  -> `RELAY-CEL-PANIC` -- contradicting the no-panic contract the arithmetic path
  holds. Not reachable through a shipped evaluator (a `datetime.timedelta` caps
  ~107x below the boundary and the TS encoder emits no duration wire), but a real
  unchecked panicking path. Now a CHECKED builder (`try_seconds` + `checked_add`)
  returns the clean `RELAY-CEL-006` bad-binding error the bindings loop already
  maps a `typed_to_value` Err to; the exact `TimeDelta::MAX` boundary still
  round-trips. `tests/test_g13_temporal_arith.py`.
- **crate-3 (P2/MED, roborev): `string(duration)` SATURATED a huge binding.**
  `format_duration_go` (the `string(d)` conversion) -- the sibling of the
  `value_to_typed` serializer crate-1 fixed -- STILL derived its seconds from
  `num_nanoseconds().unwrap_or_else(saturating_mul)`, so `string(d)` on a huge
  accepted duration binding (9e15 s) silently saturated to ~292 years
  (`"9223372036.854775807s"`) instead of `"9000000000000000s"`. (It had even been
  cited as the "already-correct sibling" during crate-1 -- it was not.) Now
  derives the second count from `num_seconds()` + the sub-second remainder +
  whole-value sign, matching `value_to_typed`; byte-identical for every in-range
  duration (the cel-spec corpus stays well inside i64 nanos, so ex-proto + parity
  are unchanged). `tests/test_g13_temporal_arith.py`.
