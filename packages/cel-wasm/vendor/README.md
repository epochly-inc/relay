# vendor/ — cel-rust-relay (vendored CEL engine fork)

`vendor/cel/` is the Relay-owned fork of the [`cel`](https://crates.io/crates/cel)
crate (cel-rust / cel-rust), vendored as source so the single CEL engine that
produces audit-grade evidence is reproducible, auditable, and modifiable in-tree.
The upstream crate README is preserved at `vendor/cel/README.md`.

| | |
|---|---|
| Upstream | https://github.com/cel-rust/cel-rust (crate `cel`) |
| Vendored version | **0.13.0** (the published crates.io release) |
| Upstream license | **MIT** (preserved in `vendor/cel/LICENSE`; compatible with the Apache-2.0 public `relay` repo) |
| Fork name | `cel-rust-relay` |

## Why a fork (not a crates.io dependency)

The Relay CEL profile requires byte-identical, CEL-spec-conformant evaluation
inside the wasm (see `../HARDENING.md` and
`planning/adr/cel-wasm-single-engine-rearchitecture.md`). Several conformance
fixes are engine-internal (the equality/ordering core, the lexer, the macro
engine, the type-value model) and cannot be done by wrapping the published crate.
They are authored ONCE here, in the fork.

We pin the **published 0.13.0** rather than upstream HEAD on purpose: HEAD
(approx `d23d0a77`) is mid-refactor (a Type-system rework) that changes
custom-function override semantics and would silently break the wrapper shims
(`size()` code-points, `int()/uint()` range checks). 0.13.0 is the verified base
the WS2 shims were built against.

## Relay modifications (diff from clean 0.13.0)

- **G6 cross-numeric equality** (`src/common/types/{int,double,uint}.rs`): the
  `Val::equals` for the numeric types delegated to a same-type-only downcast, so
  `1.0 == 1` was `false`. CEL compares numerics across int/uint/double by value.
  Fixed by delegating `equals` to the already-cross-numeric `Comparer::compare`
  (equal iff `Ordering::Equal`; a non-numeric rhs or NaN yields `false`). Mirrors
  cel-go's comparison semantics; verified against the cel-spec corpus + cel-go
  oracle. Search the files for `Relay fork (G6)`.

- **G3 type-value model** (`src/objects.rs`, `src/common/types/type_value.rs`,
  `src/common/types/mod.rs`): cel 0.13's runtime `Value` enum had no value that
  *is* a CEL type, so `type(1)` was an `UndeclaredReference` and the type
  identifiers (`int`, `uint`, ...) were unbound. Added:
  (1) `Value::Type(Arc<str>)` carrying the canonical cel-go runtime type NAME;
  (2) `CelTypeValue` -- the `dyn Val` type-value (`get_type()` is `TYPE_TYPE`,
  so the runtime type of a type value is the meta-type `type`; `equals` compares
  by name); (3) both `Value`<->`Box<dyn Val>` conversion legs for `TYPE_TYPE`;
  (4) a name-based `PartialEq` arm for `Value::Type`; (5) `Value::Type` arms in
  `type_of`/`Debug`/`ValueType`; (6) qualified-name resolution in `Expr::Select`
  (`flatten_select_to_name`) so a dotted reference like
  `google.protobuf.Timestamp` resolves to a bound type-value before field
  selection. The `type()` builtin + type-identifier bindings live in the wrapper
  (`crate/src/lib.rs`). Verified against the cel-spec corpus + cel-go oracle
  (33 type/denotation cases, zero non-G3 regressions, byte-parity held). Search
  the files for `Relay fork (G3)`.

Policy: keep Relay modifications minimal, clearly marked (`Relay fork (Gn)`
comments), and upstreamed where the fix is not Relay-opinionated.
