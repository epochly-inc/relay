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

Policy: keep Relay modifications minimal, clearly marked (`Relay fork (Gn)`
comments), and upstreamed where the fix is not Relay-opinionated.
