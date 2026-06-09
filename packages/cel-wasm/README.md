# relay-cel-wasm

The single Relay CEL evaluation engine, compiled to WebAssembly and embedded in
every runtime. This is the WS2 increment of the
[CEL-WASM single-engine re-architecture](../../../planning/adr/cel-wasm-single-engine-rearchitecture.md):
the proven WS1 spike turned into a real package, with the proto-message panic
fenced and the easy conformance gaps shimmed.

## What this is

Relay's keystone CEL invariant is **byte-identical Python <-> TypeScript
evaluation** (same verdict, same `RELAY-CEL-*` code, same RFC 8785 JCS bytes;
any divergence is a P0). Historically Relay enforced that by patching two
independent engines (`cel-python` and `@bufbuild/cel`) to agree -- a loop that
adversarial differential testing showed does not converge.

This package replaces both with **one engine** (the Rust `cel` crate) compiled
to a `wasm32-unknown-unknown` **reactor** module, run identically in:

- the Python backend (via `wasmtime`), and
- the TypeScript / Cloudflare-edge runtime (via `WebAssembly.instantiate`).

Cross-runtime byte-parity becomes **true by construction**: one engine, one
serializer, one wasm artifact. The conformance question shifts from "do two
engines agree?" to "is our one engine cel-spec-correct?", measured against the
official `google/cel-spec` corpus run against the actual wasm build.

It is **OSS-portable**: a developer with no Relay account can build and run the
wasm locally with nothing but a Rust toolchain (plus Go/Node/Python for the
conformance harness). No hosted services, no signing keys, no network.

## Architecture: one wasm, both runtimes

```
                     +------------------------------+
                     |  relay-cel-wasm (Rust crate) |
                     |  wraps `cel` 0.13 + Relay     |
                     |  profile fence + shims +      |
                     |  typed-canonical serializer   |
                     +---------------+--------------+
                                     |
                cargo build --release --target wasm32-unknown-unknown
                                     |
                                     v
                     +------------------------------+
                     |   relay_cel_wasm.wasm        |   <- ONE artifact
                     |   reactor: alloc/eval/dealloc|      (a signed evidence
                     +-------+--------------+-------+       dependency in WS3+)
                             |              |
              wasmtime-py    |              |   WebAssembly.instantiate
                             v              v
                    +-----------------+  +-----------------------------+
                    | python/         |  | typescript/                 |
                    | relay_cel_wasm  |  | relay-cel-wasm.mjs          |
                    | (RelayCel.eval) |  | (RelayCel.eval)             |
                    +-----------------+  +-----------------------------+
                          Python backend       Node / Cloudflare Workers
```

## The reactor ABI

The wasm is a reactor (no WASI, no `main`). Each host hand-writes thin glue
against exactly four exports, marshaling JSON over linear memory:

| Export | Signature | Contract |
|--------|-----------|----------|
| `memory` | (the module's linear memory) | shared buffer |
| `alloc` | `(size: i32) -> ptr: i32` | allocate `size` bytes |
| `eval` | `(ptr: i32, len: i32) -> packed: i64` | evaluate the UTF-8 JSON request at `[ptr, ptr+len)`; returns `(out_ptr << 32) | out_len`. The CALLER must `dealloc(out_ptr, out_len)` AND `dealloc(ptr, len)`. |
| `dealloc` | `(ptr: i32, size: i32)` | free a prior allocation |

### Request / response JSON

Request:

```json
{"expr": "<CEL expression>"}
{"expr": "<CEL expression>", "bindings": {"x": {"t": "int", "v": "5"}}}
```

Response:

```json
{"ok": true, "value": <typed-canonical-value>}
{"ok": false, "error": "<message>", "code": "RELAY-CEL-NNN"}
```

### Typed-canonical value form

The cross-host byte-parity contract. `int`/`uint`/`double` are kept distinct,
map keys are sorted, doubles use CEL canonical formatting:

| Type | Form |
|------|------|
| int | `{"t":"int","v":"<decimal>"}` |
| uint | `{"t":"uint","v":"<decimal>"}` |
| double | `{"t":"double","v":"<CEL canonical, e.g. 1e+12, inf, nan>"}` |
| string | `{"t":"string","v":"<utf8>"}` |
| bool | `{"t":"bool","v":true\|false}` |
| null | `{"t":"null"}` |
| bytes | `{"t":"bytes","v":"<lowercase hex>"}` |
| list | `{"t":"list","v":[<value>, ...]}` |
| map | `{"t":"map","v":[[<key>,<value>], ...]}` (sorted) |
| duration | `{"t":"duration","v":"<seconds.nanos>"}` |
| timestamp | `{"t":"timestamp","v":"<RFC3339, Z suffix>"}` |

## Current conformance

Measured against the `google/cel-spec` corpus (`tests/simple/testdata`,
in-scope files) run against the actual wasm build, with cel-go as the oracle:

| Scope | Pass / Measured | % | WS1 baseline |
|-------|-----------------|---|--------------|
| RAW (all in-scope measured) | 917 / 1319 | **69.5%** | 58.1% |
| EX-PROTO (proto-message cases removed) | 892 / 1105 | **80.7%** | 67.0% |

WS2 added the G1 proto-panic fence and the easy shims (G2 `dyn`, G9 double
format, G11 code-point `size()`, G12 idempotent conversions, G14 timestamp `Z`).
**Zero engine panics** remain: every proto/struct-construction input that
previously trapped the wasm now returns a clean `RELAY-CEL-002` error.

Cross-host byte-parity (the keystone) is verified: all 1449 in-scope records
produce byte-identical output under Python and Node (`diff` exit 0).

The remaining gaps are tracked in [`HARDENING.md`](./HARDENING.md); the HARD
semantic gaps (cross-numeric equality, macros2 two-variable comprehensions, the
type-value model) are deferred to a vendored fork in a later increment.

## Layout

```
packages/cel-wasm/
  crate/            Rust crate `relay-cel-wasm` (wraps cel 0.13)
    Cargo.toml      reproducible-build release profile + chrono-without-wasmbind
    src/lib.rs      reactor ABI, profile fence, shims, typed-canonical serializer
  conformance/
    oracle/         Go cel-spec textproto parser + cel-go oracle
    harness/        wasm driver, conformance comparator, byte-parity dumps
    build.sh        build wasm -> oracle -> run -> parity (FROM THE REPO)
  python/           RelayCel Python loader (future cel-python replacement)
  typescript/       RelayCel TS/edge loader (future @bufbuild/cel replacement)
  tests/            tier-1 plumbing tests (G1 fence + shims) over the wasm
  HARDENING.md      G1..G16 backlog: done / wrapper-feasible / needs-fork
  Makefile          convenience targets over build.sh + tests
```

## Build and run (no Relay account required)

Prerequisites: Rust + the `wasm32-unknown-unknown` target, Go 1.25 (oracle),
Node, and a Python env with `wasmtime`. The cel-spec corpus path defaults to
`/tmp/cel-spec-ws1/tests/simple/testdata` (override with `CEL_SPEC_CORPUS`).

```bash
# Build the wasm
cd packages/cel-wasm/crate
cargo build --release --target wasm32-unknown-unknown

# Full conformance pipeline (build + oracle + run + byte-parity)
cd ../conformance
./build.sh all

# Or via make, from packages/cel-wasm/
make conformance     # build wasm + run conformance, emit summary.json
make parity          # cross-host byte-parity (diff exit 0)
make test            # tier-1 pytest over the wasm
```

The loaders run standalone too:

```bash
python packages/cel-wasm/python/relay_cel_wasm.py
node   packages/cel-wasm/typescript/relay-cel-wasm.mjs
```

## M3 P3CORPUS: UDF-via-CEL corpus + wasm package data (WS-E + WS-G)

M3 added two work streams that complete the packaging and corpus story for
the single-engine cutover:

### WS-E: UDF-via-CEL corpus

`tests/conformance/cel/relay_udf_via_cel_corpus.json` is a NEW, SEPARATE
corpus (it does NOT read or mutate `relay_cel_corpus.json`). It drives all
three Relay UDFs (`relay.coverage`, `relay.tool_arg`, `relay.schema_match`)
THROUGH CEL (the dotted `relay.*` call form, e.g.
`relay.coverage(trace, "step1")`) and records the typed-canonical golden
the built wasm produces for each case.

Every case carries `"engines": ["wasm"]` (cel-js is structurally excluded;
only the wasm can evaluate dotted `relay.*` calls through CEL). The
`cel_js_parseable` flag records whether the case's `input_expression`
contains a map literal with two or more keys including a `"type"` key
(the known cel-js parser boundary, legacy task #20).

The cross-anchor that replaces the retired `test_w17_4_*` two-engine
comparison: for every case, the wasm-through-CEL result (typed-canonical)
MUST equal the cel-python direct-call result serialized to typed-canonical.
Any divergence aborts generation with a non-zero exit.

Generator: `scripts/generate-relay-udf-via-cel-corpus.py`
Guard tests: `tests/conformance/cel/test_udf_via_cel_corpus.py` (VAL-CWC-P3CORPUS-001..004)
             `tests/conformance/cel/test_udf_via_cel_byte_match_runner.py` (VAL-CWC-P3CORPUS-005)

Node cross-host driver: `conformance/harness/udf_via_cel_cross_host.mjs`
Proves VAL-CWC-P3CORPUS-006 (Py-wasm == Node-wasm byte-parity for every
UDF-via-CEL corpus case). Invocation:

```bash
# Requires CEL_WASM pointing at the built wasm and the @epochly/relay-contracts dist
CEL_WASM=packages/cel-wasm/crate/target/wasm32-unknown-unknown/release/relay_cel_wasm.wasm \
  node packages/cel-wasm/conformance/harness/udf_via_cel_cross_host.mjs

# Non-vacuity self-test (forces one case to diverge by one byte; driver must exit 1)
node packages/cel-wasm/conformance/harness/udf_via_cel_cross_host.mjs --self-test-mutation
```

Manifest commands (declared in `.ops/manifest.yaml`):
- `generate-relay-udf-via-cel-corpus` -- regenerate or check the corpus
- `test-udf-via-cel-corpus` -- run the tier-1 plumbing corpus guard tests
- `test-node-udf-cross-host` -- run the Node cross-host byte-parity driver

### WS-G: wasm as package data + pinned sha

The `relay_contracts` Python wheel now ships the wasm as package data at
`relay_contracts/_wasm/relay_cel_wasm.wasm` (resolved via
`importlib.resources.files('relay_contracts')`). This enables a
fresh-installed wheel to LOAD the wasm engine without the (gitignored)
`crate/target/` tree. The loader module is also vendored as package data
at `relay_contracts/_wasm/relay_cel_wasm.py` (a git-tracked byte-identical
copy of the canonical `packages/cel-wasm/python/relay_cel_wasm.py`).

`WASM_PINNED_SHA256` in `packages/contracts/src/relay_contracts/wasm_artifact.py`
records the exact sha256 of the `build.sh repro`-verified artifact
(`7d92aca8ca605a2b76c36e944648de72aec56d1130294c0f22923d64c7faa4c0`).
A guard test (`test_wasm_pinned_sha_matches_packaged_artifact_on_disk`)
fails CI if the vendored artifact drifts from the pinned sha. A separate
byte-identity drift guard fails CI if the vendored loader copy diverges
from the canonical loader source.

Manifest command (declared in `.ops/manifest.yaml`):
- `check-wasm-pinned-sha` -- verify vendored wasm sha256 == pinned constant

## M4 P4DUALRUN: dual-run de-risk gate (WS-F)

M4 added the CI engine-axis matrix and the host-integration parity test
(`tests/conformance/cel/test_dual_run_host_parity.py`, VAL-CWC-P4DUALRUN-004)
that asserts ZERO celpy-vs-wasm divergence on the cel-js-reachable flat-schema
corpus subset (195 reachable cases, 0 divergences when landed).

### Runtime-error error_code taxonomy (M4 disposition, NOT a defect)

During the M4 dual-run period the two engines classify RUNTIME ERRORS under
different error codes. For a CEL expression that errors at runtime (e.g. `1/0`):

- The cel-python host raises under its own host error code.
- The wasm engine maps the same failure to `RELAY-CEL-009`
  (`RelayCelEngineError`, WS-A engine-error taxonomy, VAL-CWC-P1HOST-007).

Both engines produce `outcome == "error"` (the same verdict). Only the
engine-specific error code inside the host exception differs. The pipeline
outcome envelope carries no engine-specific error_code field, so the
host-parity test (VAL-CWC-P4DUALRUN-004) is structurally unaffected: its
`_comparable` signature covers `outcome`, `udfs_invoked`, and
`udf_outputs_jcs` -- no engine error_code field is present or compared.

This is NOT a verdict-parity defect and does NOT gate the M5 flip.
It is ELIMINATED BY CONSTRUCTION at M6 when cel-python is removed and the
wasm engine (`RELAY-CEL-009`) is the only evaluator. Do NOT patch cel-python
to align its error code to wasm; the divergence goes away at M6.

## M5 P5FLIP: default flip to wasm + one-release bake (WS-H)

At M5 the default CEL engine flips from celpy/cel-js to wasm. The flip is
controlled by `RELAY_CEL_ENGINE` (Python) and the equivalent TS config. With the
env var unset the contracts factory returns a `WasmCelEvaluator` (Python) or
`WasmCelBackend` (TypeScript) instead of the legacy cel-python/cel-js evaluators.

### Rollback escape hatch (one-release bake window)

cel-python and cel-js are NOT removed at M5 (that is M6). To roll back to the
legacy engine during the bake window, set:

```bash
RELAY_CEL_ENGINE=celpy   # Python host: revert to cel-python evaluator
```

For the TypeScript host, set the equivalent engine-selection config to `cel-js`.
The rollback escape hatch remains available for the full one-release bake window.

### Runtime-error error_code policy at M5 (expected, not a regression)

After the M5 default flip, gate decisions for RUNTIME-ERRORING conditions (e.g.
a CEL expression that divides by zero or triggers a wasm exec fault) carry
`RELAY-CEL-009` as the error code -- the wasm engine taxonomy -- rather than the
cel-python host error code previously produced by the legacy default. This is
EXPECTED behavior for the bake, not a regression:

- The verdict (`outcome == "error"`) is unchanged.
- The signed canonical decision payload (VAL-CWC-P2TSGATE-012) is identical
  between engines for any VALID expression; the runtime-error taxonomy difference
  does not affect valid-expression signing parity.
- The error_code shift (from celpy-host-code to RELAY-CEL-009) is the defined
  M4/M5 disposition documented in `test_dual_run_host_parity.py` and here.
- The difference is eliminated BY CONSTRUCTION at M6 when cel-python is removed
  and RELAY-CEL-009 is the only error_code for engine-level faults.

If an operator observes `RELAY-CEL-009` on a condition that previously surfaced a
different celpy error code, this is the expected M5-bake behavior. It is NOT a
sign of a broken engine or a tampered artifact. Verify via `rly verify-self --json`
(the `cel_engine` invariant check covers UDF probing and sha-match).

### Backslash-escape lexer conformance at M5 (correctness IMPROVEMENT, not a regression)

There are EXACTLY TWO Relay-CEL corpus expressions where the M5 flip CHANGES the
computed result -- and the change is a CORRECTNESS IMPROVEMENT, not a regression.
Both are double-quoted CEL string literals whose content is a single backslash
followed by a non-ASCII digit that is NOT a valid CEL escape sequence:

- `regex_backslash_fullwidth_digit_accepted` -- `"\<U+FF10>"` (backslash + FULLWIDTH DIGIT ZERO)
- `regex_backslash_arabic_digit_accepted` -- `"\<U+0660>"` (backslash + ARABIC-INDIC DIGIT ZERO)

Per the CEL spec (langdef.md:115 and 318-320), a backslash that does not begin a
recognized escape sequence is a LEXICAL ERROR. The wasm (cel-rust) engine is
SPEC-CORRECT: it RAISES a compile error (`RELAY-CEL-009` /
`RELAY-CEL-ENGINE-COMPILE`, "token recognition error"). The legacy cel-python
host has a LENIENT lexer that instead returns the literal 2-character string --
NON-CONFORMANT behavior. This was user-adjudicated: wasm is correct; the corpus
golden recorded cel-python's wrong (lenient) result.

At the M5 default flip, these two expressions therefore change from cel-python's
lenient 2-character string to the spec-correct compile error. This is EXPECTED
and is an IMPROVEMENT in conformance, not a regression. If an operator authored a
contract relying on a bare backslash being silently accepted inside a string
literal, that contract was depending on non-conformant cel-python behavior and
must be corrected to use a valid CEL escape. The dual-run value-parity gate
(`tests/conformance/cel/test_dual_run_host_parity.py`) documents and carves out
exactly these two cases under a strong guard (`KNOWN_CELPY_NONCONFORMANCE`);
EVERY OTHER valid expression remains byte-for-byte identical across engines.

M6 migration note: once cel-python is removed and the wasm engine is the only
evaluator, reclassify these two corpus cases in
`tests/conformance/cel/relay_cel_corpus.json` from `eval_value` to `eval_error`
(the spec-correct compile-error form), and remove them from
`KNOWN_CELPY_NONCONFORMANCE` in the dual-run test. The corpus is NOT mutated
before M6: the legacy `test_w17_4_*` cross-runtime / release-block runners still
expect cel-python's current lenient `eval_value` behavior, so the
reclassification is M6 scope (cel-python-removal) by construction.

## Notes on the build config (load-bearing)

- `chrono` is depended on with `default-features = false` -- this drops the
  `wasmbind` feature. `wasmbind` injects `js-sys` / `wasm-bindgen` JS imports
  (`Date.now`, etc.) that BREAK the no-WASI reactor: the hosts instantiate with
  no imports, so any injected import is an unresolved-import failure. Do not
  re-enable chrono default features.
- The release profile (`codegen-units=1`, `lto`, `opt-level="z"`,
  `panic="abort"`, `strip="symbols"`) is the reproducible-build foundation;
  WS3 adds `trim-paths` / `SOURCE_DATE_EPOCH` / a pinned container and a
  byte-identical clean-rebuild CI gate, and signs the artifact.
