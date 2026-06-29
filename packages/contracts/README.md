# epochly-relay-contracts

Relay contract DSL evaluator -- Python side. Houses the `cel-python` wrapper
configured with the Relay CEL profile, the pure-only UDF registry, the
RFC 8785 JCS canonicalizer, and the structured error envelope shared with
the cel-js mirror that ships in W6.2.

Spec anchors: D, AM.6.
Eng plan anchors: CQ1 (single-source CEL evaluator per language;
dyn/timestamp/duration disabled; RE2-only regex; wall-clock
timeout-bounded), X4 (UDFs MUST be registered with pure=True).
CLAUDE.md anchors: keystone invariant 6, banned pattern #16.

Public surface (W6.1):

- `RelayCelEvaluator` -- the cel-python wrapper bound to the Relay profile.
- `register_udf(name, fn, *, pure: bool, ...)` -- raises
  `RelayUdfPurityError` at registration time if `pure=False`.
- `jcs_canonicalize(value)` -- RFC 8785 JCS bytes.
- `RelayCelError` and its subclasses -- the structured error envelope
  carrying canonical `RELAY-CEL-NNN` codes plus stable subtype tokens.

ASCII-only per CLAUDE.md "ASCII-Safe Source".

## M3 P3CORPUS additions (WS-G)

M3 shipped the wasm artifact and its loader as package data inside this wheel,
enabling a fresh `pip install relay-contracts` to construct the wasm engine
without the repo's `crate/target/` build tree.

### Wasm package data resolution

`wasm_artifact.py` is the single source of truth for:

- `WASM_PACKAGE_DATA_RELPATH` -- data path of the vendored wasm relative to
  the `relay_contracts` package root (`_wasm/relay_cel_wasm.wasm`). Resolved
  via `importlib.resources.files('relay_contracts')`.
- `WASM_LOADER_PACKAGE_DATA_RELPATH` -- data path of the vendored loader
  module (`_wasm/relay_cel_wasm.py`). Vendored as a git-tracked byte-identical
  copy of `packages/cel-wasm/python/relay_cel_wasm.py`; a drift guard in
  `tests/test_wasm_loader_package_data.py` fails CI on divergence.
- `WASM_PINNED_SHA256` -- the exact sha256 of the `build.sh repro`-verified
  artifact. A guard test fails CI if the on-disk package-data wasm diverges.
- `resolve_packaged_wasm_path()` / `resolve_packaged_wasm_loader_path()` --
  resolve to concrete `pathlib.Path` objects; return `None` (never raise) when
  the resource is absent, so callers map a missing artifact to a structured
  `RelayCelEngineError` (RELAY-CEL-009), never a bare `FileNotFoundError`.

### Load order (wasm engine construction)

`wasm_backed_evaluator._load_relay_cel_class()` tries three paths in order:

1. Top-level `relay_cel_wasm` import (developer or downstream with the loose
   loader on `sys.path`).
2. In-repo `packages/cel-wasm/python/relay_cel_wasm.py` by file path (the
   development tree).
3. The WS-G package-data loader at `_wasm/relay_cel_wasm.py` (wheel-only
   installs; resolved via `importlib.resources`).

If all three fail, a structured `RelayCelEngineError` (RELAY-CEL-009 /
RELAY-CEL-ENGINE-REQUEST) is raised -- never a bare `ImportError`.

### Manifest commands

Declared in `.ops/manifest.yaml` (schema-valid, `egress_default: deny`):

- `check-wasm-pinned-sha` -- run `packages/contracts/tests/test_wasm_package_data.py`
  to verify the vendored wasm sha256 matches `WASM_PINNED_SHA256`.

## CEL engine default: wasm (M5 bake window)

This section is the canonical bake/rollback procedure for the M5 engine
flip. The TypeScript mirror (`packages/contracts-typescript/README.md`)
and the docs site (CEL primer, `docs/contracts/cel-primer.md`) summarize
it and point here.

As of milestone M5 the default CEL engine is the single reproducible wasm
engine (`relay_cel_wasm.wasm`) on BOTH hosts:

- Python: `make_cel_evaluator()` (the `relay_contracts.engine` factory)
  constructs `WasmCelEvaluator` when `RELAY_CEL_ENGINE` is unset or blank.
- TypeScript: `makeCelEvaluator()` (the `@epochly/relay-contracts`
  factory) constructs the wasm backend when no `engine` option is passed.

The default was flipped at M5 only after the M1-M4 dual-run parity gates
showed zero divergence on the contract workload:

- celpy-vs-wasm host parity (Python dual-run), and
- Py-wasm-vs-Node-wasm cross-host parity (identical verdicts and
  identical JCS bytes).

### Rollback (one-release bake window only)

The legacy engines stay selectable for exactly ONE release (the M5 bake
window) as a rollback escape hatch. They are removed at M6 (cel-python
and cel-js removal); after M6 these switches no longer exist.

- Python: set `RELAY_CEL_ENGINE=celpy` in the process environment. The
  variable is read ONLY by the `relay_contracts.engine` factory (the
  single env read site); no other module consults it.
- TypeScript: pass the engine token explicitly --
  `makeCelEvaluator({ engine: "celjs" })` (the spelling `"cel-js"` is
  also accepted). This is a config parameter, NOT an environment
  variable: the TS factory deliberately has NO env read so engine
  selection stays deterministic.

Rollback procedure:

1. Set the switch for the affected host (the env var for Python, the
   `engine` option for TypeScript) in the deployment that hit the wasm
   regression.
2. Verify the install is still healthy: `uv run rly verify-self --json`
   must still exit 0. The `cel-engine-single-wasm` invariant check probes
   the PACKAGED wasm artifact directly (UDF verdict probes, fenced
   `dyn()`, pinned-sha match, fail-closed load) regardless of which
   engine the factory currently selects, so verify-self keeps validating
   the wasm engine even while a rollback is active.
3. Report the rollback. Any use of the escape hatch signals a wasm
   engine regression that must be diagnosed and fixed before M6, because
   M6 removes the legacy engines and with them this rollback path.
