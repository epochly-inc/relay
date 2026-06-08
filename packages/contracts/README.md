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
