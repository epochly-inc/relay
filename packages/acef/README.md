# epochly-relay-acef

Relay ACEF vendor pin (Apache 2.0).

## Status

**v0.3 pre-1.0 reference implementation.** The upstream project explicitly
declares v0.3 stability at the vendored pin. This is the exact maturity
phrase Relay records in `vendor_manifest.json` and consumes from the
`relay_acef.VENDOR_MATURITY` constant; it must be reproduced verbatim
because Relay's operating contract binds to the upstream's stated
maturity (VAL-W11-003).

## What this package contains

This package vendors the ACEF reference SDK at a pinned upstream commit
under `upstream/`. The vendored tree is byte-equal to
https://github.com/chandlercvaughn/ACEF at commit
`57e1d14e063d3a2a88bfe5361fd81ca02bc6d540`.

| Path | Purpose |
|------|---------|
| `vendor_manifest.json` | Pin metadata: commit SHA, license, tree digest, maturity. Authoritative. |
| `upstream/` | Vendored ACEF tree at the pinned commit. Byte-equal to upstream. |
| `src/relay_acef/__init__.py` | Workspace-package surface (constants only; no runtime import of `upstream/`). |
| `tests/` | Vendor-drift guard tests (`@pytest.mark.fulfills` bound to VAL-W11-001..008). |
| `pyproject.toml` | uv workspace member declaration. |

## License

The vendored `upstream/` tree is Apache 2.0, with the original `LICENSE`
file preserved byte-for-byte at `upstream/LICENSE`. This workspace
package itself is also Apache 2.0 to match.

## Vendor update workflow

The vendored tree under `upstream/` is **immutable outside this
workflow** (VAL-W11-004). Modifications detected outside this workflow
fail the vendor-drift guard test and block the milestone.

To bump the pin:

1. `git -C /tmp clone https://github.com/chandlercvaughn/ACEF.git acef-update`
2. `cd /tmp/acef-update && git checkout <new-sha>` (must be a commit on
   `main` or a release tag).
3. `rm -rf packages/acef/upstream && mkdir -p packages/acef/upstream`
4. `git -C /tmp/acef-update archive --format=tar <new-sha> | tar -xf - -C packages/acef/upstream`
5. Recompute `vendor_tree_sha256` using the recipe documented in
   `vendor_manifest.json#tree_digest_recipe_pseudo`:
   ```python
   import hashlib
   from pathlib import Path
   root = Path("packages/acef/upstream")
   h = hashlib.sha256()
   for f in sorted(p for p in root.rglob("*") if p.is_file()):
       file_hash = hashlib.sha256(f.read_bytes()).hexdigest()
       h.update(f"{file_hash}  {f.relative_to(root).as_posix()}\n".encode("utf-8"))
   print(h.hexdigest())
   ```
6. Update `vendor_manifest.json` (`commit_sha`, `commit_date`,
   `commit_subject`, `vendor_tree_file_count`, `vendor_tree_sha256`,
   `vendored_on`).
7. Update the hardcoded `VENDOR_COMMIT_SHA` constant in
   `src/relay_acef/__init__.py`.
8. Run `uv run pytest packages/acef/tests/ -m plumbing --timeout=60 -q`
   and confirm all VAL-W11-001..008 tests pass.

A PR that touches `upstream/` without also touching `vendor_manifest.json`
and `src/relay_acef/__init__.py` is rejected by the drift-guard test.

## Boundary

The TypeScript SDK NEVER imports ACEF symbols directly. All TS-side
consumption of ACEF bundles goes through the Python sidecar's HTTP
surface (`GET /v1/evidence/{id}`). This boundary is enforced by
VAL-W11-007 (a repo grep over `packages/sdk-typescript/src/` for
ACEF-specific identifier patterns).

## What this package is for

ACEF bundles produced by Relay carry AI Act readiness evidence: per-run
control-plane bindings, replay verification outcomes, contract-gate
results, human-oversight events, and incident-monitoring records. The
bundle Merkle root binds the evidence coverage of a run into a single
content-addressed digest so an auditor can reason about gaps in the
evidence set and decide whether a run is ready for auditor review.

This package surfaces the vendor pin, the W11.2 emission validator,
and the W11.3 byte-level roundtrip helpers (`emit_bundle`,
`parse_bundle`, `roundtrip`, `bundle_digest`, `bundle_merkle_root`).
See `RELAY-LOCAL-CHANGES.md` for the catalogue of patches Relay applies
on top of the vendored upstream and `VENDOR.md` for the vendor-pin
governance surface.
