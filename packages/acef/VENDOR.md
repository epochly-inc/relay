# Vendor pin: ACEF v0.3 reference SDK

This document records the governance surface for the ACEF reference SDK
vendor pin under `upstream/`. It is consumed by the W11.1 vendor-drift
guard tests (VAL-W11-001..008) and by reviewers approving a vendor bump.

## Pin metadata

The authoritative pin metadata lives in `vendor_manifest.json`. This
file paraphrases that manifest for human readers; the manifest is the
machine-readable source of truth and the drift guard reads it directly.

| Field | Value |
|-------|-------|
| Upstream repository | `https://github.com/chandlercvaughn/ACEF` |
| Upstream commit SHA | `57e1d14e063d3a2a88bfe5361fd81ca02bc6d540` |
| Upstream license | Apache 2.0 |
| Upstream stated maturity | `v0.3 pre-1.0 reference implementation` |
| Vendored on | See `vendor_manifest.json#vendored_on` |

## What we vendor and why

We vendor the ACEF v0.3 reference SDK at a pinned commit so that:

1. The bundle wire format Relay emits (`bundle.schema_version == "v0.3"`)
   is reproducible offline by anyone with this repository checked out --
   no network fetch is required to verify a bundle's structural shape.
2. AI Act readiness evidence Relay produces under `bundle.namespaces`
   binds to a known, content-addressed upstream tree; the evidence
   coverage of a run can be reconstructed from the pinned tree without
   a moving upstream dependency.
3. The vendor-drift guard (VAL-W11-004) detects any local mutation of
   `upstream/` that did not go through the documented bump workflow.

## What we do NOT vendor

- Trust-anchor key material (signing private keys, KMS references, TSA
  partner credentials, transparency-log custody keys). Per CLAUDE.md
  banned-pattern #14 these never live in either repository.
- Hosted-only adapters or commercial connectors. Those live in
  `relay-platform/` and consume this package via pinned versions.
- Local Relay extensions. Patches Relay applies on top of the vendored
  tree are catalogued in `RELAY-LOCAL-CHANGES.md` and live under
  `src/relay_acef/` and `relay_extensions/`, never inside `upstream/`.

## Update workflow

The vendored tree under `upstream/` is immutable outside the documented
bump workflow. See the `## Vendor update workflow` section of
`README.md` for the eight-step procedure. A PR that touches `upstream/`
without also touching `vendor_manifest.json` and the
`VENDOR_COMMIT_SHA` constant in `src/relay_acef/__init__.py` is rejected
by the drift-guard test.

## Boundary with `relay-platform`

`relay-platform/` consumes this vendor pin only through pinned package
versions or signed release manifests. `relay-platform/` does not fork
or mutate `upstream/`; if an extension is needed, it is added under
`packages/acef/relay_extensions/` in this public package and made
available to both consumers via the package surface.
