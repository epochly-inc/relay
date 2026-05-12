# Security Policy

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately via one of:

- **Email:** `security@epochly.com`
- **GitHub Security Advisory:** [open a private advisory](https://github.com/epochly-inc/relay/security/advisories/new)
  (preferred — gives you a private channel with maintainers and a CVE
  workflow if one is appropriate)

We commit to:

| Stage | Timeline |
|---|---|
| Acknowledgement | Within 3 business days |
| Initial assessment (severity + scope) | Within 7 business days |
| Patch in progress notification | Within 14 business days |
| Coordinated disclosure window | Up to 90 days from initial report |

These timelines are baseline commitments; for actively-exploited issues
in production deployments we work faster.

## What's in scope

In scope for security reports:

- Vulnerabilities in code published from this repository (`epochly-inc/relay`).
- Vulnerabilities in published packages: `epochly-relay` on PyPI (CLI
  binary `rly`), `@epochly/relay` on npm, and the
  `@epochly/relay-sidecar-bundle` standalone binaries.
- Cryptographic issues with the Relay evidence bundle format, JCS
  canonicalization, JWS signing, Merkle tree construction, or signature
  verification.
- Replay determinism bypasses (e.g., agent code that escapes the cassette
  enforcement and reaches live network).
- Trust-anchor or signing-key handling issues.
- Issues in the local sidecar's bearer-token surface (CVE-relevant
  examples: lockfile race, port hijack, DNS rebinding, origin bypass).
- Side-effect class enforcement bypasses (e.g., an `external_irreversible`
  tool that executes during replay without the audited 2-person override).

Out of scope (please don't report these):

- Vulnerabilities in customers' own agent code being replayed by Relay —
  Relay is not a kernel-isolation sandbox and does not claim to be. See
  [docs/architecture/sandbox-threat-model.md](docs/architecture/sandbox-threat-model.md)
  for the explicit threat model.
- Theoretical attacks on cryptographic primitives Relay uses (SHA-256,
  ed25519, RFC 8785) where the attack would compromise the primitive
  industry-wide.
- Issues that require physical access to a contributor's signing key.
- Outdated dependency versions in `examples/` that are not used by Relay
  itself.

## Trust anchor governance

The Relay trust anchor — the JWKS at
`relay.epochly.com/.well-known/jwks.json`, the transparency log, and the
RFC 3161 timestamp authority partnership — is governed separately. See
[docs/legal/trust-anchor-governance.md](docs/legal/trust-anchor-governance.md)
for incident response procedures specific to trust-anchor compromise
(signing-key revocation, JWKS rotation, transparency-log witness
notification, customer communication).

## Disclosure

Once a fix has shipped:

- We publish a GitHub Security Advisory (and CVE if appropriate).
- We credit the reporter unless they prefer anonymity.
- We list the affected versions and the fixed version.
- For trust-anchor incidents specifically, we additionally publish a
  signed transparency-log entry per the trust-anchor governance doc.

Thank you for helping keep Relay safe.
