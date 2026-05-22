# Trust Anchor

## What it is

A *trust anchor* is the JWKS document containing the public keys an offline
verifier uses to check the signatures on a Relay evidence bundle. Every
Relay-signed bundle carries a `trust_anchor` field naming the JWKS that
produced its signature (per spec section AO.4 line 6166). The verifier
surfaces that value in its output so a downstream consumer can see which
root of trust the bundle was signed under, and the OSS verifier resolves a
matching JWKS at verification time using the precedence rules below.

## The default trust anchor

The OSS verifier ships a compiled-in default JWKS URL. The single canonical
occurrence of the literal lives in
`packages/verifier/src/relay_verifier/constants.py`:

```python title="packages/verifier/src/relay_verifier/constants.py"
DEFAULT_JWKS_URL: Final[str] = "https://relay.epochly.com/.well-known/jwks.json"
```

Both `DEFAULT_JWKS_URL` and the backwards-compatible alias
`DEFAULT_TRUST_ANCHOR_URL` resolve to the same string object. The CLI's
`packages/cli/src/relay_cli/commands/evidence.py` imports the alias, so the
CLI and the verifier library always agree on the default.

A source-grep guard (`VAL-W10-001`) enforces exactly one occurrence of the
literal URL across the verifier package's non-test Python sources; a guard
test at `packages/verifier/tests/guards/default_trust_anchor_lock.py`
re-asserts the constant against a frozen reference value so any mutation
trips a structured CI failure.

## Bring-your-own (BYO) trust anchor

A fork, a self-hosted Relay deployment, or an air-gapped audit team can
override the default at verification time without modifying source. The
`rly evidence verify` subcommand exposes a `--trust-anchor` flag for this
purpose:

```text
$ rly evidence verify --help
Usage: rly evidence verify [OPTIONS] BUNDLE

Options:
  --trust-anchor TEXT  Override the spec-pinned default JWKS URL with a
                       BYO trust anchor (forks / self-hosters per spec
                       section AO.4). Emits a structured stderr WARN line
                       when used.
  --home TEXT          Override RELAY_HOME (test seam).
  --help               Show this message and exit.
```

Example invocation pinning a self-hosted JWKS:

```bash
rly evidence verify --trust-anchor https://jwks.example.internal/jwks.json bundle.jws
```

When the flag is provided, the CLI emits a structured stderr WARN line
recording `trust_anchor_overridden=true` and the provided URL, and the JSON
result contains both the resolved `trust_anchor` value and the
`trust_anchor_overridden` boolean. A BYO trust anchor may also be supplied
via a config-file entry (`trust_anchor_url = "..."`); the precedence rules
in the next section describe how the flag, the config entry, the cache,
and the default interact.

Use cases for BYO:

- **Forks.** A fork operating its own signer ships an inline JWKS or pins
  its own URL with `--trust-anchor`.
- **Self-hosted Relay.** An operator running the hosted control plane
  in-house signs bundles under their own JWKS and points verifiers at the
  internal URL.
- **Air-gapped audit.** An auditor on an isolated network downloads the
  JWKS once over an out-of-band channel, then verifies bundles against
  the cached copy with no live network.

## Discipline: changing the default is a board-level decision

Per spec section AO.4 line 6165:

> The OSS verifier supports BYO trust anchors but defaults to Relay-Inc's.
> A fork can ship the verifier configured against their own JWKS, but
> contributors to the OSS code path do not get to silently change the
> default. Changing the default is a board-level decision (per Section
> License posture honesty relicense conditions).

This is mirrored in `CLAUDE.md` banned pattern #13: changing the OSS
verifier's default trust anchor URL in a routine PR is CI-blocked because
every offline verifier in the wild — forks, self-hosted deployments, OSS
users who never registered with the hosted product — treats this URL as
the root of trust for evidence-bundle signatures. The supported escape
hatch is the `--trust-anchor` flag (or the `trust_anchor_url` config
entry) at runtime. Forks SHOULD use the flag; forks MUST NOT modify the
constant in source unless the change has been approved as a board-level
decision.

## JWKS resolution order

The OSS verifier's `resolve_jwks()` orchestration in
`packages/verifier/src/relay_verifier/jwks_loader.py` selects the JWKS
source for verification using the following precedence (the implementation
mirrors this order exactly):

1. **Offline mode.** With `offline=True` the verifier uses the bundled
   JWKS shipped inside the wheel; no cache, no network.
2. **BYO via `--trust-anchor` flag.** The flag overrides any config-file
   entry and the compiled-in default. The CLI emits a stderr WARN line
   recording the override.
3. **BYO via config-file entry.** A `trust_anchor_url = "..."` config
   entry overrides the compiled-in default but is itself overridden by
   the flag.
4. **Compiled-in default.** With neither flag nor config entry, the
   verifier resolves against `DEFAULT_JWKS_URL`
   (`https://relay.epochly.com/.well-known/jwks.json`) and attempts a
   live fetch.
5. **Cached JWKS fallback.** If the live fetch fails AND a fresh cached
   JWKS exists under `RELAY_HOME/jwks-cache/` (directory constant
   `JWKS_CACHE_DIRNAME = "jwks-cache"` in `jwks_loader.py`), the verifier
   uses the cache and emits a WARN to stderr with `cache_age_seconds`
   and `cache_staleness_threshold_seconds`.
6. **Bundled JWKS fallback.** If the live fetch fails AND no fresh cache
   exists AND the bundled JWKS is available, the verifier falls back to
   the wheel-bundled snapshot. With none of the above available, the
   verifier raises `RelayJWKSUnavailableError`; there is no silent
   fallback path.

A bundle that names a `trust_anchor` matching no source the verifier can
resolve is reported with a structured error rather than verified against
the wrong root.

## See also

- [Offline verification walkthrough](offline-verification.md) — full
  `rly evidence verify` walkthrough including cached-JWKS pinning.
- [Signing key lifecycle](signing-key-lifecycle.md) — rotation,
  revocation, and lifecycle behavior of the keys advertised in the
  JWKS document.
- [Trust anchor governance](../legal/trust-anchor-governance.md) — the
  governance posture and board-level change discipline behind the
  compiled-in default.

Spec: §AO, §AO.4
