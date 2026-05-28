# @epochly/relay-sidecar-bundle

PyInstaller-built standalone Relay sidecar binaries plus a Node launcher
that verifies the download against the signed release manifest before
running it.

## What this package is

`@epochly/relay-sidecar-bundle` is the npm distribution channel for the
canonical four-arch matrix of Relay sidecar binaries built by the
`release-sidecar-bundle` GitHub Actions workflow (sub-feature w12.5;
revised 2026-05-28 to drop `macos-x86_64` per CHANGELOG v0.1.16):

  1. `macos-arm64`
  2. `linux-x86_64`
  3. `linux-arm64`
  4. `windows-x86_64`

Intel-Mac users get the `macos-arm64` binary via Rosetta, which Apple
ships on every macOS since Big Sur (11.0, 2020).

The package's `relay-sidecar-bundle` bin entry (the launcher) detects
the host OS/arch, downloads the matching binary from the published
release assets, verifies it, and exec's it as a subprocess.

## Verification ordering (load-bearing)

Per contract assertion VAL-W12-025, verification runs in this strict
order:

1. **STEP A -- digest check FIRST.** Compute the downloaded binary's
   SHA-256 and compare it against the digest recorded in the signed
   release manifest. A mismatch fails immediately with
   `RELAY-RELEASE-025-DIGEST` before any Sigstore call.
2. **STEP B -- Sigstore Rekor inclusion verification SECOND.** Verify
   the Sigstore bundle against the published OIDC identity, AND fetch
   and verify the Rekor transparency-log inclusion proof. Failure of
   either step fails with `RELAY-RELEASE-025-SIGSTORE`.
3. **Launch only after both pass.** Never run an unverified binary.

The ordering is load-bearing for three reasons:

  * It bounds the failure mode (a cheap local check runs before any
    network round-trip).
  * The failure error code is diagnostic (digest vs signature) so the
    operator knows which step diverged.
  * It prevents a confused-deputy scenario where Sigstore validates a
    binary whose digest does not match the manifest.

## Usage

```bash
npx @epochly/relay-sidecar-bundle
```

The launcher prints structured status to stderr for both steps and
exits with one of:

  * `0`  -- verification passed; sidecar exited cleanly.
  * `non-zero` -- the sidecar subprocess exit code on launch failure.
  * `1` with `RELAY-RELEASE-025-DIGEST` -- digest check failed.
  * `1` with `RELAY-RELEASE-025-SIGSTORE` -- Sigstore/Rekor check failed.
  * `64` -- usage error (e.g., unsupported OS/arch).

## Trust anchor

The launcher fetches Sigstore verification material from the trust
anchor at `https://relay.epochly.com/.well-known/jwks.json` (CLAUDE.md
keystone invariant #11). Forks and self-hosted deployments can
override via `--trust-anchor <url>` on the `rly verify-install`
companion command.

## License

Apache 2.0. The bundled binaries are built from the OSS sidecar source
under `apps/local-sidecar/` in this repository.
