# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Versioning note

Pre-v0.1.0 tags (`v3-mN-sealed`, `v0.3-*`, `v0.2-*`, `scaffold-base`)
correspond to internal operation milestones from the spec-conformance
audit-resolution workstreams. They are preserved here for traceability.
SemVer-tagged releases begin at v0.1.0.

The tag `v0.3-audit-resolution-complete` points at the same commit as
`v3-m5-sealed`; both are listed below at the same date for completeness.

## [Unreleased]

## [v0.1.14] - 2026-05-28

Release-infrastructure patch: ships the docstring-token fix that
v0.1.13 sidecar-bundle linux + macos builds tripped over. v0.1.13's
new `force_kill_pid` helper in `apps/local-sidecar/relay_sidecar/process.py`
contained the literal tokens `pkill` and `killall` inside its
docstring's banned-pattern enumeration, and the VAL-W2-010 grep
guard in `test_zombie_port.py` scans every source file for those
tokens — so the docstring itself tripped the guard on every
platform.

v0.1.14 reshapes the docstring to convey the same constraint
("name-based kill variants are forbidden") without containing the
specific tokens the grep regex matches.

No SDK, CLI, schema, or sidecar runtime behavior changes from v0.1.13.

### Fixed
- `apps/local-sidecar/relay_sidecar/process.py::force_kill_pid`:
  rephrased the PROCESS SAFETY note to avoid the literal `pkill` /
  `killall` tokens. Readers consult CLAUDE.md for the full
  enumeration.

## [v0.1.13] - 2026-05-27

Windows-portability patch: makes the sidecar tier-1 plumbing parity
step actually run to completion on `windows-x86_64` runners. v0.1.12's
sidecar-bundle Windows build produced 66 failures + 171 errors over
20 minutes with three root causes (`os.O_CLOEXEC` missing,
`signal.SIGKILL` missing, `Path.home()` reads `USERPROFILE` not
`HOME`). v0.1.13 fixes all three at the source.

No SDK, CLI, schema, or sidecar runtime behavior changes on POSIX
(the changed code paths are gated by `getattr` fallbacks and
`sys.platform` branches; POSIX semantics are byte-for-byte unchanged).

### Fixed
- `apps/local-sidecar/relay_sidecar/primitives/local_atomic_file_write.py`
  and `local_two_layer_locked_write.py`: replaced the unguarded
  `os.O_CLOEXEC` reference with `getattr(os, "O_CLOEXEC", 0)`. The
  bitwise-OR with 0 is a no-op on Windows where `O_CLOEXEC` is not
  defined; POSIX behavior is unchanged.
- `apps/local-sidecar/relay_sidecar/process.py`: added
  `force_kill_pid(pid)`, a cross-platform hard-kill helper that
  dispatches to `os.kill(pid, signal.SIGKILL)` on POSIX and
  `TerminateProcess` via ctypes on Windows. Three crash-recovery
  test files now use this helper rather than calling
  `os.kill(pid, signal.SIGKILL)` directly (the latter crashes on
  Windows because `signal.SIGKILL` is undefined).
- `apps/local-sidecar/tests/test_lockfile_path.py::test_lockfile_path_default_relay_home`:
  monkeypatch now sets `HOME`, `USERPROFILE`, `HOMEDRIVE`, and
  `HOMEPATH` so the test redirects `Path.home()` consistently on
  both POSIX (which honors `HOME`) and Windows (which honors
  `USERPROFILE` + `HOMEDRIVE`/`HOMEPATH`).
- `.github/workflows/release-sidecar-bundle.yml`: added `psutil` to
  the tier-1 parity step's pip install. `pid_start_time_epoch_s` on
  Windows requires psutil (the POSIX `ps` and `/proc/<pid>/stat`
  fallbacks do not exist there). psutil stays a CI-only test
  dependency, so the published runtime is unchanged.

## [v0.1.12] - 2026-05-27

Release-infrastructure patch: makes the sidecar-bundle tier-1
plumbing parity step deterministic on macos-arm64 (Apple Silicon
runners). v0.1.11's sidecar-bundle build completed linux-x86_64 and
linux-arm64 successfully but failed on macos-arm64 because a
forced-contention test (`test_forced_contention_emits_observable_retries`)
raced a 0.005s sleep against the holder task's `BEGIN IMMEDIATE`
plus sentinel insert. On Apple Silicon's faster scheduler, the
holder lost the race -- the writers grabbed the (still free) WAL
write lock before the holder acquired it, observed zero
`sqlite_busy_retry` events, and the assertion failed.

v0.1.12 replaces the timing race with an `asyncio.Event` for
explicit ready-signaling, mirroring the synchronization pattern
used by sibling tests (`test_sqlite_busy_exhausted`,
`test_idle_timer_inflight`). Verified 3x consecutive PASS locally
on macOS arm64. No behavioral change to the writer-queue code under
test; only the test's synchronization primitive changed.

`@epochly/relay-sidecar-bundle@0.1.11` on npm is functional as a
package but its launcher cannot download a sidecar binary at runtime
because no binaries reached the v0.1.11 GitHub release (mac-arm64
build failed; mac-x86_64 and windows builds were cancelled). v0.1.12
ships a complete release pipeline.

No SDK, CLI, schema, or sidecar runtime behavior changes.

### Fixed
- `apps/local-sidecar/tests/test_writer_queue_concurrency.py::test_forced_contention_emits_observable_retries`:
  replaced the 0.005s sleep race with `asyncio.Event` synchronization
  so the holder task always wins the lock before the racing writers
  start. Bumped the hold duration from 100ms to 500ms so writers'
  combined first-attempt latency is comfortably covered on any
  supported runner.

## [v0.1.11] - 2026-05-27

Release-infrastructure patch: makes the sidecar-bundle tier-1
plumbing parity step actually pass. v0.1.10 fixed the SDK
workspace-dep install but the parity step still failed because the
sidecar's tier-1 tests transitively import workspace siblings
(`relay_gate_engine` from `packages/gate`, `relay_verifier` from
`packages/verifier`) that were not in the editable install list.

v0.1.11 installs ALL 12 workspace members editable in the
`release-sidecar-bundle.yml` install step so the CI environment
mirrors local dev (where `uv sync --all-packages --all-extras`
installs everything). With every workspace import resolvable, the
tier-1 plumbing parity tests pass and the binary build proceeds to
upload its artifacts to the v0.1.11 GitHub release.

`@epochly/relay-sidecar-bundle@0.1.10` on npm is functional as a
package but its launcher cannot download a sidecar binary at runtime
because no binaries reached the v0.1.10 GitHub release. v0.1.11
ships a complete release: PyPI packages, npm packages, AND the
5-platform sidecar binary set on the v0.1.11 GitHub release.

No SDK, CLI, schema, or sidecar runtime behavior changes.

### Fixed
- `release-sidecar-bundle.yml` install step: expanded the editable
  install list from 4 to all 12 workspace members so tier-1
  plumbing parity tests can import workspace siblings
  (`relay_gate_engine`, `relay_verifier`, etc.) the same way the
  local dev environment can.

## [v0.1.10] - 2026-05-27

Release-infrastructure patch: makes the sidecar-bundle binary build
actually produce binaries. v0.1.9 published 4 PyPI packages and the
2 npm packages cleanly, but the companion
`release-sidecar-bundle.yml` workflow (which PyInstaller-builds the
sidecar binary for each OS/arch and attaches them to the GitHub
release) failed on 4 of 5 platforms in its install step. Root cause:
`packages/cli` was missing from the editable-install list, so pip
queried PyPI for `epochly-relay-cli` (the SDK's transitive runtime
dep) while resolving the SDK's editable install, and failed with
"No matching distribution found" because v0.1.9 had not yet
published when the build ran.

v0.1.9 of `@epochly/relay-sidecar-bundle` on npm is functional as a
package, but its launcher cannot download its sidecar binary at
runtime because no binaries reached the v0.1.9 GitHub release. The
v0.1.10 release ships an `npx @epochly/relay-sidecar-bundle` whose
launcher CAN find its binaries on the v0.1.10 GitHub release.

No SDK, CLI, schema, or sidecar runtime behavior changes.

### Fixed
- `release-sidecar-bundle.yml` install step: added `-e packages/cli`
  to the editable install list so pip resolves the SDK's
  `epochly-relay-cli` workspace dep locally instead of querying PyPI.
  Updated the workspace-cycle comment from 3-way to 4-way with each
  package's full dep list enumerated.

## [v0.1.9] - 2026-05-27

Release-infrastructure patch: makes the PyPI release path actually
publish all 4 packages. v0.1.8's tag triggered a release workflow that
sat at its approval gate without ever publishing -- the underlying
constraint is that PyPI's pending-publisher table has a UNIQUE
constraint on `(owner, repo, workflow, environment)`, so a single
environment cannot host trusted-publisher bindings for 4 different
packages from the same workflow. v0.1.9 splits the publish flow into
three environment-scoped jobs, one per binding group:

- `publish-release`  (env `release`)         publishes `epochly-relay` + `epochly-relay-schemas`
- `publish-sidecar`  (env `release-sidecar`) publishes `epochly-relay-sidecar`
- `publish-cli`      (env `release-cli`)     publishes `epochly-relay-cli`

No SDK, CLI, schema, or sidecar behavior changes. v0.1.8 was never
published to PyPI; v0.1.9 is the first publish on the new pipeline.

### Fixed
- PyPI publish: a single `release` environment can no longer collide
  on its trusted-publisher unique constraint when more than one
  package is published from the same workflow. The release workflow
  is now split into three environment-scoped publish jobs, each
  approved independently from the GitHub UI.

### Added
- `release-sidecar` and `release-cli` GitHub environments (mirror
  the same protection rules as `release`: required reviewer
  `chandlercvaughn`, branch policy `v*` tag pattern, wait timer 0).
- Per-environment dist subdirs in the `build` job (`dist/release/`,
  `dist/release-sidecar/`, `dist/release-cli/`); SLSA provenance
  still binds to every artifact via a single base64-subjects payload
  spanning the whole `dist/` tree.

### Changed
- `scripts/check-pypi-publish-workflow.py` (VAL-W12-002): single
  `EXPECTED_ENVIRONMENT` constant replaced with an enumerated tuple;
  guard now requires every publish job to bind to one of the
  enumerated envs, and every enumerated env to be covered by
  exactly one publish job.
- `scripts/check-slsa-provenance.py` (VAL-W12-014, VAL-W12-044):
  `PYPI_PUBLISH_JOBS` expanded from `("publish",)` to the 3 new job
  names; provenance pairings list expanded from 1 to 3 PyPI rows
  (all pointing to the single shared provenance attestation).
- `docs/release/runbook.md` and `docs/release/compromised-oidc-drill.md`:
  per-environment binding table and per-environment incident-response
  steps.
- `packages/schemas/raw/error-codes.yaml` RELAY-RELEASE-002:
  description, triggers, and how-to-fix updated to enumerate the 3
  trusted-publishing environments.

## [v0.1.8] - 2026-05-27

Release-infrastructure patch: `pip install epochly-relay` is now
actually installable. Prior `epochly-relay` 0.1.0-0.1.7 publishes on
PyPI declared `epochly-relay-schemas` and `epochly-relay-sidecar` as
runtime dependencies, but neither package was published to PyPI, so
`pip install epochly-relay` failed with `ResolutionImpossible`. v0.1.8
publishes all four packages together and adds `epochly-relay-cli` as
a fourth dependency so the `rly` binary lands on first install.

No SDK or CLI behavior changes.

### Fixed
- `pip install epochly-relay` now resolves and installs four PyPI
  packages: `epochly-relay-schemas`, `epochly-relay-sidecar`,
  `epochly-relay-cli`, and the SDK itself. Previously only the SDK
  package was published; resolution failed at the first transitive
  dependency.
- `npm install @epochly/relay` now installs the `rly` binary
  (renamed from `relay`) so the documented CLI name matches the
  installed command.

### Added
- `packages/cli` (CLI binary) and `packages/schemas` (canonical
  schemas) and `apps/local-sidecar` (local sidecar daemon) are now
  built and published by `.github/workflows/release-pypi.yml`
  alongside the SDK.
- `packages/cli/src/relay_cli/__init__.py` `__version__` now reads
  the live distribution metadata at import time, so `rly --version`
  reports the installed version instead of a hardcoded 0.0.0.

## [v0.1.7] - 2026-05-27

Addresses the verified roborev findings from the v0.1.0 - v0.1.6
release cycle: one High-severity safety bug in the cross-platform
consistency gate, plus three Medium-severity hygiene issues
(SDK version reporting, npm install lifecycle scripts, stale
in-toto layout fixture).

No SDK or CLI behavior changes beyond version reporting.

### Fixed
- `scripts/check-npm-pypi-commit-consistency.py` previously exited 0
  whenever ANY mismatched PyPI run existed for the tag, treating all
  mismatches as "stale force-tag re-push artifacts". Active divergence
  (a PyPI publish on a different SHA than the in-flight npm publish)
  was silently passed. Reworked to fail when the MOST RECENT PyPI run
  is on a different commit, with a structured error message that
  guides re-trigger or rewind.
- `packages/sdk-python/relay/run.py` `SDK_VERSION` constant now reads
  the live package version via `importlib.metadata.version` instead
  of a hardcoded `"relay-python@0.0.0"`. Falls back to
  `"relay-python@0.0.0+local"` (valid SemVer + clearly local) when
  the package is not installed.
- `packages/sdk-typescript/src/run.ts` `SDK_VERSION` const reads the
  published package.json at module load time (resolved via
  `import.meta.url`) instead of a hardcoded `"relay-typescript@0.0.0"`.
  Falls back to `"relay-typescript@0.0.0+local"` on any error.
- `packages/sdk-typescript/src/bin/relay-sidecar.ts` `relay --version`
  output now reports the published package version instead of the
  hardcoded `v0.0.0`.
- `release-npm.yml` post-publish audit step now passes
  `--ignore-scripts` to `npm install`, preventing transitive
  dependency lifecycle scripts from executing in a job that holds
  `id-token: write` before signature verification completes.
- `tests/release/fixtures/release.layout` and the matching
  `build-ts-package-sidecar-bundle` link fixture updated to reference
  `packages/sdk-typescript-sidecar-bundle` (the canonical workspace
  path) instead of the obsolete pre-w12.5 stub name
  `packages/sidecar-bundle`. Brings the signed in-toto layout in
  sync with the actual emitted build command.

## [v0.1.6] - 2026-05-27

Release-infrastructure patch. The release-sidecar-bundle workflow
had been failing since the v0.1.0 bring-up for a reason unrelated
to the npm OIDC cleanup: the PyInstaller cell-build step ran
`pip install -e apps/local-sidecar` and pip went to PyPI for the
sidecar's `epochly-relay-schemas` dependency, which has its own
publish cadence and is not yet on the registry.

No SDK or CLI behavior changes.

### Fixed
- `release-sidecar-bundle.yml` "Install PyInstaller and sidecar
  deps" step now pre-installs `packages/schemas` and
  `packages/sdk-python` from local source before installing
  `apps/local-sidecar`. This lets pip satisfy the sidecar's
  `epochly-relay-schemas` and `epochly-relay` workspace
  dependencies locally instead of failing the registry lookup.

## [v0.1.5] - 2026-05-26

Release-infrastructure patch. v0.1.4 npm publishes via OIDC
succeeded for both `@epochly/relay@0.1.4` and
`@epochly/relay-sidecar-bundle@0.1.4`, but the post-publish
audit step still failed because the 60-second registry-propagation
retry window was too short for npm CDN propagation, which can
take 30-120s in practice.

No SDK or CLI behavior changes.

### Fixed
- `release-npm.yml` post-publish audit step retry loop replaced
  with a `npm view`-based propagation poll (cheaper than retried
  `npm install`) extended to 10 attempts at 30s each (~5 minutes).
  Once the version is visible to `npm view`, the install + audit
  proceeds as before. Applied to both publish-sdk and
  publish-sidecar-bundle audit blocks.

## [v0.1.4] - 2026-05-26

Release-infrastructure patch for v0.1.3. The v0.1.3 npm publishes
to both registries succeeded via OIDC trusted publishing, but the
post-publish `npm audit signatures` step failed because the
`npm install --no-save <pkg>` invocation did not write a
`package-lock.json`, and `npm audit signatures` requires a
lockfile to know what to audit.

No SDK or CLI behavior changes.

### Fixed
- `release-npm.yml` post-publish audit step now writes the
  `package-lock.json` (dropped `--no-save`) so `npm audit signatures`
  has a manifest to walk. Applied to both publish-sdk and
  publish-sidecar-bundle audit blocks.

## [v0.1.3] - 2026-05-26

Release-infrastructure patch for v0.1.2. The v0.1.2 npm publish
failed because Node 22's bundled npm CLI is 10.x; OIDC trusted
publishing requires npm CLI >= 11.5.1. The npm registry returned
HTTP 404 on the PUT (npm's idiomatic "you can't publish here"
response) even with trusted publisher bindings in place.

No SDK or CLI behavior changes.

### Fixed
- `release-npm.yml` publish-sdk and publish-sidecar-bundle jobs now
  install npm 11.5.1+ between `actions/setup-node@v4` and the publish
  step. Without this, OIDC trusted publishing falls back to
  unauthenticated PUT and the registry rejects with 404.

## [v0.1.2] - 2026-05-26

Cleanup release after the v0.1.0 / v0.1.1 first-publish bring-up. No
SDK or CLI behavior changes; the npm publish pipeline now uses OIDC
trusted publishing for both `@epochly/relay` and
`@epochly/relay-sidecar-bundle`, and the post-publish signature
audit is fixed.

### Fixed
- `release-npm.yml` `npm audit signatures` post-publish step previously
  exited 1 with "found no dependencies to audit that were installed
  from a supported registry" because the publish job has no
  node_modules. Replaced with a fresh-install-then-audit pattern that
  installs the just-published tarball from the registry (with 6x10s
  retry for CDN propagation) then audits, exercising the real signed
  install path.

### Removed
- One-shot `RELAY-BOOTSTRAP-v0.1.0` NPM_TOKEN bootstrap exemption.
  v0.1.0 / v0.1.1 needed it because npm trusted publishers can only be
  registered AFTER a package exists on the registry. With both
  `@epochly/relay` and `@epochly/relay-sidecar-bundle` now published
  and their OIDC trusted-publisher bindings configured (`epochly-inc/relay`
  / `release-npm.yml` / `release` env / `npm publish`), the bootstrap
  is removed: workflow `NODE_AUTH_TOKEN` env injections, the
  `NPM_TOKEN` GitHub environment secret, and both granular npm tokens
  are deleted. OIDC trusted publishing is now the only auth path.

## [v0.1.1] - 2026-05-26

Release-infrastructure patch for v0.1.0. PyPI `epochly-relay@0.1.0`
shipped successfully on the v0.1.0 tag; this release adds the missing
metadata required for the npm tier (`@epochly/relay@0.1.1`,
`@epochly/relay-sidecar-bundle@0.1.1`) to publish its first version.
No SDK or CLI behavior changed.

### Fixed
- npm `--provenance` registry validation: added `repository`, `homepage`,
  and `bugs` fields to both `packages/sdk-typescript/package.json` and
  `packages/sdk-typescript-sidecar-bundle/package.json`. Without these,
  npm registry rejects publish with HTTP 422 ("Error verifying sigstore
  provenance bundle: Failed to validate repository information").
- SLSA L3 generator caller: added `compile-generator: true` to all
  provenance jobs so the generator binary is built from the pinned-SHA
  source checkout instead of fetched from a release asset (the fetch
  path rejects bare SHA refs, leaving the attest step silently
  failing).
- Release workflow precheck jobs install PyYAML explicitly; static
  guards parse workflow YAML with PyYAML which is not pre-installed by
  `actions/setup-python@v5`.
- `release-in-toto.yml` build steps create `dist/` before invoking
  `npm pack --pack-destination`, and reference the canonical
  `packages/sdk-typescript-sidecar-bundle` workspace path.
- `check-npm-pypi-commit-consistency.py` tolerates stale prior PyPI
  workflow runs from tag re-pushes; only divergence between the
  in-flight commits across registries fails the gate.

## [v0.1.0] - 2026-05-26

First SemVer-tagged release of Relay OSS. Tracks the codebase at HEAD
of `main` after the `relay-docs-v1` documentation operation sealed
(49/49 contract assertions passed; see `~/.ops-runtime/relay-docs-v1-
20260522/`) and after the post-audit review pass (structural-review,
codex `xhigh`, and roborev all clean at tag time).

### Added
- Comprehensive user documentation effort (operation `relay-docs-v1`):
  landing page, install guide, first workflow walkthroughs, local Compose
  and devcontainer docs, plus generated CLI and error reference pages.
- Four-layer codebase-alignment audit script for documentation source,
  generated docs, package READMEs, and examples (m1-f01).
- Banned-copy scanner coverage extended across `docs/**/*.md`, excluding
  internal and release documentation surfaces (m1-f02).
- Re-derived W17.3 cel-spec conformance corpus reproducible from the
  pinned google/cel-spec v0.20.0 commit
  (`bfe4f8b06c29cc71b783819ef415e2e766606023`); 198 verified upstream
  vectors + 3 curated profile-rejection examples, all validated against
  upstream by `scripts/build-celspec-corpus.py`. Drop-list audit
  artifact (`dropped-candidates.json`) tracked in git so a NEW
  parity drop is a PR-visible diff.
- Secret-scan fork-PR fallback: licensed gitleaks-action runs on
  same-repo non-Dependabot PRs; a no-license CLI fallback (Docker image
  digest-pinned, config loaded from `origin/<base_ref>`) runs on fork
  PRs and Dependabot PRs.

### Fixed
- SemVer monotonicity gate now treats PyPI 404 as "no prior versions"
  so the first publish (this release) is not permanently blocked.
- Audit fallback (`scripts/docs/audit-codebase-alignment.py`) honors
  `.gitignore` semantics via `git ls-files` enumeration, matching
  `rg`'s skip-gitignored behavior; `rg` invocation gains `--hidden` for
  symmetric tracked-dotfile coverage.
- Rate-limit `429` tests use a deterministic clock-freeze monkeypatch
  (`relay_sidecar.runtime.datetime`) plus direct bucket seeding, so
  the assertion does not depend on whether N requests land in the same
  wall-clock second on a slow CI runner.

### Security
- gitleaks ruleset: PEM private-key regex now matches `ED25519` PEM
  armor (in addition to RSA / EC / DSA / OPENSSH / ENCRYPTED / PGP); the
  per-rule allowlist for the historical JWS conformance-corpus test key
  is scoped with `condition = AND` to the EXACT historical commit SHAs
  AND paths, so a new key added to those paths in a different commit is
  caught.
- Secret-scan `_FIXTURE` exemption restricted to `^tests/(.*/)?...`
  basename-anchored, so a real key cannot bypass scanning via a
  fixture-named path segment outside `tests/`.
- gitleaks Docker image pinned by sha256 manifest digest (v8.21.4); the
  fork-PR fallback config is loaded from the trusted base branch via
  `git show` so a fork PR cannot weaken the ruleset in the same change.

## [v0.3-audit-resolution-complete] - 2026-05-19

Alias of `v3-m5-sealed`. See that entry for the full set of changes.

## [v3-m5-sealed] - 2026-05-19

### Added
- §G.8 hosted default redaction policy constant exported with a YAML
  fixture (v3m5-f09).
- §G.3 `json_path` redaction matcher kind in both the Python and
  TypeScript SDKs (v3m5-f08).
- §AI right-to-left override, zero-width, and BOM character rejection
  at identifier boundaries (v3m5-f03).
- §AM.6 baseline-counts persistence file and CI gate so passing test
  counts cannot regress (v3m5-f12).
- Server-side ReDoS regex budget enforced at contract publish time;
  §AI regression locks (v3m5-f01).
- Error-code naming convention doc and a CLI JSON-injection guard test
  (v3m5-f11).
- §U guard registry index doc and corresponding test (v3m5-f13).
- §F.6 manifest-to-`tool_side_effect_policies` binding guard test
  (v3m5-f10).
- §AM.6 W13/W14/W15 milestone test inventory documented (v3m5-f15).
- §J public EU AI Act readiness stub mapped to the ACEF template
  (v3m5-f14).
- §AI YAML hardening: `safe_load` lint and a `depth=16` parse cap
  (v3m5-f05).
- TypeScript TSA verifier parity with the Python implementation
  (v3m5-f07).
- §AI UTS-39 confusables guard on `trust_anchor` and manifest URLs
  (v3m5-f04).
- §G.5 JCS BMP-only object key guard with Python + TypeScript parity
  (v3m5-f02).
- §AI cross-platform symlink-safe bundle and manifest reads (v3m5-f06).

### Fixed
- §AI CLI `json.dumps` pinned to `ensure_ascii=False` and
  `allow_nan=False` (v3m5-f11-followup).

### Changed
- Banned-copy tokens scrubbed from the milestone-test-map meta-doc
  (v3m5-f15-followup).

## [v3-m4-sealed] - 2026-05-19

### Added
- §AJ per-`hypothesis_class` quality thresholds (v3m4-f01).
- §AJ generator auto-disable, promotion threshold, and versioning
  (v3m4-f02).
- §AJ reviewer SLA aging at 14 business days (v3m4-f03).

### Changed
- State-engine writes-only guard allowlist extended to include
  `explain/sla.py` (v3m4-f03-guard).

## [v3-m3-sealed] - 2026-05-19

### Added
- §AP.5.a `reconstruct_scope_state_at` temporal query (v3m3-f03).
- §AP.5.b `scope_state_snapshots` table with a 90-day retention policy
  (v3m3-f04).
- Canonical `gate` `scope_kind` and `gate.stalled` state per spec
  section AD (v3m3-f05).
- Section W deferred `CONSTRAINT TRIGGER` for `scope_state` co-insert
  (v3m3-f06).
- `{scope_kind}.transition` event emitted per successful state
  transition (v3m3-f02).

### Fixed
- Per-project manifest scoping in handoff guards (v3m3-f01).
- `scope_state_snapshots` CHECK extended to include the `gate`
  `scope_kind` (v3m3-sr-r1-001).

## [v3-m2-sealed] - 2026-05-19

### Added
- OpenAPI route fill, coverage script, and uniqueness check (v3m2-f01).
- Five hosted-only routes published as 501 stubs tagged
  `[OUT-OF-SCOPE-PRIVATE]` (v3m2-f02).
- `Idempotency-Key` ULID grammar enforcement per spec §B.6 (v3m2-f03).
- Pagination on every list endpoint plus a coverage script (v3m2-f04).
- `--json` flag on `rly sidecar start/stop/status` (v3m2-f05).

### Changed
- TypeScript schemas regenerated after m2-f02 OpenAPI additions
  (codegen refresh).

## [v3-m1-sealed] - 2026-05-18

### Added
- §A.1 `run_result_contract_results` and `run_result_gate_decisions`
  join tables (v3m1-f01).
- VAL-V3M1-004 RunResult no-array guard test (v3m1-f02).
- §K full `EvidenceClaim` shape with seven new or restructured fields
  (v3m1-f05).
- VAL-V3M1-016 guard test for `EvidenceClaim` flat-subject deprecation
  (v3m1-f06).
- §K rules: `supersedes` CHECK, signer restriction, `evidence_refs`
  binding, and unknown-namespace rejection (v3m1-f07).

### Changed
- Renamed sidecar `audit_log_entries` to `admin_override_audit` to free
  the §V name (v3m1-f03).
- CLI PyYAML dependency lockfile refreshed (audit-r3 BUG-E7).

### Fixed
- Audit-R4 P0 schema reconciliation: dropped stranded `gate.v1` and
  `eval_run.v1` DDL pins, and aligned sidecar `actors.kind` to the
  envelope enum.
- Audit-R4 P1 redaction-budget race fix and tighter Python verifier path
  parity.
- §Y FK chain repair across all six OSS foreign-key references to
  undefined orgs/users (v3m1-f04).
- Schema drift: `failed_assertion_ids` is now `text[]`,
  `gate_rounds.initiated_by` uses the spec four-value enum, and
  migration 0017 annotated (v3m1-f08).
- Production code now uses the spec-restricted `initiated_by` enum
  (v3m1-f08-followup-sut).
- Test helpers updated to the spec four-value `initiated_by` enum
  (v3m1-f08-followup).
- Paired-row trigger restored and runtime `initiated_by` enum
  compliance enforced (v3m1-sr-r1).

## [v0.2-post-r3-fixes] - 2026-05-18

### Added
- W9-3 real Rekor Merkle inclusion proof verification (VAL-V2M09 w9-3).
- W9-2 real TSA cryptographic verification (VAL-V2M09 w9-2).
- W9-1 real Sigstore cryptographic verification
  (VAL-V2M09-001..010, 020, 022).
- W9-4 no-private-key-material guard and default trust anchor
  immutability guards (VAL-V2M09 w9-4).
- W9-5 xfail baseline reconciliation and `verify-self` acceptance
  (VAL-V2M09-023..025).
- W8 AI hardening, five new error codes, SSRF allowlist, path
  traversal, and ReDoS timeout (VAL-V2M08-001..019).
- W8 trust-anchor four-signature cap, per-signature reporting, and a
  `local_dev` label (VAL-V2M08 trust-anchor).
- W8 replay determinism fields: `parallel_index`, `abort_after`,
  `page_index`, retry attempts (VAL-V2M08-replay-determinism).
- W8 Agent Definition Diff, per-attempt dirs, and tier-marker CI
  gating (VAL-V2M08 w8-tooling).
- W8 redaction: `json_pointer`, salt rotation, server-side
  `raw_capture` rejection, and validation harness.
- W7 consolidated CLI completeness and `cli_invocations`
  (VAL-V2M07-001..038).
- W6 TypeScript verifier port: TSA, transparency log, key lifecycle,
  Merkle proof, retention, JWKS loader, bundle validator
  (VAL-V2M06-001..025).
- W5 `RootCauseHypothesis`, `heuristic.v1`, promotion API, and
  `passN` filter (VAL-V2M05-001..027).
- W4 side-effect markers and proofs tables, server enforcement, and
  sandbox `Protocol` (VAL-V2M04-001..035).
- W3 state-engine per-transition guards and three-anchor handoff
  inside `compare_and_set_state` (VAL-V2M03-024..035).
- W3 manifest canonical schema, `command_hash`, and sidecar
  enforcement (VAL-V2M03-001..016).
- W3 atomic `local_two_layer_locked_write` primitive with a 5s
  timeout (VAL-V2M03-017..023).
- W2 ingest endpoints test coverage and `raw_capture` import wiring
  (w2-1).
- W2 runs read, replay, and eval HTTP endpoints
  (VAL-V2M02-010..036).
- W2 gates, evidence, manifest, and redaction-policy endpoints plus
  cross-cutting idempotency, pagination, rate-limit, and auth-scope
  (VAL-V2M02-037..084).
- W1 canonical SQL tables for v2 OSS completeness; ACEF oversight,
  data-quality, data-provenance tables; legal holds and
  `evidence_bundle_registry`; `evidence_timestamps` and
  `transparency_log_entries`; `scope_state` extension to six kinds
  plus a paired-row trigger; `GateMetricCatalog` v1 and compiler.

### Changed
- `KNOWN_SCHEMA_IDS` and `_SHARED_ENVELOPES` aligned with M01
  w1-4/w1-5/w1-6 additions (schemas chore).
- Style cleanups: SIM300 ruff cleanup on audit-R3 schema fixture
  comparison; SIM105/SIM117 in audit-P0 sidecar paths; SIM103
  single-return in `_is_vendored_file`.
- TS parity and codegen tests aligned with v0.2 envelope additions
  and M09 TSA crypto.
- `package-lock.json` refreshed after `contracts-typescript` npm
  install.

### Fixed
- Audit-R3 P0 control-plane fixes: idempotency lock + primitive +
  restart, PID-reuse, timing, error envelope.
- Audit-R3 P0 schema audit: DDL completeness, `schema_version` pins,
  enum drift.
- Audit-R3 P0 SSRF guard and `approval_required` CLI bypass.
- Audit-R3 P1 TS verifier parity: path screen, JCS, wire field.
- Audit-R3 P1 mixed: TS gate-draft validation, float parity, thread
  leak, salt rotate, heuristic determinism, gitleaks pin, contract
  YAML.
- Audit-R3 P2 replay: query canonicalization, session-dir isolation,
  abort-overshoot detection.
- Sidecar `runtime.py` contract correctness -- 11 P0 audit fixes.
- Wire `check_artifact_path` into `validate_bundle` and serialize
  `writer_loop` with the state-engine writer lock (audit P0).
- CLI `cmd_evidence_assess` and `cmd_eval_run` no longer fabricate
  IDs (keystone invariant #2; audit P0).
- TypeScript verifier port: four-signature cap, `trust_anchor`
  missing-rejection, `signatures_present`, and `trust_anchor_class`
  (audit P0).
- Marker `expires_at` default, cursor TTL, salt registry semver, and
  SSRF bracketed-IPv6 (audit P1/P2).
- Rate-limit verify test uses `evidence:write` (audit P0 follow-up).
- SDK `json_pointer` null/bool leaf canonical literal and
  `gate_draft` envelope parity.
- TS subprocess cwd pinned to the repo root; `__pycache__` ignored
  in vendor-drift check.
- Test signature tampered mid-byte rather than via trailing base64
  stuffing.

### Security
- Audit-R3 P0 SSRF guard hardened; CLI `approval_required` bypass
  closed.
- Verifier path traversal screen aligned across Python and
  TypeScript (audit-R3 P1).

## [v0.2-base] - 2026-05-16

### Added
- W1 schemas: canonical envelopes for `run_results`, `gate_decisions`,
  drafts, rounds, and actors (W1.1); control-plane envelopes --
  manifest, `scope_state`, idempotency, event log (W1.2); evidence
  and replay envelopes (W1.3); `redaction_policies` and
  `error_envelope` (W1.4); cross-language codegen pipeline with
  drift check (W1.5); cross-language golden corpus (W1.6).
- W2 sidecar: lockfile, spawn, and `/health` nonce challenge (W2.1);
  asyncio runtime and lifecycle (W2.2); SQLite WAL, single-writer
  queue, reader separation (W2.3); state engine --
  `compare_and_set_state`, three-anchor handoff, scope /
  `run_results` / `gate_decisions` schemas (W2.4); event-log
  constraints, retention, anti-bypass (W2.5); quiesce protocol
  (W2.6); startup recovery and structured exit codes (W2.7).
- W3 Python SDK: client, auto-spawn, nonce challenge (W3.1);
  lifecycle metadata, gate / replay / evidence, async flush (W3.2);
  SDK-side redaction at the trace boundary (W3.3); `RelayError`
  hierarchy aligned to the error envelope schema (W3.4);
  OpenAI/Anthropic adapters with replay-mode guards (W3.5).
- W4 TypeScript SDK: client, sidecar locator, npx bundle wrapper
  (W4.1); lifecycle parity (W4.2); redaction parity (W4.3); error
  envelope parity (W4.4); OpenAI + Anthropic + Vercel AI adapters
  and replay-mode parity (W4.5).
- W5 CLI: Typer skeleton, `rly` entrypoint, JSON + exit-code
  contract, error-envelope wrapping (W5.1); `rly sidecar`
  start/status/stop/restart/install (W5.2); `rly replay`
  list/record/run (W5.3); `rly evidence` list/show/verify (W5.4);
  `rly verify-self` invariant checker (W5.5).
- W6 contracts: cel-python evaluator (W6.1); cel-js TypeScript
  evaluator (W6.2); production UDFs `relay.coverage`,
  `relay.tool_arg`, `relay.schema_match` (W6.3); contract DSL
  parser and publish/runtime pipeline (W6.4); Relay-CEL conformance
  corpus (W6.5); `rly contract publish` and coverage invariant
  (W6.6).
- W7 replay: localhost mitmproxy harness for `rly replay run`
  (W7.1); `ReplayFixture-v1` cassette format (W7.2); Python SDK
  socket-deny gate extension (W7.3); TS undici interceptor and
  `HTTPS_PROXY` support (W7.4); egress denial test matrix (W7.5).
- W8 gates: gate evaluation pipeline (W8.1); control-plane-only
  `gate_decisions` writer (W8.2); gate restart on failure (W8.3);
  gate remediation circuit breaker and admin transitions (W8.4).
- W9 evals: runner primitives (W9.1); assertion-template library
  (W9.2); LLM-as-judge evaluator stub (deferred to month 4+) (W9.3).
- W10 verifier: offline JWKS resolver (W10.1); JWS RFC 7515
  conformance -- Python and TypeScript (W10.2); RFC 8785 JCS wiring
  into the OSS verifier (W10.3); full evidence bundle validator
  (W10.4).
- W11 ACEF: vendor-pinned ACEF v0.3 reference SDK and drift guard
  (W11.1); `x-relay` extension namespaces (W11.2); emit/parse
  roundtrip, corpus, and vendor docs (W11.3).
- W12 release engineering: PyPI trusted publish workflow and
  guards (W12.1); npm provenance trusted-publishing workflow and
  guards (W12.2); SLSA L3 provenance guard and fork-detection
  (W12.3); in-toto layout and link metadata pipeline (W12.4);
  sidecar bundle build, sign, and publish pipeline (W12.5);
  `rly verify-install` and release evidence bundle (W12.6).
- W13.1 trust-anchor governance doc and 13 VAL-W13 plumbing tests.
- W14.1 EU AI Act readiness internal draft and 13 VAL-W14 plumbing
  tests.
- W15.1 sandbox threat model doc and 13 fulfills tests.
- W16 examples: OpenAI tool-agent (Python + TypeScript) (W16.1);
  LangChain RAG-agent, Anthropic-backed (W16.2); Vercel AI
  tool-agent, TypeScript-only (W16.3); MCP tool-agent, Python
  (W16.4).
- W17 conformance: RFC 8785 JCS IETF corpus (W17.1); RFC 7515 JWS
  Appendix A corpus and test-only HS verifier (W17.2); cel-spec
  conformance corpus with cross-runtime parity and nightly drift
  (W17.3); Relay-CEL conformance corpus, cross-runtime parity,
  purity, and release block (W17.4).

### Fixed
- SDK cross-language redaction parity: JSON separators, raw bytes
  leak, `schema_version` alias, NFKC splice.
- Replay cassette path traversal, tampering, header case
  (security).
- Release pipeline: SHA-pin SLSA generator and pypa action,
  contributor-assistant, strengthened guards.
- Verifier fail-closed Sigstore, Rekor, and TSA cryptographic
  verification.
- Audit round 2: control-plane race, ECMA-262 Decimal,
  `schema_match` NaN/Inf, harness `RLock`, loopback parity.
- Audit round 3: 6 P1 structural fixes -- forced-stop primitive,
  `INVALID_TRANSITION` result, UDF capture, CEL thread bound, JCS
  BMP-only, anti-bypass shell-quote.
- Audit round 4: verifier `decided_at` fail-closed, first-ok
  signature lifecycle, unified canonical encoder.
- Sidecar `event_log` `ingest_sequence` under exclusive lock (P0).

### Security
- Replay cassette traversal and tampering closed.
- Verifier moved to fail-closed Sigstore, Rekor, and TSA paths.
- JCS BMP-only object key restriction enforced.

### Changed
- W1.5 codegen pipeline relocation: `codegen_pipeline.test.ts`
  moved into `sdk-typescript`.
- W1.5 manifest `test-tier-1` no longer carries the unknown
  `--tier=plumbing` flag.
- Resolved carried-forward findings post-W1.6 (M01 docs).
- Allocated `RELAY-SIDECAR-001..006` error codes for W2.1.
- W2 startup recovery wired into the production startup path
  (str-001); `recover_partial_lockfile` moved inside the spawn
  lock (str-002).
- `@pytest.mark.fulfills` markers added to W3.1 client tests.

## [scaffold-base] - 2026-05-12

### Added
- Initial public `relay` scaffold under Apache 2.0
  (`Initial public relay scaffold (Apache 2.0)`).
- Retroactive W0 workspace bootstrap (Python + Node).
- `.gitignore` for `.claude/` session artifacts.
