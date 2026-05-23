---
status: draft
last-reviewed-by: Chandler Vaughn (Relay-Inc release engineering)
last-reviewed-on: 2026-05-16
next-review-due: 2026-11-12
---

# Sandbox Threat Model

> Threat-model and failure-mode documentation for the Relay v0.1
> replay-sandbox driver. Establishes the scope of defense the
> **local-docker** P0 driver provides, the explicit scope of defense it
> does NOT provide, and the no-Docker degraded-mode pathway that lets
> `rly replay run` operate on hosts without a Docker daemon. Authoritative
> for v0.1; supersedes prose-only references to `e2b` as P0 in spec §E.4.

This document satisfies the W15 deliverable of the Relay v0.1 OSS wedge
(eng plan W15; CEO plan T-F threat model cherry-pick; OV-16 disposition).
It is the canonical written record of the threat boundaries of the v0.1
replay sandbox; the engineering implementation that backs the doc-first
design lands in W7 (A4 layered proxy). It is reviewed semi-annually; see
the front-matter `next-review-due` field for the scheduled cadence.

## Overview

The Relay replay sandbox is the runtime substrate that hosts an agent
under deterministic replay. Its primary job is **replay determinism**:
ensuring that an agent re-executing against a recorded cassette produces
byte-identical span IDs, tool-call argument hashes, and outputs that match
the cassette's `model_signature`. Its secondary job is **side-effect
containment** at the driver level: refusing to dispatch tool calls whose
`side_effect_class` (spec §E.3) would be inappropriate for the current
replay mode (cassette vs. live).

Per CEO plan D10, the v0.1 P0 driver is `local-docker`. This represents
the elevation of `local-docker` to P0 status. Spec §E.4 (lines 3939-4005)
currently names `e2b` as P0; this document resolves the contradiction in
favor of `local-docker` for v0.1, and the spec hygiene TODO that updates
§E.4 is filed and tracked outside this milestone. The `e2b` driver
remains a documented opt-in for users who need stronger kernel-level
isolation than `local-docker` provides.

The threat model here is intentionally narrow. Relay v0.1 is a tool for
trusted local-developer use, not an untrusted-code execution platform.
We will spell out what that means below.

## Threat Model (T)

Per CEO plan T-F threat model (cherry-pick), the v0.1 replay sandbox
enumerates the following threat actor classes. Each class is named
explicitly so that downstream documentation, marketing copy, and
customer questions all converge on the same in-scope / out-of-scope
boundary. Spec citations: §E.3, §E.4, OV-16.

- **T1: Trusted local-dev customer code (in-scope for P0).** The agent
  binary under test was written by the same person running `rly replay
  run`. The threat is not malice; it is non-determinism (network calls
  leaking to live providers, time-of-day variance, environment-variable
  divergence) and accidental side effects (an agent that wires up a
  production write API and then re-executes under replay). The
  local-docker P0 driver defends this class by intercepting tool calls
  at the driver level and by enforcing network egress denial via the A4
  layered proxy (mitmproxy + HTTPS_PROXY + socket deny + undici
  interceptor; see eng plan A4 and the No-Docker Degraded Mode section
  below).

- **T2: Untrusted third-party agent code (explicitly out-of-scope for
  the P0 local-docker sandbox).** An adversary-supplied binary running
  inside the sandbox is NOT in scope. The local-docker sandbox does not
  provide adversarial isolation. Users who need to run untrusted agent
  code must use an opt-in driver with kernel-level isolation (e2b is the
  documented opt-in option; future drivers may include
  firecracker-microvm). See the Out-of-Scope Use Cases section.

- **T3: Network-side adversary (egress-deny defended).** A
  man-in-the-middle on the path from the agent to a live LLM or tool
  endpoint. The replay sandbox defends this class by default-deny
  network egress (spec §E.4 NetworkPolicy default-deny), implemented at
  the driver level via the A4 layered proxy. The adversary cannot
  intercept what the agent never speaks.

- **T4: Compromised tool destination (side-effect-class policy
  defended).** A previously-trusted external tool (a webhook, an
  outbound HTTP API, an SDK call) that has been compromised by the
  adversary. The replay sandbox defends this class by enforcing
  `side_effect_class` policy at the driver level (spec §E.3): tools
  marked `mutating` or `external_irreversible` are refused dispatch
  during cassette replay. See the Local-Docker Sandbox (P0) section for
  the side-effect blocking mechanism.

- **T5: Host kernel-level adversary (explicitly NOT defended by
  local-docker).** An adversary with kernel-level capability on the
  host running `rly replay run` is outside the trust boundary of the
  local-docker P0 driver. Docker shares the host kernel; a host-root
  attacker bypasses the sandbox entirely. Users who require defense at
  this layer must use a driver with stronger isolation (e2b, or a
  microvm-based driver). This is stated explicitly so that customers
  do not infer a defense the v0.1 P0 driver does not provide.

## Failure Modes (F)

Per CEO plan T-F threat model, the following failure modes are
enumerated as the named ways the v0.1 replay sandbox can fail. Each
mode names its detection surface and its mitigation. Spec citations:
§E.3, §E.4, §K (evidence binding), §AM.6 (test cadence).

- **F1: Sandbox provision failure.** The driver fails to start the
  container (Docker daemon unavailable, image pull failure, disk full,
  permission denial). Detection: driver exits with structured error
  code; `rly replay run` surfaces `RELAY-REPLAY-PROVISION-FAILED`.
  Mitigation: degraded-mode fallback per the No-Docker Degraded Mode
  section, or operator action to repair the host. Tier-2 smoke tests
  exercise the success path (`rly verify-self`); the
  failure path is exercised by injected-fault unit tests.

- **F2: Network egress leak.** A path the A4 layered proxy did not
  catch lets traffic reach a live external endpoint during replay.
  Detection: the egress-denial conformance tests
  (`apps/replay-proxy/tests/test_w7_5_egress_denial_python.py` for
  in-process Python transports; `apps/replay-proxy/tests/test_w7_5_subprocess_curl.py`
  for out-of-process child-process egress via `curl`;
  `packages/sdk-typescript/test/w7_5_node_egress_denial.test.ts` for Node)
  exercise every named transport (requests, urllib, aiohttp,
  subprocess, raw socket, fetch, axios, curl). Mitigation: per eng plan A4, all transports are pinned
  to the loopback mitmproxy and a residual socket-level deny rule
  refuses any connection the proxy did not authorize. A leak is a P0
  bug; the conformance test is run as plumbing tier-1 to prevent
  regression. Spec §E.4 NetworkPolicy default-deny.

- **F3: Side-effect tool-call leak.** A tool whose `side_effect_class`
  is `mutating` or `external_irreversible` is dispatched during
  cassette replay without an audited override. Detection: the
  side-effect blocking guard rejects the dispatch and writes a
  `RELAY-REPLAY-014` (side effect attempted during replay) to the
  evidence bundle. Mitigation: the dispatcher is the only path; tools
  are denied at the driver level (NOT at the kernel level), so a tool
  that bypasses the dispatcher (via a raw HTTP request, for example)
  is caught by F2's egress denial instead. Spec §E.3.

- **F4: Cassette tamper / fixture digest mismatch.** A recorded
  cassette has been modified (byte-for-byte) since its
  `model_signature` was computed, or the provider rotated
  `system_fingerprint` between capture and replay. Detection: the
  replay engine recomputes the cassette's digest at load time and
  refuses to play a tampered fixture. Mitigation: capture a fresh
  fixture and accept the new `model_signature`; this is the refresh
  policy doing its job. Spec §E.2.

- **F5: Docker absent on host (Windows / minimal Linux).** The host
  has no Docker daemon (Windows users without Docker Desktop / WSL2;
  minimal Linux containers; CI runners with Docker disabled).
  Detection: shell out to `docker version` (or `docker info`) and check
  the exit code; non-zero means the daemon is unreachable. The Relay
  CLI does NOT currently expose a structured docker-availability field
  in `rly verify-self --json` (the v0.1 verify-self surface emits the
  invariants schema only). Mitigation: the No-Docker Degraded Mode
  pathway lets `rly replay run` operate without a Docker-based sandbox;
  the A4 layered proxy remains the default enforcement surface for
  replay determinism. See the No-Docker Degraded Mode section.

- **F6: Kernel-level escape (explicitly not in P0 scope).** An attacker
  inside the sandbox container escalates to host root via a Docker /
  kernel CVE. This is NOT in scope for the v0.1 P0 driver. Users who
  need defense at this layer must opt in to a driver with kernel-level
  isolation (e2b, microvm). The threat is named here so that customers
  do not infer the v0.1 P0 driver defends against it; it does not.

## Local-Docker Sandbox (P0)

Per CEO plan D10, the v0.1 P0 driver is **local-docker**. This is the
elevation of local-docker to P0 status; `e2b` remains a documented
opt-in driver for users who need stronger kernel-level isolation. The
in-scope defense surface of the local-docker P0 driver is:

- **Docker resource isolation.** The agent under replay runs inside a
  Docker container with declared CPU and memory limits, a read-only
  rootfs, a fresh ephemeral writable scratch volume, and a non-root
  uid/gid. This contains accidental host-filesystem writes and
  accidental resource exhaustion. It does NOT provide adversarial
  isolation; see T5 / F6 above.

- **Network policy enforcement.** Egress is default-deny (spec §E.4
  NetworkPolicy). The container has no route to the host's default
  gateway; the only reachable endpoint is the loopback mitmproxy that
  the A4 layered proxy stands up. Every transport the agent might use
  is pinned to that proxy at the language-runtime level (Python
  `HTTPS_PROXY` + `requests`/`urllib`/`aiohttp` env vars; Node `undici`
  interceptor and global fetch override). The proxy in turn refuses to
  forward to any host not in the cassette's allow-list.

- **Side-effect blocking at the driver level.** Per spec §E.3, every
  tool the agent might call carries a declared `side_effect_class`
  (`none`, `reversible`, `mutating`, `external_irreversible`). The
  driver intercepts tool dispatch and refuses to forward calls whose
  class is incompatible with the current replay mode (cassette mode
  refuses everything except `none`). This operates at the driver
  level — at the dispatcher boundary — NOT at the kernel level. A
  tool that bypasses the dispatcher (raw socket, subprocess to
  `curl`) is caught by network egress denial instead.

What the local-docker P0 driver explicitly does NOT provide:

- **Kernel-level isolation is NOT provided.** Docker shares the host
  kernel; an attacker with kernel CVE leverage bypasses the sandbox.
  This is the load-bearing limit. Customers who need defense at this
  layer must opt in to `e2b` (or a future microvm-based driver) and
  must not assume the v0.1 P0 driver substitutes for it.

## No-Docker Degraded Mode

A material share of Relay users will not have Docker available on their
host: Windows users without Docker Desktop / WSL2, minimal Linux
containers, locked-down corporate laptops, and CI runners where Docker
is disabled. For these users, `rly replay run` works **without** a
Docker-based sandbox, because the A4 layered proxy (mitmproxy +
HTTPS_PROXY + socket deny + undici interceptor) is the **default**
enforcement surface for replay determinism. The Docker container is a
secondary defense layer; the A4 layered proxy is the primary one.

In no-Docker degraded mode:

- `rly replay run` operates against the recorded cassette using the A4
  layered proxy alone. Egress denial is enforced by the proxy and the
  socket-level deny rule at the language-runtime layer. Replay
  determinism is preserved because the cassette, not the sandbox, is
  the source of truth for provider responses.

- The sandbox driver is only required for tier-3 evals (which require
  the full isolation envelope for LLM-judged correctness scoring).
  `rly verify-self` does NOT itself probe for a working Docker daemon
  (the v0.1 verify-self surface runs the invariants schema only --
  Docker availability detection is the user's responsibility via
  `docker version` exit code, per F5 above). Windows users without
  Docker Desktop get this degraded mode by default.

- The degraded mode is documented as degraded, not as equivalent.
  Today the OSS surface does not yet expose a `sandbox_driver` field
  that an auditor can use to enforce a Docker-only policy on a
  per-run basis: the CLI's `rly replay run` emits
  `relay.cli.replay_run.v1` on stdout (per `REPLAY_RUN_SCHEMA` in
  `packages/cli/src/relay_cli/commands/replay.py`) and does not
  include a sandbox-driver field; the sidecar's persisted
  `relay.replay_result.v1` record (created in
  `apps/local-sidecar/relay_sidecar/runtime.py`) is shaped from the
  set `{schema_version, replay_result_id, case_id, replay_mode,
  manifest_commit_hash, digest_ok, outcome, evidence, written_by,
  created_at}` -- the schema enum reserves `sandbox_driver` (per
  `relay_schemas/envelopes.py` and SQL migration 0004) but the
  current sidecar writer omits it. Auditors who must enforce a
  Docker-only replay policy on the OSS local profile today rely on
  out-of-band evidence -- the host's manifest declarations and
  deployment configuration -- to confirm the driver in use. Closing
  this gap (populating `sandbox_driver` from the runtime) is a
  scheduled OSS hardening item, not a v0.1 contract.

**A4 layered proxy is implemented in W7; this doc establishes the doc-first design.**
The W15 doc (this file) lands in week 1-2 of the v0.1 buildout; the W7
implementation lands in week 6-7. The forward reference is intentional:
doc-first design is the workspace's standard operating procedure
(CW-005 action; see eng plan A4 / L2).

## Spec Hygiene TODO (§E.4 contradiction)

Spec §E.4 (lines 3939-4005) currently lists `e2b` as the P0 replay
sandbox driver. CEO plan D10 elevates `local-docker` to P0 instead.
This document **resolves** that contradiction for v0.1 in favor of
`local-docker` as P0, with `e2b` as a documented opt-in.

The spec hygiene TODO that updates §E.4 to match D10 is **filed and
tracked** outside this milestone. The W15 doc you are reading is the
authoritative resolution for v0.1: where §E.4 disagrees with this
doc, this doc wins for v0.1 only; the spec text itself will be
updated by the spec hygiene TODO before v0.2. The stable line range
form (§E.4 lines 3939-4005) is used here per the C-MIN-005
reconciliation, dropping the prior "line ~3941" hedging that drifted
as the spec was edited.

This section exists so that future readers can trace why W15 documents
`local-docker P0` while §E.4 still says `e2b P0` until the spec hygiene
TODO closes; the discrepancy is intentional and resolved here for v0.1,
not a doc-drift bug.

## Out-of-Scope Use Cases

The v0.1 local-docker P0 sandbox is NOT appropriate for the following
use cases. Customers who reach for the sandbox to do any of these must
choose a different driver (e2b, microvm) or a different tool entirely.

- **Running untrusted third-party agent code.** The local-docker P0
  sandbox does not provide adversarial isolation. An untrusted binary
  inside the sandbox can attack the host kernel via Docker / kernel
  CVEs; see T2 / T5 / F6 above. Use e2b or a microvm-based driver for
  this use case.

- **Multi-tenant sandbox-as-a-service.** The local-docker P0 sandbox
  is a single-tenant, single-host driver. It is not a multi-tenant
  isolation primitive. Hosting customer code from multiple
  organizations on the same host with only the local-docker P0 driver
  between them is NOT supported. The hosted Relay platform uses a
  different sandbox stack (out of scope for this OSS-side doc; see
  `relay-platform/services/replay-workers/`).

- **Security-critical isolation against malicious code.** Any use case
  whose threat model assumes an adversary has read or write access to
  the agent binary under replay is out of scope. The local-docker P0
  driver is designed for trusted local-dev use; substituting it for a
  hardened isolation primitive is a misuse.

## Cross-References

This doc references the following architectural surfaces:

- Spec §E.3 — Side-effect classes and the driver-level dispatch
  blocking mechanism cited in the Local-Docker Sandbox (P0) section.
- Spec §E.4 — Replay sandbox driver interface and NetworkPolicy
  default-deny; the section whose `e2b P0` text is resolved by this
  doc for v0.1.
- [Trust Anchor Governance](../legal/trust-anchor-governance.md) —
  evidence-signing and the trust-anchor JWKS that binds replay
  evidence bundles to Relay-Inc. W13 sibling doc.

The above three links (§E.3, §E.4, and the W13 trust-anchor doc) are
the canonical cross-references for this document.

## No Legal Advice

This document is not legal advice. It documents the threat boundaries
of the v0.1 replay sandbox for engineering and operator audiences.
Customers whose use cases include regulated workloads must obtain
their own counsel review before relying on the local-docker P0 driver
for any compliance-relevant claim.

Spec: §E.3, §E.4
