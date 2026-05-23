# How to Debug Replay Failures

This guide is for SREs and oncall engineers triaging a failing production
agent run: ingest the failure, locate its cassette, replay it
deterministically, read the `RELAY-REPLAY-*` exit, and decide whether to
stay in cassette mode or step up to live mode.

## The general flow

The investigation moves in five steps:

1. **Locate the failing run** by `run_id` and confirm the failure shape.
2. **Locate (or create) the cassette** that captures the run's provider
   calls and tool calls.
3. **Replay deterministically** against that cassette.
4. **Read the resulting `RELAY-REPLAY-*` error** (if any) and apply the
   remediation for that specific code.
5. **Decide cassette vs. live mode.** Cassette is default. Live is a
   degraded approximation and requires explicit policy.

Cassette-first replay is not a stylistic preference. Per spec section
E.1, no major LLM provider guarantees deterministic output, so
re-running a failing case live almost never reproduces the original
failure byte-for-byte. The cassette is the ground truth.

## Step 1 -- Locate the failing run

Start with the `run_id` from your alert, dashboard, or trace export.
`rly trace` fetches the run's structured envelope from the sidecar:

```bash
rly trace "00000000-0000-0000-0000-000000000001"
```

Add `--json` to force JSON output on a TTY (the default already emits
JSON when stdout is redirected). Exit codes follow the standard CLI
table: `0` on success, `1` on a 4xx with `action=block`, `2` on a
4xx with `action=remediate`, `3` on an auth/handoff failure (typically
`RELAY-GATE-021` or a `RELAY-AUTH-*` code), `4` on a transient
condition such as a cassette miss, `64` on a CLI usage error, `130`
on Ctrl-C.

What you want from this step: the canonical `run_id`, the
`scope_id`, the failure code, and enough span context to know which
provider call or tool call failed. Note the failure code -- it tells
you whether the root cause was a contract violation, an auth/handoff
issue, a side-effect block, or a cassette miss.

## Step 2 -- Locate the cassette

`rly replay list` paginates the local replay registry. The flags it
accepts today are `--limit` (1..500; default 50), `--cursor` (opaque
pagination token from a prior response's `next_cursor`), and `--home`
(test seam to override `RELAY_HOME`). There is no `--run` filter
on `rly replay list` at this writing; filter the JSON output yourself
to find cases whose `source_run_id` matches your `run_id`:

```bash
rly replay list --limit 200 \
  | python -c 'import json,sys; \
data=json.load(sys.stdin); \
print(json.dumps([c for c in data.get("items",[]) \
  if c.get("source_run_id")=="00000000-0000-0000-0000-000000000001"], indent=2))'
```

If no case exists for this `run_id`, create one with `rly replay create`:

```bash
rly replay create --from-run "00000000-0000-0000-0000-000000000001"
```

`rly replay create` mints a new `replay_case_id`, returns it on stdout
under `schema_version: relay.cli.replay_create.v1`, and freezes the run's
inputs and candidate fixtures. Missing `--from-run` exits `64` with a
structured usage envelope.

If the case exists but its cassette is incomplete, use `rly replay record`
(documented in
[Your First Replay](../getting-started/first-replay.md)) to capture the
missing fixtures.

## Step 3 -- Replay deterministically

`rly replay run` plays a cassette back against the replay sandbox. The
only required flag is `--case`:

```bash
rly replay run --case "<replay_case_id from Step 2>"
```

`rly replay run --help` (canonical source: the CLI itself) shows the
other flags: `--mode` (only `cassette` is supported today),
`--allow-side-effects` (comma-separated; permitted values are
`mutating` and `external_irreversible`; `approval_required` is NOT
accepted here), `--approval-token` (single-use human approval token
required when a fixture's class is `approval_required`),
`--proxy` / `--no-proxy` (spawn the mitmproxy harness for this
replay; default off), `--session` (override the session_id used by
`--proxy`; defaults to the case id), and `--home`.

Exit codes match the standard CLI table: `0` success, `1` block, `2`
remediate, `3` auth/handoff, `4` transient (cassette miss is the
canonical example), `5` 5xx + network transient, `6` WAL/storage
error, `64` wrong-flag, `70` uncaught internal, `130` interrupted.

If `rly replay run` exits `0`, the failure does not reproduce under
cassette playback. Go to Step 5.

If it exits non-zero, read the `RELAY-REPLAY-*` code in the
envelope's `details` field. Step 4 enumerates them.

## Step 4 -- Read `RELAY-REPLAY-*` errors

Every code below is registered in
`packages/schemas/raw/error-codes.yaml`. Click through to the
auto-generated reference page for the canonical machine-readable
definition.

### `RELAY-REPLAY-001`

Default replay-namespace rejection (catch-all). Emitted when the
replay request failed in a way more specific codes do not classify.
**Likely cause:** an unexpected sidecar or driver error. **Remediation:**
inspect the envelope's `details` block; re-run with `--json` and
file the structured response if the failure repeats. Reference:
[RELAY-REPLAY-001](../reference/errors/RELAY-REPLAY-001/index.md).

### `RELAY-REPLAY-002`

Replay precondition not met: the case lacks a recorded cassette, an
active manifest binding, or the three-anchor handoff is stale.
**Likely cause:** the case was created from a run whose manifest
commit hash has rotated past the grace window, OR no `rly replay
record` has been run for this case yet. **Remediation:** confirm the
case has a recorded cassette (`rly replay list` shows `fixture_count`)
and that the case's manifest binding is current; re-record if needed.
Reference:
[RELAY-REPLAY-002](../reference/errors/RELAY-REPLAY-002/index.md).

### `RELAY-REPLAY-014`

A side-effecting tool attempted execution during replay without an
audited policy override. Cassette-first replay is default-deny for
`mutating` and `external_irreversible` tools (spec section E.3).
**Likely cause:** the recorded fixture declares a non-`read_only`
`side_effect_class` and you ran `rly replay run` without the matching
`--allow-side-effects` value (for `mutating` / `external_irreversible`)
or without `--approval-token` (for `approval_required`). **Remediation:**
prefer cassette mode (the recorded output replays without re-executing
the side effect); only when you genuinely need re-execution, supply
the audited override per Step 5. Reference:
[RELAY-REPLAY-014](../reference/errors/RELAY-REPLAY-014/index.md).

### `RELAY-REPLAY-021`

Replay envelope failed schema validation at the `_021` ordinal in
the replay namespace. **Likely cause:** the CLI was upgraded ahead
of the sidecar (or vice versa) and the wire envelope shape no longer
matches. **Remediation:** align the CLI and sidecar versions; the
SDK/sidecar release matrix is documented in `docs/reference/`.
Reference:
[RELAY-REPLAY-021](../reference/errors/RELAY-REPLAY-021/index.md).

### `RELAY-REPLAY-022`

Replay-namespace rejection ordinal `_022`. **Likely cause:** a
fixture digest mismatch between what the case expects and what the
cassette contains -- typical when the cassette was edited after
recording or when the case's `inputs_digest` rotated. **Remediation:**
re-record from the source `run_id` (`rly replay record`) so the
cassette and case agree on inputs. Reference:
[RELAY-REPLAY-022](../reference/errors/RELAY-REPLAY-022/index.md).

### `RELAY-REPLAY-023`

Replay-namespace rejection ordinal `_023`. **Likely cause:** the
replay sandbox driver refused to provision (driver not installed, or
the configured driver is not available on this host). **Remediation:**
confirm the configured driver and its dependencies are present on the
host; the default OSS local profile uses `local-docker`. Reference:
[RELAY-REPLAY-023](../reference/errors/RELAY-REPLAY-023/index.md).

### `RELAY-REPLAY-031`

Replay-namespace rejection ordinal `_031`. **Likely cause:** an
`output_ref` (recorded provider response) is missing or unreadable
from the cassette store. **Remediation:** re-record the case so every
span has a fresh `output_ref`. Reference:
[RELAY-REPLAY-031](../reference/errors/RELAY-REPLAY-031/index.md).

### `RELAY-REPLAY-032`

Replay-namespace rejection ordinal `_032`. **Likely cause:** a
`refresh_policy` triggered staleness (e.g.,
`invalidate_on_signature_change` saw a rotated `system_fingerprint`,
or `invalidate_on_model_version_change` saw a pinned model bump). The
envelope carries `divergence_reason: "signature_drift"` or similar.
**Remediation:** re-record the cassette against the current model, OR
pin the fixture to `refresh_policy: hold_forever` if you need the
historical regression-test behavior (understanding that you are
pinning to a provider artifact that no longer exists in production).
Reference:
[RELAY-REPLAY-032](../reference/errors/RELAY-REPLAY-032/index.md).

### `RELAY-REPLAY-033`

Replay-namespace rejection ordinal `_033`. **Likely cause:** the
replay sandbox's default-deny network policy blocked an egress that
was not on the project `egress_allowlist`. **Remediation:** either
keep the call in cassette mode (preferred -- cassette playback needs
no egress), or add the destination to the project's
`egress_allowlist` if a `read_only` live call is genuinely required.
Reference:
[RELAY-REPLAY-033](../reference/errors/RELAY-REPLAY-033/index.md).

A `4` exit with no `RELAY-REPLAY-*` code is the cassette-miss case:
the cassette does not contain a fixture for a call the agent made.
Run `rly replay record` against the source `run_id` so every span has
a recorded fixture, then retry Step 3.

## Step 5 -- When (not) to use live mode

Cassette playback is the right answer in the overwhelming majority of
investigations. It runs offline (the replay sandbox is default-deny
for network egress), costs nothing in API calls, and reproduces byte
for byte across machines.

You may legitimately need live mode in two narrow situations:

1. The cassette does not reproduce the failure AND you have ruled out
   `system_fingerprint` drift, manifest binding rot, and missing
   fixtures.
2. You are debugging a side-effecting tool whose downstream behavior
   under a freshly-recorded input genuinely matters (rare).

For (1), live mode against a `read_only` tool requires the destination
to be on the project's `egress_allowlist` (spec section E.3 / E.4 --
the sandbox `NetworkPolicy.egress_default` stays `deny` in P0 and a
live `read_only` call requires an explicit allowlist entry).

For (2), live re-execution against a `mutating` or
`external_irreversible` tool is the loaded weapon of replay. Per spec
section E.3:

> A worker that attempts a `mutating` or `external_irreversible` side
> effect during replay without explicit override produces
> `RELAY-REPLAY-014` and the replay run is marked `blocked`.

If you genuinely need to re-execute one of those classes -- and you
should treat that as a last resort -- pass the matching
`--allow-side-effects` value. The override is intended for narrow,
audited situations: per spec section E.3 the authority to allow a
`mutating` call is a dashboard JWT admin plus an audit-log entry, and
an `external_irreversible` call additionally requires 2-person
approval with a 24 h expiry. `approval_required` is never accepted
via `--allow-side-effects`; that class requires `--approval-token=<single-use token>`
issued to a named human.

Treat `--allow-side-effects` the way you treat `--force`: real, but
not the happy path. If a cassette and a live run diverge, the
cassette is the ground truth and the live run is the "degraded
approximation"; do not edit the cassette to match the live diff.

## Cross-links

- [How to audit a gate decision](./audit-gate-decision.md) -- the ML
  safety reviewer's path; useful when a replay's gate outcome itself
  is what you are investigating.
- [How to verify an evidence bundle offline](./verify-bundle-offline.md)
  -- the auditor's path; useful when the replay produced an evidence
  bundle you need to verify against a pinned trust anchor.
- [Your First Replay](../getting-started/first-replay.md) -- the
  basic walkthrough this how-to assumes as background.
- Error-code reference pages:
  [RELAY-REPLAY-001](../reference/errors/RELAY-REPLAY-001/index.md),
  [RELAY-REPLAY-002](../reference/errors/RELAY-REPLAY-002/index.md),
  [RELAY-REPLAY-014](../reference/errors/RELAY-REPLAY-014/index.md),
  [RELAY-REPLAY-021](../reference/errors/RELAY-REPLAY-021/index.md),
  [RELAY-REPLAY-022](../reference/errors/RELAY-REPLAY-022/index.md),
  [RELAY-REPLAY-023](../reference/errors/RELAY-REPLAY-023/index.md),
  [RELAY-REPLAY-031](../reference/errors/RELAY-REPLAY-031/index.md),
  [RELAY-REPLAY-032](../reference/errors/RELAY-REPLAY-032/index.md),
  [RELAY-REPLAY-033](../reference/errors/RELAY-REPLAY-033/index.md).

---

Spec: §E, §E.3
