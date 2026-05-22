# Your First Replay

This page walks a recorded Relay run from capture (`rly replay record`)
through deterministic playback (`rly replay run`) against a cassette.
Every shell block tagged `run` is executed end-to-end by the docs
codebase-alignment audit (`scripts/docs/audit-codebase-alignment.py`);
if the CLI surface drifts, the audit fails and the page does not ship.

The canonical reference fixture for this walkthrough lives at
`examples/openai-tool-agent/python/cassettes/openai-tool-agent.jsonl`.
It is the same cassette the OpenAI tool-agent example uses, so anything
you learn here applies one-to-one to that example.

## Why cassettes

Relay's default replay mode is **cassette playback** of recorded
provider responses, not live re-execution. The reasons are empirical:
no major LLM provider guarantees deterministic output. Floating-point
reductions on GPUs, batch reordering, KV-cache differences, and silent
`system_fingerprint` rotations defeat `seed`+`temperature=0` for
OpenAI; Anthropic exposes no seed at all. Cassettes sidestep all of
that. They run offline (the replay sandbox's network policy is
default-deny), cost nothing in API calls, and produce byte-identical
output across machines and CI runs. Live re-execution exists as a
"degraded approximation" mode and is clearly marked as such in any
evidence bundle it produces.

## Step 1 -- Record a run

`rly replay record` captures the provider calls + tool calls from a
prior `run_id` into a deterministic fixture stored under
`${RELAY_HOME}/cassettes/`. The minimum-viable invocation is:

```bash
rly replay record \
  --run-id "00000000-0000-0000-0000-000000000001" \
  --name "first-replay-walkthrough"
```

Flags (`rly replay record --help`):

| Flag | Required | Purpose |
|---|---|---|
| `--run-id` | yes | Run identifier (UUID) whose tool calls + provider responses to capture. |
| `--name` | no | Human-friendly name stored with the registry entry. |
| `--home` | no | Override `RELAY_HOME` (test seam). |

The stdout envelope is structured JSON
(`schema_version: relay.cli.replay_record.v1` line) carrying the
newly-minted `replay_case_id`. You will use that `replay_case_id` in
the next step. To find existing cases, run `rly replay list`.

## Step 2 -- Play the cassette back

`rly replay run` plays a recorded cassette deterministically. The only
required flag is `--case`:

```bash
rly replay run --case "<replay_case_id from step 1>"
```

Flags (`rly replay run --help`):

| Flag | Required | Purpose |
|---|---|---|
| `--case` | yes | `replay_case_id` to play back (from `rly replay list` or `rly replay create`). |
| `--mode` | no | Playback mode. Only `cassette` is supported today. |
| `--allow-side-effects` | no | Comma-separated side-effect classes to permit. Default empty. See below. |
| `--approval-token` | no | Single-use human approval token required when a fixture's side-effect class is `approval_required`. |
| `--proxy` / `--no-proxy` | no | Spawn the mitmproxy harness for this replay. Default off. |
| `--session` | no | Override the session_id used by `--proxy`. Defaults to the replay case_id. |
| `--home` | no | Override `RELAY_HOME` (test seam). |

### About `--allow-side-effects`

This flag exists, and you should almost never reach for it casually.
Per spec section E.3 each replay fixture carries a `side_effect_class`
of `read_only`, `mutating`, `external_irreversible`, or
`approval_required`. The replay sandbox blocks anything other than
`read_only` by default. `--allow-side-effects` accepts a
comma-separated list of `mutating` and/or `external_irreversible` to
opt into letting the recorded fixture re-execute those classes, and it
is intended for narrow, audited situations (typically with a recorded
project-admin override). It does NOT accept `approval_required`; that
class requires `--approval-token=<single-use token>`. Treat
`--allow-side-effects` the way you treat `--force`: real, but
not the happy path.

If a cassette contains a `mutating` or `external_irreversible` fixture
and you run it without the matching `--allow-side-effects` value, the
replay terminates with `RELAY-REPLAY-014` and the run is marked
`blocked`. That is the system working as designed.

## What just happened

Cassette playback runs inside the replay sandbox driver. The sandbox's
network policy is default-deny: the only traffic permitted out is the
exact destinations on the project's `egress_allowlist`, and cassette
mode does not need any of them because every provider response is
served from the recorded fixture. No prompts, no completions, and no
tool arguments hit the public internet. This is the same default-deny
discipline Relay applies to evidence handling (no raw prompts /
outputs are persisted unless `raw_capture` is enabled on the active
redaction policy, which requires a signed DPA and a recorded org-admin
approver -- not in scope for this walkthrough).

If the cassette played back cleanly, the run is reproducible offline
on any machine, in CI, and inside a customer's air-gapped audit
environment.

## Common pitfalls

**`system_fingerprint` drifted.** OpenAI silently rotates
`system_fingerprint`. The default refresh policy
(`invalidate_on_signature_change`) marks the fixture stale on the next
replay and records `divergence_reason: "signature_drift"`. The fix is
to re-record the cassette against the current model. Pin a fixture to
its historical signature with `refresh_policy: hold_forever` if you
need the regression-test behavior, but understand you are pinning to a
provider artifact that no longer exists in production.

**Cassette vs live diff.** If you compare a cassette replay to a live
re-run and they differ, the cassette is the ground truth and live is
the "degraded approximation". Do not edit the cassette to match the
live diff; either re-record (acknowledging the provider rotation) or
file a regression against the agent under test.

**Cassette miss.** If `rly replay run` exits with code 4, the
fixture for a required call is not in the cassette. Re-run
`rly replay record` against the source `run_id` so every span has a
recorded fixture.

## Next

The next page wires this same `rly replay run` step into a GitHub
Actions CI workflow so every PR replays the cassette on a clean
runner: see [CI integration](ci-integration.md).

---

Spec: §E.1, §E.3
