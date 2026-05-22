# Your First Agent

This page walks you from a working `rly` install to a live Relay run: a
real OpenAI tool-calling agent, wrapped by the Relay Python SDK, with a
canonical trace you can view from the CLI. The code on this page mirrors
[`examples/openai-tool-agent/python/main.py`](https://github.com/epochly-inc/relay/blob/main/examples/openai-tool-agent/python/main.py)
byte-for-byte for imports and call shapes; the docs codebase-alignment
audit fails if the snippet ever drifts from the example source.

## Prerequisites

- A working `rly` CLI. Follow [install.md](install.md) first; you need
  `uv run rly --version` to print a `relay.cli.version.v1` envelope on
  stdout before continuing.
- An OpenAI API key in the environment variable `OPENAI_API_KEY`.
  The live mode shown below calls `openai.OpenAI().chat.completions.create`
  through the Relay adapter; without a key the live entry point raises
  `RuntimeError` before any network egress. Forks and offline workflows
  can use the cassette path instead -- see "Run it offline" below.
- The workspace dependencies installed: `uv sync --all-packages` from
  the repo root. This brings in the `openai` provider package alongside
  the workspace `relay` SDK.

The Relay SDK package is entirely side-effect-free at import time
(`VAL-W3-001`): importing `relay` does not spawn the sidecar, bind a
port, or open a connection. The first SDK *operation* that needs the
sidecar (here, entering the `relay.run(...)` context manager) is what
triggers the lazy spawn or attach.

## The code

Save the following as `agent.py` at the repo root. It is the live-mode
entry point from `examples/openai-tool-agent/python/main.py`, condensed
to the minimum surface that produces a Relay run plus a real OpenAI
tool call. The imports, the `Relay(...)` constructor shape, the
three-anchor handoff kwargs (`actor_identity_hash`,
`manifest_commit_hash`, `redaction_policy_version`), the `wrap_openai`
adapter call, and the `with relay.run(agent=...) as run:` context
manager all match the example file exactly.

```python title="agent.py"
"""First Relay agent: wrap an OpenAI call, produce a trace."""

from __future__ import annotations

import hashlib
import json
import os
import sys

from relay import Relay
from relay.adapters import wrap_openai


def _actor_identity_hash() -> str:
    """Return a deterministic actor identity hash for this example.

    Production workers source the actor identity hash from a signed
    worker identity certificate. This example derives a stable
    SHA-256 from a fixed namespace so the three-anchor handoff
    (spec C.5) is reproducible across runs.
    """
    seed = b"relay.docs.first-agent::v1"
    return "sha256-" + hashlib.sha256(seed).hexdigest()


def _manifest_commit_hash() -> str:
    """Return a stable manifest_commit_hash for this example.

    Real callers pass the SHA-256 over their `.ops/manifest.yaml`
    bytes; the example uses a fixed digest so the snippet is
    self-contained and the three-anchor handoff stays internally
    consistent.
    """
    seed = b"relay.docs.first-agent::manifest::v1"
    return "sha256-" + hashlib.sha256(seed).hexdigest()


def main() -> int:
    if "OPENAI_API_KEY" not in os.environ:
        print("OPENAI_API_KEY not set; export it before running.", file=sys.stderr)
        return 0

    # Deferred import: the openai package is only required for the live
    # path. Importing it lazily lets this script load on systems that
    # have not installed openai yet (matches the deferred-import pattern
    # in examples/openai-tool-agent/python/main.py).
    import openai

    raw_client = openai.OpenAI()
    relay = Relay(
        project_key=os.environ.get(
            "RELAY_PROJECT_KEY", "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        ),
        actor_identity_hash=_actor_identity_hash(),
        manifest_commit_hash=_manifest_commit_hash(),
        redaction_policy_version="v1",
    )
    wrapped = wrap_openai(raw_client)

    with relay.run(agent={"name": "first-agent", "version": "0.1.0"}) as run:
        response = wrapped.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "user",
                    "content": "What is the weather in Reykjavik, Iceland?",
                }
            ],
        )
        choices = getattr(response, "choices", []) or []
        if choices:
            print(json.dumps({"reply": choices[0].message.content}))
        # The SDK never writes a canonical run_result -- the local
        # sidecar's control plane is the sole writer (CLAUDE.md
        # keystone invariant #1). The SDK exposes the run_id and
        # trace_id so the harness can correlate the canonical row.
        print(f"relay run_id: {run.run_id}")
        print(f"relay trace_id: {run.trace_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

A few load-bearing points the snippet mirrors from the example:

- `from relay import Relay` and `from relay.adapters import wrap_openai`
  are the canonical public imports. The Relay SDK exports `Relay` from
  the top-level package (`packages/sdk-python/relay/__init__.py`); the
  OpenAI adapter is exported from the `relay.adapters` subpackage
  (`packages/sdk-python/relay/adapters/__init__.py`).
- The three-anchor handoff anchors (`actor_identity_hash`,
  `manifest_commit_hash`, `redaction_policy_version`) are required.
  The SDK raises `RelayConfigError` synchronously if any anchor is
  missing -- there is no fallback path.
- `wrap_openai(raw_client)` returns a duck-typed wrapper. Every
  `chat.completions.create(...)` call is captured as a Relay span on
  the active run; you do not need to manage span lifetimes by hand.
- The `with relay.run(agent=...) as run:` context manager is the
  lifecycle scope. The SDK only submits *lifecycle metadata* inside
  this block; the canonical `run_results` row is written by the local
  sidecar's control plane on flush.

## Run it

Make sure your venv is active (or use `uv run`), then:

```bash
OPENAI_API_KEY=sk-... uv run python agent.py
```

On a successful run the script prints the model reply, then the Relay
`run_id` and `trace_id`. Capture the `run_id`; you need it for the
trace lookup in the next step.

If `OPENAI_API_KEY` is unset the script prints a message to stderr
and exits 0 without contacting OpenAI or the sidecar -- nothing to
report, nothing to clean up. A Python traceback on stderr means an
uncaught internal failure -- file an issue with the full traceback.

## View the trace

`rly trace <run_id>` queries the local sidecar's
`GET /v1/runs/{run_id}/trace` endpoint and emits a canonical
`relay.cli.trace.v1` envelope on stdout. Substitute the `run_id` your
script printed:

```bash
uv run rly trace 01J9MP4VWNS3W6BV3SM2GR7JZQ
```

Expected output shape (a single JSON object on stdout):

```json
{
  "schema_version": "relay.cli.trace.v1",
  "run_id": "01J9MP4VWNS3W6BV3SM2GR7JZQ",
  "spans": [
    {
      "span_id": "01J9MP4VWNS3W6BV3SM2GR7JZR",
      "parent_span_id": null,
      "start_time_unix_nano": 1747958400000000000,
      "end_time_unix_nano": 1747958401234000000,
      "name": "relay.run",
      "attributes": {"span_type": "run", "status": "ok", "error_class": null}
    },
    {
      "span_id": "01J9MP4VWNS3W6BV3SM2GR7JZS",
      "parent_span_id": "01J9MP4VWNS3W6BV3SM2GR7JZR",
      "start_time_unix_nano": 1747958400100000000,
      "end_time_unix_nano": 1747958401100000000,
      "name": "openai.chat.completions.create",
      "attributes": {"span_type": "model_call", "status": "ok", "error_class": null}
    }
  ]
}
```

Field meanings:

- `schema_version` -- always `relay.cli.trace.v1` for this CLI
  envelope. Consumers parse the envelope by version.
- `run_id` -- the `run_id` you passed; echoed for correlation.
- `spans[]` -- one entry per recorded span. Each span has
  `span_id`, `parent_span_id` (null on the root), monotonic
  nanosecond timestamps (`start_time_unix_nano` /
  `end_time_unix_nano`), a `name`, and an `attributes` object.

If `rly trace` exits with code 1 and an envelope on stderr containing
`run_id ... not found`, the sidecar has no record for that `run_id` --
double-check you copied the right ULID from `agent.py`'s stdout, and
that you ran `agent.py` against the same sidecar (the local sidecar
auto-spawns on first SDK operation and shares its home directory
through `${RELAY_HOME}` or `~/.relay`).

## What just happened

The lifecycle in one paragraph: importing `relay` did nothing visible.
Entering `relay.run(...)` triggered the local sidecar to spawn (or
attach to an existing one), authenticated the SDK to the sidecar over
loopback, and opened a lifecycle run keyed by the three-anchor
handoff. Each `wrapped.chat.completions.create(...)` call inside the
context manager produced a span on the SDK's span recorder; on
`__exit__` the SDK flushed the lifecycle envelope to the sidecar.
The control plane (the sidecar, not the SDK) wrote the canonical
`run_results` row. `rly trace <run_id>` then read that row's span
manifest back and projected it into the
`relay.cli.trace.v1` envelope you saw.

The key invariant on display: at no point did the SDK write a
canonical result. The SDK submits *evidence* (lifecycle metadata,
spans, draft envelopes); the control plane writes the canonical
outcome. This separation is the load-bearing rule the rest of the
product is built on.

## Run it offline

Forks without an OpenAI key, or workflows that need a deterministic
trace, can replay the canonical example from a recorded cassette:

```bash
uv run python examples/openai-tool-agent/python/main.py --cassette
```

The cassette path produces zero network egress and emits the
deterministic summary the smoke harness asserts against. See
[`examples/openai-tool-agent/python/README.md`](https://github.com/epochly-inc/relay/blob/main/examples/openai-tool-agent/python/README.md)
for the recording workflow.

## Next step

Now that you have a live trace, write your first contract and gate
the run on a behavioral assertion: continue to
[first-contract.md](first-contract.md).

---

Spec: §A.1, §C.5, §E.1, §O
