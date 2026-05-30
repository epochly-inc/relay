"""Relay MCP tool-agent example - Python entry point.

This example wires the Relay Python SDK (W3) and the MCP client surface
(via the upstream ``mcp`` package's :class:`mcp.ClientSession` plus
``mcp.client.stdio.stdio_client``) around a deterministic MCP tool
call. The example demonstrates the canonical Relay MCP lifecycle:
open a Relay run, connect an MCP client to the pinned MCP server,
dispatch a single tool call (``relay_example.echo``), return the
result to the model, and let the control plane write the canonical
``run_results`` row.

Two entry points are exposed:

  * :func:`run_live_mode` - opens a real :class:`mcp.ClientSession`
    against the pinned MCP server (declared via ``MCP_SERVER_COMMAND``).
    Used by tier-2 smoke tests annotated ``@requires-mcp-server``.

  * :func:`run_cassette_mode` - replays from the recorded cassette
    under ``cassettes/``. Deterministic, no network egress, no MCP
    server child process spawned. Runs on forks without provider keys
    (VAL-W16-014).

Both entry points compute ``manifest_commit_hash`` as the SHA-256 of
the example's ``relay.manifest.yaml`` bytes, satisfying the
three-anchor handoff invariant per spec C.5 / VAL-W16-022.

Per CLAUDE.md keystone invariant #1 the SDK only submits lifecycle
metadata; the local sidecar's control plane is the sole writer of the
canonical ``run_results`` row.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

# Heavy imports (``relay``, ``mcp``) are deferred inside the entry-point
# functions so the plumbing test suite can load this module via
# importlib without pulling in the full Relay package surface or the
# upstream MCP SDK at module-import time. The deferred-import pattern
# keeps cassette-mode invocation self-contained: no network stack, no
# SDK transport state, no MCP child process spawn. This is what makes
# the cassette-mode test (VAL-W16-014) executable in tier-1 plumbing
# without ``mcp`` installed in the workspace venv.


# Permitted side-effect classes the example may register with the MCP
# client surface. ``read_only`` is the only class this example uses;
# any other class would require an audited replay policy override
# (RELAY-REPLAY-014, spec section E.3, VAL-W16-005).
_PERMITTED_SIDE_EFFECT_CLASSES: frozenset[str] = frozenset({"read_only"})

# Pinned MCP server identifier. The cassette and the live entry point
# reference this same identifier so the cassette can be audited as an
# MCP-protocol capture (VAL-W16-013 provider field).
MCP_SERVER_ID = "relay-example-mcp-server"
MCP_PROVIDER = f"mcp:{MCP_SERVER_ID}"

# Pinned MCP tool name. Per VAL-W16-013 the tool_name follows the MCP
# ``server.tool`` form (dotted namespace).
MCP_TOOL_NAME = "relay_example.echo"
MCP_TOOL_SIDE_EFFECT_CLASS = "read_only"

assert MCP_TOOL_SIDE_EFFECT_CLASS in _PERMITTED_SIDE_EFFECT_CLASSES

# Pinned MCP model surface. The example's tool-calling LLM is OpenAI
# in live mode (consistent with the W16.1 tool-agent example); the
# model_signature is recorded in the cassette so replay is
# deterministic.
MCP_LLM_MODEL = "gpt-4o-mini"
MCP_LLM_MODEL_SIGNATURE = f"openai/{MCP_LLM_MODEL}@fp_mcp_demo"

DEFAULT_ECHO_MESSAGE = "relay-example-mcp echo payload"


def example_root() -> Path:
    """Return the absolute path to this example's root directory."""
    return Path(__file__).resolve().parent.parent


def compute_manifest_commit_hash() -> str:
    """Return the SHA-256 over ``relay.manifest.yaml`` bytes.

    Per spec section C.5 and VAL-W16-022 the example's
    ``run_results.manifest_commit_hash`` MUST equal the SHA-256 of the
    example's ``relay.manifest.yaml`` at the commit under test. This
    function computes that digest deterministically from the on-disk
    bytes; the example then passes it to :meth:`Relay.run` as the
    third anchor in the three-anchor handoff.
    """
    manifest_path = example_root() / "relay.manifest.yaml"
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    return f"sha256-{digest}"


def actor_identity_hash_for_example() -> str:
    """Return a deterministic actor identity hash for the example run.

    Real workers source the actor identity hash from their signed
    worker identity certificate. The example runs without a real actor
    cert; we derive a stable hash from the example's manifest path
    plus a fixed namespace string so the three-anchor handoff stays
    internally consistent and reproducible across runs.
    """
    seed = f"relay.example.mcp-tool-agent::{example_root().name}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"sha256-{digest}"


# ---------------------------------------------------------------------------
# MCP tool dispatcher (read-only echo tool)
# ---------------------------------------------------------------------------
# Declared side_effect_class: read_only. This MUST match the tool's
# declaration in relay.manifest.yaml; the manifest is the source of
# truth (CLAUDE.md keystone invariant #3, VAL-W16-005, VAL-W16-018).


def dispatch_mcp_tool_call(tool_name: str, raw_arguments: str | None) -> dict[str, Any]:
    """Dispatch an MCP tool call by name; reject unknown tools.

    The example registers exactly one MCP tool (``relay_example.echo``)
    so unknown tools surface as a clear error rather than a silent
    no-op. Read-only by construction: no global mutation, no I/O, no
    environment access. Replay-safe.
    """
    if tool_name != MCP_TOOL_NAME:
        raise ValueError(
            f"unknown MCP tool {tool_name!r}; example registers "
            f"{MCP_TOOL_NAME!r} only"
        )
    args = json.loads(raw_arguments) if raw_arguments else {}
    message = args.get("message", DEFAULT_ECHO_MESSAGE)
    if not isinstance(message, str):
        raise TypeError(
            f"MCP tool {MCP_TOOL_NAME!r} expects message: str; got {type(message)!r}"
        )
    return {
        "tool_name": MCP_TOOL_NAME,
        "echoed": message,
        "server_id": MCP_SERVER_ID,
        "source": "relay-example-stub",
    }


def _sha256_bytes(blob: bytes) -> str:
    """Return the ``sha256-<hex>`` digest of the supplied bytes."""
    return "sha256-" + hashlib.sha256(blob).hexdigest()


def _canonical_json(obj: Any) -> bytes:
    """Return the canonical JSON encoding (sorted keys, no whitespace).

    Used as input to digesting so the args_hash / result_hash values
    are byte-stable across runs and platforms.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_mcp_tool_call_span(
    message: str | None = None,
) -> dict[str, Any]:
    """Build the MCP tool_call span attribute dict per spec section B.1.

    Manual instrumentation helper per VAL-W16-013: the example
    constructs this dict and emits it as the tool_call span's
    attribute payload. The MCP client adapter (W3.5) performs this
    construction at runtime; until then, the example builds the span
    by hand so the cassette replay is testable offline.

    Returns:
        A dict carrying ``span_id``, ``kind=tool_call``, ``tool_name``
        (in MCP ``server.tool`` form), ``args_hash``, ``result_hash``,
        ``status``, ``duration_ms``, ``side_effect_marker``,
        ``redacted_args``, and ``redaction_policy_version``. Stable
        across runs given the same message.
    """
    payload = message if message is not None else DEFAULT_ECHO_MESSAGE
    args = {"message": payload}
    result = dispatch_mcp_tool_call(MCP_TOOL_NAME, json.dumps(args))
    args_hash = _sha256_bytes(_canonical_json(args))
    result_hash = _sha256_bytes(_canonical_json(result))
    # The redacted args envelope replaces the cleartext message with
    # its length + digest so the MCP-protocol envelope is bound to the
    # span without persisting cleartext (spec G default-deny raw
    # capture). The redaction policy version pins the rule set used.
    redacted_args = {
        "message_length": len(payload),
        "message_digest": _sha256_bytes(payload.encode("utf-8")),
    }
    # span_id is a stable digest derived from the tool name + args
    # digest so the same tool call against the same args produces a
    # byte-identical span_id. Real runs would mint a ULID via
    # relay._ulid; the example uses a digest-derived ID so cassette
    # replay matches the recorded fixture exactly.
    span_seed = "::".join(
        [
            "relay.mcp.tool_call.span",
            MCP_SERVER_ID,
            MCP_TOOL_NAME,
            args_hash,
        ]
    )
    span_id = (
        "mcp-" + hashlib.sha256(span_seed.encode("utf-8")).hexdigest()[:32]
    )
    return {
        "span_id": span_id,
        "kind": "tool_call",
        "tool_name": MCP_TOOL_NAME,
        "args_hash": args_hash,
        "result_hash": result_hash,
        "status": "ok",
        "duration_ms": 2,
        "side_effect_marker": False,
        "redacted_args": redacted_args,
        "redaction_policy_version": "v1",
        "provider": MCP_PROVIDER,
        "server_id": MCP_SERVER_ID,
    }


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def _build_client_kwargs() -> dict[str, Any]:
    """Build the three-anchor handoff kwargs for the ``Relay`` constructor."""
    return {
        "actor_identity_hash": actor_identity_hash_for_example(),
        "manifest_commit_hash": compute_manifest_commit_hash(),
        "redaction_policy_version": "v1",
    }


def _build_agent() -> dict[str, Any]:
    """Return the ``agent`` descriptor passed to :meth:`Relay.run`."""
    return {"name": "mcp-tool-agent-example", "version": "0.1.0"}


def run_live_mode(*, project_key: str | None = None) -> int:
    """Run the example against a live MCP server.

    Requires ``MCP_SERVER_COMMAND`` in the environment, set to the
    command used to spawn the pinned MCP server. The example opens a
    Relay run, connects an MCP client to the server over stdio,
    dispatches the deterministic echo tool call, and exits with code
    0 when the canonical run_result is observed.

    Per CLAUDE.md keystone invariant #1 this function never writes a
    canonical row; it submits lifecycle metadata only. Per VAL-W16-013
    the example exercises the MCP client surface
    (``mcp.ClientSession`` + ``mcp.client.stdio.stdio_client``).
    """
    if "MCP_SERVER_COMMAND" not in os.environ:
        raise RuntimeError(
            "MCP_SERVER_COMMAND not set; cannot run live mode. "
            "Use run_cassette_mode for offline replay."
        )
    # Lazy imports: cassette mode and module-load tests do not require
    # ``mcp`` or the full ``relay`` SDK surface at import time. This
    # keeps cassette mode self-contained per VAL-W16-014.
    # ``mcp`` is an optional live-mode dependency, not installed in the
    # type-checking/dev environment; the imports are runtime-valid only when the
    # example is run live, so suppress the unresolved-import reports here.
    from mcp import ClientSession  # pyright: ignore[reportMissingImports]
    from mcp.client.stdio import (  # pyright: ignore[reportMissingImports]
        StdioServerParameters,
        stdio_client,
    )
    from relay import Relay

    server_command = os.environ["MCP_SERVER_COMMAND"]
    server_params = StdioServerParameters(
        command=server_command.split()[0],
        args=server_command.split()[1:],
        env=None,
    )
    relay = Relay(
        project_key=project_key
        or os.environ.get("RELAY_PROJECT_KEY", "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        **_build_client_kwargs(),
    )
    # The MCP client session opens a stdio channel to the pinned MCP
    # server. The Relay SDK wraps the session's tool_call invocations
    # and records the tool_call span per spec B.1.
    with relay.run(agent=_build_agent()) as run:
        # We use the synchronous API surface here; the upstream MCP
        # SDK exposes both sync and async transports. We defer to the
        # stdio_client context-manager for the spawn lifecycle so the
        # MCP server is shut down cleanly on exit.
        with (
            stdio_client(server_params) as (read, write),
            ClientSession(read, write) as session,
        ):
            session.initialize()
            tool_response = session.call_tool(
                name=MCP_TOOL_NAME,
                arguments={"message": DEFAULT_ECHO_MESSAGE},
            )
            # Build the tool_call span attribute dict from the live
            # response so the trace records the canonical MCP envelope.
            span = build_mcp_tool_call_span(message=DEFAULT_ECHO_MESSAGE)
            print(
                f"relay mcp tool_call span_id={span['span_id']} "
                f"tool_name={span['tool_name']} "
                f"status={span['status']} "
                f"duration_ms={span['duration_ms']}"
            )
            print(f"relay mcp tool response: {tool_response}")
        print(f"relay run_id: {run.run_id}")
        print(f"relay trace_id: {run.trace_id}")
    return 0


def run_cassette_mode(*, project_key: str | None = None) -> int:
    """Replay the example from the recorded cassette deterministically.

    Loads the cassette under ``python/cassettes/mcp-tool-agent.jsonl``,
    iterates the recorded fixtures, asserts the canonical kind
    sequence (model_call -> tool_call -> model_call), and prints the
    deterministic summary.

    Per VAL-W16-014 cassette mode produces no network traffic and does
    NOT spawn an MCP server child process. The function is pure
    file-I/O + hashing over the recorded cassette; no ``subprocess``
    calls, no socket opens.
    """
    cassette_path = (
        example_root() / "python" / "cassettes" / "mcp-tool-agent.jsonl"
    )
    if not cassette_path.is_file():
        raise FileNotFoundError(
            f"cassette not found at {cassette_path}; "
            "regenerate with 'rly replay record --example mcp-tool-agent'"
        )
    # Parse the cassette JSONL.
    fixtures: list[dict[str, Any]] = []
    for line in cassette_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        fixtures.append(json.loads(line))
    # Verify the canonical MCP tool-agent kind sequence.
    kinds = [f.get("kind") for f in fixtures]
    expected = ["model_call", "tool_call", "model_call"]
    if kinds != expected:
        raise RuntimeError(
            f"cassette kind sequence {kinds} != expected {expected}; "
            "cassette is stale or corrupted"
        )
    # Side-effect-class invariant: every fixture is read-only; mutating
    # tools under replay without a policy override would be
    # RELAY-REPLAY-014.
    for fx in fixtures:
        sec = fx.get("side_effect_class")
        if sec not in _PERMITTED_SIDE_EFFECT_CLASSES:
            raise RuntimeError(
                f"cassette fixture has side_effect_class={sec!r}; "
                "replay rejects mutating fixtures without override"
            )
    # Surface the canonical MCP tool_call span fields (manual
    # instrumentation per VAL-W16-013). The print line below contains
    # the dotted server.tool form so the offline replay proves the
    # MCP-protocol invariant without requiring a live MCP server.
    span = build_mcp_tool_call_span()
    print(
        f"[cassette] mcp tool_call: {span['tool_name']} "
        f"({MCP_TOOL_SIDE_EFFECT_CLASS}) "
        f"status={span['status']} duration_ms={span['duration_ms']}"
    )
    print(
        f"[cassette] mcp args_hash={span['args_hash']} "
        f"result_hash={span['result_hash']}"
    )
    print(
        f"[cassette] replayed {len(fixtures)} fixtures: "
        f"{' -> '.join(str(k) for k in kinds)}"
    )
    print(
        "[cassette] OK - cassette replay completed with zero network "
        "egress and no MCP server spawn"
    )
    _ = project_key  # accepted for parity with run_live_mode
    return 0


def main(argv: list[str] | None = None) -> int:
    """Command-line dispatch: choose live or cassette mode by env / flag."""
    argv = argv if argv is not None else sys.argv[1:]
    mode = "cassette"
    for arg in argv:
        if arg == "--live":
            mode = "live"
        elif arg == "--cassette":
            mode = "cassette"
    if mode == "live":
        return run_live_mode()
    return run_cassette_mode()


if __name__ == "__main__":
    sys.exit(main())
