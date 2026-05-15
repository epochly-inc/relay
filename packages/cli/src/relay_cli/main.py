"""``rly`` CLI entrypoint (W5.1 Typer skeleton).

Wires Typer + Click on top of the SDK error hierarchy and the canonical
exit-code table. Sub-feature w5.1 ships:

  * ``rly --version`` -- emits ``relay.cli.version.v1`` JSON when piped
    (VAL-W5-001) and human-readable text on TTY (VAL-W5-003).
  * ``rly --help`` -- emits ``relay.cli.help.v1`` JSON when piped
    (VAL-W5-010) and Typer-formatted help on TTY.
  * Subcommand stubs for the W5 milestone groups: ``init``, ``trace``,
    ``gate``, ``evidence``, ``replay``, ``verify-self``, ``sidecar``,
    ``contract``. Each stub emits a structured "not yet implemented"
    envelope on stderr and exits with the canonical CLI usage code
    (64) so callers can detect the unimplemented state without parsing
    free text. Sub-features w5.2 through w5.5 wire the real
    implementations.
  * Top-level exception wrapper -- any uncaught exception is converted
    into a ``RELAY-CLI-070`` envelope on stderr with exit code 70
    (VAL-W5-004 + VAL-W5-006).
  * SIGINT/SIGTERM handler -- emits a ``RELAY-CLI-130`` envelope on
    stderr and exits 130 (VAL-W5-007).

Per CLAUDE.md keystone invariant #3 the CLI never invokes
kill-by-name primitives; sidecar lifecycle commands (W5.2) read PID and
port from the lockfile.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import platform as _platform
import signal
import sys
import traceback
from typing import Any, Final

import click
import typer
import typer.core
from relay.errors import RelayError

from . import __version__
from .errors import (
    RELAY_CLI_INTERRUPTED_CODE,
    RELAY_CLI_UNCAUGHT_CODE,
    build_envelope,
    emit_envelope,
    envelope_from_relay_error,
)
from .exit_codes import (
    EXIT_CLI_USAGE,
    EXIT_SIGINT_INTERRUPTED,
    EXIT_SUCCESS,
    EXIT_UNCAUGHT_INTERNAL,
    exit_code_for_code_and_status,
    exit_code_for_relay_error,
)
from .output import (
    build_help_envelope,
    build_version_envelope,
    emit_human,
    emit_json,
    should_emit_json,
)

# -----------------------------------------------------------------------------
# Canonical exit-code table for ``--help`` JSON envelope.
# Mirrors :data:`relay_cli.exit_codes.CANONICAL_EXIT_CODE_TABLE` but with
# human-readable meaning strings keyed for VAL-W5-010 consumers (doc
# generators) that want a single payload to render an exit-code reference
# table without screen-scraping.
# -----------------------------------------------------------------------------

_EXIT_CODE_HELP_ROWS: Final[list[dict[str, Any]]] = [
    {"code": 0, "meaning": "success (2xx)"},
    {"code": 1, "meaning": "4xx with action=block"},
    {"code": 2, "meaning": "4xx with action=remediate"},
    {"code": 3, "meaning": "4xx auth/handoff (RELAY-GATE-021, RELAY-AUTH-*)"},
    {"code": 4, "meaning": "cassette miss (RELAY-CASSETTE-MISS)"},
    {"code": 5, "meaning": "5xx + network transient"},
    {"code": 6, "meaning": "WAL/storage error (RELAY-SIDECAR-STORAGE-*)"},
    {"code": 7, "meaning": "gate TTL expired (RELAY-GATE-024)"},
    {"code": 8, "meaning": "LLM-judge deferred (RELAY-EVAL-EVALUATOR-DEFERRED)"},
    {"code": 64, "meaning": "wrong-flag (CLI usage error)"},
    {"code": 70, "meaning": "uncaught internal"},
    {"code": 130, "meaning": "SIGINT/SIGTERM interrupted"},
]


# -----------------------------------------------------------------------------
# Typer app construction.
# -----------------------------------------------------------------------------
#
# context_settings carry shared Click options. ``help_option_names`` adds
# ``-h`` as an alias for ``--help`` per common CLI convention.
#
# add_completion=False suppresses the Typer "install shell completion"
# helper subcommand: w5.1 has not designed the completion contract yet
# (the snapshot fixtures would conflict with it). A future feature can
# re-enable.
#
# rich_markup_mode=None disables Rich rendering of help text. Rich emits
# unicode glyphs (box-drawing, em-dashes) which violates CLAUDE.md
# ASCII-Safe Source. Plain Click formatting is used instead.

class _RelayTyperGroup(typer.core.TyperGroup):
    """TyperGroup subclass that emits JSON help when stdout is non-TTY.

    Per VAL-W5-010 every subcommand's ``--help`` MUST emit a
    machine-readable ``relay.cli.help.v1`` JSON envelope when piped (non-
    TTY). The vanilla TyperGroup renders Click's plain-text help in both
    cases.

    Implementation: override ``get_help`` (called by Click via
    ``ctx.get_help()`` from the ``--help`` option callback) and by Click's
    ``no_args_is_help`` path. When :func:`relay_cli.output.should_emit_json`
    returns True, we build the canonical JSON help envelope and return its
    string form. When it returns False, we delegate to the parent class so
    Typer's plain-text rendering is preserved verbatim.

    Subclassing rather than monkey-patching avoids the
    typer.main.get_command rebuild trap: each call to that helper produces
    a fresh Click command tree, but the ``cls=`` parameter on the Typer()
    constructor binds the subclass at construction so every rebuild
    inherits the override.
    """

    def get_help(self, ctx: click.Context) -> str:  # type: ignore[override]
        if should_emit_json():
            envelope = build_help_envelope(
                command=ctx.command_path,
                options=_build_options_payload(self),
                subcommands=_build_subcommands_payload(self),
                exit_codes=list(_EXIT_CODE_HELP_ROWS),
            )
            return json.dumps(envelope, separators=(",", ":"), ensure_ascii=True)
        return super().get_help(ctx)


class _RelayTyperCommand(typer.core.TyperCommand):
    """TyperCommand subclass mirroring _RelayTyperGroup for leaf commands.

    Leaf commands (like ``rly verify-self``) are TyperCommand instances,
    not TyperGroup; their ``--help`` goes through the same
    ``ctx.get_help()`` path but on a TyperCommand subclass. This class
    keeps the JSON-help rule identical for leaves.
    """

    def get_help(self, ctx: click.Context) -> str:  # type: ignore[override]
        if should_emit_json():
            envelope = build_help_envelope(
                command=ctx.command_path,
                options=_build_options_payload(self),
                subcommands=[],  # leaves have no subcommands
                exit_codes=list(_EXIT_CODE_HELP_ROWS),
            )
            return json.dumps(envelope, separators=(",", ":"), ensure_ascii=True)
        return super().get_help(ctx)


app = typer.Typer(
    name="rly",
    cls=_RelayTyperGroup,
    help=(
        "Relay control surface (rly). Apache 2.0 CLI for the Relay agent "
        "reliability OS. JSON output by default when piped; human-readable "
        "text on a TTY. Exit codes follow the canonical Relay exit-code "
        "table (see --help for the full list)."
    ),
    add_completion=False,
    no_args_is_help=False,
    rich_markup_mode=None,
    context_settings={"help_option_names": ["-h", "--help"]},
)


# -----------------------------------------------------------------------------
# JSON-when-piped --help override.
# -----------------------------------------------------------------------------
#
# Click's default ``format_help`` renders text. We monkey-patch each Typer
# group's underlying Click ``Group`` so that when stdout is NOT a TTY the
# JSON envelope is emitted instead. The override is registered after the
# Typer app is fully built so every subgroup inherits the same behavior.


def _build_options_payload(cmd: click.Command) -> list[dict[str, Any]]:
    """Project Click options into the VAL-W5-010 JSON shape."""
    payload: list[dict[str, Any]] = []
    for param in cmd.get_params(click.Context(cmd)):
        if not isinstance(param, click.Option):
            continue
        # ``opts`` is the user-visible flag list (e.g., ``["--json"]``);
        # ``secondary_opts`` carries the negative form (e.g., ``["--no-json"]``).
        names = list(param.opts) + list(param.secondary_opts)
        type_name = getattr(param.type, "name", "string") or "string"
        payload.append(
            {
                "name": "/".join(names) if names else (param.name or ""),
                "type": str(type_name),
                "required": bool(param.required),
                "help": param.help or "",
            }
        )
    return payload


def _build_subcommands_payload(cmd: click.Command) -> list[dict[str, Any]]:
    """Project Click subcommands into the VAL-W5-010 JSON shape."""
    if not isinstance(cmd, click.Group):
        return []
    payload: list[dict[str, Any]] = []
    for name in sorted(cmd.list_commands(click.Context(cmd))):
        sub = cmd.get_command(click.Context(cmd), name)
        if sub is None:
            continue
        payload.append({"name": name, "help": (sub.short_help or sub.help or "").strip()})
    return payload


# -----------------------------------------------------------------------------
# Top-level options and the --version handler.
# -----------------------------------------------------------------------------


def _emit_version(force_json: bool) -> None:
    """Emit version output respecting TTY detection (VAL-W5-001 / VAL-W5-003)."""
    py = sys.version_info
    envelope = build_version_envelope(
        version=__version__,
        python_version=f"{py.major}.{py.minor}.{py.micro}",
        platform=_platform.system().lower(),
    )
    if should_emit_json(force_json=force_json):
        emit_json(envelope)
    else:
        emit_human(
            "rly {version} (python {python}, {platform})".format(**envelope)
        )


def _version_callback(value: bool) -> None:
    """Typer callback invoked when ``--version`` is passed.

    Per Typer convention an ``is_eager`` callback raises ``typer.Exit``
    after side effects so the rest of the dispatch is short-circuited.
    Exit code 0 (success) per VAL-W5-001.
    """
    if value:
        # ``--version`` always emits JSON when piped or when --json is
        # active in the env; build_envelope honors the TTY and
        # RELAY_OUTPUT_FORMAT controls.
        _emit_version(force_json=False)
        raise typer.Exit(code=EXIT_SUCCESS)


# -----------------------------------------------------------------------------
# Top-level command callback.
# -----------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the rly version and exit.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Force JSON output even when stdout is a TTY.",
    ),
) -> None:
    """Top-level callback. Stores parsed options on the Typer context."""
    ctx.ensure_object(dict)
    ctx.obj["json_output"] = bool(json_output)
    if ctx.invoked_subcommand is None and not version:
        # No subcommand and no --version: show help.
        click.echo(ctx.get_help())
        raise typer.Exit(code=EXIT_SUCCESS)


# -----------------------------------------------------------------------------
# Subcommand group stubs (w5.2 through w5.5 wire real implementations).
#
# Each stub emits a structured "not yet implemented" envelope on stderr
# and exits with the CLI usage code (64). The envelope carries the
# ``RELAY-CLI-070`` code so machine consumers see a stable wire token;
# the message text indicates the feature is gated on a later W5
# sub-feature. This keeps the stub honest about being a stub (no silent
# success) while still satisfying the "every exception path produces a
# structured envelope" rule (VAL-W5-004).
# -----------------------------------------------------------------------------


def _emit_not_implemented(group: str, sub_feature: str) -> None:
    """Emit a structured 'not implemented' envelope and raise typer.Exit.

    Used by every w5.1 stub command. The wire code is ``RELAY-CLI-070``
    because no specific code is allocated for "stub" today; the
    ``message`` field explains the situation in a stable form.
    """
    envelope = build_envelope(
        code=RELAY_CLI_UNCAUGHT_CODE,
        http_status=501,
        message=(
            f"Command 'rly {group}' is not yet implemented in this build. "
            f"It lands in W5 sub-feature {sub_feature}."
        ),
        blocked_surface=f"rly {group}",
        retry_advice="do_not_retry",
        details={"unimplemented_group": group, "sub_feature": sub_feature},
    )
    emit_envelope(envelope)
    raise typer.Exit(code=EXIT_CLI_USAGE)


# --- init group --------------------------------------------------------------

init_app = typer.Typer(
    name="init",
    cls=_RelayTyperGroup,
    help="Initialize a Relay project (sidecar config, manifest scaffold).",
    no_args_is_help=False,
    rich_markup_mode=None,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(init_app, name="init")


@init_app.callback(invoke_without_command=True)
def _init_root(ctx: typer.Context) -> None:
    """Stub root for ``rly init``. Lands in a future W5 sub-feature."""
    if ctx.invoked_subcommand is None:
        _emit_not_implemented("init", "w5.future")


# --- trace group -------------------------------------------------------------

trace_app = typer.Typer(
    name="trace",
    cls=_RelayTyperGroup,
    help="Submit and inspect agent runs (lifecycle metadata only).",
    no_args_is_help=False,
    rich_markup_mode=None,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(trace_app, name="trace")


@trace_app.callback(invoke_without_command=True)
def _trace_root(ctx: typer.Context) -> None:
    """Stub root for ``rly trace``. Lands in a future W5 sub-feature."""
    if ctx.invoked_subcommand is None:
        _emit_not_implemented("trace", "w5.future")


# --- gate group --------------------------------------------------------------

gate_app = typer.Typer(
    name="gate",
    cls=_RelayTyperGroup,
    help="Evaluate a contract gate against a run (drafts only; CP writes decision).",
    no_args_is_help=False,
    rich_markup_mode=None,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(gate_app, name="gate")


@gate_app.callback(invoke_without_command=True)
def _gate_root(ctx: typer.Context) -> None:
    """Stub root for ``rly gate``. Lands in W5.4."""
    if ctx.invoked_subcommand is None:
        _emit_not_implemented("gate", "w5.4")


# --- evidence group (W5.4 wired) --------------------------------------------
# Per VAL-W5-025..030 the evidence group ships list/show/verify in W5.4. The
# subcommand module owns the implementation; main.py re-cls the group app
# to _RelayTyperGroup so the JSON-help override in this module covers
# ``rly evidence --help`` consistently with the rest of the tree.

from .commands.evidence import (  # noqa: E402 - late import keeps load order stable
    _cmd_evidence_list,
    _cmd_evidence_show,
    _cmd_evidence_verify,
)

evidence_app = typer.Typer(
    name="evidence",
    cls=_RelayTyperGroup,
    help=(
        "List, show, and verify evidence bundles. The verifier defaults "
        "to the spec-pinned trust anchor; --trust-anchor accepts a BYO "
        "JWKS URL for forks and self-hosters and emits a structured "
        "stderr WARN when used."
    ),
    no_args_is_help=False,
    rich_markup_mode=None,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)
evidence_app.command("list", cls=_RelayTyperCommand)(_cmd_evidence_list)
evidence_app.command("show", cls=_RelayTyperCommand)(_cmd_evidence_show)
evidence_app.command("verify", cls=_RelayTyperCommand)(_cmd_evidence_verify)
app.add_typer(evidence_app, name="evidence")


@evidence_app.callback(invoke_without_command=True)
def _evidence_root(ctx: typer.Context) -> None:
    """``rly evidence`` root: defer to subcommand or emit not-implemented stub."""
    if ctx.invoked_subcommand is None:
        _emit_not_implemented("evidence", "w5.4")


# --- replay group (W5.3 wired) ----------------------------------------------
# Per VAL-W5-019..024 the replay group ships list/record/run in W5.3. The
# subcommand module owns the implementation; main.py re-cls the group app to
# _RelayTyperGroup so the JSON-help override in this module covers ``rly
# replay --help`` consistently with the rest of the tree.

from .commands.replay import (  # noqa: E402 - late import keeps load order stable
    _cmd_replay_list,
    _cmd_replay_record,
    _cmd_replay_run,
)

replay_app = typer.Typer(
    name="replay",
    cls=_RelayTyperGroup,
    help=(
        "Record and play back agent traffic. Cassette mode is the default; "
        "live mode lands in W6. Side effects are blocked without an explicit "
        "--allow-side-effects override."
    ),
    no_args_is_help=False,
    rich_markup_mode=None,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)
replay_app.command("list", cls=_RelayTyperCommand)(_cmd_replay_list)
replay_app.command("record", cls=_RelayTyperCommand)(_cmd_replay_record)
replay_app.command("run", cls=_RelayTyperCommand)(_cmd_replay_run)
app.add_typer(replay_app, name="replay")


@replay_app.callback(invoke_without_command=True)
def _replay_root(ctx: typer.Context) -> None:
    """``rly replay`` root: defer to subcommand or emit not-implemented stub.

    A bare ``rly replay`` with no subcommand surfaces the canonical
    not-implemented envelope so machine consumers see a structured signal
    that they passed no subcommand. The three subcommands (list/record/run)
    are wired above.
    """
    if ctx.invoked_subcommand is None:
        _emit_not_implemented("replay", "w5.3")


# --- sidecar group (W5.2 wired) ---------------------------------------------
# Per VAL-W5-008b/011..018 the sidecar group ships start/stop/status/
# restart/install in W5.2. The subcommand module owns its own Typer app;
# we re-cls the app to _RelayTyperGroup here so the JSON-help override
# in this module covers ``rly sidecar --help`` consistently with the rest
# of the tree.

from .commands.sidecar import (  # noqa: E402 - local import to avoid cycle
    _cmd_install,
    _cmd_restart,
    _cmd_start,
    _cmd_status,
    _cmd_stop,
)

sidecar_app = typer.Typer(
    name="sidecar",
    cls=_RelayTyperGroup,
    help=(
        "Manage the local Relay sidecar: start, stop, status, restart, install. "
        "Lifecycle commands NEVER kill processes by name; PID is read from "
        "the sidecar lockfile."
    ),
    no_args_is_help=False,
    rich_markup_mode=None,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)
sidecar_app.command("start", cls=_RelayTyperCommand)(_cmd_start)
sidecar_app.command("status", cls=_RelayTyperCommand)(_cmd_status)
sidecar_app.command("stop", cls=_RelayTyperCommand)(_cmd_stop)
sidecar_app.command("restart", cls=_RelayTyperCommand)(_cmd_restart)
sidecar_app.command("install", cls=_RelayTyperCommand)(_cmd_install)
app.add_typer(sidecar_app, name="sidecar")


@sidecar_app.callback(invoke_without_command=True)
def _sidecar_root(ctx: typer.Context) -> None:
    """``rly sidecar`` root: defer to subcommand or show help envelope."""
    if ctx.invoked_subcommand is None:
        # Bare ``rly sidecar`` with no subcommand: emit the canonical
        # not-implemented envelope so machine consumers see a structured
        # signal that they passed no subcommand. Keeps parity with the
        # W5.1 stub-test (test_stub_command_emits_structured_envelope).
        _emit_not_implemented("sidecar", "w5.2")


# --- contract group ----------------------------------------------------------

contract_app = typer.Typer(
    name="contract",
    cls=_RelayTyperGroup,
    help="Publish and validate Relay contract definitions (CEL + UDF).",
    no_args_is_help=False,
    rich_markup_mode=None,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(contract_app, name="contract")


@contract_app.callback(invoke_without_command=True)
def _contract_root(ctx: typer.Context) -> None:
    """Stub root for ``rly contract``. Lands in W5.5."""
    if ctx.invoked_subcommand is None:
        _emit_not_implemented("contract", "w5.5")


# --- verify-self standalone command -----------------------------------------


@app.command("verify-self", cls=_RelayTyperCommand)
def _verify_self() -> None:
    """Stub for ``rly verify-self``. Lands in W5.5."""
    _emit_not_implemented("verify-self", "w5.5")


# -----------------------------------------------------------------------------
# Signal handlers (VAL-W5-007).
# -----------------------------------------------------------------------------


def _interrupted_handler(signum: int, frame: Any) -> None:
    """Emit the RELAY-CLI-130 envelope and exit 130.

    Per VAL-W5-007 the CLI MUST exit 130 on SIGINT/SIGTERM mid-command and
    emit a structured cancel envelope on stderr. The envelope carries the
    ``RELAY-CLI-130`` wire code and a ``signal`` detail field so callers
    can attribute the interrupt to a specific signal.

    This handler does NOT issue any cleanup HTTP calls in W5.1; the
    "best-effort cancel" behavior described in VAL-W5-007 lands when the
    sidecar surface ships in W5.2 (a single POST to the sidecar's cancel
    endpoint, with a 1-second timeout). Until then the handler emits the
    envelope and exits.
    """
    try:
        signal_name = signal.Signals(signum).name
    except (ValueError, AttributeError):
        signal_name = f"signal_{signum}"
    envelope = build_envelope(
        code=RELAY_CLI_INTERRUPTED_CODE,
        http_status=499,  # spec section P.3 cancel maps to client-closed-request 499
        message=f"rly was interrupted by {signal_name}; partial work may be unfinished.",
        blocked_surface="rly",
        retry_advice="after_fix",
        details={"signal": signal_name, "signum": int(signum)},
    )
    emit_envelope(envelope)
    sys.exit(EXIT_SIGINT_INTERRUPTED)


def _install_signal_handlers() -> None:
    """Register SIGINT/SIGTERM handlers for the duration of this process.

    Skipped silently on platforms that don't support a signal (Windows
    historically lacked SIGTERM Python-level handling; modern Pythons
    expose it). On Windows, Ctrl-C raises ``KeyboardInterrupt`` and the
    top-level wrapper in :func:`run` catches that and dispatches to the
    same envelope.
    """
    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _interrupted_handler)
        except (ValueError, OSError):
            # signal.signal raises ValueError off the main thread and OSError
            # on platforms that disallow override (e.g., signal already
            # handled by the embedding process); skip silently.
            continue


# -----------------------------------------------------------------------------
# Top-level run() entrypoint.
# -----------------------------------------------------------------------------


def run() -> None:
    """The ``rly`` console-script entrypoint.

    Top-level exception wrapper:
      * :class:`SystemExit` -- propagated unchanged (Typer's normal exit
        path).
      * :class:`KeyboardInterrupt` -- emit RELAY-CLI-130 envelope, exit 130.
      * :class:`click.ClickException` -- Click's own usage error envelope;
        emit RELAY-CLI-070 envelope with exit code 64, then bypass Click's
        plain-text emit.
      * :class:`RelayError` -- emit envelope_from_relay_error, exit per
        the canonical mapping (VAL-W5-006).
      * Any other ``BaseException`` -- emit RELAY-CLI-070 envelope with
        a redacted ``details["traceback"]``, exit 70 (VAL-W5-004).

    Rich tracebacks on stderr are a release-blocker (VAL-W5-004), so any
    leak of ``Traceback (most recent call last):`` would fail the
    plumbing test. The wrapper catches every base exception that can
    bubble out of the Typer dispatch.
    """
    # JSON-help override is bound at construction time via the
    # ``cls=_RelayTyperGroup`` / ``cls=_RelayTyperCommand`` parameters on
    # every Typer instance and command decorator above; no runtime install
    # step is required.
    _install_signal_handlers()

    try:
        # In standalone_mode=False the Typer/Click runtime intercepts
        # typer.Exit and RETURNS its exit_code (an int) rather than
        # propagating the exception. Capture the return value and exit
        # with it; the click.exceptions.Exit branch below is a defensive
        # guard for any Click version that re-introduces propagation.
        result = app(standalone_mode=False)
        if isinstance(result, int):
            sys.exit(result)
        sys.exit(EXIT_SUCCESS)
    except SystemExit:
        # A raw SystemExit (rare; typer.Exit is a RuntimeError subclass
        # via click.exceptions.Exit, NOT SystemExit). Re-raise verbatim.
        raise
    except click.exceptions.Exit as exc:
        # Typer.Exit / typer.exit raises click.exceptions.Exit. In
        # standalone_mode=False we receive the exception here and must
        # translate the .exit_code attribute into a process exit. The
        # envelope (when there is one to emit) was already written by
        # the command callback before raising; we ONLY translate the
        # exit code here.
        sys.exit(int(exc.exit_code))
    except KeyboardInterrupt:
        # Windows Ctrl-C path: KeyboardInterrupt is raised in the main
        # thread before our SIGINT handler fires.
        envelope = build_envelope(
            code=RELAY_CLI_INTERRUPTED_CODE,
            http_status=499,
            message="rly was interrupted by KeyboardInterrupt.",
            blocked_surface="rly",
            retry_advice="after_fix",
            details={"signal": "KeyboardInterrupt", "signum": 0},
        )
        emit_envelope(envelope)
        sys.exit(EXIT_SIGINT_INTERRUPTED)
    except click.UsageError as exc:
        # Click usage errors (bad flag, missing arg). Map to exit code 64
        # (CLI usage error) per the canonical exit-code table.
        envelope = build_envelope(
            code=RELAY_CLI_UNCAUGHT_CODE,
            http_status=400,
            message=f"usage error: {str(exc)}",
            blocked_surface="rly",
            retry_advice="after_fix",
            details={"exception_class": type(exc).__name__},
        )
        emit_envelope(envelope)
        sys.exit(EXIT_CLI_USAGE)
    except click.ClickException as exc:
        # Other Click exceptions (e.g., file path errors). Same exit code
        # as usage errors per the canonical table.
        envelope = build_envelope(
            code=RELAY_CLI_UNCAUGHT_CODE,
            http_status=400,
            message=f"cli error: {exc.format_message()}",
            blocked_surface="rly",
            retry_advice="after_fix",
            details={"exception_class": type(exc).__name__},
        )
        emit_envelope(envelope)
        sys.exit(EXIT_CLI_USAGE)
    except RelayError as exc:
        # SDK-typed error. Map via the canonical exit-code table; the
        # envelope carries the same wire code the SDK produced.
        envelope = envelope_from_relay_error(exc)
        emit_envelope(envelope)
        sys.exit(exit_code_for_relay_error(exc))
    except BaseException as exc:  # noqa: BLE001 -- top-level wrapper
        # Anything else: emit a generic uncaught envelope. The traceback
        # is captured into ``details["traceback_summary"]`` as a list of
        # ``"file:line"`` strings (no prose) so log forwarders preserve
        # the failure provenance without exposing source text. The
        # canonical "Traceback (most recent call last):" header is NEVER
        # emitted on stderr (VAL-W5-004 forbids it).
        tb_summary = [
            f"{fr.filename}:{fr.lineno}"
            for fr in traceback.extract_tb(exc.__traceback__)
        ]
        envelope = build_envelope(
            code=RELAY_CLI_UNCAUGHT_CODE,
            http_status=500,
            message=f"{type(exc).__name__}: {str(exc)}",
            blocked_surface="rly",
            retry_advice="do_not_retry",
            details={
                "exception_class": type(exc).__name__,
                "traceback_summary": tb_summary,
            },
        )
        emit_envelope(envelope)
        # Compute the exit code from the synthetic envelope; for the
        # uncaught path this resolves to EXIT_UNCAUGHT_INTERNAL (70)
        # because RELAY-CLI-070 is in the exact-code map.
        code = exit_code_for_code_and_status(
            RELAY_CLI_UNCAUGHT_CODE,
            500,
            None,
        )
        # Defensive: if the exact-code map is mutated and returns a
        # non-70 value, force exit 70 to honor VAL-W5-004's contract that
        # the uncaught path is unambiguous. The canonical table at
        # ``relay.exit_codes`` keeps RELAY-CLI-070 -> 70; this clamp is
        # belt-and-braces.
        if code != EXIT_UNCAUGHT_INTERNAL:
            code = EXIT_UNCAUGHT_INTERNAL
        sys.exit(code)


__all__ = ["app", "run"]
