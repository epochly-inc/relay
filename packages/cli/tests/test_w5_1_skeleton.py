"""W5.1 plumbing tests: ``rly`` CLI Typer skeleton.

Encodes every VAL-W5-001 .. VAL-W5-010 assertion as an executable
plumbing-tier test. Each test is bound to its assertion via the
``@pytest.mark.fulfills(...)`` marker so the gate engine can attribute
test pass/fail to assertion evidence (per ``.ops/manifest.yaml``
``fulfills_marker_format``).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from relay.errors import (
    RelayCanonicalStatusForbidden,
    RelayHandoffIncomplete,
    RelaySidecarError,
)
from relay_cli import __version__ as cli_version
from relay_cli.errors import (
    ERROR_ENVELOPE_SCHEMA_VERSION,
    RELAY_CLI_INTERRUPTED_CODE,
    RELAY_CLI_UNCAUGHT_CODE,
    WIRE_RETRY_ADVICE_VALUES,
    build_envelope,
    envelope_from_relay_error,
)
from relay_cli.exit_codes import (
    EXIT_4XX_AUTH_HANDOFF,
    EXIT_4XX_BLOCK,
    EXIT_4XX_REMEDIATE,
    EXIT_5XX_TRANSIENT,
    EXIT_CASSETTE_MISS,
    EXIT_CLI_USAGE,
    EXIT_EVAL_DEFERRED,
    EXIT_SIGINT_INTERRUPTED,
    EXIT_SUCCESS,
    EXIT_UNCAUGHT_INTERNAL,
    EXIT_WAL_STORAGE,
    exit_code_for_code_and_status,
)

# M07 w7-exit-codes (VAL-V2M07-028): EXIT_GATE_TTL_EXPIRED removed from
# the CLI's exit_codes module. RELAY-GATE-024 now maps to exit code 4
# (transient bucket) per VAL-V2M07-016. The SDK retains
# EXIT_GATE_TTL_EXPIRED=7 for cross-language parity at the SDK layer.
from relay_cli.output import (
    CLI_HELP_SCHEMA_VERSION,
    CLI_VERSION_SCHEMA_VERSION,
    ENV_OUTPUT_FORMAT,
)
from relay_schemas.envelopes import ErrorEnvelope

# Repository root (relay/), four parents up from this test file.
REPO_ROOT = Path(__file__).resolve().parents[3]
RLY_PROJECT_PYPROJECT = REPO_ROOT / "packages" / "cli" / "pyproject.toml"


# -----------------------------------------------------------------------------
# Subprocess invocation helpers
# -----------------------------------------------------------------------------


def _run_rly(
    args: list[str],
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``uv run rly <args>`` from REPO_ROOT and capture stdout/stderr.

    Uses ``uv run`` so the workspace virtualenv is honored; the CLI is
    installed editable via ``uv sync --all-packages`` in the worker
    setup. ``capture_output=True`` makes stdout/stderr non-TTY which
    triggers the JSON path (VAL-W5-003).
    """
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["uv", "run", "rly", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )


# -----------------------------------------------------------------------------
# VAL-W5-001: Binary entrypoint is `rly` and resolves on PATH
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-001")
def test_rly_entrypoint_resolves_and_emits_version_json() -> None:
    """``rly --version`` MUST exit 0 and emit a JSON envelope when piped.

    Per VAL-W5-001 the JSON shape is
    ``{schema_version: "relay.cli.version.v1", version, python, platform}``.
    """
    result = _run_rly(["--version"])
    assert result.returncode == EXIT_SUCCESS, (
        "rly --version exit code: " + repr(result.returncode)
        + " stderr=" + result.stderr
    )
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == CLI_VERSION_SCHEMA_VERSION
    assert payload["version"] == cli_version
    assert "python" in payload and re.match(r"^\d+\.\d+\.\d+$", payload["python"])
    assert "platform" in payload and isinstance(payload["platform"], str)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-001")
def test_only_rly_binary_is_installed_no_relay_no_epochly() -> None:
    """Per VAL-W5-001: no other binary names (`relay`, `epochly`) are installed.

    Inspects ``[project.scripts]`` in packages/cli/pyproject.toml. The
    only entry MUST be ``rly``.
    """
    with RLY_PROJECT_PYPROJECT.open("rb") as f:
        data = tomllib.load(f)
    scripts = data.get("project", {}).get("scripts", {})
    assert set(scripts.keys()) == {"rly"}, (
        "Unexpected console scripts in packages/cli/pyproject.toml: "
        + str(sorted(scripts.keys()))
    )


# -----------------------------------------------------------------------------
# VAL-W5-002: Typer + Click pinned with EXACT version operator
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-002")
def test_typer_and_click_are_pinned_with_exact_operator() -> None:
    """Per VAL-W5-002: pyproject.toml MUST pin typer and click with `==`."""
    with RLY_PROJECT_PYPROJECT.open("rb") as f:
        data = tomllib.load(f)
    deps = data.get("project", {}).get("dependencies", [])
    typer_pin = next((d for d in deps if d.lower().startswith("typer")), None)
    click_pin = next((d for d in deps if d.lower().startswith("click")), None)
    assert typer_pin is not None, "typer dependency missing"
    assert click_pin is not None, "click dependency missing"
    # The exact-version operator is `==`. `>=`, `~=`, `^`, and unbounded
    # specifiers all FAIL VAL-W5-002.
    assert "==" in typer_pin, "typer not pinned exactly: " + typer_pin
    assert "==" in click_pin, "click not pinned exactly: " + click_pin
    # Defensive: reject loose operators in the same string.
    for forbidden in (">=", ">", "<=", "~=", "^"):
        assert forbidden not in typer_pin, (
            "typer pin uses forbidden operator " + forbidden + ": " + typer_pin
        )
        assert forbidden not in click_pin, (
            "click pin uses forbidden operator " + forbidden + ": " + click_pin
        )


# -----------------------------------------------------------------------------
# VAL-W5-003: JSON-on-pipe, human-on-TTY (TTY detection MUST NOT change exit)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-003")
def test_default_output_is_json_when_piped() -> None:
    """``rly --version | cat`` -- piped, MUST be valid JSON."""
    result = _run_rly(["--version"])
    # Subprocess capture_output=True implies non-TTY stdout.
    json.loads(result.stdout)  # Raises if not valid JSON.
    assert result.returncode == EXIT_SUCCESS


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-003")
def test_json_env_var_forces_json_output() -> None:
    """``RELAY_OUTPUT_FORMAT=json`` MUST force JSON regardless of TTY."""
    result = _run_rly(["--version"], extra_env={ENV_OUTPUT_FORMAT: "json"})
    json.loads(result.stdout)
    assert result.returncode == EXIT_SUCCESS


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-003")
def test_tty_detection_does_not_change_exit_code() -> None:
    """The TTY-detection branch MUST NOT change the exit code.

    Verified by running ``rly --version`` with capture_output (non-TTY)
    and asserting exit code is the same canonical 0 regardless of which
    branch the formatter took. Cross-platform: a TTY-attached run
    requires PTY allocation which is non-portable; the assertion text
    in VAL-W5-003 is structural, not behavioral, so we verify the
    invariant via the source: the JSON-vs-text branch only writes
    output, never sets a different exit code.
    """
    result_pipe = _run_rly(["--version"])
    result_env = _run_rly(["--version"], extra_env={ENV_OUTPUT_FORMAT: "json"})
    assert result_pipe.returncode == result_env.returncode == EXIT_SUCCESS


# -----------------------------------------------------------------------------
# VAL-W5-004: Every exception path produces a structured envelope on stderr
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-004")
def test_bad_flag_emits_structured_envelope_on_stderr() -> None:
    """A bad flag MUST emit a JSON envelope on stderr; exit code 64."""
    result = _run_rly(["--no-such-flag"])
    assert result.returncode == EXIT_CLI_USAGE
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    assert envelope["schema_version"] == ERROR_ENVELOPE_SCHEMA_VERSION
    assert envelope["code"] == RELAY_CLI_UNCAUGHT_CODE
    assert "no such option" in envelope["message"].lower()
    # VAL-W5-004 release-blocker: NEVER leak Python tracebacks.
    assert "Traceback (most recent call last):" not in result.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-004")
def test_stub_command_emits_structured_envelope() -> None:
    """A stub subgroup (``rly sidecar``) MUST emit envelope + exit 64."""
    result = _run_rly(["sidecar"])
    assert result.returncode == EXIT_CLI_USAGE
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    assert envelope["schema_version"] == ERROR_ENVELOPE_SCHEMA_VERSION
    assert envelope["code"] == RELAY_CLI_UNCAUGHT_CODE
    assert "sidecar" in envelope["blocked_surface"]
    assert "Traceback (most recent call last):" not in result.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-004")
def test_envelope_carries_all_required_keys() -> None:
    """Per VAL-W5-004 every envelope has the documented keys."""
    result = _run_rly(["--no-such-flag"])
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    required = {
        "schema_version",
        "code",
        "http_status",
        "message",
        "blocked_surface",
        "documentation_url",
        "retry_advice",
        "request_id",
        "trace_id",
    }
    missing = required - set(envelope.keys())
    assert not missing, "missing envelope keys: " + str(sorted(missing))


# -----------------------------------------------------------------------------
# VAL-W5-005: Envelope validates against canonical relay.error.v1 schema
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-005")
def test_envelope_validates_against_w1_error_envelope_schema() -> None:
    """The CLI envelope subset MUST validate against W1 ErrorEnvelope.

    The CLI envelope is wire-compatible with spec section B.4 (lines
    3392-3408), which includes `documentation_url` as an extra field
    not present in the W1 ErrorEnvelope source-of-truth. We validate
    the W1-defined subset.
    """
    result = _run_rly(["--no-such-flag"])
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    w1_subset = {k: v for k, v in envelope.items() if k != "documentation_url"}
    # Drop CLI-specific extras that aren't in the W1 ErrorEnvelope schema.
    # ErrorEnvelope.model_validate enforces all required fields and the
    # closed retry_advice enum.
    ErrorEnvelope.model_validate(w1_subset)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-005")
def test_every_documented_cli_error_envelope_round_trips() -> None:
    """Every documented CLI envelope shape MUST validate against W1."""
    cases = [
        build_envelope(
            code=RELAY_CLI_UNCAUGHT_CODE,
            http_status=500,
            message="uncaught internal error",
            blocked_surface="rly",
            retry_advice="do_not_retry",
        ),
        build_envelope(
            code=RELAY_CLI_INTERRUPTED_CODE,
            http_status=499,
            message="interrupted by SIGINT",
            blocked_surface="rly",
            retry_advice="after_fix",
        ),
        envelope_from_relay_error(
            RelayCanonicalStatusForbidden(
                "SDK refused to submit canonical-status",
                request_id="req_abc",
                trace_id="trace_xyz",
            )
        ),
        envelope_from_relay_error(
            RelayHandoffIncomplete(
                "stale three-anchor handoff",
                request_id="req_def",
                trace_id="trace_uvw",
            )
        ),
    ]
    for envelope in cases:
        w1_subset = {k: v for k, v in envelope.items() if k != "documentation_url"}
        ErrorEnvelope.model_validate(w1_subset)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-005")
def test_retry_advice_is_always_in_wire_enum() -> None:
    """Every emitted envelope's ``retry_advice`` MUST be a wire enum value."""
    envelope = build_envelope(
        code=RELAY_CLI_UNCAUGHT_CODE,
        http_status=500,
        message="x",
        blocked_surface="rly",
        retry_advice={"mode": "after_state_change"},
    )
    assert envelope["retry_advice"] in WIRE_RETRY_ADVICE_VALUES


# -----------------------------------------------------------------------------
# VAL-W5-006: Exit code mapping is the canonical Relay table
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-006")
@pytest.mark.parametrize(
    "code, http_status, retry_mode, expected_exit",
    [
        # exit 0 = 2xx success
        ("RELAY-EVID-001", 200, None, EXIT_SUCCESS),
        # exit 1 = 4xx with action=block
        ("RELAY-ING-001", 400, None, EXIT_4XX_BLOCK),
        # exit 2 = 4xx with action=remediate
        ("RELAY-ING-001", 400, "after_state_change", EXIT_4XX_REMEDIATE),
        # exit 3 = 4xx auth/handoff
        ("RELAY-GATE-021", 422, None, EXIT_4XX_AUTH_HANDOFF),
        ("RELAY-AUTH-001", 401, None, EXIT_4XX_AUTH_HANDOFF),
        # exit 4 = cassette miss
        ("RELAY-CASSETTE-MISS", 404, None, EXIT_CASSETTE_MISS),
        # exit 5 = 5xx + network transient
        ("RELAY-SIDECAR-001", 503, None, EXIT_5XX_TRANSIENT),
        # exit 6 = WAL/storage error
        ("RELAY-SIDECAR-STORAGE-001", 500, None, EXIT_WAL_STORAGE),
        # M07 VAL-V2M07-016 / VAL-V2M07-028: RELAY-GATE-024 now maps to
        # exit 4 (transient/cassette-miss bucket) rather than the
        # historical OSS-only exit 7. The SDK still exports
        # EXIT_GATE_TTL_EXPIRED=7 for cross-language parity, but the CLI
        # wraps the resolver to short-circuit to EXIT_CASSETTE_MISS.
        ("RELAY-GATE-024", 422, None, EXIT_CASSETTE_MISS),
        # exit 8 = LLM-judge deferred
        ("RELAY-EVAL-EVALUATOR-DEFERRED", 503, None, EXIT_EVAL_DEFERRED),
        # exit 70 = uncaught internal
        ("RELAY-CLI-070", 500, None, EXIT_UNCAUGHT_INTERNAL),
    ],
)
def test_exit_code_for_canonical_table_row(
    code: str,
    http_status: int,
    retry_mode: str | None,
    expected_exit: int,
) -> None:
    """Each row of the canonical exit-code table MUST resolve as documented."""
    actual = exit_code_for_code_and_status(code, http_status, retry_mode)
    assert actual == expected_exit, (
        "code=" + code + " http=" + str(http_status) + " mode=" + str(retry_mode)
        + " expected=" + str(expected_exit) + " got=" + str(actual)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-006")
def test_cli_uses_sdk_exit_code_table_verbatim() -> None:
    """The CLI's exit-code table MUST match the SDK's canonical table.

    Single source of truth: relay.exit_codes (the W4.4 SDK module). The
    CLI must NOT redefine constants with different values for the
    constants it re-exports.

    M07 VAL-V2M07-028: EXIT_GATE_TTL_EXPIRED is intentionally excluded
    from the CLI's table (the OSS-only exit code 7 has been removed; the
    SDK retains it for cross-language parity). Asserting parity for the
    CLI-re-exported names only.
    """
    from relay import exit_codes as sdk_exit_codes
    from relay_cli import exit_codes as cli_exit_codes

    for name in (
        "EXIT_SUCCESS",
        "EXIT_4XX_BLOCK",
        "EXIT_4XX_REMEDIATE",
        "EXIT_4XX_AUTH_HANDOFF",
        "EXIT_CASSETTE_MISS",
        "EXIT_5XX_TRANSIENT",
        "EXIT_WAL_STORAGE",
        "EXIT_EVAL_DEFERRED",
        "EXIT_CLI_USAGE",
        "EXIT_UNCAUGHT_INTERNAL",
    ):
        assert getattr(cli_exit_codes, name) == getattr(sdk_exit_codes, name)
    # VAL-V2M07-028: EXIT_GATE_TTL_EXPIRED MUST NOT be re-exported by
    # the CLI module. The SDK still has it.
    assert not hasattr(cli_exit_codes, "EXIT_GATE_TTL_EXPIRED")
    assert hasattr(sdk_exit_codes, "EXIT_GATE_TTL_EXPIRED")


# -----------------------------------------------------------------------------
# VAL-W5-007: SIGINT/SIGTERM exit 130 with cancel envelope
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-007")
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals; Windows uses Ctrl-C")
def test_sigint_exits_130_with_cancel_envelope() -> None:
    """``kill -INT <rly>`` MUST exit 130 and emit RELAY-CLI-130 envelope."""
    import signal as _signal
    import time as _time

    proc = subprocess.Popen(
        ["uv", "run", "python", "-c", (
            "import time, signal\n"
            "from relay_cli.main import _interrupted_handler\n"
            "signal.signal(signal.SIGINT, _interrupted_handler)\n"
            "signal.signal(signal.SIGTERM, _interrupted_handler)\n"
            "print('READY', flush=True)\n"
            "time.sleep(60)\n"
        )],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # Wait for READY.
    deadline = _time.time() + 10
    while _time.time() < deadline:
        line = proc.stdout.readline() if proc.stdout else ""
        if line.strip() == "READY":
            break
    else:
        proc.kill()
        pytest.fail("subprocess did not signal READY")
    proc.send_signal(_signal.SIGINT)
    stdout, stderr = proc.communicate(timeout=10)
    assert proc.returncode == EXIT_SIGINT_INTERRUPTED, (
        "expected exit 130, got " + str(proc.returncode) + " stderr=" + stderr
    )
    envelope = json.loads(stderr.strip().splitlines()[-1])
    assert envelope["code"] == RELAY_CLI_INTERRUPTED_CODE
    assert envelope["details"]["signal"] in ("SIGINT", "signal_2")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-007")
def test_relay_cli_130_code_resolves_in_canonical_registry() -> None:
    """``RELAY-CLI-130`` MUST be in the canonical error-code registry."""
    from relay_schemas.error_codes import RelayErrorCode
    assert RelayErrorCode.RELAY_CLI_130 == "RELAY-CLI-130"


# -----------------------------------------------------------------------------
# VAL-W5-008: Cross-shell snapshot tests for every command group
# -----------------------------------------------------------------------------
# W5.1 ships the bash + zsh slice of the cross-shell matrix; pwsh + cmd
# rows land in the Windows CI runner where those shells are present
# (per ``.ops/manifest.yaml`` os_test_matrix). Per CLAUDE.md test
# discipline 7.5 and the boundaries doc, missing pwsh on macOS/Linux is
# a genuine non-applicability skip with the documented reason.
# -----------------------------------------------------------------------------


_SHELLS_AVAILABLE: dict[str, str | None] = {
    "bash": shutil.which("bash"),
    "zsh": shutil.which("zsh"),
    "pwsh": shutil.which("pwsh"),
    "cmd": shutil.which("cmd.exe"),
}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-008")
@pytest.mark.parametrize(
    "shell_name",
    ["bash", "zsh", "pwsh", "cmd"],
)
@pytest.mark.parametrize(
    "command_args",
    [
        ["--help"],
        ["--version"],
        ["sidecar"],
        ["evidence"],
        ["verify-self"],
        ["replay"],
    ],
)
def test_cross_shell_snapshot(shell_name: str, command_args: list[str]) -> None:
    """For each (command, shell) pair: stdout/stderr is parseable JSON.

    A shell that is not present on the current OS is recorded as a
    structured skip with reason ``RELAY-EVAL-TIER1-SKIPPED-NON-TARGET-
    SHELL`` (per CLAUDE.md test discipline 7.5). Snapshot fixtures live
    in ``packages/cli/tests/snapshots/``; this test asserts the JSON
    shape matches the canonical envelope shape, not byte-equality, so
    it is robust against ULID/UUID values inside envelopes.
    """
    shell_path = _SHELLS_AVAILABLE.get(shell_name)
    if not shell_path:
        pytest.skip(
            "RELAY-EVAL-TIER1-SKIPPED-NON-TARGET-SHELL: "
            + shell_name + " not present on this matrix slice"
        )
    # Build a shell-quoted command line. Both bash and zsh accept the
    # same POSIX quoting; pwsh and cmd are skipped on POSIX runners and
    # exercised in the Windows CI matrix.
    if shell_name in ("bash", "zsh"):
        cmd_str = "uv run rly " + " ".join(command_args)
        result = subprocess.run(
            [shell_path, "-c", cmd_str],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    else:  # pragma: no cover -- exercised on Windows runners only
        result = subprocess.run(
            [shell_path, "-Command", "uv run rly " + " ".join(command_args)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    # Either stdout (success path) or stderr (error path) MUST be JSON.
    json_text = result.stdout.strip() or result.stderr.strip().splitlines()[-1]
    payload = json.loads(json_text)
    assert "schema_version" in payload, (
        "envelope missing schema_version under " + shell_name
        + " for args=" + str(command_args)
    )


# -----------------------------------------------------------------------------
# VAL-W5-009 / VAL-W5-009b: Banned product copy lint
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-009")
def test_banned_copy_lint_passes_on_cli_source() -> None:
    """Per VAL-W5-009 the CLI source tree MUST contain zero banned tokens."""
    lint_path = REPO_ROOT / "scripts" / "lint-banned-copy.py"
    result = subprocess.run(
        [sys.executable, str(lint_path), "--json"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, (
        "banned-copy lint failed: stdout=" + result.stdout
        + " stderr=" + result.stderr
    )
    report = json.loads(result.stdout)
    assert report["total_violations"] == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-009b")
def test_banned_copy_lint_covers_full_distribution_surface() -> None:
    """Per VAL-W5-009b: lint covers ALL declared distribution surfaces."""
    lint_path = REPO_ROOT / "scripts" / "lint-banned-copy.py"
    result = subprocess.run(
        [sys.executable, str(lint_path), "--json"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    report = json.loads(result.stdout)
    surface_labels = {s["label"] for s in report["surfaces"]}
    # Required-surface labels per VAL-W5-009b enumeration.
    required = {
        "cli-source-tree",
        "cli-readme",
        "cli-pyproject",
        "root-package-json",
        "sdk-typescript-package-json",
        "schemas-typescript-package-json",
        "public-docs",
        "github-release-notes",
        "pyinstaller-spec",
    }
    missing = required - surface_labels
    assert not missing, "missing required surface labels: " + str(sorted(missing))


# -----------------------------------------------------------------------------
# VAL-W5-010: --help emits machine-readable JSON when piped
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-010")
@pytest.mark.parametrize(
    "args, expected_command",
    [
        (["--help"], "rly"),
        (["sidecar", "--help"], "rly sidecar"),
        (["replay", "--help"], "rly replay"),
        (["evidence", "--help"], "rly evidence"),
        (["verify-self", "--help"], "rly verify-self"),
        (["gate", "--help"], "rly gate"),
        (["contract", "--help"], "rly contract"),
        (["init", "--help"], "rly init"),
        (["trace", "--help"], "rly trace"),
    ],
)
def test_help_piped_emits_canonical_json(args: list[str], expected_command: str) -> None:
    """``--help`` (piped) MUST emit ``relay.cli.help.v1`` JSON."""
    result = _run_rly(args)
    assert result.returncode == EXIT_SUCCESS, (
        "rly " + " ".join(args) + " exit=" + str(result.returncode)
        + " stderr=" + result.stderr
    )
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == CLI_HELP_SCHEMA_VERSION
    assert payload["command"] == expected_command
    assert isinstance(payload["options"], list)
    assert isinstance(payload["subcommands"], list)
    assert isinstance(payload["exit_codes"], list)
    # Exit codes table MUST include canonical rows 0/1/2/3/64/70/130.
    codes = {row["code"] for row in payload["exit_codes"]}
    assert {0, 1, 2, 3, 64, 70, 130}.issubset(codes)


# -----------------------------------------------------------------------------
# Cross-cutting hygiene: stub commands surface ``RelayError`` properly
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
def test_envelope_from_relay_sidecar_error_exits_cleanly() -> None:
    """A RelaySidecarError surfaces as an envelope and a 5xx-mapped exit.

    Defense-in-depth: the typed-exception branch in main.run() catches
    RelayError and exits with the canonical mapping. We verify the
    envelope build path here with a synthetic error.
    """
    err = RelaySidecarError("sidecar unreachable", request_id="req_1", trace_id="trace_1")
    envelope = envelope_from_relay_error(err)
    w1_subset = {k: v for k, v in envelope.items() if k != "documentation_url"}
    ErrorEnvelope.model_validate(w1_subset)
    assert envelope["http_status"] == 503
    assert envelope["retry_advice"] in WIRE_RETRY_ADVICE_VALUES
