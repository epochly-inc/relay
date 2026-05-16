"""``rly verify-self`` command (W5.5 VAL-W5-031..040).

Wires the invariant runner + the §K-conformant evidence bundle writer
into the canonical Typer command surface.

Behavior:

  * Stdout JSON envelope: ``{schema_version, overall, checks,
    invariants_checked, failures, duration_ms}`` per VAL-W5-031.
  * Exit 0 iff ``overall == "pass"`` AND ``failures == 0``.
  * On any single failing check: exit 1, with a structured stderr
    envelope listing each failed check and its top-level finding count.
  * On internal failure (a checker raised, malformed envelope, etc.):
    exit 70 with ``RELAY-CLI-VERIFY-SELF-INTERNAL`` stderr envelope.
    Stdout still emits a valid JSON envelope ``{overall: "fail", error:
    <envelope>, checks: []}`` per VAL-W5-039.
  * Always writes a §K-conformant evidence bundle to
    ``${RELAY_HOME}/evidence/verify-self/<timestamp>-<run_id>.json``
    (VAL-W5-040). Bundle write failure does NOT prevent the JSON
    envelope from being emitted, but it DOES make the overall outcome
    ``fail`` because the contract gate depends on bundle presence.

Per CLAUDE.md keystone invariant #1 the CLI never writes ``run_results``
or ``gate_decisions`` -- this command computes the verification result
locally and reports it; an external gate engine (W6+) will treat the
emitted bundle as a draft submitted to the control plane.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Final

import typer

from ..errors import build_envelope, emit_envelope
from ..evidence_bundle import BundleInputs, write_bundle
from ..exit_codes import (
    EXIT_4XX_BLOCK,
    EXIT_SUCCESS,
    EXIT_UNCAUGHT_INTERNAL,
)
from ..invariants.runner import (
    VERIFY_SELF_RESULT_SCHEMA,
    run_all_checks,
)

# -----------------------------------------------------------------------------
# Wire codes
# -----------------------------------------------------------------------------

RELAY_CLI_VERIFY_SELF_FAIL: Final[str] = "RELAY-CLI-VERIFY-SELF-FAIL"
RELAY_CLI_VERIFY_SELF_INTERNAL: Final[str] = "RELAY-CLI-VERIFY-SELF-INTERNAL"
RELAY_CLI_VERIFY_SELF_BUNDLE_WRITE_FAILED: Final[str] = (
    "RELAY-CLI-VERIFY-SELF-BUNDLE-WRITE-FAILED"
)
RELAY_CLI_VERIFY_SELF_NO_TREE: Final[str] = (
    "RELAY-CLI-VERIFY-SELF-NO-RELAY-TREE"
)

# Exit code used when the verifier cannot locate a relay working tree
# from the resolved repo root. POSIX-2 ("misuse of shell builtins" /
# "incorrect invocation") matches the user-facing intent: "you ran this
# in the wrong directory" -- distinct from EXIT_SUCCESS (0) which would
# falsely claim every invariant passed, and from EXIT_4XX_BLOCK (1)
# which would falsely claim an invariant violation was found.
EXIT_NO_RELAY_TREE: Final[int] = 2


# -----------------------------------------------------------------------------
# Repo root resolution
# -----------------------------------------------------------------------------
#
# The verifier scans the relay/ working tree. Resolution policy:
#   1. ``--repo-root`` flag (test seam) -> use verbatim
#   2. ``RELAY_VERIFY_SELF_REPO_ROOT`` env var (test seam) -> use verbatim
#   3. Otherwise: walk upward from the current working directory looking
#      for the first directory containing both ``packages/`` and
#      ``apps/`` (the relay/ workspace marker). Falls back to CWD if
#      none found, which would yield zero findings (empty scan); the
#      caller sees overall=pass with zero invariants_checked-failures
#      counts that the test surface can detect.

ENV_REPO_ROOT: Final[str] = "RELAY_VERIFY_SELF_REPO_ROOT"

# Directories the verifier scans (see ``relay_cli.invariants.util.SCAN_ROOTS``).
# Duplicated here only for the "no relay tree detected" check because the
# CLI command must report exit 2 BEFORE the invariant runner imports
# happen to walk into a nonexistent tree.
RELAY_TREE_MARKERS: Final[tuple[str, ...]] = ("packages", "apps")


def _looks_like_relay_root(p: Path) -> bool:
    return all((p / name).is_dir() for name in RELAY_TREE_MARKERS)


def _resolve_repo_root(
    explicit: Path | None,
) -> tuple[Path, bool]:
    """Resolve the relay/ working-tree root.

    Returns ``(resolved_path, detected)`` where ``detected`` is True iff
    the resolution found a directory that actually looks like a relay
    working tree (contains every entry in :data:`RELAY_TREE_MARKERS`).

    An explicit ``--repo-root`` flag or the ``RELAY_VERIFY_SELF_REPO_ROOT``
    environment variable is honored verbatim and reported as ``detected``
    when the markers are present. If the caller passes an explicit path
    that does NOT contain the markers, ``detected`` is False so the
    command surface can emit the structured ``no_relay_tree_detected``
    envelope rather than silently scanning zero files and exiting 0.
    """
    if explicit is not None:
        resolved = explicit.resolve()
        return (resolved, _looks_like_relay_root(resolved))
    env_value = os.environ.get(ENV_REPO_ROOT, "").strip()
    if env_value:
        resolved = Path(env_value).expanduser().resolve()
        return (resolved, _looks_like_relay_root(resolved))
    here = Path.cwd().resolve()
    candidate = here
    for _ in range(8):  # walk up at most 8 levels
        if _looks_like_relay_root(candidate):
            return (candidate, True)
        if candidate.parent == candidate:
            break
        candidate = candidate.parent
    # Fell through: no relay tree found. Return CWD so callers can
    # report the path they were standing in, with ``detected=False``.
    return (here, False)


# -----------------------------------------------------------------------------
# Result-to-envelope projection
# -----------------------------------------------------------------------------


def _build_pass_fail_stderr_envelope(
    *, runner_dict: dict[str, Any]
) -> dict[str, Any]:
    """Build the structured stderr envelope for a ``fail`` overall.

    Lists every failed check with its name, status, and finding count.
    """
    failed: list[dict[str, Any]] = []
    for c in runner_dict.get("checks", []):
        if c.get("status") != "pass":
            failed.append(
                {
                    "name": c.get("name"),
                    "status": c.get("status"),
                    "details_count": len(c.get("details", [])),
                }
            )
    return build_envelope(
        code=RELAY_CLI_VERIFY_SELF_FAIL,
        http_status=400,
        message=(
            f"verify-self FAIL: {runner_dict.get('failures')} of "
            f"{runner_dict.get('invariants_checked')} invariants reported "
            f"violations."
        ),
        blocked_surface="rly verify-self",
        retry_advice="after_fix",
        details={"failed_checks": failed},
    )


def _build_internal_stderr_envelope(
    *, exception_class: str, message: str, check_name: str | None = None
) -> dict[str, Any]:
    """Build the RELAY-CLI-VERIFY-SELF-INTERNAL stderr envelope (VAL-W5-039)."""
    details: dict[str, Any] = {"exception_class": exception_class}
    if check_name is not None:
        details["check_name"] = check_name
    return build_envelope(
        code=RELAY_CLI_VERIFY_SELF_INTERNAL,
        http_status=500,
        message=f"verify-self internal failure: {message}",
        blocked_surface="rly verify-self",
        retry_advice="do_not_retry",
        details=details,
    )


# -----------------------------------------------------------------------------
# Typer command callback
# -----------------------------------------------------------------------------


def cmd_verify_self(
    repo_root: str = typer.Option(
        "",
        "--repo-root",
        help="Override the repo-root directory scanned by the verifier.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Force JSON output even when stdout is a TTY.",
    ),
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME for the evidence bundle write path.",
    ),
) -> None:
    """Run every checked invariant and emit a §K-conformant evidence bundle.

    Exit 0 iff every invariant is green; exit 1 on any failure with a
    structured stderr envelope; exit 70 on internal failure (no Python
    traceback). Writes the bundle on every invocation (pass or fail).
    """
    # The ``--json`` flag is accepted for parity with other rly
    # commands; stdout JSON is ALWAYS emitted by verify-self because
    # the canonical envelope shape is machine-consumed. The flag is
    # therefore an alias for "default behavior" and emits a one-line
    # JSON record on stdout regardless of TTY.
    _ = json_output

    repo_root_path = Path(repo_root).expanduser() if repo_root else None
    home_path = Path(home).expanduser() if home else None

    resolved_root, tree_detected = _resolve_repo_root(repo_root_path)

    # ----- Step 0: short-circuit if no relay working tree is detected -----
    # Without this, the runner walks an empty directory, every checker
    # produces zero findings, ``overall == "pass"``, and the command
    # exits 0 -- silently claiming every invariant is green when in
    # fact no invariant was meaningfully checked. Emit a structured
    # ``no_relay_tree_detected`` envelope on stdout, document the paths
    # we tried, and exit 2 ("misuse / wrong invocation directory").
    if not tree_detected:
        checked_paths = [
            str(resolved_root / marker) for marker in RELAY_TREE_MARKERS
        ]
        envelope = {
            "schema_version": VERIFY_SELF_RESULT_SCHEMA,
            "overall": "unknown",
            "reason": "no_relay_tree_detected",
            "checked_paths": checked_paths,
            "resolved_root": str(resolved_root),
            "code": RELAY_CLI_VERIFY_SELF_NO_TREE,
        }
        stdout_bytes = (
            json.dumps(envelope, separators=(",", ":"), ensure_ascii=True) + "\n"
        ).encode("utf-8")
        sys.stdout.buffer.write(stdout_bytes)
        sys.stdout.flush()
        stderr_envelope = build_envelope(
            code=RELAY_CLI_VERIFY_SELF_NO_TREE,
            http_status=400,
            message=(
                "verify-self could not locate a relay working tree at "
                f"{resolved_root!s}; expected directories: "
                + ", ".join(RELAY_TREE_MARKERS)
                + ". Run from inside the relay/ repo or pass --repo-root."
            ),
            blocked_surface="rly verify-self",
            retry_advice="after_fix",
            details={
                "resolved_root": str(resolved_root),
                "checked_paths": checked_paths,
            },
        )
        emit_envelope(stderr_envelope)
        raise typer.Exit(code=EXIT_NO_RELAY_TREE)

    # ----- Step 1: run the invariant suite -----
    runner_dict: dict[str, Any]
    internal_failure_envelope: dict[str, Any] | None = None
    try:
        runner_result = run_all_checks(resolved_root)
        runner_dict = runner_result.to_dict()
    except Exception as exc:  # noqa: BLE001 - VAL-W5-039 wrap
        internal_failure_envelope = _build_internal_stderr_envelope(
            exception_class=type(exc).__name__,
            message=str(exc),
        )
        runner_dict = {
            "schema_version": VERIFY_SELF_RESULT_SCHEMA,
            "overall": "fail",
            "checks": [],
            "invariants_checked": 0,
            "failures": 1,
            "duration_ms": 0,
            "error": internal_failure_envelope,
        }

    # ----- Step 2: serialize stdout JSON -----
    stdout_bytes = (
        json.dumps(
            runner_dict, separators=(",", ":"), ensure_ascii=True
        )
        + "\n"
    ).encode("utf-8")

    # Determine the exit code from the runner result.
    if internal_failure_envelope is not None:
        exit_code = EXIT_UNCAUGHT_INTERNAL
    elif runner_dict.get("overall") == "pass" and int(
        runner_dict.get("failures", 0)
    ) == 0:
        exit_code = EXIT_SUCCESS
    else:
        exit_code = EXIT_4XX_BLOCK

    # ----- Step 3: write evidence bundle (VAL-W5-040) -----
    # Bundle write failure must not eat the stdout JSON envelope (the
    # caller may still want to inspect it), but it MUST surface as a
    # structured stderr envelope and an exit-code escalation when the
    # rest of the run was a pass.
    bundle_write_envelope: dict[str, Any] | None = None
    try:
        # The stderr buffer is empty at this point (we have not yet
        # emitted the fail/internal envelope). Stamp empty bytes so the
        # stderr_sha256 in the bundle reflects the "no stderr emitted"
        # observation.
        write_bundle(
            BundleInputs(
                stdout_bytes=stdout_bytes,
                stderr_bytes=b"",
                exit_code=exit_code,
            ),
            home=home_path,
        )
    except Exception as exc:  # noqa: BLE001 - bundle errors get an envelope
        bundle_write_envelope = build_envelope(
            code=RELAY_CLI_VERIFY_SELF_BUNDLE_WRITE_FAILED,
            http_status=500,
            message=f"verify-self could not write evidence bundle: {exc}",
            blocked_surface="rly verify-self",
            retry_advice="after_fix",
            details={"exception_class": type(exc).__name__},
        )
        # Bundle write failure forces a non-zero exit.
        if exit_code == EXIT_SUCCESS:
            exit_code = EXIT_UNCAUGHT_INTERNAL

    # ----- Step 4: emit stdout JSON -----
    sys.stdout.buffer.write(stdout_bytes)
    sys.stdout.flush()

    # ----- Step 5: emit stderr envelope (if any) -----
    if internal_failure_envelope is not None:
        emit_envelope(internal_failure_envelope)
    elif runner_dict.get("overall") != "pass":
        emit_envelope(
            _build_pass_fail_stderr_envelope(runner_dict=runner_dict)
        )
    if bundle_write_envelope is not None:
        emit_envelope(bundle_write_envelope)

    # ----- Step 6: exit -----
    raise typer.Exit(code=exit_code)


__all__ = [
    "EXIT_NO_RELAY_TREE",
    "RELAY_CLI_VERIFY_SELF_BUNDLE_WRITE_FAILED",
    "RELAY_CLI_VERIFY_SELF_FAIL",
    "RELAY_CLI_VERIFY_SELF_INTERNAL",
    "RELAY_CLI_VERIFY_SELF_NO_TREE",
    "cmd_verify_self",
]
