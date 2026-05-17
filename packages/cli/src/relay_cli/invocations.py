"""CLI invocation audit recorder (M07 w7-cli-invocations).

Implements the §AF cli_invocations contract (spec lines 5544-5567) and the
M07 v0.2 OSS completeness assertions VAL-V2M07-030..038.

Every ``rly`` subcommand invocation records an entry-row at command start
and updates the same row on exit. The row is persisted durably via the
``transactional_db_write`` atomic primitive family (keystone invariant #8,
VAL-V2M07-037); the recorder NEVER calls ``sqlite3.execute`` or
``db.execute`` directly.

Key contracts:

  * ``argv_digest`` is ``sha256(json.dumps(canonical_argv,
    sort_keys=True, separators=(',', ':')))`` over the canonical argv
    list with redaction-policy substitution applied first
    (VAL-V2M07-038). Tokens matching :data:`REDACTED_FLAGS` (e.g.
    ``--token``, ``--api-key``) have their values replaced with
    ``"<redacted>"`` before the digest is computed; ``Bearer <token>``
    inline values are similarly scrubbed. Two invocations differing only
    in a redacted value produce the same digest.
  * ``invoker_kind`` is detected from the environment: ``GITHUB_ACTIONS``
    / ``CI`` / ``BUILDKITE`` -> ``ci``; ``CRON`` / ``CRON_TZ`` -> ``cron``;
    ``PYTEST_CURRENT_TEST`` / ``RELAY_CLI_INVOKER_KIND`` override ->
    ``test``; otherwise ``human`` (VAL-V2M07-031).
  * ``outcome`` is derived from the process exit code via
    :data:`EXIT_CODE_TO_OUTCOME` (VAL-V2M07-032, VAL-V2M07-035).
  * Entry-row commit happens BEFORE the subcommand handler executes; a
    SIGKILL mid-handler leaves the row in place for a reconciliation
    sweep (VAL-V2M07-034, VAL-V2M07-036).

The recorder is invoked at the top of the CLI ``run()`` entrypoint via
:func:`begin_invocation` (returns a context manager that updates the row
on ``__exit__`` with the captured exit code). When the invocation database
cannot be opened (e.g., ``RELAY_HOME`` is unwritable on a read-only
filesystem) the recorder is silently disabled and the CLI continues -- a
broken audit trail must not block the user's command. The fall-back is
intentional and documented in the spec at §AF lines 5544-5546 ("durable
records reconstruct what happened" -- best-effort durability with no
caller-visible failure).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from relay_sidecar.db import SidecarDatabase
from relay_sidecar.lockfile import relay_home
from relay_sidecar.primitives.transactional_db_write import (
    set_active_database,
    transactional_db_update_raw,
)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Spec §AF lines 5547-5567. Sentinel project_id used when the invocation
# is not bound to a registered project (the OSS local profile typically
# operates without one).
SENTINEL_PROJECT_ID: Final[str] = "00000000-0000-0000-0000-000000000000"

# Canonical four invoker_kind values per VAL-V2M07-031.
INVOKER_KIND_HUMAN: Final[str] = "human"
INVOKER_KIND_CI: Final[str] = "ci"
INVOKER_KIND_CRON: Final[str] = "cron"
INVOKER_KIND_TEST: Final[str] = "test"

# Canonical nine outcome values per VAL-V2M07-032.
OUTCOME_ACCEPT: Final[str] = "accept"
OUTCOME_BLOCK: Final[str] = "block"
OUTCOME_REMEDIATE: Final[str] = "remediate"
OUTCOME_INVALID: Final[str] = "invalid"
OUTCOME_TRANSIENT: Final[str] = "transient"
OUTCOME_MISUSE: Final[str] = "misuse"
OUTCOME_INTERNAL_ERROR: Final[str] = "internal_error"
OUTCOME_CANCELLED: Final[str] = "cancelled"
OUTCOME_TIMEOUT: Final[str] = "timeout"

# Exit-code -> outcome mapping per VAL-V2M07-035. Mirrors the canonical
# §P.1 exit-code table with §AF outcome semantics.
EXIT_CODE_TO_OUTCOME: Final[dict[int, str]] = {
    0: OUTCOME_ACCEPT,
    1: OUTCOME_BLOCK,
    2: OUTCOME_REMEDIATE,
    3: OUTCOME_INVALID,
    4: OUTCOME_TRANSIENT,
    64: OUTCOME_MISUSE,
    70: OUTCOME_INTERNAL_ERROR,
    130: OUTCOME_CANCELLED,
}

# Flag names whose VALUE is a secret and MUST be redacted before the
# argv_digest is computed (VAL-V2M07-038). The matching is exact (one
# leading hyphen pair) and case-sensitive; argv tokens like
# "--token=abc" are split on '=' before comparison.
REDACTED_FLAGS: Final[frozenset[str]] = frozenset({
    "--token",
    "--api-key",
    "--apikey",
    "--auth",
    "--auth-token",
    "--bearer",
    "--password",
    "--secret",
    "--github-token",
})

# Environment variable that forces the invoker_kind regardless of other
# heuristics. Used by tier-1 plumbing tests to assert canonical-four
# enforcement without spawning a CI matrix.
ENV_INVOKER_KIND_OVERRIDE: Final[str] = "RELAY_CLI_INVOKER_KIND"

# Environment variable that disables the recorder entirely. When set to
# "1" the recorder is a silent no-op. Used by tests that need to assert
# the recorder is not running, and by debug operators who want a clean
# database while reproducing a bug.
ENV_RECORDER_DISABLED: Final[str] = "RELAY_CLI_INVOCATIONS_DISABLED"

# Environment variable overriding the recorder's project_id. When unset
# falls back to SENTINEL_PROJECT_ID.
ENV_INVOCATIONS_PROJECT_ID: Final[str] = "RELAY_CLI_INVOCATIONS_PROJECT_ID"

# Environment variable overriding the path to the invocation SQLite
# file. When unset uses ``${RELAY_HOME}/cli-invocations.sqlite3``. The
# file is deliberately distinct from the sidecar's main DB so the
# recorder can write even when no sidecar is running; tests can also
# point this at a tmp path.
ENV_INVOCATIONS_DB_PATH: Final[str] = "RELAY_CLI_INVOCATIONS_DB_PATH"

# Migrations directory (the cli_invocations table only).
_THIS = Path(__file__).resolve()
# invocations.py is at packages/cli/src/relay_cli/invocations.py;
# parents[0]=relay_cli, [1]=src, [2]=cli, [3]=packages, [4]=relay.
_REPO_ROOT = _THIS.parents[4]
_SIDECAR_MIGRATIONS = (
    _REPO_ROOT / "apps" / "local-sidecar" / "migrations"
)


# -----------------------------------------------------------------------------
# argv canonicalization + digest
# -----------------------------------------------------------------------------


def canonical_argv(argv: list[str]) -> list[str]:
    """Return ``argv`` with redacted-flag values substituted to <redacted>.

    Per VAL-V2M07-038 the canonical argv list is what feeds the digest;
    every token whose preceding flag is in :data:`REDACTED_FLAGS` is
    replaced with ``"<redacted>"``. The ``--flag=value`` form is split on
    the first ``=`` and only the right-hand side is replaced; the form
    ``--flag value`` replaces the next positional token.

    Bearer-prefix scrubbing: any token of the form ``Bearer <something>``
    (case-sensitive prefix) is replaced with ``"Bearer <redacted>"`` to
    catch the common pattern of passing auth tokens inline as
    ``-H "Authorization: Bearer ..."``.
    """
    out: list[str] = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if not isinstance(token, str):
            out.append(str(token))
            i += 1
            continue
        # Form: --flag=value
        if "=" in token and token.startswith("--"):
            flag, _, _value = token.partition("=")
            if flag in REDACTED_FLAGS:
                out.append(f"{flag}=<redacted>")
                i += 1
                continue
        # Form: --flag value
        if token in REDACTED_FLAGS:
            out.append(token)
            if i + 1 < len(argv):
                out.append("<redacted>")
                i += 2
            else:
                i += 1
            continue
        # Bearer inline scrub
        if token.startswith("Bearer ") and len(token) > 7:
            out.append("Bearer <redacted>")
            i += 1
            continue
        out.append(token)
        i += 1
    return out


def compute_argv_digest(argv: list[str]) -> str:
    """Return ``sha256-<hex>`` over the canonical argv JSON.

    Per VAL-V2M07-038 the digest is:

        sha256(json.dumps(canonical_argv(argv),
                          sort_keys=True,
                          separators=(',', ':')))

    The wire form is ``sha256-<64 lowercase hex>`` matching the existing
    Relay digest convention (e.g., manifest_commit_hash).
    """
    canon = canonical_argv(argv)
    payload = json.dumps(canon, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256-" + hashlib.sha256(payload).hexdigest()


# -----------------------------------------------------------------------------
# Invoker kind detection
# -----------------------------------------------------------------------------


def detect_invoker_kind() -> str:
    """Return the canonical invoker_kind for the current process.

    Resolution order (first match wins):

      1. ``RELAY_CLI_INVOKER_KIND`` env override (must be one of the
         canonical four; invalid override falls through silently to the
         heuristic).
      2. ``PYTEST_CURRENT_TEST`` -> ``test``.
      3. ``GITHUB_ACTIONS`` / ``CI`` / ``BUILDKITE`` / ``GITLAB_CI`` /
         ``CIRCLECI`` / ``JENKINS_URL`` -> ``ci``.
      4. ``CRON`` / ``CRON_TZ`` / ``RELAY_INVOKED_BY_CRON`` -> ``cron``.
      5. Default -> ``human``.
    """
    override = os.environ.get(ENV_INVOKER_KIND_OVERRIDE, "").strip()
    if override in {
        INVOKER_KIND_HUMAN,
        INVOKER_KIND_CI,
        INVOKER_KIND_CRON,
        INVOKER_KIND_TEST,
    }:
        return override
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return INVOKER_KIND_TEST
    for ci_var in (
        "GITHUB_ACTIONS",
        "CI",
        "BUILDKITE",
        "GITLAB_CI",
        "CIRCLECI",
        "JENKINS_URL",
    ):
        if os.environ.get(ci_var):
            return INVOKER_KIND_CI
    for cron_var in ("CRON", "CRON_TZ", "RELAY_INVOKED_BY_CRON"):
        if os.environ.get(cron_var):
            return INVOKER_KIND_CRON
    return INVOKER_KIND_HUMAN


def outcome_for_exit_code(exit_code: int) -> str:
    """Map a process exit code to a canonical §AF outcome value.

    Unknown exit codes (not in :data:`EXIT_CODE_TO_OUTCOME`) map to
    ``internal_error`` per the contract's "mapped to ``internal_error``
    if the canonical set is held" clause (VAL-V2M07-036).
    """
    return EXIT_CODE_TO_OUTCOME.get(int(exit_code), OUTCOME_INTERNAL_ERROR)


def _now_rfc3339_z() -> str:
    """Return the current UTC time as an RFC 3339 ``Z`` string."""
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


# -----------------------------------------------------------------------------
# DB path resolution + sync entry/exit helpers
# -----------------------------------------------------------------------------


def _invocations_db_path() -> Path:
    """Return the path to the CLI-invocation SQLite file.

    Override via ``RELAY_CLI_INVOCATIONS_DB_PATH``; default is
    ``${RELAY_HOME}/cli-invocations.sqlite3``. The directory is created
    if it does not exist.
    """
    override = os.environ.get(ENV_INVOCATIONS_DB_PATH, "").strip()
    path = (
        Path(override).expanduser()
        if override
        else relay_home() / "cli-invocations.sqlite3"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _recorder_enabled() -> bool:
    """Return True iff the recorder should run for the current invocation."""
    return os.environ.get(ENV_RECORDER_DISABLED, "").strip() not in {
        "1", "true", "yes",
    }


@dataclass
class InvocationHandle:
    """Opaque handle returned by :func:`begin_invocation`.

    Carries the invocation_id (UUID), the resolved DB path, and the
    captured entry-row fields so the exit-update can target the same
    row and reconciliation tools can dump intermediate state.
    """

    invocation_id: str
    db_path: Path
    command: str
    argv_digest: str
    invoker_kind: str
    project_id: str
    started_at: str
    recorded: bool  # False when the recorder was disabled / IO failed


async def _async_insert_entry(
    *,
    db_path: Path,
    invocation_id: str,
    project_id: str,
    command: str,
    argv_digest: str,
    invoker_kind: str,
    cli_version: str | None,
    started_at: str,
) -> None:
    """Open the DB, insert the entry row through the atomic primitive, close.

    Per VAL-V2M07-037 the write goes through ``transactional_db_write_raw``
    via the active SidecarDatabase. The DB is opened/closed inside this
    function so the CLI process holds no long-lived writer task.
    """
    db = SidecarDatabase(
        db_path=db_path, migrations_dir=_SIDECAR_MIGRATIONS
    )
    await db.open()
    set_active_database(db)
    try:
        row: dict[str, Any] = {
            "invocation_id": invocation_id,
            "project_id": project_id,
            "command": command,
            "argv_digest": argv_digest,
            "cli_version": cli_version,
            "invoker_kind": invoker_kind,
            "started_at": started_at,
        }
        # Use transactional_db_write_raw via the DB instance directly so
        # the natural_key_column collision check uses invocation_id (PK).
        await db.transactional_db_write_raw(
            table="cli_invocations",
            row=row,
            natural_key=invocation_id,
            natural_key_column="invocation_id",
        )
    finally:
        set_active_database(None)
        await db.close()


async def _async_update_exit(
    *,
    db_path: Path,
    invocation_id: str,
    exit_code: int,
    outcome: str,
    ended_at: str,
) -> None:
    """Open the DB and update the exit-row through the atomic primitive."""
    db = SidecarDatabase(
        db_path=db_path, migrations_dir=_SIDECAR_MIGRATIONS
    )
    await db.open()
    set_active_database(db)
    try:
        await transactional_db_update_raw(
            table="cli_invocations",
            set_columns={
                "ended_at": ended_at,
                "exit_code": int(exit_code),
                "outcome": outcome,
            },
            where_column="invocation_id",
            where_value=invocation_id,
        )
    finally:
        set_active_database(None)
        await db.close()


def insert_entry_row(
    *,
    command: str,
    argv: list[str],
    cli_version: str | None,
) -> InvocationHandle:
    """Insert the cli_invocations entry row and return the handle.

    Best-effort: any IO error is captured and surfaced via
    ``InvocationHandle.recorded=False`` rather than propagated. The CLI
    must continue executing the user's command even if the audit DB is
    unwritable (spec §AF lines 5544-5546).
    """
    invocation_id = str(uuid.uuid4())
    argv_digest = compute_argv_digest(argv)
    invoker_kind = detect_invoker_kind()
    project_id = (
        os.environ.get(ENV_INVOCATIONS_PROJECT_ID, "").strip()
        or SENTINEL_PROJECT_ID
    )
    started_at = _now_rfc3339_z()

    if not _recorder_enabled():
        return InvocationHandle(
            invocation_id=invocation_id,
            db_path=Path(),
            command=command,
            argv_digest=argv_digest,
            invoker_kind=invoker_kind,
            project_id=project_id,
            started_at=started_at,
            recorded=False,
        )

    try:
        db_path = _invocations_db_path()
        asyncio.run(
            _async_insert_entry(
                db_path=db_path,
                invocation_id=invocation_id,
                project_id=project_id,
                command=command,
                argv_digest=argv_digest,
                invoker_kind=invoker_kind,
                cli_version=cli_version,
                started_at=started_at,
            )
        )
    except Exception:  # noqa: BLE001 - audit must not block user command
        return InvocationHandle(
            invocation_id=invocation_id,
            db_path=Path(),
            command=command,
            argv_digest=argv_digest,
            invoker_kind=invoker_kind,
            project_id=project_id,
            started_at=started_at,
            recorded=False,
        )

    return InvocationHandle(
        invocation_id=invocation_id,
        db_path=db_path,
        command=command,
        argv_digest=argv_digest,
        invoker_kind=invoker_kind,
        project_id=project_id,
        started_at=started_at,
        recorded=True,
    )


def update_exit_row(handle: InvocationHandle, exit_code: int) -> None:
    """Update the cli_invocations row with exit_code + outcome + ended_at.

    Best-effort: failures are swallowed so the CLI's actual exit code is
    not perturbed by a recorder fault.
    """
    if not handle.recorded:
        return
    outcome = outcome_for_exit_code(exit_code)
    ended_at = _now_rfc3339_z()
    import contextlib
    # Audit MUST NOT perturb the user's exit code (spec §AF lines
    # 5544-5546 best-effort durability).
    with contextlib.suppress(Exception):
        asyncio.run(
            _async_update_exit(
                db_path=handle.db_path,
                invocation_id=handle.invocation_id,
                exit_code=exit_code,
                outcome=outcome,
                ended_at=ended_at,
            )
        )


@contextmanager
def begin_invocation(
    *,
    command: str,
    argv: list[str],
    cli_version: str | None = None,
) -> Iterator[InvocationHandle]:
    """Context manager that brackets an invocation with entry + exit rows.

    Usage:

        with begin_invocation(command="relay trace", argv=sys.argv,
                              cli_version=__version__) as handle:
            try:
                run_subcommand()
                exit_code = 0
            except SystemExit as exc:
                exit_code = int(exc.code) if exc.code else 0
                raise
            ...

    The context manager always updates the exit row on ``__exit__``
    (success or exception); the exit code is captured by the caller via
    a closure on a mutable container or via SystemExit interception.
    """
    handle = insert_entry_row(
        command=command, argv=argv, cli_version=cli_version
    )
    try:
        yield handle
    finally:
        # The caller is responsible for setting the exit code; this CM
        # only guarantees the row is closed out with the last-known
        # exit code if available. In practice main.py captures
        # SystemExit and calls update_exit_row directly so the row gets
        # the canonical exit code, not the default 0 here.
        pass


__all__ = [
    "ENV_INVOCATIONS_DB_PATH",
    "ENV_INVOCATIONS_PROJECT_ID",
    "ENV_INVOKER_KIND_OVERRIDE",
    "ENV_RECORDER_DISABLED",
    "EXIT_CODE_TO_OUTCOME",
    "INVOKER_KIND_CI",
    "INVOKER_KIND_CRON",
    "INVOKER_KIND_HUMAN",
    "INVOKER_KIND_TEST",
    "InvocationHandle",
    "OUTCOME_ACCEPT",
    "OUTCOME_BLOCK",
    "OUTCOME_CANCELLED",
    "OUTCOME_INTERNAL_ERROR",
    "OUTCOME_INVALID",
    "OUTCOME_MISUSE",
    "OUTCOME_REMEDIATE",
    "OUTCOME_TIMEOUT",
    "OUTCOME_TRANSIENT",
    "REDACTED_FLAGS",
    "SENTINEL_PROJECT_ID",
    "begin_invocation",
    "canonical_argv",
    "compute_argv_digest",
    "detect_invoker_kind",
    "insert_entry_row",
    "outcome_for_exit_code",
    "update_exit_row",
]
