#!/usr/bin/env python3
"""Atomic-persistence bypass lint (manifest ``lint-no-bypass-primitives``).

CLAUDE.md keystone invariant #8 + spec section H: business logic NEVER
calls a raw persistence operation directly. Every persistent write goes
through exactly one of the four atomic-persistence primitives --
``transactional_db_write``, ``object_put_with_digest``,
``queue_publish_with_idempotency``, ``local_atomic_file_write`` (plus the
local-profile ``local_two_layer_locked_write`` / ``acquire_or_attach``).
The banned direct calls are:

    db.execute(        s3.put_object(        queue.send(
    open(..., 'w' | 'wb' | 'a' | ...)   # any write-mode open()

This guard greps every source file under ``packages/``, ``services/``,
``apps/`` for those banned literals OUTSIDE the primitives' own
definition modules, and exits non-zero on any match.

Implementation: this command is the manifest-declared, standalone entry
point for the SAME invariant the ``rly verify-self`` runner enforces via
``relay_cli.invariants.atomic_primitives``. Rather than re-implement the
detection regex and its exclusion intent (which would risk drift between
two copies of a load-bearing guard), this script delegates to that
checker -- the single source of truth for the VAL-W5-034 pattern. The
checker already:

  * matches ``db\\.execute\\(|s3\\.put_object\\(|queue\\.send\\(|
    \\bopen\\([^)]*['"]w['"]`` (the contract regex);
  * scans ``packages/`` + ``services/`` (when present; the OSS profile
    has no ``services/`` tree yet -- a missing root contributes zero
    files and is not a failure) + ``apps/``;
  * excludes any ``primitives/`` directory (where the atomic primitives
    THEMSELVES legitimately call the raw operations), tests, the
    vendored ``packages/acef/upstream`` tree, generated codegen output,
    and the verifier's own self-mentioning source;
  * skips matches inside comments / docstrings / backtick-quoted
    references so prose mentions of the banned literal do not false-
    positive.

The CLI package is a uv-workspace member, so it is importable under
``uv run`` (the manifest invokes this script as ``uv run python
scripts/lint-no-bypass-primitives.py``). If the import is unavailable
(e.g. the workspace is not synced) the script fails LOUD with a non-zero
exit and a diagnostic -- it never silently passes.

Output is ASCII-only (``[OK]`` / ``[FAIL]``). The sole side effect is
the exit code: 0 = clean, 1 = at least one violation, 2 = the checker
could not be loaded (environment error).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Final

# Repo root -- this script lives at <repo>/scripts/.
REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent

# The four sanctioned atomic-persistence primitives (for the report and
# the remediation hint). Mirrors CLAUDE.md keystone invariant #8.
ATOMIC_PRIMITIVES: Final[tuple[str, ...]] = (
    "transactional_db_write",
    "object_put_with_digest",
    "queue_publish_with_idempotency",
    "local_atomic_file_write",
)


def _ensure_cli_importable() -> None:
    """Make ``relay_cli.invariants`` importable.

    Under ``uv run`` the workspace members are installed into the
    environment, so ``import relay_cli`` resolves directly. As a
    defensive fallback (e.g. running the script with a bare interpreter
    against a synced ``.venv``) we also add the CLI package's ``src``
    directory and the ``verify_self`` source root to ``sys.path`` if the
    direct import is not yet resolvable. This never mutates global state
    beyond ``sys.path`` and is idempotent.
    """
    try:
        import relay_cli.invariants.atomic_primitives  # noqa: F401
        return
    except ImportError:
        pass
    cli_src = REPO_ROOT / "packages" / "cli" / "src"
    if cli_src.is_dir():
        p = str(cli_src)
        if p not in sys.path:
            sys.path.insert(0, p)


def main(argv: list[str]) -> int:
    """Entry point.

    Returns 0 on clean lint, 1 on any violation, 2 if the underlying
    invariant checker cannot be loaded (a real environment failure that
    must NOT be reported as a pass).
    """
    json_output = "--json" in argv

    _ensure_cli_importable()
    try:
        from relay_cli.invariants.atomic_primitives import run as run_check
        from relay_cli.invariants.util import finding_to_dict
    except ImportError as exc:
        # Fail loud. A missing checker is an environment error, not a
        # clean tree. Exit code 2 distinguishes it from a real violation.
        msg = (
            "[FAIL] lint-no-bypass-primitives: could not import the "
            "atomic-primitives invariant checker "
            f"(relay_cli.invariants.atomic_primitives): {exc}. "
            "Run `uv sync --all-packages` first."
        )
        if json_output:
            print(
                json.dumps(
                    {
                        "schema_version": "relay.lint.no_bypass_primitives.v1",
                        "exit_code": 2,
                        "error": "checker_import_failed",
                        "detail": str(exc),
                    },
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
            )
        else:
            print(msg)
        return 2

    _check_name, findings = run_check(REPO_ROOT)
    total = len(findings)

    if json_output:
        report = {
            "schema_version": "relay.lint.no_bypass_primitives.v1",
            "exit_code": 0 if total == 0 else 1,
            "total_violations": total,
            "atomic_primitives": list(ATOMIC_PRIMITIVES),
            "findings": [finding_to_dict(f) for f in findings],
        }
        print(json.dumps(report, separators=(",", ":"), ensure_ascii=True))
    else:
        if total == 0:
            print(
                "[OK] no-bypass-primitives lint: 0 banned direct-write "
                "calls outside the four atomic primitives"
            )
        else:
            for f in findings:
                print(
                    f"[FAIL] {f.file}:{f.line} matched {f.pattern!r} "
                    f"({f.code})"
                )
                print(f"       fix: {f.suggested_fix}")
            print(
                "[FAIL] no-bypass-primitives lint: {n} violation(s); route "
                "writes through one of: {prims}".format(
                    n=total, prims=", ".join(ATOMIC_PRIMITIVES)
                )
            )
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
