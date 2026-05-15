"""DB role tokens + grants for the W8.2 gate_decisions write path.

Canonical role tokens shared between:

  * the SQLite emulation in apps/local-sidecar/migrations/0009_*.sql
    (which uses the W2.5 ``_sidecar_role`` table as a single-row
    role-of-record), AND
  * the hosted Postgres mirror in
    services/gate-engine/migrations/ (real DB role grants).

VAL-W8-011 narrative: ``relay_gate_engine`` is the only role permitted
to ``INSERT INTO gate_decisions``. All other roles (sdk, worker,
eval_worker, replay_worker) have ``SELECT`` only. The OSS local profile
emulates this via a BEFORE INSERT trigger that consults
``_sidecar_role.role``; the hosted profile uses Postgres ``GRANT INSERT,
UPDATE ON gate_decisions TO relay_gate_engine`` and ``GRANT SELECT ON
gate_decisions TO <other roles>``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

# ---------------------------------------------------------------------------
# Canonical role tokens.
# ---------------------------------------------------------------------------
#
# These literals MUST match the strings used by:
#   * apps/local-sidecar/migrations/0009_gate_decision_writer.sql
#     (gate_decisions_role_check trigger condition)
#   * apps/local-sidecar/relay_sidecar/state_engine/retention.py
#     (ROLE_STATE_ENGINE / ROLE_RETENTION_ARCHIVE)
#   * the hosted Postgres migration in services/gate-engine/migrations/.
#
# Touching one without updating the others is a silent break. The
# integration test surface (apps/local-sidecar/tests/test_w8_2_*.py)
# imports from this module so any drift surfaces at test time.

ROLE_GATE_ENGINE: Final[str] = "relay_gate_engine"
ROLE_STATE_ENGINE: Final[str] = "relay_state_engine"
ROLE_RETENTION_ARCHIVE: Final[str] = "relay_retention_archive"
ROLE_ANTI_BYPASS: Final[str] = "relay_anti_bypass"

# Non-engine roles that have SELECT only on gate_decisions
# (VAL-W8-011 narrative). These tokens are documentation-only on the
# OSS local profile (SQLite has no role concept beyond the
# _sidecar_role single-row table); the hosted Postgres profile uses
# them as real role names in the migration's GRANT statements.
ROLE_SDK: Final[str] = "relay_sdk"
ROLE_WORKER: Final[str] = "relay_worker"
ROLE_EVAL_WORKER: Final[str] = "relay_eval_worker"
ROLE_REPLAY_WORKER: Final[str] = "relay_replay_worker"

NON_ENGINE_ROLES: Final[tuple[str, ...]] = (
    ROLE_SDK,
    ROLE_WORKER,
    ROLE_EVAL_WORKER,
    ROLE_REPLAY_WORKER,
)

# ---------------------------------------------------------------------------
# Hosted Postgres grants (declarative reference; not executed here).
# ---------------------------------------------------------------------------
#
# Documented for VAL-W8-011 evidence: the assertion's narrative names
# the four non-engine roles and asserts an INSERT from any of them
# fails with Postgres SQLSTATE 42501. The hosted migration applies
# these grants verbatim; this module exposes the SQL string so the
# compatibility test in services/gate-engine/tests/ can diff the
# migration against this canonical text.

POSTGRES_GATE_DECISIONS_GRANTS: Final[str] = """\
-- gate_decisions write privileges (VAL-W8-011).
-- Only relay_gate_engine may INSERT or UPDATE; all other roles SELECT only.
REVOKE ALL ON gate_decisions FROM PUBLIC;
GRANT INSERT, UPDATE ON gate_decisions TO relay_gate_engine;
GRANT SELECT ON gate_decisions TO relay_sdk;
GRANT SELECT ON gate_decisions TO relay_worker;
GRANT SELECT ON gate_decisions TO relay_eval_worker;
GRANT SELECT ON gate_decisions TO relay_replay_worker;
"""


# ---------------------------------------------------------------------------
# OSS local profile: _sidecar_role helper.
# ---------------------------------------------------------------------------
#
# The W8.2 decision_writer uses this helper to switch the connection's
# active role token to ``relay_gate_engine`` immediately before issuing
# the gate_decisions INSERT, then restore it to ``relay_state_engine``
# inside the same BEGIN IMMEDIATE..COMMIT block. The retention pass
# uses a sibling helper (relay_sidecar.state_engine.retention.
# set_sidecar_role) for the same single-row table; both paths take an
# asyncio.Lock around the borrow so two coroutines never observe each
# other's role.
#
# This helper is intentionally async-agnostic (synchronous): the W8.2
# writer calls it via ``await conn.execute(...)`` directly and does
# not need a context-manager wrapping that hides the COMMIT/ROLLBACK
# boundary. For a context-manager-style helper see
# relay_sidecar.state_engine.retention.set_sidecar_role.


_ROLE_UPDATE_SQL: Final[str] = "UPDATE _sidecar_role SET role = ? WHERE id = 0"


def role_update_sql() -> str:
    """Return the parameterized UPDATE for ``_sidecar_role.role``.

    Callers use ``await conn.execute(role_update_sql(), (role,))`` to
    switch the active role inside an open transaction. The single-row
    constraint (``id = 0``) is enforced by the W2.5 0007 migration's
    PRIMARY KEY CHECK.
    """
    return _ROLE_UPDATE_SQL


@contextmanager
def assert_role_token(role: str) -> Iterator[None]:
    """Validate ``role`` is one of the four canonical tokens.

    Raises:
        ValueError: if ``role`` is not one of the declared constants.

    The helper is a no-op context manager that fires the validation at
    entry; callers use it as a static guard before issuing the SQL
    UPDATE so a typoed literal is caught at the call site rather than
    silently inserted into the role-of-record.
    """
    allowed = {
        ROLE_GATE_ENGINE,
        ROLE_STATE_ENGINE,
        ROLE_RETENTION_ARCHIVE,
        ROLE_ANTI_BYPASS,
    }
    if role not in allowed:
        raise ValueError(
            f"role {role!r} is not a canonical role token; "
            f"valid tokens: {sorted(allowed)}"
        )
    yield None


__all__ = [
    "NON_ENGINE_ROLES",
    "POSTGRES_GATE_DECISIONS_GRANTS",
    "ROLE_ANTI_BYPASS",
    "ROLE_EVAL_WORKER",
    "ROLE_GATE_ENGINE",
    "ROLE_REPLAY_WORKER",
    "ROLE_RETENTION_ARCHIVE",
    "ROLE_SDK",
    "ROLE_STATE_ENGINE",
    "ROLE_WORKER",
    "assert_role_token",
    "role_update_sql",
]
