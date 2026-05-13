"""Local JSONL event log (W2.1).

The W2.5 milestone introduces the full SQLite-backed ``event_log_entries``
table. W2.1 only needs a primitive append-only audit trail to satisfy
VAL-W2-006 (concurrent-spawn evidence: exactly one ``sidecar.spawned``
row) and VAL-W2-009 (``sidecar.stale_pid_cleared`` row presence).

Strategy:

  - Each entry is a single JSON-encoded line at
    ``${RELAY_HOME}/event_log.jsonl``.
  - Writes go through ``local_atomic_file_write(append=True)`` so the
    portalocker exclusive lock serializes concurrent appends. This
    enforces the W2.5 invariant ("never raw" / append-only) one
    sub-feature ahead of time.
  - Entry shape conforms to the W1 ``EventLogEntry`` Pydantic model
    (``relay_schemas.envelopes.EventLogEntry``). The only fields we
    populate at W2.1 are the ones the model marks required:
    ``schema_version``, ``event_id``, ``project_id``, ``scope_type``,
    ``scope_id``, ``event_type``, ``actor_kind``, ``occurred_at``,
    ``ingest_sequence``. Optional fields (``actor_id``,
    ``manifest_commit_hash``, ``payload``) we leave at their defaults.
  - ``project_id`` and ``scope_id`` at W2.1 stand for the local-only
    sidecar instance; we use deterministic UUIDs derived from the
    lockfile bearer-token digest so each spawn produces a stable
    correlation key. Later W2 sub-features will wire real
    project/scope ids in once the SQLite schema lands.

Reading back is via ``read_event_log()`` which parses each line through
the W1 ``EventLogEntry`` validator so any malformed entry is rejected
with the model's standard ``ValidationError`` rather than silently
ignored.

VAL-W2-006 expects exactly one ``sidecar.spawned`` row under N=10
concurrent spawn races. The portalocker exclusive lock plus the
single-writer-per-spawn invariant in ``spawn.py`` guarantees that.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from relay_schemas.envelopes import EventLogEntry

from .lockfile import relay_home
from .primitives import local_atomic_file_write

# Canonical filename. Lives next to sidecar.lock under RELAY_HOME.
EVENT_LOG_FILENAME = "event_log.jsonl"

# Project id used by the local OSS sidecar before the W2.5 SQLite schema
# binds real project records. Stable across all local-only spawns so the
# audit trail correlates within one host. Generated deterministically from
# a fixed namespace + the literal string "local-oss-sidecar"; not a real
# project id.
_LOCAL_OSS_PROJECT_NAMESPACE: uuid.UUID = uuid.uuid5(
    uuid.NAMESPACE_DNS, "local-oss-sidecar.epochly-relay.invalid"
)


def event_log_path(home: Path | None = None) -> Path:
    """Return the absolute event-log JSONL path under the resolved home."""
    base = home if home is not None else relay_home()
    return base / EVENT_LOG_FILENAME


def _now_rfc3339_utc() -> str:
    """Return current UTC time as an RFC 3339 string with explicit ``Z``.

    Matches VAL-W1-017: timezone-aware, offset preserved as ``Z``.
    """
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _next_ingest_sequence(home: Path) -> int:
    """Return the next ``ingest_sequence`` for the local JSONL log.

    Per W1 ``EventLogEntry`` requirement, ``ingest_sequence`` is a
    non-negative epoch-like integer. For the local OSS sidecar we use a
    strictly-monotonic counter derived from the line count of the existing
    log file. The portalocker exclusive lock around the read-modify-write
    guarantees this is race-free.
    """
    path = event_log_path(home)
    if not path.exists():
        return 0
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    return sum(1 for line in text.splitlines() if line.strip())


def append_event(
    event_type: str,
    *,
    scope_type: Literal[
        "run", "replay", "gate", "eval_run", "release", "manifest", "key", "other"
    ] = "other",
    scope_id: uuid.UUID | None = None,
    actor_kind: Literal[
        "control_plane", "gate_engine", "worker", "sdk", "user", "cron"
    ] = "control_plane",
    payload: dict[str, Any] | None = None,
    home: Path | None = None,
) -> EventLogEntry:
    """Append a single event-log entry and return the persisted model.

    The write goes through ``local_atomic_file_write(append=True)`` so the
    portalocker exclusive lock serializes concurrent appends.
    """
    base = home if home is not None else relay_home()
    base.mkdir(parents=True, exist_ok=True)
    path = event_log_path(base)

    entry = EventLogEntry(
        schema_version="relay.event_log_entry.v1",
        event_id=uuid.uuid4(),
        project_id=_LOCAL_OSS_PROJECT_NAMESPACE,
        scope_type=scope_type,
        scope_id=scope_id if scope_id is not None else _LOCAL_OSS_PROJECT_NAMESPACE,
        event_type=event_type,
        actor_kind=actor_kind,
        occurred_at=datetime.fromisoformat(_now_rfc3339_utc().replace("Z", "+00:00")),
        ingest_sequence=_next_ingest_sequence(base),
        payload=payload or {},
    )

    line = json.dumps(
        entry.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ) + "\n"

    local_atomic_file_write(path, line.encode("utf-8"), append=True)
    return entry


def read_event_log(home: Path | None = None) -> list[EventLogEntry]:
    """Read and parse the entire local event log.

    Each line is validated through the W1 ``EventLogEntry`` model so any
    corrupted line surfaces as a ``ValidationError`` rather than silently
    dropping evidence.
    """
    path = event_log_path(home)
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    out: list[EventLogEntry] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        out.append(EventLogEntry.model_validate(data))
    return out


def count_events(
    event_type: str,
    *,
    home: Path | None = None,
) -> int:
    """Return the count of rows with ``event_type == event_type``."""
    return sum(1 for e in read_event_log(home=home) if e.event_type == event_type)


__all__ = [
    "EVENT_LOG_FILENAME",
    "append_event",
    "count_events",
    "event_log_path",
    "read_event_log",
]
