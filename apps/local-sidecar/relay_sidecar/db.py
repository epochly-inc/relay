"""W2.3 sidecar SQLite connection manager + single-writer queue.

Owns:

  - One ``writer_conn`` aiosqlite connection (private to the single
    ``_writer_loop`` coroutine). All state-mutation transactions
    (``BEGIN IMMEDIATE``) execute on this connection.
  - ``reader_conns`` -- a list of aiosqlite connections opened with
    ``PRAGMA query_only = 1`` immediately after ``PRAGMA busy_timeout = 5000``.
    Readers proceed in parallel while the writer queue is busy
    (VAL-W2-023).
  - A bounded ``asyncio.Queue`` of pending write requests. The writer
    coroutine pulls one request at a time, opens ``BEGIN IMMEDIATE``,
    executes the parameterised insert, retries on ``SQLITE_BUSY`` with
    exponential backoff capped at 1000ms (total <= 5000ms busy_timeout
    window), and emits an observable ``event_kind='sqlite_busy_retry'``
    row for EACH retry attempt (VAL-W2-019 forced-contention evidence).

Per CLAUDE.md keystone invariant #8: this module IS the atomic primitive
#2 (``transactional_db_write``) referenced by the directive. Business
logic anywhere in the sidecar invokes ``transactional_db_write(...)``
and never calls ``aiosqlite.connect`` / ``conn.execute`` directly for
writes.

Statement trace buffer: each connection installs a per-connection trace
callback via ``aiosqlite.Connection.set_trace_callback`` so VAL-W2-022
can assert ``BEGIN IMMEDIATE`` is the first statement in every state-
mutation transaction.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite

from .errors import RelayDiskFullError, RelaySQLiteBusyExhausted

# Default reader-pool size. Configurable via ``SidecarDatabase`` ctor.
DEFAULT_READER_COUNT: int = 2

# Backoff schedule for SQLITE_BUSY retries (ms). Capped at 1000ms; total
# elapsed under worst-case contention <= 5000ms (matches busy_timeout).
# 20 + 40 + 80 + 160 + 320 + 640 + 1000 + 1000 + 1000 + ... but we cap
# attempts BEFORE the sum exceeds the budget. See _next_backoff_ms.
INITIAL_BACKOFF_MS: int = 20
MAX_BACKOFF_MS: int = 1000

# Two related but distinct budgets:
#   CONN_BUSY_TIMEOUT_MS - SQLite's own per-connection wait window. Set
#     via ``PRAGMA busy_timeout = ?``. sqlite blocks the writer up to
#     this many milliseconds waiting for the write lock BEFORE returning
#     ``SQLITE_BUSY``. VAL-W2-018 asserts this is 5000.
#   BUSY_TIMEOUT_MS - the application-level retry/backoff budget. After
#     sqlite returns SQLITE_BUSY (because the lock held for longer than
#     CONN_BUSY_TIMEOUT_MS), the retry loop in ``_execute_with_retry``
#     keeps trying with exponential backoff until this deadline elapses,
#     then raises ``RelaySQLiteBusyExhausted``. VAL-W2-020 asserts the
#     structured-error surface; default also 5000.
# Tests patch one or both independently to simulate forced contention
# without making the test itself take seconds.
CONN_BUSY_TIMEOUT_MS: int = 5000
BUSY_TIMEOUT_MS: int = 5000

# Writer-queue capacity. Generous default so callers do not block under
# normal load; sustained > 1024 ops/sec is unsupported and would surface
# via QueueFull (translated to a structured error at the HTTP layer).
DEFAULT_WRITER_QUEUE_MAXSIZE: int = 1024


@dataclass
class WriteResult:
    """Outcome of one ``transactional_db_write`` call.

    Attributes:
        ok: True when the row was committed (or idempotently deduped).
        ingest_sequence: The persisted ``ingest_sequence`` value. For
            idempotent dedupe (same ``(scope_id, idempotency_key)``),
            returns the pre-existing row's sequence.
        idempotent: True when the call deduped against an existing row.
        retry_count: Number of SQLITE_BUSY retries observed before
            success. Zero on the happy path.
    """

    ok: bool
    ingest_sequence: int
    idempotent: bool = False
    retry_count: int = 0


@dataclass
class _WriteRequest:
    """One queued write request awaiting the single writer coroutine.

    ``mode`` selects the column-augmentation policy:

      - ``"event_log"`` (default, W2.3 behavior): the writer augments
        ``row`` with ``ingest_sequence`` (monotonic via SELECT MAX+1) and
        ``idempotency_key``; an existing
        ``(scope_id, idempotency_key)`` pair short-circuits to the prior
        row's ``ingest_sequence`` (idempotent retry semantics).
      - ``"raw"`` (M04 w4-side-effects): the writer issues a plain INSERT
        of ``row`` verbatim and returns the row's caller-supplied primary
        key in ``WriteResult.ingest_sequence``. Idempotency is enforced
        at the schema layer (UNIQUE constraint on the table's natural
        key, e.g. ``side_effect_markers.idempotency_key``); the primitive
        catches IntegrityError and surfaces ``idempotent=True`` so the
        caller can attach to the prior winning write.
    """

    table: str
    row: dict[str, Any]
    scope_id: str
    idempotency_key: str | None
    future: asyncio.Future[WriteResult]
    mode: str = "event_log"
    natural_key_column: str | None = None  # required when mode='raw'
    return_column: str | None = None  # column to surface in WriteResult.ingest_sequence
    # M07 w7-cli-invocations: mode='update_raw' carries an UPDATE shape.
    # ``row`` is the SET column->value map; ``where_column``/``where_value``
    # identify the target row by primary key. The update runs inside the
    # same BEGIN IMMEDIATE/COMMIT envelope as INSERTs and serializes through
    # the single writer queue, preserving keystone invariant #8.
    where_column: str | None = None
    where_value: Any = None


@dataclass
class StatementTrace:
    """Per-connection ordered list of executed SQL statements (for tests).

    VAL-W2-022 inspects this buffer to assert the first statement of every
    state-mutation transaction is ``BEGIN IMMEDIATE``. The buffer is opt-in:
    when ``enabled=False`` the trace callback is a no-op so production
    overhead is nil.
    """

    enabled: bool = False
    statements: list[str] = field(default_factory=list)

    def record(self, sql: str) -> None:
        if self.enabled:
            self.statements.append(sql)

    def clear(self) -> None:
        self.statements.clear()


def _digest_sql(sql: str) -> str:
    """Return the canonical sha256-<hex> wire form of an SQL statement.

    Used for the ``sql_statement_digest`` column on sqlite_busy_retry rows
    so audit consumers can correlate retry events with the originating
    statement without persisting raw SQL text.
    """
    h = hashlib.sha256(sql.encode("utf-8")).hexdigest()
    return f"sha256-{h}"


def _next_backoff_ms(attempt: int) -> int:
    """Return the backoff for the n-th retry (1-indexed). Capped at MAX."""
    # 20, 40, 80, 160, 320, 640, then cap.
    raw = INITIAL_BACKOFF_MS * (2 ** (attempt - 1))
    return min(raw, MAX_BACKOFF_MS)


# W2.7: ENOSPC (POSIX) and ERROR_DISK_FULL (Windows errno 39 / 112) all
# surface from SQLite as ``sqlite3.OperationalError`` with one of these
# substrings (lowercased). The integer errno embedded in the exception
# is captured separately by ``_extract_errno`` for forensic detail.
_DISK_FULL_MESSAGE_TOKENS: tuple[str, ...] = (
    "database or disk is full",
    "disk full",
    "no space left on device",
    "enospc",
)


def _is_disk_full_message(lowercased_msg: str) -> bool:
    """Return True iff ``lowercased_msg`` carries a disk-full marker.

    Cross-version: SQLite has emitted the message in various forms. The
    detector matches any of the canonical substrings.
    """
    return any(token in lowercased_msg for token in _DISK_FULL_MESSAGE_TOKENS)


def _extract_errno(exc: BaseException) -> int | None:
    """Best-effort extract of an OS errno from ``exc.__cause__`` or args.

    sqlite3.OperationalError chains may carry an OSError with a
    ``errno`` attribute. When unavailable returns None; the caller
    surfaces None in the structured envelope.
    """
    cause = getattr(exc, "__cause__", None)
    if isinstance(cause, OSError) and cause.errno is not None:
        return int(cause.errno)
    # Some sqlite builds set the errno directly on the OperationalError.
    direct = getattr(exc, "errno", None)
    if isinstance(direct, int):
        return direct
    return None


def _now_rfc3339_utc() -> str:
    """RFC 3339 UTC timestamp with explicit ``Z`` offset (VAL-W1-017)."""
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


async def _apply_pragmas_writer(conn: aiosqlite.Connection) -> None:
    """Run the writer-connection pragmas in canonical order.

    Sequence: journal_mode=WAL (per-file; idempotent re-application) ->
    busy_timeout=5000ms -> synchronous=NORMAL (WAL recommended) ->
    foreign_keys=ON.
    """
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute(f"PRAGMA busy_timeout = {CONN_BUSY_TIMEOUT_MS}")
    await conn.execute("PRAGMA synchronous = NORMAL")
    await conn.execute("PRAGMA foreign_keys = ON")
    await conn.commit()


async def _apply_pragmas_reader(conn: aiosqlite.Connection) -> None:
    """Run the reader-connection pragmas in canonical order.

    Sequence: busy_timeout=5000ms (VAL-W2-018) -> query_only=1 (VAL-W2-023).
    Note: PRAGMA query_only is SET on the connection itself; readers
    cannot run BEGIN IMMEDIATE / INSERT / UPDATE / DELETE. Attempting any
    write raises ``sqlite3.OperationalError: attempt to write a readonly
    database``.
    """
    await conn.execute(f"PRAGMA busy_timeout = {CONN_BUSY_TIMEOUT_MS}")
    await conn.execute("PRAGMA query_only = 1")
    # Do NOT call ``conn.commit()`` here -- query_only blocks any commit
    # that has a write to flush; the pragmas above are auto-committed by
    # SQLite for connection-scoped state.


class SidecarDatabase:
    """Owns the writer + reader connections and the single-writer queue.

    Lifecycle:

      - ``open()`` constructs all connections, runs migrations, starts
        the writer task. Called from the FastAPI lifespan startup hook.
      - ``close()`` cancels the writer task, drains pending requests
        (failing them with RelaySQLiteBusyExhausted), closes all
        connections. Called from the lifespan shutdown hook.

    Thread-safety: aiosqlite serialises operations per connection via an
    internal queue; multiple coroutines awaiting the writer connection
    would serialise but lose the BEGIN IMMEDIATE atomicity guarantee.
    The single-writer-coroutine pattern below sidesteps that: only
    ``_writer_loop`` ever touches ``self._writer``.
    """

    def __init__(
        self,
        *,
        db_path: Path,
        reader_count: int = DEFAULT_READER_COUNT,
        queue_maxsize: int = DEFAULT_WRITER_QUEUE_MAXSIZE,
        migrations_dir: Path | None = None,
    ) -> None:
        self._db_path = db_path
        self._reader_count = reader_count
        self._queue_maxsize = queue_maxsize
        self._migrations_dir = migrations_dir
        # Filled in by open().
        self._writer: aiosqlite.Connection | None = None
        self._readers: list[aiosqlite.Connection] = []
        self._reader_rr_index = 0  # round-robin reader checkout
        self._queue: asyncio.Queue[_WriteRequest] | None = None
        self._writer_task: asyncio.Task[None] | None = None
        # Statement trace buffers (per-connection). Disabled by default.
        self._writer_trace = StatementTrace()
        self._reader_traces: list[StatementTrace] = []
        # Connection-count instrumentation (VAL-W2-023 evidence).
        self._connect_call_count = 0

    # ---- Properties for tests / diagnostics ----

    @property
    def writer_trace(self) -> StatementTrace:
        return self._writer_trace

    @property
    def reader_traces(self) -> list[StatementTrace]:
        return list(self._reader_traces)

    @property
    def connect_call_count(self) -> int:
        return self._connect_call_count

    @property
    def reader_count(self) -> int:
        return len(self._readers)

    @property
    def db_path(self) -> Path:
        return self._db_path

    # ---- Lifecycle ----

    async def open(self) -> None:
        """Open all connections, run migrations, start writer task."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        # Writer connection (single).
        self._writer = await aiosqlite.connect(str(self._db_path))
        self._connect_call_count += 1
        await _apply_pragmas_writer(self._writer)
        await self._install_trace(self._writer, self._writer_trace)

        # Run migrations on the writer connection. They run inside a
        # plain transaction (DDL); we do NOT use BEGIN IMMEDIATE here
        # because migration is a one-shot startup operation, not a
        # state-mutation write through the queue.
        await self._run_migrations()

        # Reader connections (N).
        for _ in range(self._reader_count):
            r = await aiosqlite.connect(str(self._db_path))
            self._connect_call_count += 1
            await _apply_pragmas_reader(r)
            trace = StatementTrace()
            await self._install_trace(r, trace)
            self._readers.append(r)
            self._reader_traces.append(trace)

        # State-engine writer lock: pre-created here so the writer_loop
        # task and every CAS/gate-decision/retention borrow share ONE
        # asyncio.Lock instance. Eagerly creating here (rather than
        # lazily on first borrow) eliminates the check-then-create race
        # window where two callers could install two separate Lock
        # instances and silently lose serialization. Per W2.5 (audit
        # 2026-05-17): the writer_loop MUST take this lock around its
        # BEGIN IMMEDIATE..COMMIT block because it shares the
        # ``self._writer`` connection with ``compare_and_set_state``,
        # ``GateDecisionWriter``, and the retention pass. Without the
        # lock the writer_loop can interleave a queued INSERT between
        # CAS's SELECT and UPDATE, surfacing as "cannot start a
        # transaction within a transaction" (SQLite forbids nested
        # BEGIN). Pre-existing CAS/gate/retention callers also use
        # ``getattr(database, "_state_engine_writer_lock", None)`` with
        # a lazy create fallback; pre-installing here keeps that pattern
        # working AND removes the race.
        if not hasattr(self, "_state_engine_writer_lock") or getattr(
            self, "_state_engine_writer_lock", None
        ) is None:
            self._state_engine_writer_lock = asyncio.Lock()
        # Writer queue + task.
        self._queue = asyncio.Queue(maxsize=self._queue_maxsize)
        self._writer_task = asyncio.create_task(
            self._writer_loop(), name="sidecar-db-writer"
        )

    async def close(self) -> None:
        """Cancel writer task, drain queue, close all connections."""
        if self._writer_task is not None:
            self._writer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._writer_task
            self._writer_task = None
        # Fail any still-pending requests.
        if self._queue is not None:
            while not self._queue.empty():
                req = self._queue.get_nowait()
                if not req.future.done():
                    req.future.set_exception(
                        RelaySQLiteBusyExhausted(
                            message="sidecar shut down while write was pending",
                            attempts=0,
                            sql_statement_digest=_digest_sql(
                                f"INSERT INTO {req.table}"
                            ),
                        )
                    )
        # Close connections.
        for r in self._readers:
            with contextlib.suppress(Exception):
                await r.close()
        self._readers.clear()
        self._reader_traces.clear()
        if self._writer is not None:
            with contextlib.suppress(Exception):
                await self._writer.close()
            self._writer = None

    # ---- Trace helper ----

    async def _install_trace(
        self, conn: aiosqlite.Connection, trace: StatementTrace
    ) -> None:
        """Install a statement-tracer on ``conn`` writing into ``trace``.

        Uses ``aiosqlite.Connection.set_trace_callback`` which schedules
        the underlying ``sqlite3.Connection.set_trace_callback`` call on
        the connection's worker thread (sqlite3 forbids cross-thread
        access). The callback runs synchronously inside that worker
        thread on every executed SQL statement; ``trace.record`` is a
        pure-Python list append guarded by the ``enabled`` flag so the
        overhead is negligible when disabled.
        """
        await conn.set_trace_callback(trace.record)

    # ---- Reader checkout (round-robin) ----

    def acquire_reader(self) -> aiosqlite.Connection:
        """Return a reader connection for read-only queries.

        Round-robin allocation across the reader pool. Callers MUST NOT
        attempt INSERT/UPDATE/DELETE on the returned connection;
        ``PRAGMA query_only = 1`` blocks any such attempt with
        ``OperationalError: attempt to write a readonly database``.
        """
        if not self._readers:
            raise RuntimeError(
                "SidecarDatabase.open() not called or readers absent"
            )
        idx = self._reader_rr_index % len(self._readers)
        self._reader_rr_index += 1
        return self._readers[idx]

    # ---- Public write API ----

    async def transactional_db_write_raw(
        self,
        *,
        table: str,
        row: dict[str, Any],
        natural_key: str,
        natural_key_column: str,
    ) -> WriteResult:
        """Atomic raw INSERT through the sidecar writer queue (M04 w4).

        Mirrors :meth:`transactional_db_write` but skips the
        ingest_sequence/idempotency_key augmentation. Used for tables
        whose shape predates W2.3 (side_effect_markers,
        side_effect_proofs). Idempotency is enforced at the schema layer
        via a UNIQUE constraint on ``natural_key_column``; on collision
        this method returns the prior row's rowid with
        ``WriteResult.idempotent=True``.

        All writes serialize through the SAME single-writer coroutine as
        :meth:`transactional_db_write` so the keystone invariant #8
        ("four atomic primitives") and the single-writer guarantee are
        both preserved.
        """
        if self._queue is None or self._writer_task is None:
            raise RuntimeError(
                "SidecarDatabase.open() not called or already closed"
            )
        loop = asyncio.get_running_loop()
        future: asyncio.Future[WriteResult] = loop.create_future()
        req = _WriteRequest(
            table=table,
            row=row,
            scope_id="",  # not used in raw mode; natural key is the dedupe surface
            idempotency_key=natural_key,
            future=future,
            mode="raw",
            natural_key_column=natural_key_column,
        )
        await self._queue.put(req)
        return await future

    async def transactional_db_update_raw(
        self,
        *,
        table: str,
        set_columns: dict[str, Any],
        where_column: str,
        where_value: Any,
    ) -> WriteResult:
        """Atomic UPDATE through the sidecar writer queue (M07 w7-cli-invocations).

        Used for the cli_invocations exit-row update (VAL-V2M07-035,
        VAL-V2M07-037). Serializes through the SAME single-writer queue as
        :meth:`transactional_db_write` / :meth:`transactional_db_write_raw`
        so keystone invariant #8 ("four atomic primitives") is preserved:
        UPDATE is the same atomic operation shape as INSERT (BEGIN
        IMMEDIATE -> mutate -> COMMIT inside one txn).

        Returns ``WriteResult(ok=True, ingest_sequence=<rows_updated>)``.
        When the WHERE clause matches no rows the result still resolves
        ``ok=True`` with ``ingest_sequence=0`` so callers can detect
        no-op updates (e.g., exit-update racing a reconciliation sweep
        that already marked the row).
        """
        if self._queue is None or self._writer_task is None:
            raise RuntimeError(
                "SidecarDatabase.open() not called or already closed"
            )
        loop = asyncio.get_running_loop()
        future: asyncio.Future[WriteResult] = loop.create_future()
        req = _WriteRequest(
            table=table,
            row=dict(set_columns),
            scope_id="",
            idempotency_key=None,
            future=future,
            mode="update_raw",
            where_column=where_column,
            where_value=where_value,
        )
        await self._queue.put(req)
        return await future

    async def transactional_db_write(
        self,
        *,
        table: str,
        row: dict[str, Any],
        scope_id: str,
        idempotency_key: str | None = None,
    ) -> WriteResult:
        """Submit a write request to the single-writer queue.

        The caller awaits the returned future; the writer coroutine
        executes the BEGIN IMMEDIATE transaction, handles SQLITE_BUSY
        retries with observable backoff (sqlite_busy_retry rows in the
        same log), and resolves the future with the WriteResult.

        Args:
            table: SQLite table name. Currently only
                ``event_log_entries`` is supported; future migrations
                will widen the surface.
            row: Column-value map. Keys MUST match the table columns
                exactly; unknown columns raise ``sqlite3.OperationalError``.
            scope_id: Scope correlation id (matches ``event_log_entries.scope_id``).
            idempotency_key: When non-None, the row is deduped on
                ``(scope_id, idempotency_key)``; the second call with
                the same pair returns the first row's ``ingest_sequence``
                with ``WriteResult.idempotent=True``.

        Returns:
            WriteResult carrying ``ok``, ``ingest_sequence``,
            ``idempotent``, and ``retry_count``.

        Raises:
            RelaySQLiteBusyExhausted: when the busy_timeout + backoff
                budget is exhausted without acquiring the write lock.
        """
        if self._queue is None or self._writer_task is None:
            raise RuntimeError(
                "SidecarDatabase.open() not called or already closed"
            )
        loop = asyncio.get_running_loop()
        future: asyncio.Future[WriteResult] = loop.create_future()
        req = _WriteRequest(
            table=table,
            row=row,
            scope_id=scope_id,
            idempotency_key=idempotency_key,
            future=future,
        )
        await self._queue.put(req)
        return await future

    # ---- Migrations ----

    async def _run_migrations(self) -> None:
        """Apply every .sql file under ``migrations_dir`` in lex order.

        Migration tracking: the runner records each applied migration's
        filename in the ``__schema_migrations`` table and skips any file
        whose name is already recorded. This permits non-CREATE-IF-NOT-EXISTS
        migrations (DROP, ALTER, RENAME) to land cleanly without re-firing
        their destructive statements on every sidecar restart. Pre-existing
        ``CREATE IF NOT EXISTS`` migrations remain compatible because their
        first application records into ``__schema_migrations`` and
        subsequent restarts skip them as no-ops.

        This idiom was deferred at W2.3 when the runner shipped (see the
        prior version's docstring); it is now installed to support the
        2026-05-17 audit fix in 0021_idempotency_records_align.sql which
        rebuilds the ``idempotency_records`` table to mirror the canonical
        Postgres shape.
        """
        assert self._writer is not None  # noqa: S101
        migrations = self._migrations_dir
        if migrations is None:
            # Default: <repo>/apps/local-sidecar/migrations/
            here = Path(__file__).resolve()
            migrations = here.parent.parent / "migrations"
        if not migrations.is_dir():
            return

        # Bootstrap the tracker table itself. Idempotent.
        await self._writer.executescript(
            "CREATE TABLE IF NOT EXISTS __schema_migrations ("
            "  filename   TEXT PRIMARY KEY,"
            "  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
            ");"
        )

        for sql_file in sorted(migrations.glob("*.sql")):
            filename = sql_file.name
            # Check whether this migration was already applied.
            async with self._writer.execute(
                "SELECT 1 FROM __schema_migrations WHERE filename = ?",
                (filename,),
            ) as cur:
                already_applied = await cur.fetchone()
            if already_applied is not None:
                continue
            sql_text = sql_file.read_text(encoding="utf-8")
            # Atomicity: wrap the script + tracker INSERT in a single
            # explicit transaction so that a crash mid-script rolls back
            # the rebuild AND the tracker record together. Without this,
            # a crash between executescript COMMIT and the tracker INSERT
            # would leave a successfully-rebuilt schema unrecorded; the
            # restart would re-run the script and fail (because the
            # rebuild references legacy columns that no longer exist).
            #
            # Migration scripts MUST NOT issue their own BEGIN/COMMIT
            # (SQLite raises "cannot start a transaction within a
            # transaction"). See the comment block at the top of
            # 0021_idempotency_records_align.sql.
            await self._writer.execute("BEGIN")
            try:
                await self._writer.executescript(sql_text)
                await self._writer.execute(
                    "INSERT INTO __schema_migrations (filename) VALUES (?)",
                    (filename,),
                )
                await self._writer.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(Exception):
                    await self._writer.execute("ROLLBACK")
                raise
        await self._writer.commit()

    # ---- Writer loop (private; only this coroutine touches self._writer) ----

    async def _writer_loop(self) -> None:
        """Single-writer coroutine: drain the queue forever.

        Per CLAUDE.md keystone invariant #8 + spec H.2, all canonical
        writes serialise through one coroutine. Concurrency at the
        caller side is unrestricted (asyncio.Queue.put is wait-free
        for non-full queues); under contention the queue blocks the
        caller until a slot frees.

        W2.5 lock discipline (audit 2026-05-17): each queued request's
        ``BEGIN IMMEDIATE..COMMIT`` block runs under
        ``self._state_engine_writer_lock`` -- the SAME asyncio.Lock that
        ``compare_and_set_state`` (relay_sidecar/state_engine/
        compare_and_set.py), ``GateDecisionWriter`` (packages/gate/.../
        decision_writer.py), and the retention pass acquire. The lock
        is required because all four code paths share
        ``self._writer`` (one aiosqlite connection). Without the lock
        the writer_loop could pop a request and issue ``BEGIN IMMEDIATE``
        while CAS holds the connection mid-transaction, surfacing as
        ``OperationalError: cannot start a transaction within a
        transaction`` and (worse) corrupting CAS's atomicity by
        sneaking a committed INSERT between its SELECT and UPDATE.

        The lock is taken per-request rather than once outside the loop
        so cancellation (``close()`` cancels the task) does not leave
        the lock held: if cancellation arrives between requests we are
        outside the ``async with`` block; if it arrives mid-request the
        ``async with`` releases the lock during unwinding before the
        ``CancelledError`` propagates.

        Cancellation: ``close()`` cancels this task; the suppressed
        CancelledError unwinds cleanly. Any in-flight request whose
        future has not yet resolved is failed in ``close()``.
        """
        assert self._queue is not None  # noqa: S101
        while True:
            req = await self._queue.get()
            try:
                async with self._state_engine_writer_lock:
                    result = await self._execute_with_retry(req)
                if not req.future.done():
                    req.future.set_result(result)
            except RelaySQLiteBusyExhausted as e:
                if not req.future.done():
                    req.future.set_exception(e)
            except Exception as e:  # noqa: BLE001
                # Any non-BUSY error (IntegrityError, OperationalError on
                # bad schema, etc.) surfaces to the caller without retry.
                if not req.future.done():
                    req.future.set_exception(e)

    async def _execute_with_retry(self, req: _WriteRequest) -> WriteResult:
        """Run one BEGIN IMMEDIATE transaction with SQLITE_BUSY retries.

        Loop:
          1. BEGIN IMMEDIATE.
          2. INSERT row (with idempotent dedupe check if key supplied).
          3. COMMIT.
          4. On SQLITE_BUSY at any step, ROLLBACK (best-effort), buffer
             a sqlite_busy_retry observability event in memory, sleep
             ``_next_backoff_ms(attempt)``, retry up to the budget cap.
          5. On final COMMIT success, flush the buffered retry events as
             a sequence of INSERTs on the now-uncontended writer
             connection. (Flushing during contention would itself hit
             BUSY, which is why we buffer.)
          6. On EXHAUSTED: raise; buffered retry events are dropped (the
             contention is unbounded so a later flush also can't succeed).
             The structured ``RelaySQLiteBusyExhausted`` carries the
             attempt count + digest as evidence-of-record instead.
        """
        assert self._writer is not None  # noqa: S101
        loop = asyncio.get_running_loop()
        deadline = loop.time() + (BUSY_TIMEOUT_MS / 1000.0)
        attempt = 0
        sql_statement_digest = _digest_sql(
            f"INSERT INTO {req.table}"
        )
        retry_buffer: list[tuple[int, int]] = []  # (attempt_number, backoff_ms)

        while True:
            try:
                result = await self._execute_one_attempt(req)
                # Flush buffered retry rows on the now-uncontended
                # connection. Failures here are non-fatal: the parent
                # write succeeded; observability is best-effort.
                if retry_buffer:
                    result = WriteResult(
                        ok=result.ok,
                        ingest_sequence=result.ingest_sequence,
                        idempotent=result.idempotent,
                        retry_count=len(retry_buffer),
                    )
                    await self._flush_retry_buffer(
                        scope_id=req.scope_id,
                        events=retry_buffer,
                        sql_statement_digest=sql_statement_digest,
                    )
                return result
            except sqlite3.OperationalError as e:
                msg = str(e).lower()
                # VAL-W2-052: SQLite surfaces disk-full as
                # "database or disk is full" / "disk i/o error"
                # carrying the underlying ENOSPC errno. We catch BEFORE
                # the busy/locked branch so a disk-full error never
                # masquerades as a transient retry.
                if _is_disk_full_message(msg):
                    raise RelayDiskFullError(
                        message=(
                            f"SQLite write to table {req.table!r} failed: "
                            f"disk full (no space left on device)"
                        ),
                        table=req.table,
                        scope_id=req.scope_id,
                        os_errno=_extract_errno(e),
                    ) from e
                # SQLITE_BUSY / SQLITE_LOCKED surface as OperationalError
                # with these prefixes. We retry on both; any other
                # OperationalError (e.g. malformed SQL) escapes.
                if "database is locked" not in msg and "busy" not in msg:
                    raise
                attempt += 1
                backoff_ms = _next_backoff_ms(attempt)
                # Buffer the observability event; flush on commit. We do
                # NOT write directly during contention because the
                # writer connection is itself blocked by the competing
                # holder; an in-line INSERT here would re-hit BUSY.
                retry_buffer.append((attempt, backoff_ms))
                # Budget check: if backoff would exceed the deadline,
                # surface EXHAUSTED. We check BEFORE sleeping so a tight
                # deadline doesn't waste a full backoff window.
                now = loop.time()
                budget_remaining_s = deadline - now
                if budget_remaining_s <= 0 or backoff_ms / 1000.0 > budget_remaining_s:
                    raise RelaySQLiteBusyExhausted(
                        message=(
                            f"SQLITE_BUSY retry budget exhausted "
                            f"after {attempt} attempts on table {req.table!r}"
                        ),
                        attempts=attempt,
                        sql_statement_digest=sql_statement_digest,
                    ) from e
                await asyncio.sleep(backoff_ms / 1000.0)
                # Loop and retry.

    async def _execute_one_attempt(self, req: _WriteRequest) -> WriteResult:
        """Execute a single BEGIN IMMEDIATE -> INSERT -> COMMIT attempt.

        On idempotency-key collision (unique-index violation), returns
        the pre-existing row's ingest_sequence with idempotent=True
        instead of propagating IntegrityError.

        M04 w4-side-effects: when ``req.mode == "raw"`` the augmentation
        step (adding ``ingest_sequence`` + ``idempotency_key`` columns)
        is skipped; the row is inserted verbatim. Idempotency is enforced
        by the schema's UNIQUE constraint on ``req.natural_key_column``.
        Used by the side_effect_markers / side_effect_proofs writer to
        keep keystone invariant #8 ("four atomic primitives") satisfied
        for tables whose shape predates the W2.3 event_log convention.
        """
        assert self._writer is not None  # noqa: S101
        conn = self._writer

        if req.mode == "raw":
            return await self._execute_raw_attempt(req, conn)

        if req.mode == "update_raw":
            return await self._execute_update_raw_attempt(req, conn)

        # Pre-check idempotency: if a row with (scope_id, idempotency_key)
        # already exists, return its ingest_sequence without writing.
        # This is a fast path that avoids the round-trip when the caller
        # retries an already-completed operation. The unique index also
        # protects against concurrent inserts in the (rare) case where
        # this read races with another writer (BEGIN IMMEDIATE serialises
        # this connection's writes; readers don't write).
        if req.idempotency_key is not None:
            async with conn.execute(
                f"SELECT ingest_sequence FROM {req.table} "
                f"WHERE scope_id = ? AND idempotency_key = ?",
                (req.scope_id, req.idempotency_key),
            ) as cur:
                existing = await cur.fetchone()
            if existing is not None:
                return WriteResult(
                    ok=True,
                    ingest_sequence=int(existing[0]),
                    idempotent=True,
                    retry_count=0,
                )

        # Begin the state-mutation transaction. Per VAL-W2-022: the
        # FIRST statement on this transaction MUST be BEGIN IMMEDIATE,
        # not the default BEGIN / BEGIN DEFERRED. aiosqlite's connection
        # is configured with isolation_level=None implicitly inside
        # ``conn.execute("BEGIN IMMEDIATE")`` since we ran our own
        # pragmas above; we manage the txn manually.
        await conn.execute("BEGIN IMMEDIATE")
        try:
            # Compute next ingest_sequence atomically inside the txn.
            async with conn.execute(
                f"SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
                f"FROM {req.table}"
            ) as cur:
                row = await cur.fetchone()
            next_seq = int(row[0]) if row is not None else 0

            # Build the INSERT. row keys are trusted (caller-supplied)
            # but values are bound via parameter substitution to prevent
            # SQL injection on string columns.
            full_row: dict[str, Any] = dict(req.row)
            full_row["ingest_sequence"] = next_seq
            full_row["idempotency_key"] = req.idempotency_key
            columns = sorted(full_row.keys())
            placeholders = ",".join("?" for _ in columns)
            colnames = ",".join(columns)
            values = tuple(_encode_value(full_row[c]) for c in columns)
            sql = (
                f"INSERT INTO {req.table} ({colnames}) "
                f"VALUES ({placeholders})"
            )
            try:
                await conn.execute(sql, values)
            except sqlite3.IntegrityError:
                # Idempotency-key collision (concurrent retry races
                # past the pre-check). Roll back, then re-query for
                # the winning row.
                await conn.execute("ROLLBACK")
                async with conn.execute(
                    f"SELECT ingest_sequence FROM {req.table} "
                    f"WHERE scope_id = ? AND idempotency_key = ?",
                    (req.scope_id, req.idempotency_key),
                ) as cur:
                    existing = await cur.fetchone()
                if existing is not None:
                    return WriteResult(
                        ok=True,
                        ingest_sequence=int(existing[0]),
                        idempotent=True,
                        retry_count=0,
                    )
                # Not an idempotency collision; re-raise. The outer
                # retry loop only catches OperationalError so this
                # IntegrityError surfaces to the caller.
                raise
            await conn.execute("COMMIT")
            return WriteResult(
                ok=True,
                ingest_sequence=next_seq,
                idempotent=False,
                retry_count=0,
            )
        except BaseException:
            with contextlib.suppress(Exception):
                await conn.execute("ROLLBACK")
            raise

    async def _execute_raw_attempt(
        self,
        req: _WriteRequest,
        conn: aiosqlite.Connection,
    ) -> WriteResult:
        """Execute a verbatim INSERT for ``req.mode == 'raw'``.

        Used by M04 w4-side-effects' side_effect_markers /
        side_effect_proofs writer. The schema's UNIQUE constraint on
        ``req.natural_key_column`` carries the load-bearing idempotency
        invariant; on collision we return the prior row's primary key
        with ``idempotent=True``.

        ``req.return_column`` names the column whose integer value (or
        positional row id) is surfaced as ``WriteResult.ingest_sequence``.
        For tables without an integer primary key (side_effect_markers
        uses a TEXT uuid), the rowid is returned instead.
        """
        # Pre-check by natural key. Cheap fast path that avoids the
        # round-trip on retry.
        if req.natural_key_column and req.idempotency_key is not None:
            async with conn.execute(
                f"SELECT rowid FROM {req.table} "
                f"WHERE {req.natural_key_column} = ?",
                (req.idempotency_key,),
            ) as cur:
                existing = await cur.fetchone()
            if existing is not None:
                return WriteResult(
                    ok=True,
                    ingest_sequence=int(existing[0]),
                    idempotent=True,
                    retry_count=0,
                )

        await conn.execute("BEGIN IMMEDIATE")
        try:
            columns = sorted(req.row.keys())
            placeholders = ",".join("?" for _ in columns)
            colnames = ",".join(columns)
            values = tuple(_encode_value(req.row[c]) for c in columns)
            sql = f"INSERT INTO {req.table} ({colnames}) VALUES ({placeholders})"
            try:
                cursor = await conn.execute(sql, values)
                row_id = cursor.lastrowid or 0
            except sqlite3.IntegrityError:
                await conn.execute("ROLLBACK")
                if req.natural_key_column and req.idempotency_key is not None:
                    async with conn.execute(
                        f"SELECT rowid FROM {req.table} "
                        f"WHERE {req.natural_key_column} = ?",
                        (req.idempotency_key,),
                    ) as cur:
                        existing = await cur.fetchone()
                    if existing is not None:
                        return WriteResult(
                            ok=True,
                            ingest_sequence=int(existing[0]),
                            idempotent=True,
                            retry_count=0,
                        )
                raise
            await conn.execute("COMMIT")
            return WriteResult(
                ok=True,
                ingest_sequence=int(row_id),
                idempotent=False,
                retry_count=0,
            )
        except BaseException:
            with contextlib.suppress(Exception):
                await conn.execute("ROLLBACK")
            raise

    async def _execute_update_raw_attempt(
        self,
        req: _WriteRequest,
        conn: aiosqlite.Connection,
    ) -> WriteResult:
        """Execute a single BEGIN IMMEDIATE -> UPDATE -> COMMIT attempt.

        Used by M07 w7-cli-invocations exit-row update. ``req.row`` is the
        SET column-value map; ``req.where_column`` / ``req.where_value``
        identify the target row by primary key.

        Returns ``WriteResult(ok=True, ingest_sequence=<rows_updated>)``
        where ``ingest_sequence`` is the SQLite ``cursor.rowcount`` for
        the UPDATE. Zero rows updated is NOT an error (no-op detection
        for racing reconciliation sweeps).
        """
        if not req.row:
            return WriteResult(
                ok=True, ingest_sequence=0, idempotent=False, retry_count=0
            )
        if req.where_column is None:
            raise ValueError(
                "update_raw requires where_column to identify the target row"
            )
        await conn.execute("BEGIN IMMEDIATE")
        try:
            columns = sorted(req.row.keys())
            set_clause = ", ".join(f"{c} = ?" for c in columns)
            values = tuple(_encode_value(req.row[c]) for c in columns)
            sql = (
                f"UPDATE {req.table} SET {set_clause} "
                f"WHERE {req.where_column} = ?"
            )
            cursor = await conn.execute(
                sql, values + (_encode_value(req.where_value),)
            )
            rows_updated = cursor.rowcount or 0
            await conn.execute("COMMIT")
            return WriteResult(
                ok=True,
                ingest_sequence=int(rows_updated),
                idempotent=False,
                retry_count=0,
            )
        except BaseException:
            with contextlib.suppress(Exception):
                await conn.execute("ROLLBACK")
            raise

    async def _flush_retry_buffer(
        self,
        *,
        scope_id: str,
        events: list[tuple[int, int]],
        sql_statement_digest: str,
    ) -> None:
        """Flush the in-memory retry buffer to the event log.

        Called from ``_execute_with_retry`` AFTER the parent transaction
        commits successfully -- the writer connection is now uncontended
        (the competitor released the lock; otherwise our own COMMIT
        wouldn't have succeeded). Each buffered (attempt_number,
        backoff_ms) tuple becomes one ``event_kind='sqlite_busy_retry'``
        row.

        Best-effort: if a flush row itself hits BUSY (theoretical, since
        we just released the lock), we swallow the OperationalError so
        the parent caller's success isn't poisoned. The
        ``WriteResult.retry_count`` field still reports the buffered
        count even if the flush partially fails.
        """
        assert self._writer is not None  # noqa: S101
        if not events:
            return
        sentinel_project_id = "00000000-0000-0000-0000-000000000000"
        try:
            # Wrap the flush in BEGIN IMMEDIATE so all retry rows land
            # atomically. Use a fresh transaction (the parent already
            # committed).
            await self._writer.execute("BEGIN IMMEDIATE")
            try:
                # Read the current MAX(ingest_sequence) once; assign
                # consecutive sequences to each buffered row.
                async with self._writer.execute(
                    "SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
                    "FROM event_log_entries"
                ) as cur:
                    row = await cur.fetchone()
                base_seq = int(row[0]) if row is not None else 0
                for offset, (attempt_number, backoff_ms) in enumerate(events):
                    event_id = str(uuid.uuid4())
                    occurred_at = _now_rfc3339_utc()
                    await self._writer.execute(
                        "INSERT INTO event_log_entries ("
                        "  event_id, schema_version, project_id, scope_type, "
                        "  scope_id, event_type, actor_kind, payload, "
                        "  occurred_at, ingest_sequence, event_kind, "
                        "  attempt_number, backoff_ms, sql_statement_digest"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            event_id,
                            "relay.event_log_entry.v1",
                            sentinel_project_id,
                            "other",
                            scope_id,
                            "sidecar.sqlite_busy_retry",
                            "control_plane",
                            "{}",
                            occurred_at,
                            base_seq + offset,
                            "sqlite_busy_retry",
                            attempt_number,
                            backoff_ms,
                            sql_statement_digest,
                        ),
                    )
                await self._writer.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(Exception):
                    await self._writer.execute("ROLLBACK")
                raise
        except sqlite3.OperationalError:
            # Best-effort observability: never poison a successful parent
            # write by raising on a deferred flush. The retry_count on
            # the WriteResult still reports the count.
            pass


def _encode_value(value: Any) -> Any:
    """Coerce a Python value to a SQLite parameter binding.

    - dict / list -> compact JSON string
    - uuid.UUID -> canonical 8-4-4-4-12 lowercase hex
    - datetime -> ISO 8601 with offset preserved
    - everything else passes through (int, float, str, bool, None, bytes)
    """
    if isinstance(value, dict | list):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


# -----------------------------------------------------------------------------
# Convenience helper: build a canonical event_log_entries row from kwargs.
# -----------------------------------------------------------------------------


def build_event_log_row(
    *,
    event_type: str,
    scope_id: uuid.UUID | str,
    project_id: uuid.UUID | str,
    scope_type: str = "other",
    actor_kind: str = "control_plane",
    actor_id: uuid.UUID | str | None = None,
    manifest_commit_hash: str | None = None,
    payload: dict[str, Any] | None = None,
    event_id: uuid.UUID | str | None = None,
    occurred_at: datetime | str | None = None,
    event_kind: str = "",
) -> dict[str, Any]:
    """Build a row dict suitable for ``transactional_db_write``.

    Mirrors the W1 EventLogEntry envelope field set + the W2.3 event_kind
    column. ``ingest_sequence`` and ``idempotency_key`` are added by the
    primitive itself; the caller does not supply them here.
    """
    event_id_str = str(uuid.uuid4()) if event_id is None else str(event_id)
    if occurred_at is None:
        occurred_at_str = _now_rfc3339_utc()
    elif isinstance(occurred_at, datetime):
        occurred_at_str = occurred_at.isoformat()
    else:
        occurred_at_str = occurred_at
    return {
        "event_id": event_id_str,
        "schema_version": "relay.event_log_entry.v1",
        "project_id": str(project_id),
        "scope_type": scope_type,
        "scope_id": str(scope_id),
        "event_type": event_type,
        "actor_kind": actor_kind,
        "actor_id": str(actor_id) if actor_id is not None else None,
        "manifest_commit_hash": manifest_commit_hash,
        "payload": payload or {},
        "occurred_at": occurred_at_str,
        "event_kind": event_kind,
    }


__all__ = [
    "BUSY_TIMEOUT_MS",
    "CONN_BUSY_TIMEOUT_MS",
    "DEFAULT_READER_COUNT",
    "DEFAULT_WRITER_QUEUE_MAXSIZE",
    "INITIAL_BACKOFF_MS",
    "MAX_BACKOFF_MS",
    "SidecarDatabase",
    "StatementTrace",
    "WriteResult",
    "_apply_pragmas_reader",
    "_apply_pragmas_writer",
    "_digest_sql",
    "_next_backoff_ms",
    "build_event_log_row",
]


def _allowed_tables() -> Iterable[str]:
    """Whitelist of tables transactional_db_write may target.

    W2.3 only ships ``event_log_entries``; the W2.4 state engine adds
    ``run_results`` and ``scope_state``. This whitelist exists so future
    callers cannot point the primitive at arbitrary tables.
    """
    return (
        "event_log_entries",
        # M04 w4-side-effects (VAL-V2M04-034): the side-effect tables are
        # written exclusively through ``transactional_db_write_raw`` which
        # serializes through the SAME single-writer queue as the W2.3
        # event_log path. Listing them here documents the surface and gives
        # the lint guard a single source of truth.
        "side_effect_markers",
        "side_effect_proofs",
        # M07 w7-cli-invocations (VAL-V2M07-037): the cli_invocations audit
        # table is written exclusively through transactional_db_write_raw
        # (entry insert) and update_existing_row (exit update) via the SAME
        # single-writer queue as event_log_entries. Listing here makes the
        # surface explicit and keeps keystone invariant #8 satisfied for the
        # CLI's invocation recorder.
        "cli_invocations",
        # Audit R3 BUG-A1 (2026-05-18): the HTTP idempotency cache is
        # persisted to ``idempotency_records`` so the replay semantics
        # survive sidecar restart (BUG-A2). Writes are routed through
        # ``transactional_db_write_raw`` so they serialize through the
        # SAME single-writer queue as event_log_entries / CAS; without
        # this, a bare ``db._writer.execute(...)`` would race
        # compare_and_set_state's BEGIN IMMEDIATE under
        # ``_state_engine_writer_lock`` and surface as "cannot start a
        # transaction within a transaction".
        "idempotency_records",
        # V3M1-F01 (2026-05-18; VAL-V3M1-001 / VAL-V3M1-002 /
        # VAL-V3M1-003): the run_result -> {contract_results,
        # gate_decisions} join tables. Spec authority is spec A.1 (the
        # join form replaces the historical array-column form for FK
        # integrity). Per CLAUDE.md keystone invariant #8 ("four atomic
        # primitives"), writes to these tables MUST route through
        # ``transactional_db_write_raw`` so they serialize through the
        # SAME single-writer queue as the canonical run_results /
        # gate_decisions writes (keystone invariant #1: control plane
        # writes the result). Direct ``db._writer.execute(...)`` is a
        # banned bypass per the audit-r3 BUG-A1 precedent.
        "run_result_contract_results",
        "run_result_gate_decisions",
        # F5 (manifest persistence): POST /v1/manifests persists the
        # ManifestVersion anchor row to ``manifest_versions`` via
        # ``transactional_db_write_raw`` (natural_key=commit_hash) so the
        # DB-backed three-anchor handoff lookup
        # (handoff._manifest_is_active_or_in_grace) can find it -- keystone
        # invariant #4. Listing it here makes the writable surface explicit
        # and keeps keystone invariant #8 ("four atomic primitives") the
        # single source of truth for what the writer queue may target.
        "manifest_versions",
    )
