"""Side-effecting tool idempotency markers (W3.5, VAL-W3-047).

Per spec X and CLAUDE.md keystone invariant #6, a tool declared
``side_effect=True`` MUST emit:

  * a ``tool.pre_action`` event_log entry BEFORE the function runs, and
  * a ``tool.post_success_proof`` event_log entry on success carrying
    ``result_hash`` and ``idempotency_key``.

This module owns the SDK-side computation of those markers and the
:class:`SideEffectRecorder` that the gate engine consumes. The recorder
is in-memory only; the SDK persists the events via the lifecycle ingest
surface in :mod:`relay.run`.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from typing import Any


class SideEffectMarkerMissing(Exception):
    """Raised when ``validate_pairing`` observes a post-success proof
    without a preceding pre-action marker."""


class NonDeterministicIdempotencyKey(Exception):
    """Raised when an idempotency key cannot be derived deterministically.

    Per spec X and CLAUDE.md keystone invariant #6 a side-effecting tool's
    idempotency key MUST be stable across runs and processes so a replayed
    invocation matches its original marker. If a tool argument is not
    JSON-serialisable and its ``str()`` falls back to CPython's default
    ``object.__repr__`` (an ADDRESS-bearing form like ``<C object at
    0x7f...>``), folding it into the key would embed a process-local
    ``id()`` and make the key non-deterministic. We refuse to compute such
    a key and require the caller to make the argument canonicalisable
    (give it a stable ``__repr__`` / serialise it) or pass an explicit
    stable idempotency key instead of silently emitting an
    address-dependent digest.
    """


@dataclass
class SideEffectEvent:
    """One side-effect event_log entry.

    Attributes:
        kind: ``"tool.pre_action"`` or ``"tool.post_success_proof"``.
        occurred_at: Monotonic-clock-derived timestamp (seconds, float).
            We use monotonic to guarantee strict ordering within a process;
            the wire envelope serialises this to ``occurred_at`` ISO-8601
            at lifecycle ingest.
        attributes: Free-form per-event payload (tool_name, idempotency_key,
            args_hash for pre_action; tool_name, idempotency_key,
            result_hash for post_success_proof).
    """

    kind: str
    occurred_at: float
    attributes: dict[str, Any] = field(default_factory=dict)


class SideEffectRecorder:
    """In-memory store of side-effect event_log entries.

    Thread-safe: concurrent ``record`` calls are serialised by an
    internal lock so the resulting list reflects a consistent insertion
    order.
    """

    def __init__(self) -> None:
        self._events: list[SideEffectEvent] = []
        self._lock = threading.Lock()

    def record(self, kind: str, **attributes: Any) -> SideEffectEvent:
        if kind not in {"tool.pre_action", "tool.post_success_proof"}:
            raise ValueError(f"unknown event kind: {kind!r}")
        evt = SideEffectEvent(
            kind=kind,
            occurred_at=time.monotonic(),
            attributes=dict(attributes),
        )
        with self._lock:
            self._events.append(evt)
        return evt

    @property
    def events(self) -> list[SideEffectEvent]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


# ---------------------------------------------------------------------------
# Marker computation
# ---------------------------------------------------------------------------


# CPython's default ``object.__repr__`` form, e.g.
# ``<module.Class object at 0x7f3c9a4b1d90>``. The embedded ``0x...`` is
# the object's ``id()`` -- process-local and non-deterministic. Any value
# whose ``str()`` lands here must NOT be folded into an idempotency key.
_ADDRESS_BEARING_REPR = re.compile(r" at 0x[0-9a-fA-F]+>$")


def _is_address_bearing(value: Any) -> bool:
    """True if ``str(value)`` falls back to CPython's address-bearing
    default ``object.__repr__`` (``<... at 0x...>``).

    Objects that define a stable ``__str__``/``__repr__`` (e.g. datetimes,
    enums, dataclasses with a content repr) are NOT address-bearing and
    remain deterministically serialisable.
    """
    return _ADDRESS_BEARING_REPR.search(str(value)) is not None


def _strict_default(value: Any) -> str:
    """``json.dumps`` ``default`` callback for the idempotency-key path.

    Refuse any non-JSON value that would serialise to an address-bearing
    repr (non-deterministic). Otherwise fall back to a stable ``str()``.
    """
    if _is_address_bearing(value):
        raise NonDeterministicIdempotencyKey(
            "cannot derive a deterministic idempotency key from a value "
            "whose str() is an address-bearing repr "
            f"({str(value)!r}); give the argument a stable __repr__/JSON "
            "form or supply an explicit stable idempotency key"
        )
    return str(value)


def _canonical_args(
    name: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    strict: bool = False,
) -> bytes:
    """Produce a deterministic byte representation of (name, args, kwargs).

    The output is JSON-encoded with sorted keys. Non-JSON types (datetimes,
    dataclasses with a content repr) fall back to their string repr. Two
    identical invocations produce identical bytes; differing invocations
    produce different bytes (by construction of canonical JSON).

    When ``strict`` is True (the idempotency-key path), a value whose
    ``str()`` is an address-bearing default repr raises
    :class:`NonDeterministicIdempotencyKey` instead of silently folding a
    process-local ``id()`` into the bytes. The non-strict path preserves
    the historical ``default=str`` behaviour for the args/result marker
    hashes, which are observability digests rather than replay-matching
    keys.
    """
    default = _strict_default if strict else str
    try:
        encoded = json.dumps(
            {"name": name, "args": list(args), "kwargs": kwargs},
            sort_keys=True,
            default=default,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        if strict:
            # In strict mode the address-bearing repr would re-enter via
            # repr() of the whole tuple; refuse rather than emit an
            # id()-dependent key.
            for value in (*args, *kwargs.values()):
                if _is_address_bearing(value):
                    raise NonDeterministicIdempotencyKey(
                        "cannot derive a deterministic idempotency key "
                        "from a value whose str() is an address-bearing "
                        f"repr ({str(value)!r}); give the argument a "
                        "stable __repr__/JSON form or supply an explicit "
                        "stable idempotency key"
                    ) from None
        # Last-resort fallback for the non-strict marker path: never raise
        # from marker computation. Stringify everything via repr.
        encoded = repr((name, args, kwargs)).encode("utf-8")
    return encoded


def compute_idempotency_key(
    name: str, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> str:
    """SHA-256 of the canonical (name, args, kwargs) bytes, hex digest.

    Stable across identical invocations; differs for different args.

    Raises :class:`NonDeterministicIdempotencyKey` (VAL-ISO-017) when an
    argument would only serialise to a process-local address-bearing repr,
    which would make the key non-deterministic across runs/processes and
    break replay idempotency (keystone #6).
    """
    return hashlib.sha256(
        _canonical_args(name, args, kwargs, strict=True)
    ).hexdigest()


def compute_args_hash(args_bytes: bytes) -> str:
    return hashlib.sha256(args_bytes).hexdigest()


def compute_result_hash(result: Any) -> str:
    """SHA-256 hex of the result's canonical JSON-or-repr bytes."""
    try:
        encoded = json.dumps(result, sort_keys=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        encoded = repr(result).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# ---------------------------------------------------------------------------
# Public tool registration helper
# ---------------------------------------------------------------------------


def register_tool(
    func: Callable[..., Any],
    *,
    name: str,
    side_effect: bool,
    recorder: SideEffectRecorder | None = None,
) -> Callable[..., Any]:
    """Wrap ``func`` so it emits pre/post markers when ``side_effect=True``.

    Args:
        func: The tool function to wrap.
        name: The tool's canonical name (e.g. ``"crm.create_case_note"``).
            Embedded in markers so the gate engine can attribute the
            event to the right tool descriptor.
        side_effect: When ``True`` the wrapped callable emits a
            ``tool.pre_action`` marker before calling ``func`` and (on
            success) a ``tool.post_success_proof`` marker after. When
            ``False`` the wrapper is a transparent passthrough.
        recorder: Where to write markers. When ``None`` and
            ``side_effect=True`` a fresh recorder is created and exposed
            as ``wrapped._recorder`` for caller inspection (mostly for
            tests; production code passes the run-level recorder).

    Returns:
        A wrapped callable with the same calling convention as ``func``.
    """
    if not side_effect:
        # Transparent passthrough; no markers emitted at all.
        return func

    if recorder is None:
        recorder = SideEffectRecorder()

    @wraps(func)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        ikey = compute_idempotency_key(name, args, kwargs)
        args_bytes = _canonical_args(name, args, kwargs)
        ahash = compute_args_hash(args_bytes)
        recorder.record(
            "tool.pre_action",
            tool_name=name,
            idempotency_key=ikey,
            args_hash=ahash,
        )
        result = func(*args, **kwargs)
        rhash = compute_result_hash(result)
        recorder.record(
            "tool.post_success_proof",
            tool_name=name,
            idempotency_key=ikey,
            result_hash=rhash,
        )
        return result

    wrapped._recorder = recorder  # type: ignore[attr-defined]
    return wrapped


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


def validate_pairing(events: list[dict[str, Any]]) -> None:
    """Verify every post-success proof has a preceding pre-action marker.

    Used by the gate engine when consolidating event_log entries for a
    run: a ``tool.post_success_proof`` without a matching
    ``tool.pre_action`` (matched by ``idempotency_key``) is rejected.

    Raises:
        SideEffectMarkerMissing: A post-success proof has no matching
            pre-action marker.
    """
    pre_keys: set[str] = set()
    for evt in events:
        kind = evt.get("kind")
        ikey = evt.get("idempotency_key") or evt.get("attributes", {}).get(
            "idempotency_key"
        )
        if kind == "tool.pre_action" and isinstance(ikey, str) and ikey:
            pre_keys.add(ikey)
        elif kind == "tool.post_success_proof" and (
            not isinstance(ikey, str) or not ikey or ikey not in pre_keys
        ):
            raise SideEffectMarkerMissing(
                f"tool.post_success_proof for idempotency_key={ikey!r} "
                "has no preceding tool.pre_action marker"
            )


__all__ = [
    "NonDeterministicIdempotencyKey",
    "SideEffectEvent",
    "SideEffectMarkerMissing",
    "SideEffectRecorder",
    "compute_args_hash",
    "compute_idempotency_key",
    "compute_result_hash",
    "register_tool",
    "validate_pairing",
]
