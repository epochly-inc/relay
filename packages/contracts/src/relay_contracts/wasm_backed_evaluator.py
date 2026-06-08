"""WASM-backed Relay CEL evaluator -- the WS-A central host facade.

``WasmCelEvaluator`` is a drop-in substitute for :class:`RelayCelEvaluator`
(same ``__init__(*, timeout_ms, udfs)`` signature + identical ``timeout_ms``
bounds, same ``compile`` / ``evaluate`` / ``_env`` surface) so the contracts
engine factory (a later feature) can select it behind ``CelEvaluatorProtocol``
without any caller change. It routes the expression through the SINGLE wasm CEL
engine (``RelayCel.eval(..., relay_profile=True)``; see
``packages/cel-wasm/python/relay_cel_wasm.py``) instead of cel-python, but keeps
the engine-agnostic host guards HOST-SIDE so the wasm path enforces the same
invariants as the celpy path:

  - the whole-expression regex-backreference pre-screen (RELAY-CEL-007 /
    RELAY-CEL-PROFILE-REGEX-BACKREF) runs at ``compile`` BEFORE the wasm call;
  - any caller-supplied extra UDF is rejected fail-closed BEFORE evaluation
    (the wasm exposes only the 3 hardcoded ``relay.*`` UDFs and has no
    registration slot): RELAY-CEL-004 / RELAY-CEL-UDF-UNREGISTERED;
  - ``_check_finite`` runs host-side on the ``typed_to_py``-converted result so
    a NaN / +-Inf or an out-of-safe-range integer / whole double is rejected
    with RELAY-CEL-006 / RELAY-CEL-NUMERIC-OOB;
  - the wall-clock timeout + orphan-thread cap reuse the SHARED
    :meth:`RelayCelEvaluator._run_with_timeout` host helper.

A wasm ``{"ok": false}`` engine envelope is translated by cause:

  - the wasm's RELAY-CEL-002 PROFILE rejection carries a STRUCTURED ``subtype``;
    it surfaces as :class:`RelayCelProfileError` with that subtype (no message
    parsing);
  - the wasm's OWN compile (001) / exec (004) / request (006) codes and the
    loader's RELAY-CEL-PANIC trap marker map to the DISTINCT RELAY-CEL-009
    :class:`RelayCelEngineError` with a per-cause subtype
    (ENGINE-COMPILE/-EXEC/-REQUEST/-PANIC) via
    :meth:`RelayCelEngineError.from_wasm_envelope`. A wasm exec (004) or request
    (006) failure NEVER surfaces as the host UDF-impurity (004) /
    numeric-out-of-bounds (006) classification, which would poison the gate's
    signed per-condition ``error_code``.

Threading model (RelayCel's Store is NOT thread-safe -- it bundles one wasmtime
``Store``): a per-thread ``RelayCel`` handle (:class:`threading.local`) over a
SHARED ``Engine`` + ``Module`` (compiled once), so concurrent ``evaluate()``
calls on different threads never share a Store. A host wall-clock timeout that
orphans a worker thread QUARANTINES that thread's handle: the orphaned worker is
still running inside its Store, so the next ``evaluate()`` on the SAME thread
discards the (possibly mid-flight) handle and instantiates a fresh Store. This
keeps a timed-out evaluation from corrupting the next one on the same thread.

Engine selection (``RELAY_CEL_ENGINE``) is NOT read here -- the contracts engine
factory owns it. This module never touches ``os.environ``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import threading
from collections.abc import Iterable, Mapping
from typing import Any

from relay_schemas.error_codes import RelayErrorCode

from .errors import (
    RelayCelEngineError,
    RelayCelError,
    RelayCelProfileError,
    RelayCelUnsupportedUdfError,
)
from .evaluator import (
    DEFAULT_TIMEOUT_MS,
    MAX_TIMEOUT_MS,
    RelayCelEvaluator,
    _check_finite,
    _check_regex_backref,
)
from .udf import PureUdf
from .udfs import (
    RELAY_COVERAGE_NAME,
    RELAY_SCHEMA_MATCH_NAME,
    RELAY_TOOL_ARG_NAME,
)
from .wasm_artifact import resolve_packaged_wasm_path
from .wasm_codec import typed_to_py

# The three relay.* UDFs the wasm hosts natively. A caller may pass these
# (e.g. via RELAY_UDFS) without rejection; any OTHER UDF name has no
# registration slot in the wasm and is rejected fail-closed.
_NATIVE_UDF_NAMES: frozenset[str] = frozenset(
    {RELAY_COVERAGE_NAME, RELAY_TOOL_ARG_NAME, RELAY_SCHEMA_MATCH_NAME}
)

# The wasm engine's structured RELAY-CEL-002 profile-rejection code. It carries
# a structured ``subtype`` (DYN/TS/DUR/STRUCT-DISABLED) which the host maps
# verbatim onto RelayCelProfileError -- NEVER by parsing the message string.
_WASM_PROFILE_CODE: str = RelayErrorCode.RELAY_CEL_002


def _load_relay_cel_class() -> type:
    """Resolve the ``RelayCel`` wasm-loader class.

    Prefers the installed ``relay_cel_wasm`` module (so once WS-G ships the
    loader as package data this Just Works); falls back to loading it from the
    in-repo ``packages/cel-wasm/python/relay_cel_wasm.py`` source by file path
    for the development tree, where the loader is a bare module not yet on
    ``sys.path``. The fallback is import-path resolution only -- it does not
    copy or fork the loader (CLAUDE.md import-boundary rule: consume, do not
    mutate).
    """
    try:
        module = importlib.import_module("relay_cel_wasm")
    except ModuleNotFoundError:
        module = _load_relay_cel_from_repo()
    return module.RelayCel


def _load_relay_cel_from_repo() -> Any:
    """Load ``relay_cel_wasm`` from the in-repo loader path by file location.

    ``packages/contracts/src/relay_contracts/wasm_backed_evaluator.py`` ->
    repo root is four parents up; the loader lives at
    ``packages/cel-wasm/python/relay_cel_wasm.py``.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(here, "..", "..", "..", ".."))
    loader_path = os.path.join(
        repo_root, "packages", "cel-wasm", "python", "relay_cel_wasm.py"
    )
    spec = importlib.util.spec_from_file_location("relay_cel_wasm", loader_path)
    if spec is None or spec.loader is None:
        raise RelayCelEngineError(
            f"wasm CEL loader not resolvable at {loader_path!r}",
            subtype="RELAY-CEL-ENGINE-REQUEST",
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _crate_target_wasm_path() -> str | None:
    """Resolve the in-repo ``crate/target/`` release wasm by file path.

    This is the DEV-tree fallback used only when neither the package-data wasm
    (WS-G) nor a ``CEL_WASM`` override resolves -- e.g. a from-source checkout
    that has run ``build.sh build`` but not vendored the artifact. The path
    mirrors the loader's ``_DEFAULT_WASM`` (this module ->
    ``packages/contracts/src/relay_contracts`` -> repo root is four parents up;
    the artifact lives at ``packages/cel-wasm/crate/target/.../release/...``).
    Returns the path only if it exists as a regular file, else ``None``.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(here, "..", "..", "..", ".."))
    candidate = os.path.join(
        repo_root,
        "packages",
        "cel-wasm",
        "crate",
        "target",
        "wasm32-unknown-unknown",
        "release",
        "relay_cel_wasm.wasm",
    )
    return candidate if os.path.isfile(candidate) else None


def _resolve_wasm_path(override: str | None = None) -> str:
    """Resolve a concrete wasm artifact path, gated on presence (WS-G).

    Resolution order (NO environment read -- the ``CEL_WASM`` env override is the
    loader's concern, applied in :meth:`_ensure_shared` when this resolver finds
    no path; keeping env access out of ``packages/contracts/src`` preserves the
    VAL-W8-005 / VAL-CWC-P4DUALRUN-008 determinism guard
    ``test_relay_cel_engine_read_only_in_engine_module``):

      1. ``override`` -- an explicit caller-supplied path (used by
         :meth:`WasmCelEvaluator.evaluate_with_wasm_path` to point the resolver
         at a specific -- possibly absent -- artifact for the presence-gate
         test). An override that is not an existing file is a structured engine
         error (NOT a bare ``FileNotFoundError``).
      2. The shipped PACKAGE-DATA wasm via ``importlib.resources`` (the WS-G
         primary path; works from an installed wheel without ``crate/target/``).
      3. The in-repo ``crate/target/`` release wasm (dev-tree fallback).

    When NONE of these resolve, raises a structured
    :class:`RelayCelEngineError` (RELAY-CEL-009 / RELAY-CEL-ENGINE-REQUEST) so a
    missing artifact is a clear, catchable ``RelayCelError`` -- never a bare
    ``FileNotFoundError`` / generic exception. The celpy default path does not
    call this resolver, so a missing wasm never affects the celpy engine.
    """
    if override is not None:
        if os.path.isfile(override):
            return override
        raise RelayCelEngineError(
            f"wasm CEL artifact not resolvable at the supplied path "
            f"{override!r} (file does not exist)",
            subtype="RELAY-CEL-ENGINE-REQUEST",
        )

    packaged = resolve_packaged_wasm_path()
    if packaged is not None:
        return str(packaged)

    crate = _crate_target_wasm_path()
    if crate is not None:
        return crate

    raise RelayCelEngineError(
        "wasm CEL artifact not resolvable: no packaged relay_contracts wasm "
        "(importlib.resources) and no in-repo crate/target/ release build. Run "
        "'bash packages/cel-wasm/conformance/build.sh build', set the CEL_WASM "
        "env override, or install a relay_contracts wheel that ships the wasm "
        "package data.",
        subtype="RELAY-CEL-ENGINE-REQUEST",
    )


def _resolve_wasm_path_or_none(override: str | None = None) -> str | None:
    """Like :func:`_resolve_wasm_path` but return ``None`` instead of raising.

    Used by :meth:`_ensure_shared` so that when no package-data / crate-target
    wasm resolves, the loader is invoked with no explicit path and applies its
    OWN ``CEL_WASM`` env / default resolution (env access stays in the loader,
    never in ``packages/contracts/src``). The override branch still raises a
    structured error for an explicitly-supplied absent path.
    """
    if override is not None:
        # An explicit absent override is a hard structured error (presence gate).
        return _resolve_wasm_path(override)
    packaged = resolve_packaged_wasm_path()
    if packaged is not None:
        return str(packaged)
    crate = _crate_target_wasm_path()
    if crate is not None:
        return crate
    return None


class WasmCelEvaluator:
    """Wasm-backed CEL evaluator with the exact :class:`RelayCelEvaluator` facade.

    Construction is cheap relative to evaluation: the shared wasm ``Engine`` +
    ``Module`` are compiled once on first construction of the underlying loader
    handle (deferred to first use), and per-thread Stores are created lazily.
    Extra-UDF rejection happens eagerly at construction (fail-closed before any
    evaluation can run).
    """

    def __init__(
        self,
        *,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        udfs: Iterable[PureUdf] = (),
    ) -> None:
        # Validate timeout_ms with the SAME bounds RelayCelEvaluator enforces
        # (positive int, <= MAX_TIMEOUT_MS); bool is an int subclass so it is
        # routed out explicitly (True/False are not valid timeouts).
        if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or timeout_ms <= 0:
            raise ValueError(
                f"timeout_ms MUST be a positive int; got {timeout_ms!r}"
            )
        if timeout_ms > MAX_TIMEOUT_MS:
            raise ValueError(
                f"timeout_ms exceeds Relay cap ({MAX_TIMEOUT_MS} ms); "
                f"got {timeout_ms}"
            )
        self.timeout_ms = timeout_ms

        # Reject any caller-supplied extra UDF fail-closed BEFORE evaluation:
        # the wasm has no registration slot for a custom callable, so an
        # unsupported UDF is a structured RELAY-CEL-004 / UNREGISTERED error.
        # The 3 native relay.* UDFs are accepted (they are baked into the wasm).
        for udf in udfs:
            if not isinstance(udf, PureUdf):
                raise TypeError(
                    "WasmCelEvaluator: udfs must be PureUdf instances "
                    "(use register_udf to construct)."
                )
            if udf.name not in _NATIVE_UDF_NAMES:
                raise RelayCelUnsupportedUdfError(
                    f"WasmCelEvaluator: the wasm CEL engine exposes only the 3 "
                    f"native relay.* UDFs and has no registration slot for "
                    f"{udf.name!r}. Caller-supplied extra UDFs are rejected "
                    f"fail-closed before evaluation."
                )

        # A delegate RelayCelEvaluator supplies the ``_env`` facade attribute
        # AND the shared host-side ``_run_with_timeout`` (the wall-clock timeout
        # + process-wide orphan-thread cap, VAL-CWC-P1HOST-002). Reusing one
        # bound helper keeps the orphan budget process-wide (the tracker is a
        # RelayCelEvaluator class attribute, shared across all instances) and
        # avoids re-deriving the mechanism here.
        #
        # The ``_env`` attribute is part of the RelayCelEvaluator facade
        # (CelEvaluatorProtocol consumers and pipeline.py's udfs_invoked path
        # read it). The wasm engine carries no celpy Environment, so the delegate
        # exposes a celpy Environment WITHOUT the extra UDFs (their names are
        # reserved native dotted identifiers in the wasm) -- a typed stand-in
        # that keeps the facade total. The wasm hot path never evaluates through
        # it.
        self._timeout_host = RelayCelEvaluator(timeout_ms=timeout_ms)
        self._env: Any = self._timeout_host._env

        # Lazily-built shared Engine+Module (compiled once on first handle), and
        # a per-thread RelayCel handle over that shared module. The loader class
        # is resolved at runtime (it is a bare in-repo module until WS-G ships it
        # as package data), so it is typed Any.
        self._relay_cel_cls: Any = None
        self._shared_engine: Any = None
        self._shared_module: Any = None
        self._shared_lock = threading.Lock()
        self._tlocal = threading.local()

    # --- shared-engine / per-thread handle lifecycle -----------------

    def _ensure_shared(self) -> None:
        """Build the shared Engine + Module exactly once (thread-safe)."""
        if self._shared_module is not None:
            return
        with self._shared_lock:
            if self._shared_module is not None:
                return
            cls = _load_relay_cel_class()
            # Resolve the wasm artifact path through the WS-G resolver: package
            # data (importlib.resources) first, then the in-repo crate/target
            # release build. When the resolver finds neither it returns None and
            # the loader is invoked with no explicit path so it applies its OWN
            # CEL_WASM env / default resolution -- env access stays in the loader,
            # never in packages/contracts/src (determinism guard). Passing the
            # package-data path explicitly means the shared Engine+Module compile
            # from the vendored wasm even when the gitignored crate/target/ dev
            # path is absent (e.g. a fresh wheel install).
            wasm_path = _resolve_wasm_path_or_none()
            # Construct one bootstrap handle to obtain a compiled Engine+Module;
            # all per-thread handles reuse these (the Module compile is the
            # expensive step and is shareable across threads). The bootstrap
            # handle itself is discarded. Any load failure (a missing artifact
            # the loader cannot resolve, or a corrupt module) is converted to the
            # structured RELAY-CEL-009 engine error -- never a bare
            # FileNotFoundError / wasmtime exception escaping the host facade.
            try:
                bootstrap = cls(wasm_path=wasm_path) if wasm_path else cls()
            except RelayCelError:
                raise
            except Exception as exc:  # noqa: BLE001 -- map any load failure structurally
                raise RelayCelEngineError(
                    "wasm CEL engine failed to load its module: "
                    f"{type(exc).__name__}: {exc}",
                    subtype="RELAY-CEL-ENGINE-REQUEST",
                ) from exc
            self._relay_cel_cls = cls
            self._shared_engine = bootstrap._engine
            self._shared_module = bootstrap._module

    def _new_handle(self) -> Any:
        """Instantiate a fresh per-thread RelayCel handle over the shared module.

        Uses ``RelayCel.__new__`` + ``_reinit()`` so the per-thread handle reuses
        the SHARED Engine+Module (only a new wasmtime Store + Instance is
        created) while exposing the loader's full ``eval()`` method. This avoids
        recompiling the Module per thread and keeps a single source of the
        request/response glue (the loader).
        """
        self._ensure_shared()
        assert self._relay_cel_cls is not None
        handle = self._relay_cel_cls.__new__(self._relay_cel_cls)
        handle._engine = self._shared_engine
        handle._module = self._shared_module
        handle._reinit()
        return handle

    def _thread_handle(self) -> Any:
        """Return this thread's RelayCel handle, building it on first use.

        Each thread gets its OWN handle (its own Store) because RelayCel's Store
        is not thread-safe. The handle is cached on a :class:`threading.local`
        so repeated evaluations on the same thread reuse the same compiled
        Store.
        """
        handle = getattr(self._tlocal, "handle", None)
        if handle is None:
            handle = self._new_handle()
            self._tlocal.handle = handle
        return handle

    def _quarantine_thread_handle(self) -> None:
        """Discard this thread's handle so the next evaluate builds a fresh one.

        Called after a host wall-clock timeout: the orphaned worker is still
        running inside this thread's Store, so the Store may be mid-mutation.
        Dropping the reference quarantines it -- the next ``_thread_handle()``
        on this thread instantiates a clean Store. The orphaned worker keeps the
        old Store alive until it finishes, then it is garbage-collected.
        """
        self._tlocal.handle = None

    # --- compilation (host-side profile pre-screen) ------------------

    def compile(self, expression: str) -> str:
        """Validate ``expression`` against the host-side pre-screens.

        Returns the expression unchanged on success (the wasm compiles + checks
        the AST itself; there is no host-side cel-python program to cache). The
        regex-backreference pre-screen (RELAY-CEL-007 / REGEX-BACKREF) runs here
        so a backref in ANY string literal surfaces the structured host error
        BEFORE the wasm call -- mirroring :meth:`RelayCelEvaluator.compile`.
        """
        _check_regex_backref(expression)
        return expression

    # --- evaluation --------------------------------------------------

    def evaluate(
        self,
        expression: str,
        bindings: Mapping[str, Any] | None = None,
    ) -> Any:
        """Evaluate ``expression`` through the wasm under the Relay profile.

        Host guards run host-side: the regex-backref pre-screen at
        :meth:`compile` (before the wasm call), and ``_check_finite`` on the
        ``typed_to_py``-converted result. The wasm runs under the shared
        wall-clock timeout + orphan-cap helper; a timeout quarantines this
        thread's Store.
        """
        # Host pre-screen (regex backref) BEFORE the wasm call (fail-closed).
        self.compile(expression)
        typed_bindings = self._encode_bindings(bindings)
        handle = self._thread_handle()

        def _run() -> dict[str, Any]:
            return handle.eval(
                expression, typed_bindings or None, relay_profile=True
            )

        try:
            envelope = self._timeout_host._run_with_timeout(
                _run, self.timeout_ms / 1000.0
            )
        except RelayCelError as err:
            # A wall-clock timeout (or resource-exhausted) leaves the worker
            # orphaned inside this thread's Store -- quarantine it so the next
            # evaluate on this thread starts clean.
            from .errors import RelayCelTimeoutError

            if isinstance(err, RelayCelTimeoutError):
                self._quarantine_thread_handle()
            raise

        return self._decode_envelope(envelope)

    def evaluate_with_wasm_path(
        self,
        expression: str,
        *,
        wasm_path: str,
        bindings: Mapping[str, Any] | None = None,
    ) -> Any:
        """Evaluate ``expression`` over the wasm at an EXPLICIT ``wasm_path``.

        This is the artifact-presence gate (VAL-CWC-P3CORPUS-010). The supplied
        path is resolved through :func:`_resolve_wasm_path` with the path as an
        override: an ABSENT path raises a structured
        :class:`RelayCelEngineError` (RELAY-CEL-009 / RELAY-CEL-ENGINE-REQUEST)
        -- never a bare ``FileNotFoundError`` / generic exception -- so a missing
        packaged wasm surfaces as a clear, catchable ``RelayCelError``.

        On a present path the expression is evaluated over a ONE-SHOT handle
        built from that path (independent of the cached shared Engine+Module,
        which may have been compiled from a different artifact). The same
        host-side guards run: the regex-backref pre-screen at :meth:`compile`,
        the wall-clock timeout via the shared ``_run_with_timeout`` helper, and
        ``_check_finite`` on the converted result.
        """
        # The resolver raises the structured RELAY-CEL-009 engine error if the
        # supplied path does not exist (the presence gate). This MUST run before
        # any wasm load so an absent artifact never reaches wasmtime as a bare
        # FileNotFoundError.
        resolved = _resolve_wasm_path(override=wasm_path)

        # Host pre-screen (regex backref) BEFORE the wasm call (fail-closed).
        self.compile(expression)
        typed_bindings = self._encode_bindings(bindings)

        cls = _load_relay_cel_class()
        handle = cls(wasm_path=resolved)

        def _run() -> dict[str, Any]:
            return handle.eval(
                expression, typed_bindings or None, relay_profile=True
            )

        envelope = self._timeout_host._run_with_timeout(
            _run, self.timeout_ms / 1000.0
        )
        return self._decode_envelope(envelope)

    def evaluate_with_trace(
        self,
        expression: str,
        bindings: Mapping[str, Any] | None = None,
    ) -> tuple[Any, dict[str, list[Any]]]:
        """Evaluate ``expression`` and return ``(value, udf_trace)``.

        Identical evaluation path to :meth:`evaluate` (same host guards, same
        wall-clock timeout + Store quarantine, same ``{"ok": false}`` error
        mapping), but ALSO surfaces the wasm ``udf_trace`` response field so the
        M1 pipeline can reconstruct ``udf_outputs_jcs`` / ``udfs_invoked`` from
        it on the wasm hot path WITHOUT a cel-python ``_env`` AST walk
        (VAL-CWC-P1HOST-014).

        ``udf_trace`` is the per-UDF-name list of typed-canonical
        ``{"t":...,"v":...}`` return values in CALL ORDER, exactly as the wasm
        emitted them (``packages/cel-wasm/crate/src/lib.rs`` ``udf_trace_drain``).
        It is the empty dict when no relay.* UDF executed (the wasm omits the
        field; a short-circuited branch is never recorded). The presence of this
        method is the capability the pipeline uses to DETECT the wasm path (it
        never reads ``RELAY_CEL_ENGINE``).
        """
        self.compile(expression)
        typed_bindings = self._encode_bindings(bindings)
        handle = self._thread_handle()

        def _run() -> dict[str, Any]:
            return handle.eval(
                expression, typed_bindings or None, relay_profile=True
            )

        try:
            envelope = self._timeout_host._run_with_timeout(
                _run, self.timeout_ms / 1000.0
            )
        except RelayCelError as err:
            from .errors import RelayCelTimeoutError

            if isinstance(err, RelayCelTimeoutError):
                self._quarantine_thread_handle()
            raise

        # Capture the udf_trace BEFORE decoding (decode may raise a structured
        # error; the trace is only meaningful on the success envelope, and the
        # crate only attaches it on {"ok": true}). _decode_envelope enforces the
        # host finiteness guard and error mapping on the value itself.
        value = self._decode_envelope(envelope)
        udf_trace = self._extract_udf_trace(envelope)
        return value, udf_trace

    # --- helpers -----------------------------------------------------

    def _encode_bindings(
        self, bindings: Mapping[str, Any] | None
    ) -> dict[str, Any]:
        """Encode caller bindings into the wasm typed-canonical form.

        ``None`` / empty -> ``{}``. Each binding value is converted via
        ``py_to_typed`` (the single Python<->wasm value codec).
        """
        if not bindings:
            return {}
        from .wasm_codec import py_to_typed

        return {name: py_to_typed(value) for name, value in bindings.items()}

    def _extract_udf_trace(self, envelope: Any) -> dict[str, list[Any]]:
        """Return the wasm ``udf_trace`` field as a per-name list-of-typed map.

        The crate attaches ``udf_trace`` (an object mapping each executed UDF
        name to a list of typed-canonical values in call order) only on a
        success envelope where at least one relay.* UDF ran; it is ABSENT
        otherwise (``lib.rs`` ``udf_trace_drain`` returns ``None`` -> field
        omitted). This helper normalizes that absence to an empty dict and
        validates the shape fail-closed so a malformed trace cannot silently
        corrupt the reconstructed ``udf_outputs_jcs`` (which feeds a digest).
        """
        if not isinstance(envelope, dict):
            return {}
        trace = envelope.get("udf_trace")
        if trace is None:
            return {}
        if not isinstance(trace, dict):
            raise RelayCelEngineError(
                f"wasm udf_trace must be an object; got {type(trace).__name__}",
                subtype="RELAY-CEL-ENGINE-REQUEST",
            )
        normalized: dict[str, list[Any]] = {}
        for name, values in trace.items():
            if not isinstance(name, str):
                raise RelayCelEngineError(
                    f"wasm udf_trace key must be a string; got {type(name).__name__}",
                    subtype="RELAY-CEL-ENGINE-REQUEST",
                )
            if not isinstance(values, list):
                raise RelayCelEngineError(
                    f"wasm udf_trace[{name!r}] must be a list; "
                    f"got {type(values).__name__}",
                    subtype="RELAY-CEL-ENGINE-REQUEST",
                )
            normalized[name] = list(values)
        return normalized

    def _decode_envelope(self, envelope: Any) -> Any:
        """Translate a wasm response envelope into a value or a structured error.

        Success -> ``typed_to_py`` of the typed-canonical value, then host
        ``_check_finite`` (RELAY-CEL-006 / NUMERIC-OOB) on the converted result.
        Failure -> RELAY-CEL-002 PROFILE (with the wasm's structured subtype) ->
        :class:`RelayCelProfileError`; every other ``{"ok": false}`` cause (001
        compile / 004 exec / 006 request / RELAY-CEL-PANIC) ->
        :class:`RelayCelEngineError` (RELAY-CEL-009) via
        :meth:`RelayCelEngineError.from_wasm_envelope` (never the host 004/006).
        """
        if not isinstance(envelope, dict):
            raise RelayCelEngineError(
                f"wasm engine returned a non-dict response: {type(envelope).__name__}",
                subtype="RELAY-CEL-ENGINE-REQUEST",
            )

        if envelope.get("ok") is True:
            value = typed_to_py(envelope["value"])
            # Host-side finiteness / safe-integer guard on the converted result.
            _check_finite(value)
            return value

        code = envelope.get("code", "")
        message = envelope.get("error", "wasm engine error")

        # RELAY-CEL-002 profile rejection: the wasm emits a STRUCTURED subtype;
        # map (code, subtype) -> RelayCelProfileError without message parsing.
        if code == _WASM_PROFILE_CODE:
            subtype = envelope.get("subtype")
            if not isinstance(subtype, str) or not subtype:
                # A profile rejection MUST carry a structured subtype; absent
                # one, treat it as an engine-request anomaly rather than guess.
                raise RelayCelEngineError(
                    f"wasm profile rejection missing structured subtype: {message}",
                    subtype="RELAY-CEL-ENGINE-REQUEST",
                )
            raise RelayCelProfileError(message, subtype=subtype)

        # Every other wasm failure cause -> the dedicated RELAY-CEL-009 engine
        # error with a per-cause subtype. Reuse the canonical mapping in
        # errors.py (do NOT reinvent it).
        raise RelayCelEngineError.from_wasm_envelope(code, message)


__all__ = ["WasmCelEvaluator"]
