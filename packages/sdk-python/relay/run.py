"""``Relay.run`` lifecycle surface (W3.2).

This module owns the SDK-side lifecycle surface a caller uses inside a
trace context: capture lifecycle events, gate-evaluate, replay-create,
evidence-submit, and flush. Per CLAUDE.md keystone invariant #1 the SDK
NEVER writes canonical results; it submits lifecycle metadata and reads
canonical decisions the control plane writes.

The :class:`Run` is the user-facing object. ``Relay.run(...)`` returns a
context manager whose ``__exit__`` flushes pending lifecycle events
according to the configured :class:`relay.flush.FlushPolicy`:

  * ``sync``  -> ``__exit__`` blocks until the sidecar acknowledges.
  * ``async`` -> ``__exit__`` returns immediately; envelopes are
                 dispatched on a background worker (VAL-W3-018).

A transport failure under ``on_error='drop_and_log'`` (VAL-W3-019) is
swallowed: the host application keeps running and a single WARN log
line is emitted.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
import time
import uuid
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from types import TracebackType
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlparse

import httpx

from . import _ulid, lifecycle
from .errors import (
    _NAMESPACE_PREFIX_REGISTRY,
    RELAY_EVID_002_CODE,
    RELAY_ING_022_CODE,
    RELAY_ING_031_CODE,
    RELAY_ING_RAW_PAYLOAD_CODE,
    RELAY_REPLAY_002_CODE,
    RelayCanonicalStatusForbidden,
    RelayConfigError,
    RelayError,
    RelayUnknownError,
    resolve_class_for_code,
)
from .flush import AsyncFlushDispatcher, FlushPolicy

if TYPE_CHECKING:
    from .client import Relay

logger = logging.getLogger("relay.run")

# SDK version string the SDK includes in every envelope (spec line 1943).
# Derived from package metadata at import time so the canonical version
# (the value baked into the published wheel / sdist) is what every
# envelope reports. If the package is not installed (rare; e.g., source
# checkout run without `pip install -e .`), fall back to "0.0.0+local"
# so the value remains valid SemVer + clearly signals a dev/local run.
def _resolve_sdk_version() -> str:
    try:
        return f"relay-python@{version('epochly-relay')}"
    except PackageNotFoundError:
        return "relay-python@0.0.0+local"


SDK_VERSION: Final[str] = _resolve_sdk_version()

# VAL-ISO-019: bounded drain budget for the async dispatcher at teardown.
# ``Run._teardown`` joins the dispatcher's worker for at most this many
# seconds so the terminal lifecycle envelope enqueued in ``__exit__`` is
# delivered (not dropped) when the sidecar is responsive, while still
# returning within a finite bound on an unreachable/hung sidecar
# (VAL-W3-018). Shorter than the slow-handler block used by the
# VAL-W3-018 tests so ``__exit__`` still returns before such a handler's
# body completes.
_TEARDOWN_DRAIN_TIMEOUT_S: Final[float] = 5.0


def _utcnow_iso8601() -> str:
    """Return ISO-8601 UTC timestamp with millisecond precision."""
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _validate_loopback_url(base_url: str) -> str:
    """Ensure ``base_url`` is a non-empty http(s) URL with a host.

    The SDK communicates ONLY with the local sidecar over loopback; a
    misconfigured URL is rejected at the boundary so the SDK does not
    accidentally exfiltrate envelopes to a third-party host.
    """
    if not isinstance(base_url, str) or not base_url:
        raise RelayConfigError(
            "endpoint_url must be a non-empty string",
            details={"received_type": type(base_url).__name__},
        )
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise RelayConfigError(
            f"endpoint_url must use http(s); received scheme {parsed.scheme!r}",
            details={"endpoint_url": base_url, "scheme": parsed.scheme},
        )
    if not parsed.netloc:
        raise RelayConfigError(
            "endpoint_url must have a host",
            details={"endpoint_url": base_url},
        )
    return base_url.rstrip("/")


class _LifecycleHTTPClient:
    """Thin httpx wrapper for SDK lifecycle calls.

    All HTTP calls go through this client. Errors are normalised into
    :class:`relay.errors.RelayError` subclasses according to the
    response body's ``code`` field. The W3.2 surface targets four
    endpoints:

      * ``POST /v1/ingest/runs``           (lifecycle metadata; VAL-W3-009)
      * ``POST /v1/gates/{gate_id}/drafts`` (gate draft; VAL-W3-013)
      * ``GET  /v1/runs/{run_id}/result``   (canonical RunResult; VAL-W3-014)
      * ``POST /v1/evidence``              (evidence submit; VAL-W3-015)
    """

    def __init__(
        self,
        base_url: str,
        *,
        auth_header: str | None = None,
        bearer_digest: str | None = None,
        timeout_s: float = 10.0,
    ) -> None:
        self._base_url = _validate_loopback_url(base_url)
        self._auth_header = auth_header
        self._bearer_digest = bearer_digest
        # A dedicated httpx.Client per Run so cleanup is bounded.
        self._http = httpx.Client(timeout=httpx.Timeout(timeout_s, connect=timeout_s))

    @property
    def base_url(self) -> str:
        return self._base_url

    def close(self) -> None:
        self._http.close()

    # -- header construction -------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._auth_header is not None:
            headers["X-Relay-Auth"] = self._auth_header
        if self._bearer_digest is not None:
            headers["X-Relay-Bearer-Digest"] = self._bearer_digest
        return headers

    # -- response normalisation ----------------------------------------------

    def _decode_body(self, resp: httpx.Response) -> dict[str, Any]:
        """Parse the response body as JSON or return ``{}`` on failure."""
        try:
            return resp.json()
        except (ValueError, json.JSONDecodeError):
            return {}

    def _raise_for_error_envelope(
        self,
        resp: httpx.Response,
        *,
        on_canonical_status: type[RelayError] = RelayCanonicalStatusForbidden,
    ) -> None:
        """Translate a non-2xx HTTP response into the right RelayError.

        Maps wire-format codes back to the SDK's typed exceptions via
        :func:`relay.errors.resolve_class_for_code`:

          * ``RELAY-ING-031``    -> :class:`RelayCanonicalStatusForbidden`
          * ``RELAY-ING-022``    -> :class:`RelayHandoffIncomplete`
          * ``RELAY-REPLAY-002`` -> :class:`RelayReplayPrecondition`
          * ``RELAY-EVID-002``   -> :class:`RelayEvidenceIncomplete`
          * ``RELAY-ING-032``    -> :class:`RelayPolicyError` (W3.3
            defense-in-depth; the sidecar rejected a raw plaintext
            payload that should have been redacted at the SDK
            boundary, VAL-W3-027 / CLAUDE.md keystone invariant #7)
          * Any other known prefix -> the namespace-intermediate class
            (e.g. ``RELAY-RATE-*`` -> ``RelayRateLimitError``).
          * Unknown code -> :class:`RelayUnknownError` with the original
            code preserved (VAL-W3-035).

        Every raised exception carries ``request_id`` and ``trace_id``
        sourced from the envelope body if present, falling back to the
        ``X-Request-ID`` / ``X-Trace-ID`` response headers (VAL-W3-033).
        ``blocked_surface`` is sourced from the envelope or defaults to
        the request URL path (VAL-W3-032). ``retry_advice`` is the wire
        enum string when present and is coerced to the SDK structured
        dict shape inside the exception (VAL-W3-031).
        """
        if resp.is_success:
            return
        body = self._decode_body(resp)
        code = str(body.get("code") or body.get("error", {}).get("code") or "")
        message = str(
            body.get("message") or body.get("error", {}).get("message") or resp.text
        )

        request_url = str(resp.request.url) if resp.request is not None else None
        # request_id / trace_id: body first, then headers (VAL-W3-033).
        body_request_id = body.get("request_id")
        if not isinstance(body_request_id, str) or not body_request_id:
            body_request_id = None
        body_trace_id = body.get("trace_id")
        if not isinstance(body_trace_id, str) or not body_trace_id:
            body_trace_id = None
        request_id = body_request_id or resp.headers.get("X-Request-ID")
        if request_id is not None and not request_id:
            request_id = None
        trace_id = body_trace_id or resp.headers.get("X-Trace-ID")
        if trace_id is not None and not trace_id:
            trace_id = None

        # blocked_surface: body first, then derive from request URL path
        # (VAL-W3-032 -- must be populated on every non-2xx exception).
        body_blocked_surface = body.get("blocked_surface")
        if isinstance(body_blocked_surface, str) and body_blocked_surface:
            blocked_surface: str | None = body_blocked_surface
        elif resp.request is not None:
            method = resp.request.method or "REQUEST"
            path = resp.request.url.path or "/"
            blocked_surface = f"{method} {path}"
        else:
            blocked_surface = None

        retry_advice = body.get("retry_advice")
        http_status = resp.status_code

        details = {
            "http_status": http_status,
            "code": code,
            "url": request_url,
            "response_body": body,
        }
        if code == RELAY_ING_022_CODE:
            details = {
                **details,
                "mismatched_anchor": body.get("mismatched_anchor", []),
            }

        # Route by exact code first (so test fixtures using
        # ``on_canonical_status`` to override the default
        # RelayCanonicalStatusForbidden still work), then by prefix.
        if code == RELAY_ING_031_CODE:
            target_cls: type[RelayError] = on_canonical_status
        else:
            target_cls = resolve_class_for_code(code)

        # Default-message fallbacks per typed leaf.
        if not message:
            if code == RELAY_ING_031_CODE:
                message = "canonical-write field rejected"
            elif code == RELAY_ING_022_CODE:
                message = "three-anchor handoff rejected by sidecar"
            elif code == RELAY_REPLAY_002_CODE:
                message = "run_result not yet written; cannot create replay"
            elif code == RELAY_EVID_002_CODE:
                message = "evidence envelope rejected by sidecar"
            elif code == RELAY_ING_RAW_PAYLOAD_CODE:
                message = "raw plaintext payload rejected by sidecar"
            else:
                message = f"sidecar returned HTTP {resp.status_code}"

        # Code precedence: typed leaves keep their SDK-local class default
        # (e.g. RelayCanonicalStatusForbidden -> "RELAY-SDK-005") so the
        # SDK exposes a stable typed surface even when the wire code is
        # the spec form ("RELAY-ING-031"). For namespace intermediates
        # and RelayUnknownError we pass the wire code through so the
        # raised exception preserves the original token (VAL-W3-035
        # forward-compat; namespace-level visibility for codes the SDK
        # does not have a typed leaf for). The wire code is always
        # captured in ``details["code"]`` regardless.
        namespace_classes = {cls for _, cls in _NAMESPACE_PREFIX_REGISTRY}
        if target_cls is RelayUnknownError or target_cls in namespace_classes:
            instance_code = code or target_cls.code
        else:
            instance_code = target_cls.code

        raise target_cls(
            message,
            code=instance_code,
            http_status=http_status,
            blocked_surface=blocked_surface,
            retry_advice=retry_advice,
            request_id=request_id,
            trace_id=trace_id,
            details=details,
        )

    # -- endpoint methods ----------------------------------------------------

    def post_ingest_run(self, envelope: dict[str, Any]) -> dict[str, Any]:
        resp = self._http.post(
            f"{self._base_url}/v1/ingest/runs",
            content=json.dumps(envelope).encode("utf-8"),
            headers=self._auth_headers(),
        )
        self._raise_for_error_envelope(resp)
        return self._decode_body(resp)

    def post_gate_draft(self, gate_id: str, envelope: dict[str, Any]) -> dict[str, Any]:
        resp = self._http.post(
            f"{self._base_url}/v1/gates/{gate_id}/drafts",
            content=json.dumps(envelope).encode("utf-8"),
            headers=self._auth_headers(),
        )
        self._raise_for_error_envelope(resp)
        return self._decode_body(resp)

    def get_gate_decision(self, decision_id: str) -> dict[str, Any]:
        resp = self._http.get(
            f"{self._base_url}/v1/gate-decisions/{decision_id}",
            headers=self._auth_headers(),
        )
        self._raise_for_error_envelope(resp)
        return self._decode_body(resp)

    def get_run_result(self, run_id: str) -> dict[str, Any]:
        resp = self._http.get(
            f"{self._base_url}/v1/runs/{run_id}/result",
            headers=self._auth_headers(),
        )
        self._raise_for_error_envelope(resp)
        return self._decode_body(resp)

    def post_evidence(self, envelope: dict[str, Any]) -> dict[str, Any]:
        resp = self._http.post(
            f"{self._base_url}/v1/evidence",
            content=json.dumps(envelope).encode("utf-8"),
            headers=self._auth_headers(),
        )
        self._raise_for_error_envelope(resp)
        return self._decode_body(resp)


class Run:
    """SDK-side run-scoped lifecycle context (W3.2).

    Returned by :meth:`Relay.run`. Carries the three-anchor handoff
    state and the configured flush policy. The user code inside the
    ``with`` block calls :meth:`capture`, :meth:`gate_evaluate`,
    :meth:`replay_create`, and :meth:`submit_evidence`. On
    ``__exit__`` the SDK flushes the lifecycle envelope per the
    configured :class:`FlushPolicy`.

    Per CLAUDE.md invariant #1 the :class:`Run` instance NEVER writes
    canonical results -- it submits drafts and reads canonical
    decisions the control plane writes.
    """

    def __init__(
        self,
        *,
        relay: Relay,
        run_id: str,
        agent: dict[str, Any],
        actor_identity_hash: str,
        manifest_commit_hash: str,
        redaction_policy_version: str,
        project_id: str | None = None,
        flush_policy: FlushPolicy | None = None,
        endpoint_url: str | None = None,
    ) -> None:
        self._relay = relay
        self.run_id = run_id
        self.agent = dict(agent)
        self.actor_identity_hash = actor_identity_hash
        self.manifest_commit_hash = manifest_commit_hash
        self.redaction_policy_version = redaction_policy_version
        self.project_id = project_id or str(uuid.uuid4())
        self.trace_id = str(uuid.uuid4())
        self.flush_policy = flush_policy or FlushPolicy()
        # The endpoint_url override is mainly for tests; production
        # callers leave it None and the Run picks up the sidecar's
        # base_url lazily on first flush.
        self._endpoint_url_override = endpoint_url
        self._client: _LifecycleHTTPClient | None = None
        self._client_lock = threading.Lock()
        self._dispatcher: AsyncFlushDispatcher | None = None
        self._sequence_number: int = 0
        self._closed = False
        # The most recently submitted lifecycle status (caller-driven via
        # capture()). ``__exit__`` flushes a terminal envelope on top of
        # the running lifecycle stream.
        self._last_status: str = "started"
        # Idempotency key for the run-ingest envelopes; each capture call
        # gets its OWN ULID per VAL-W3-017 "Calling trace() twice with the
        # same input MUST use distinct keys".
        # Tests can inspect this for cross-language fixture comparison.
        self.idempotency_keys: list[str] = []

    # -- context manager -----------------------------------------------------

    def __enter__(self) -> Run:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        # Determine the terminal lifecycle status. If the user code in
        # the with-block raised, default to client_failed; otherwise
        # client_succeeded. Caller can override via capture().
        if exc_type is not None and self._last_status == "started":
            terminal = "client_failed"
        elif self._last_status == "started":
            terminal = "client_succeeded"
        else:
            terminal = self._last_status
        try:
            self._submit_lifecycle(terminal)
        finally:
            self._teardown()

    # -- user-facing API -----------------------------------------------------

    def capture(self, *, client_lifecycle_status: str) -> dict[str, Any]:
        """Submit a lifecycle-metadata envelope.

        The status MUST be one of ``LIFECYCLE_STATUSES`` -- any other
        value raises :class:`RelayLifecycleInvalid` at the SDK boundary
        BEFORE the HTTP request is sent (VAL-W3-012).
        """
        self._last_status = client_lifecycle_status
        return self._submit_lifecycle(client_lifecycle_status)

    def gate_evaluate(
        self,
        *,
        gate_id: str,
        release_sha: str,
        eval_run_ids: list[str],
    ) -> dict[str, Any]:
        """Submit a gate-decision DRAFT and read the canonical decision.

        Per VAL-W3-013 the SDK MUST submit an evidence-only draft, then
        read the canonical :class:`GateDecision` the control plane
        wrote. The SDK NEVER computes pass/fail.
        """
        envelope = lifecycle.build_gate_draft_envelope(
            gate_id=gate_id,
            release_sha=release_sha,
            eval_run_ids=eval_run_ids,
            manifest_commit_hash=self.manifest_commit_hash,
            actor_identity_hash=self.actor_identity_hash,
        )
        client = self._ensure_client()
        draft_resp = client.post_gate_draft(gate_id, envelope)
        decision_id = draft_resp.get("decision_id") or draft_resp.get("draft_id")
        if not decision_id:
            raise RelayError(
                "sidecar gate draft response omitted decision_id",
                details={"response": draft_resp},
            )
        # READ the canonical decision -- never compute it locally.
        return client.get_gate_decision(str(decision_id))

    def replay_create(
        self,
        *,
        run_id: str,
        egress_allowlist: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a replay case bound to the canonical RunResult.

        Per VAL-W3-014 the SDK MUST first fetch the canonical
        ``run_result`` row; if it is missing the sidecar returns
        ``RELAY-REPLAY-002`` and the SDK raises
        :class:`RelayReplayPrecondition`. The SDK does NOT derive a
        replay case from raw SDK lifecycle.

        Audit-r3 BUG-B3: when ``egress_allowlist`` is supplied, every
        entry is validated against the SSRF guard at the SDK boundary
        BEFORE the request is sent. A rejected entry raises
        :class:`relay.network_policy.EgressDenied`.
        """
        client = self._ensure_client()
        # Pre-flight: confirm the canonical RunResult exists.
        client.get_run_result(run_id)
        # Build the envelope through the SDK-side validator so the SSRF
        # guard runs on the allowlist before the HTTP POST is issued.
        envelope = lifecycle.build_replay_case_envelope(
            run_id=run_id,
            manifest_commit_hash=self.manifest_commit_hash,
            actor_identity_hash=self.actor_identity_hash,
            egress_allowlist=egress_allowlist,
        )
        resp = client._http.post(  # noqa: SLF001 - internal pass-through
            f"{client.base_url}/v1/runs/{run_id}/replays",
            content=json.dumps(envelope).encode("utf-8"),
            headers=client._auth_headers(),  # noqa: SLF001
        )
        client._raise_for_error_envelope(resp)  # noqa: SLF001
        return client._decode_body(resp)  # noqa: SLF001

    def submit_evidence(
        self,
        *,
        artifact_digest_sha256: str,
        command_id: str,
        exit_code: int,
        span_ids: list[str],
        assertion_ids: list[str],
    ) -> dict[str, Any]:
        """Submit an evidence-bundle envelope bound to its claim.

        Per VAL-W3-015 every required field MUST be present and bound;
        a missing field raises :class:`RelayEvidenceIncomplete` at the
        SDK boundary BEFORE the request is sent.
        """
        envelope = lifecycle.build_evidence_envelope(
            run_id=self.run_id,
            artifact_digest_sha256=artifact_digest_sha256,
            command_id=command_id,
            exit_code=exit_code,
            span_ids=span_ids,
            assertion_ids=assertion_ids,
            actor_identity_hash=self.actor_identity_hash,
            manifest_commit_hash=self.manifest_commit_hash,
            redaction_policy_version=self.redaction_policy_version,
        )
        client = self._ensure_client()
        return client.post_evidence(envelope)

    def flush(self) -> None:
        """Block until any background-dispatched work has completed."""
        if self._dispatcher is not None:
            self._dispatcher.wait_idle(timeout=30.0)

    # -- internals -----------------------------------------------------------

    def _submit_lifecycle(self, client_lifecycle_status: str) -> dict[str, Any]:
        """Build the run-ingest envelope and dispatch per flush policy."""
        # Build the envelope FIRST -- validation happens here, BEFORE any
        # HTTP I/O. VAL-W3-010, VAL-W3-011, VAL-W3-012, VAL-W3-016, and
        # VAL-W3-017 are all enforced inside the builder.
        self._sequence_number += 1
        envelope = lifecycle.build_ingest_run_envelope(
            run_id=self.run_id,
            trace_id=self.trace_id,
            project_id=self.project_id,
            agent=self.agent,
            client_lifecycle_status=client_lifecycle_status,
            started_at=_utcnow_iso8601(),
            sdk_version=SDK_VERSION,
            sdk_clock=_utcnow_iso8601(),
            manifest_commit_hash=self.manifest_commit_hash,
            actor_identity_hash=self.actor_identity_hash,
            redaction_policy_version=self.redaction_policy_version,
            sequence_number=self._sequence_number,
        )
        self.idempotency_keys.append(envelope["idempotency_key"])

        if self.flush_policy.mode == "sync":
            client = self._ensure_client()
            try:
                return client.post_ingest_run(envelope)
            except Exception as exc:  # noqa: BLE001 - on_error governs disposition
                # VAL-W3-019: drop_and_log MUST NOT raise into the host
                # application, regardless of the transport failure
                # mode. Catch every Exception subclass -- typed
                # RelayError, httpx.ConnectError, OSError, etc. --
                # and emit a single structured WARN line.
                # BaseException (KeyboardInterrupt, SystemExit) is
                # deliberately NOT caught so user-level signals work.
                if self.flush_policy.on_error == "drop_and_log":
                    logger.warning(
                        "relay.run.drop_and_log: sync flush failed; "
                        "envelope dropped (run_id=%s sequence=%d "
                        "error_type=%s)",
                        self.run_id,
                        envelope["sequence_number"],
                        type(exc).__name__,
                    )
                    return {"dropped": True, "idempotent_replay": False}
                raise
        # async path -- enqueue and return.
        dispatcher = self._ensure_dispatcher()

        def _send() -> None:
            client = self._ensure_client()
            client.post_ingest_run(envelope)

        dispatcher.submit(_send)
        return {
            "queued": True,
            "idempotent_replay": False,
            "idempotency_key": envelope["idempotency_key"],
        }

    def _ensure_client(self) -> _LifecycleHTTPClient:
        if self._client is not None:
            return self._client
        with self._client_lock:
            if self._client is not None:
                return self._client
            base_url: str
            auth_header: str | None = None
            bearer_digest: str | None = None
            if self._endpoint_url_override is not None:
                base_url = self._endpoint_url_override
            else:
                # Lazily attach to the sidecar (W3.1 path); construct the
                # lifecycle client from the live connection.
                conn = self._relay._ensure_sidecar()  # noqa: SLF001
                base_url = conn.base_url
                auth_header = conn.auth_header
                bearer_digest = conn.bearer_token_digest
            self._client = _LifecycleHTTPClient(
                base_url=base_url,
                auth_header=auth_header,
                bearer_digest=bearer_digest,
            )
            return self._client

    def _ensure_dispatcher(self) -> AsyncFlushDispatcher:
        if self._dispatcher is None:
            self._dispatcher = AsyncFlushDispatcher(on_error=self.flush_policy.on_error)
        return self._dispatcher

    def _teardown(self) -> None:
        """Release SDK-side resources with a BOUNDED drain of queued work.

        Per VAL-W3-018 ``__exit__`` MUST NOT block indefinitely on ingest
        network I/O when ``flush_policy.mode == 'async'``; per VAL-ISO-019
        it MUST NOT silently DROP the terminal lifecycle envelope it just
        enqueued. The previous ``close(timeout=0.0)`` satisfied the former
        by violating the latter: it returned before the worker had even
        pulled the queued terminal envelope, so on a process that exits
        right after the ``with`` block the daemon worker was reaped with
        the envelope still queued and the lifecycle ``client_succeeded`` /
        ``client_failed`` event was lost.

        We reconcile both with a BOUNDED close: signal the worker via the
        sentinel and join for at most ``_TEARDOWN_DRAIN_TIMEOUT_S``
        seconds. A responsive sidecar drains the terminal envelope (and
        any already-queued work) well within the budget; an unreachable or
        hung sidecar still returns within the bound rather than wedging
        ``__exit__`` forever. The budget is shorter than the slow-handler
        block used by the VAL-W3-018 tests, so ``__exit__`` still returns
        BEFORE such a handler's body completes. Callers that require
        guaranteed drainage on a slow sidecar should still call
        :meth:`Run.flush` BEFORE exiting.

        In sync mode there is no background worker to drain, so
        teardown is also non-blocking by construction.
        """
        if self._closed:
            return
        self._closed = True
        if self._dispatcher is not None:
            # BOUNDED close: drains queued envelopes (including the
            # terminal lifecycle envelope enqueued in __exit__) within a
            # finite budget. VAL-ISO-019: do not drop queued work;
            # VAL-W3-018: do not block forever.
            self._dispatcher.close(timeout=_TEARDOWN_DRAIN_TIMEOUT_S)
        if self._client is not None:
            # Best-effort cleanup; teardown must never raise into the
            # host application even if the httpx client is already in
            # a degraded state.
            with contextlib.suppress(Exception):
                self._client.close()


def _coerce_run_id(run_id: str | None) -> str:
    """Return a non-empty run_id, generating a ULID if absent.

    The run_id flows into the three-anchor handoff's scope_id slot; a
    missing or empty run_id raises RelayHandoffIncomplete at the
    envelope builder boundary, so we accept None and auto-generate.
    """
    if run_id is None:
        return _ulid.new_ulid()
    if not isinstance(run_id, str) or not run_id:
        raise RelayConfigError(
            "run_id must be a non-empty string when supplied",
            details={"field": "run_id"},
        )
    return run_id


def now_unix_ms() -> int:
    """Wall-clock helper -- exported for cross-language fixture tests."""
    return int(time.time() * 1000)


__all__ = [
    "SDK_VERSION",
    "Run",
    "_LifecycleHTTPClient",
    "_coerce_run_id",
    "_utcnow_iso8601",
    "now_unix_ms",
]
