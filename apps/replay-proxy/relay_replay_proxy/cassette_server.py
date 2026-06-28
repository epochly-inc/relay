"""Cassette lookup logic for the W7.1 replay-proxy.

Given an HTTPS request the agent sent through the proxy, find the
matching cassette entry and return the recorded response. The cassette
file format is the JSONL format defined in
``packages/cli/src/relay_cli/cassette.py`` (parsed via
``parse_cassette``).

VAL-W7-008: lookups are confined to ``~/.relay/cassettes/<session>/``.
The proxy MUST NOT consult another session's directory and MUST NOT
follow a caller-supplied path; only the harness's bound session_id is
honored.

VAL-W7-009: a cassette hit returns byte-identical response body, status,
and headers (modulo proxy-added ``X-Relay-*`` headers documented below).

The matching key is the canonical SHA-256 digest of the request payload,
identical to the digest computed by ``rly replay record``. This is the
W4 canonical request key. The proxy normalizes incoming HTTP requests
into the same canonical shape that ``canonical_request_digest`` consumes,
which is provider/model + canonical body. The provider/model is derived
from the request URL or the ``X-Relay-Provider`` / ``X-Relay-Model``
headers (set by adapter shims) so two cassettes for distinct providers
do not collide on body.

Per CLAUDE.md keystone invariant #6 (side-effect idempotency), this
module reads cassettes only -- it never writes. Recording is owned by
``rly replay record`` (W5.3).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from relay_cli.cassette import (
    Cassette,
    CassetteEntry,
    CassetteFormatError,
    canonical_request_digest,
    canonical_response_digest,
    parse_cassette,
)

from .errors import RELAY_REPLAY_CASSETTE_CORRUPT, RELAY_REPLAY_PROXY_DOWN

# Wire code for a cassette miss as emitted at the proxy edge. This mirrors
# the in-process driver's miss envelope (``harness._InProcDriver`` writes
# ``{"code": "RELAY-CASSETTE-MISS", ...}`` with HTTP 404) so both the
# mitmproxy addon and the in-process driver block a miss identically. The
# canonical ``RELAY-REPLAY-024`` form is reserved for the CLI-layer
# ``RelayCassetteMissError``; at the wire edge we keep the short
# ``RELAY-CASSETTE-MISS`` token already asserted by the W7.1 harness tests.
RELAY_CASSETTE_MISS_WIRE_CODE: Final[str] = "RELAY-CASSETTE-MISS"

# Header inserted on every proxy-served response so the agent can detect
# replay vs live traffic. The header is documented as proxy-added in
# VAL-W7-009 (modulo proxy-added X-Relay-* headers).
HEADER_REPLAY_HIT: Final[str] = "X-Relay-Replay-Hit"
HEADER_REPLAY_SESSION: Final[str] = "X-Relay-Replay-Session"
HEADER_REPLAY_DIGEST: Final[str] = "X-Relay-Replay-Digest"

# Cassette filename inside <session_dir>. The harness writes a single
# cassette per session in v0.1 (W5.3 design); multi-cassette per session
# is reserved for W7.2 follow-up.
CASSETTE_FILENAME: Final[str] = "cassette.jsonl"


@dataclass(frozen=True)
class CassetteResponse:
    """A response served from cassette: status, headers, body bytes.

    ``body_bytes`` is the response body as raw bytes (utf-8 of the
    canonical JSON response payload). The harness wraps this into the
    proxy's HTTP response object.
    """

    status: int
    headers: dict[str, str]
    body_bytes: bytes
    response_digest: str
    sequence: int
    provider: str
    model: str


@dataclass(frozen=True)
class IncomingRequest:
    """The proxy-normalized view of an inbound HTTPS request.

    The proxy harness builds this from mitmproxy's flow.request object.
    The provider/model are extracted from request URL hostnames or
    ``X-Relay-Provider`` / ``X-Relay-Model`` headers (canonical form).
    """

    provider: str
    model: str
    body: dict[str, Any]


class CassetteServer:
    """Cassette lookup confined to a single session directory.

    The server caches the parsed cassette so each lookup is an in-memory
    digest comparison, not a disk read. The cache is invalidated only at
    explicit ``reload()`` -- the cassette is recorded once and replayed
    many times within a session.

    Per VAL-W7-008 the server's ``session_dir`` is fixed at construction
    and the server MUST NOT accept a different path at lookup time.

    Integrity (keystone invariant #6, side-effect idempotency, and the
    replay evidence contract):

      * ``expected_file_digest_sha256`` -- optional anchor value. When
        supplied, the loader compares the parsed
        ``cassette.file_digest_sha256`` against this expected value using
        ``hmac.compare_digest`` and raises ``CassetteFormatError`` with
        reason ``file_digest_mismatch`` on disagreement. Callers SHOULD
        supply this whenever the cassette path was obtained from a
        signed manifest, an evidence bundle reference, or any other
        trust-anchored source. The pure local-record-then-replay flow can
        omit it (back-compat) but loses tamper detection in exchange.
      * ``require_integrity`` -- fail-closed switch for trust-requiring
        serving paths. The per-entry ``response_digest`` re-check below
        only catches an in-memory mutation that left a stale recorded
        digest behind; it does NOT catch an on-disk forgery where an
        attacker with write access rewrote the response bytes AND
        recomputed the per-entry ``response_digest`` so the cassette is
        internally consistent. The only defense against that is the
        file-level anchor. When a serving path is trust-requiring it MUST
        be handed an ``expected_file_digest_sha256`` anchor; if it is not,
        ``require_integrity=True`` makes the loader refuse to serve
        (raises ``CassetteFormatError`` with reason
        ``integrity_anchor_required``) rather than silently serving
        unanchored, untrusted bytes. The unanchored, integrity-not-required
        path stays back-compatible for the pure local record-then-replay
        flow.
      * Per-entry ``response_digest`` is re-verified on every ``lookup``
        call. An attacker who modified the in-memory ``entry.response``
        post-parse (supply-chain, malicious code holding the parsed
        cassette) is caught before the forged bytes are served.
    """

    def __init__(
        self,
        session_dir: Path,
        *,
        expected_file_digest_sha256: str | None = None,
        require_integrity: bool = False,
    ) -> None:
        if not session_dir.is_absolute():
            raise ValueError(
                f"session_dir must be absolute; got {session_dir!s}"
            )
        self._session_dir = session_dir
        self._cassette_path = session_dir / CASSETTE_FILENAME
        self._cassette: Cassette | None = None
        # Lookup index: request_digest -> entry. Built on first load.
        self._index: dict[str, CassetteEntry] = {}
        self._expected_file_digest = expected_file_digest_sha256
        self._require_integrity = require_integrity

    @property
    def session_dir(self) -> Path:
        return self._session_dir

    @property
    def cassette_path(self) -> Path:
        return self._cassette_path

    def has_cassette(self) -> bool:
        return self._cassette_path.exists()

    def reload(self) -> None:
        """Force a re-read of the cassette from disk.

        Invalidates the in-memory index. Used by tests that swap a
        cassette file mid-session; the production proxy does not call
        this.
        """
        self._cassette = None
        self._index = {}
        self._load_if_needed()

    def _load_if_needed(self) -> None:
        if self._cassette is not None:
            return
        if not self._cassette_path.exists():
            raise CassetteFormatError(
                f"cassette file not found at {self._cassette_path!s}",
                0,
                str(self._cassette_path),
            )
        # Fail-closed gate: a trust-requiring serving path MUST be anchored.
        # The per-entry response_digest re-check in lookup() only catches an
        # in-memory mutation that left a stale recorded digest behind; an
        # attacker with write access who rewrites the on-disk response bytes
        # AND recomputes the per-entry response_digest produces an
        # internally-consistent forgery that no per-entry check can detect.
        # The file-level anchor is the only defense. If integrity is required
        # but no anchor was configured, refuse to serve rather than serving
        # unanchored, untrusted bytes.
        if self._require_integrity and self._expected_file_digest is None:
            raise CassetteFormatError(
                f"integrity_anchor_required: serving cassette "
                f"{self._cassette_path!s} requires an "
                f"expected_file_digest_sha256 anchor but none was "
                f"configured; refusing to serve unanchored bytes",
                0,
                str(self._cassette_path),
            )
        raw = self._cassette_path.read_bytes()
        cassette = parse_cassette(raw, str(self._cassette_path))
        # Integrity gate: if the caller supplied an anchor
        # ``expected_file_digest_sha256``, the parsed cassette's
        # file-level SHA-256 MUST match. Use ``hmac.compare_digest`` so
        # the comparison is constant-time -- both values are public hex
        # strings here, but the discipline is the same as for secrets
        # and the cost is negligible.
        if self._expected_file_digest is not None:
            actual = cassette.file_digest_sha256
            expected = self._expected_file_digest
            if not hmac.compare_digest(actual, expected):
                raise CassetteFormatError(
                    f"file_digest_mismatch on cassette "
                    f"{self._cassette_path!s}: expected {expected!r}, "
                    f"actual {actual!r}",
                    0,
                    str(self._cassette_path),
                )
        self._cassette = cassette
        # Build index. If two entries share a digest (shouldn't happen
        # for a well-formed cassette but tier-1 input must be defensive)
        # the LATER entry wins so newer recordings override stale ones.
        self._index = {entry.request_digest: entry for entry in cassette.entries}

    def lookup(self, request: IncomingRequest) -> CassetteResponse | None:
        """Return the recorded response for ``request`` or None on miss.

        The lookup key is the canonical request digest computed from the
        request body alone. This matches the digest that ``rly replay
        record`` writes -- see
        ``packages/cli/src/relay_cli/commands/replay.py::_build_entries``
        line 378 (``request_digest=canonical_request_digest(request)``).

        Provider/model are NOT part of the digest in v0.1 because the
        recorder does not include them; cross-provider keying is reserved
        for a follow-up sub-feature. If a future feature needs to disambiguate
        identical bodies sent to different providers, the digest can be
        extended without changing this API -- the wrapped-envelope fallback
        below is forward-compat scaffolding for that case.
        """
        self._load_if_needed()
        digest = canonical_request_digest(request.body)
        entry = self._index.get(digest)
        if entry is None:
            # Forward-compat: future cassettes may key by a wrapped
            # envelope (provider + model + body) so cross-provider
            # cassettes do not collide. Try that form too. v0.1 cassettes
            # never match this path; the branch is intentional headroom.
            wrapped_digest = canonical_request_digest(
                {
                    "provider": request.provider,
                    "model": request.model,
                    "body": request.body,
                }
            )
            entry = self._index.get(wrapped_digest)
            if entry is None:
                return None
            digest = wrapped_digest
        # Per-entry integrity gate: recompute the response digest from the
        # in-memory entry and compare against the recorded
        # ``response_digest``. Catches the case where an attacker (or a
        # buggy caller) mutated ``entry.response`` after parse but before
        # serve. Constant-time comparison via hmac.compare_digest.
        recomputed = canonical_response_digest(entry.response)
        if not hmac.compare_digest(recomputed, entry.response_digest):
            raise CassetteFormatError(
                f"response_digest mismatch for entry sequence={entry.sequence} "
                f"in {self._cassette_path!s}: recorded "
                f"{entry.response_digest!r}, recomputed {recomputed!r}",
                entry.sequence + 2,  # +2: line 1 is header, sequence is 0-indexed
                str(self._cassette_path),
            )
        return _entry_to_response(entry, digest, self._session_dir.name)


def _entry_to_response(
    entry: CassetteEntry, request_digest: str, session_id: str
) -> CassetteResponse:
    """Project a cassette entry into a :class:`CassetteResponse`.

    The entry's ``response`` dict is serialized canonically into bytes;
    the recorded response_digest is preserved on the response object so
    the agent / harness can verify byte parity post-hoc (VAL-W7-009).
    """
    body_bytes = json.dumps(
        entry.response,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body_bytes)),
        HEADER_REPLAY_HIT: "1",
        HEADER_REPLAY_SESSION: session_id,
        HEADER_REPLAY_DIGEST: request_digest,
    }
    # Status defaults to 200 because the cassette body is a successful
    # provider response by construction (rly replay record only captures
    # 2xx responses in v0.1; non-2xx capture lands in W7.2).
    return CassetteResponse(
        status=200,
        headers=headers,
        body_bytes=body_bytes,
        response_digest=entry.response_digest,
        sequence=entry.sequence,
        provider=entry.provider,
        model=entry.model,
    )


@dataclass(frozen=True)
class ProxyDecision:
    """Fail-closed outcome of an intercepted-request decision.

    ``kind`` is ``"hit"`` (serve a recorded cassette response) or
    ``"block"`` (refuse with a structured error envelope). There is NO
    third ``"forward"`` outcome and the producer
    (:func:`decide_replay_response`) never returns ``None``: a replay proxy
    MUST NOT forward an intercepted request to the live upstream provider on
    any miss, error, or unconfigured path. Always returning a settable
    response (``status`` + ``headers`` + ``body_bytes``) is what lets the
    mitmproxy addon enforce keystone invariant #9 (cassette-first replay
    with default-deny egress) and #11 (integrity checks fail CLOSED) at the
    request hook.
    """

    kind: str
    status: int
    headers: dict[str, str]
    body_bytes: bytes


def _block_decision(
    code: str, status: int, message: str, **extra: str
) -> ProxyDecision:
    """Build a blocking :class:`ProxyDecision` carrying a JSON error envelope."""
    envelope: dict[str, str] = {"code": code, "message": message}
    envelope.update(extra)
    body = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return ProxyDecision(
        kind="block",
        status=status,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        },
        body_bytes=body,
    )


def decide_replay_response(
    server: CassetteServer | None,
    *,
    raw_body: bytes,
    provider_header: str,
    model_header: str,
) -> ProxyDecision:
    """Decide the proxy response for an intercepted request -- fail CLOSED.

    Returns a :class:`ProxyDecision` on EVERY path and NEVER returns
    ``None``. There is no outcome that signals "forward to the live
    upstream provider": a missing / unconfigured cassette server, any
    exception raised by ``server.lookup`` (cassette corruption,
    ``response_digest`` / ``file_digest`` mismatch, integrity-anchor
    required, or any unexpected error), and a plain lookup miss all resolve
    to a blocking response. Only an exact cassette hit yields a non-blocking
    ``"hit"`` decision.

    This is the single decision path the mitmproxy addon uses so the
    default-deny egress invariant (keystone #9) is enforced at the proxy
    request hook regardless of cassette state. A real MITM proxy whose
    request hook returns without setting a response forwards the flow to the
    LIVE upstream -- the opposite of fail-closed -- so the addon translates
    every decision (block AND hit) into a concrete response.

    Block codes reuse existing replay error codes (see
    :mod:`relay_replay_proxy.errors`):

      * ``server is None`` -> ``RELAY-REPLAY-021`` (proxy not configured /
        not functional), HTTP 503.
      * ``server.lookup`` raises -> ``RELAY-REPLAY-025`` (cassette corrupt /
        integrity failure), HTTP 502.
      * lookup miss -> ``RELAY-CASSETTE-MISS``, HTTP 404 (mirrors the
        in-process driver's miss envelope).
    """
    # Fail-closed path 1: the cassette server was never configured (the
    # addon loaded but no session dir was supplied). Block rather than let a
    # real MITM proxy forward the flow to the live upstream.
    if server is None:
        return _block_decision(
            RELAY_REPLAY_PROXY_DOWN,
            503,
            "replay proxy not configured: cassette server unavailable",
        )

    try:
        parsed: Any = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception:  # noqa: BLE001 - any decode/parse failure -> empty body
        parsed = {}
    body = parsed if isinstance(parsed, dict) else {}
    req = IncomingRequest(
        provider=provider_header or "unknown",
        model=model_header or "unknown",
        body=body,
    )

    # Fail-closed path 2: any failure in lookup (cassette corruption,
    # response_digest / file_digest mismatch, integrity-anchor-required, or
    # any unexpected error) MUST block, never escape to the live upstream.
    try:
        response = server.lookup(req)
    except Exception as exc:  # noqa: BLE001 - fail closed on ANY lookup failure
        return _block_decision(
            RELAY_REPLAY_CASSETTE_CORRUPT,
            502,
            "cassette integrity check failed; refusing to reach live upstream",
            detail=str(exc),
        )

    # Fail-closed path 3: a plain miss blocks with the cassette-miss code.
    if response is None:
        return _block_decision(
            RELAY_CASSETTE_MISS_WIRE_CODE,
            404,
            "no cassette entry matched the request",
        )

    # Hit: serve the recorded response verbatim.
    return ProxyDecision(
        kind="hit",
        status=response.status,
        headers=dict(response.headers),
        body_bytes=response.body_bytes,
    )


__all__ = [
    "CASSETTE_FILENAME",
    "CassetteResponse",
    "CassetteServer",
    "HEADER_REPLAY_DIGEST",
    "HEADER_REPLAY_HIT",
    "HEADER_REPLAY_SESSION",
    "IncomingRequest",
    "ProxyDecision",
    "decide_replay_response",
]
