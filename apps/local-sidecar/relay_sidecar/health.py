"""``/health`` route with bearer-digest auth + nonce challenge (W2.1).

VAL-W2-007: ``GET /health`` requires header ``X-Relay-Bearer-Digest:
<digest>`` matching the lockfile's ``bearer_token_digest`` field.
Mismatch -> HTTP 401 with envelope code ``RELAY-SIDECAR-AUTH-MISMATCH``.

VAL-W2-008: A nonce challenge prevents "another process bound the port
between lockfile read and HTTP attach". Flow:

  1. Client issues ``GET /health/nonce`` with the bearer digest. Server
     returns ``{nonce, issued_at}``.
  2. Client signs ``f"{nonce}:{bearer_token}"`` with SHA-256, sends the
     hex digest as ``X-Relay-Nonce-Proof`` header on the actual ``/health``
     request along with ``X-Relay-Nonce: <nonce>``.
  3. Server verifies the proof AND checks ``issued_at`` is within 5s of
     the current time. Expired nonces -> 401 ``RELAY-SIDECAR-NONCE-EXPIRED``.

For W2.1 the route handlers are exposed via ``build_app(state)`` which
returns a FastAPI app. The full uvicorn lifecycle lands in W2.2; W2.1
exercises the routes via FastAPI's ``TestClient`` (httpx-based).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request

from . import __version__
from .errors import (
    RELAY_SIDECAR_AUTH_MISMATCH,
    RELAY_SIDECAR_AUTH_MISMATCH_CODE,
    RELAY_SIDECAR_NONCE_EXPIRED,
    RELAY_SIDECAR_NONCE_EXPIRED_CODE,
)

# Nonce time-to-live. Per the eng plan A1 "port hijack mitigation" the
# default TTL is 5 seconds; >5s replays return RELAY-SIDECAR-NONCE-EXPIRED.
DEFAULT_NONCE_TTL_S: float = 5.0


@dataclass
class HealthState:
    """Per-process server state for the /health surface.

    Attributes:
        port: The bound port (recorded in the lockfile).
        bearer_token: Plaintext bearer token. Held in process memory only;
            never serialized to disk. Returned to the spawner of the
            sidecar by ``acquire_or_attach``.
        bearer_token_digest: ``sha256-<hex>`` form matching the lockfile.
        nonce_ttl_s: Override the default TTL (tests use a tiny TTL).
        _issued_nonces: Map ``nonce -> issued_at`` for replay detection.
    """

    port: int
    bearer_token: str
    bearer_token_digest: str
    nonce_ttl_s: float = DEFAULT_NONCE_TTL_S
    _issued_nonces: dict[str, float] = field(default_factory=dict)


def _bearer_digest_of(token: str) -> str:
    """Return the canonical ``sha256-<hex>`` digest of ``token``."""
    return f"sha256-{hashlib.sha256(token.encode('utf-8')).hexdigest()}"


def _proof_of(nonce: str, token: str) -> str:
    """Compute the canonical nonce proof: SHA-256(``nonce:token``)."""
    return hashlib.sha256(f"{nonce}:{token}".encode()).hexdigest()


def build_app(state: HealthState) -> FastAPI:
    """Build the FastAPI app exposing /health and /health/nonce."""
    app = FastAPI(title="relay-sidecar", version=__version__)

    @app.get("/health/nonce")
    async def issue_nonce(
        x_relay_bearer_digest: str | None = Header(default=None),
    ) -> dict[str, Any]:
        if x_relay_bearer_digest != state.bearer_token_digest:
            raise HTTPException(
                status_code=401,
                detail={
                    "code": RELAY_SIDECAR_AUTH_MISMATCH_CODE,
                    "error_class": RELAY_SIDECAR_AUTH_MISMATCH,
                    "message": "bearer digest mismatch on nonce issue",
                },
            )
        # 128 bits of entropy is sufficient for a 5-second TTL anti-replay.
        nonce = secrets.token_urlsafe(16)
        issued_at = time.monotonic()
        state._issued_nonces[nonce] = issued_at
        return {"nonce": nonce, "issued_at": issued_at}

    @app.get("/health")
    async def health(
        request: Request,
        x_relay_bearer_digest: str | None = Header(default=None),
        x_relay_nonce: str | None = Header(default=None),
        x_relay_nonce_proof: str | None = Header(default=None),
    ) -> dict[str, Any]:
        # VAL-W2-007: bearer-digest match is mandatory.
        if x_relay_bearer_digest != state.bearer_token_digest:
            raise HTTPException(
                status_code=401,
                detail={
                    "code": RELAY_SIDECAR_AUTH_MISMATCH_CODE,
                    "error_class": RELAY_SIDECAR_AUTH_MISMATCH,
                    "message": "bearer digest mismatch",
                },
            )

        # VAL-W2-008: when a nonce is presented, verify TTL + proof.
        if x_relay_nonce is not None or x_relay_nonce_proof is not None:
            if x_relay_nonce is None or x_relay_nonce_proof is None:
                raise HTTPException(
                    status_code=401,
                    detail={
                        "code": RELAY_SIDECAR_AUTH_MISMATCH_CODE,
                        "error_class": RELAY_SIDECAR_AUTH_MISMATCH,
                        "message": "nonce headers must be presented together",
                    },
                )
            issued_at = state._issued_nonces.get(x_relay_nonce)
            if issued_at is None:
                raise HTTPException(
                    status_code=401,
                    detail={
                        "code": RELAY_SIDECAR_NONCE_EXPIRED_CODE,
                        "error_class": RELAY_SIDECAR_NONCE_EXPIRED,
                        "message": "unknown nonce (expired or never-issued)",
                    },
                )
            age = time.monotonic() - issued_at
            if age > state.nonce_ttl_s:
                # Evict so subsequent attempts get the same error class.
                state._issued_nonces.pop(x_relay_nonce, None)
                raise HTTPException(
                    status_code=401,
                    detail={
                        "code": RELAY_SIDECAR_NONCE_EXPIRED_CODE,
                        "error_class": RELAY_SIDECAR_NONCE_EXPIRED,
                        "message": (
                            f"nonce age {age:.3f}s exceeds TTL {state.nonce_ttl_s}s"
                        ),
                    },
                )
            expected_proof = _proof_of(x_relay_nonce, state.bearer_token)
            if not secrets.compare_digest(expected_proof, x_relay_nonce_proof):
                raise HTTPException(
                    status_code=401,
                    detail={
                        "code": RELAY_SIDECAR_AUTH_MISMATCH_CODE,
                        "error_class": RELAY_SIDECAR_AUTH_MISMATCH,
                        "message": "nonce proof did not verify",
                    },
                )
            # One-shot: evict on successful verification so the same proof
            # can't be replayed even within the TTL window.
            state._issued_nonces.pop(x_relay_nonce, None)

        # Suppress unused-arg lint (request is part of the FastAPI signature
        # contract; it may be consulted by future W2.2+ logic).
        _ = request

        return {"ok": True, "port": state.port, "sidecar_version": __version__}

    return app


__all__ = [
    "DEFAULT_NONCE_TTL_S",
    "HealthState",
    "_bearer_digest_of",
    "_proof_of",
    "build_app",
]
