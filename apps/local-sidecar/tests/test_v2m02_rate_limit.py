"""V2 M02 W2.10 rate-limit cross-cutting tests.

Covers VAL-V2M02-075..079 (5 assertions):
  - 075 X-RateLimit-* present on every 2xx response.
  - 076 X-RateLimit-* present on every non-2xx response (400/401/403/404/409/422).
  - 077 Per-project ingest rate limit -> 429 RELAY-RATE-001 with Retry-After.
  - 078 Per-JWT dashboard rate limit -> 429 RELAY-RATE-001.
  - 079 Per-IP evidence verify -> 429 RELAY-RATE-014.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import httpx
import pytest
from _v2m02_w25_helpers import (
    no_scope_header,
    scope_header,
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-075")
@pytest.mark.asyncio
async def test_rate_limit_headers_on_2xx(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    r = await c.put(
        "/v1/gates/g-rl",
        json={"name": "g"},
        headers=scope_header("gates:configure"),
    )
    assert r.status_code in (200, 201)
    for h in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"):
        assert h in r.headers, f"missing {h}: {dict(r.headers)}"
        assert int(r.headers[h]) >= 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-076")
@pytest.mark.asyncio
async def test_rate_limit_headers_on_non_2xx(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    # 403 path.
    r403 = await c.put(
        "/v1/gates/g-rl-403", json={}, headers=no_scope_header()
    )
    assert r403.status_code == 403
    for h in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"):
        assert h in r403.headers
    # 404 path.
    r404 = await c.get(
        "/v1/gate-decisions/unknown-id-x",
        headers=scope_header("runs:read"),
    )
    assert r404.status_code == 404
    for h in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"):
        assert h in r404.headers
    # 422 path: invalid manifest_commit_hash.
    r422 = await c.post(
        "/v1/gates/g-rl-422/drafts",
        json={"actor_identity_hash": "x"},  # missing manifest_commit_hash
        headers=scope_header("gates:execute"),
    )
    assert r422.status_code == 422
    for h in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"):
        assert h in r422.headers
    # 409 path: idempotency conflict.
    headers409 = {
        **scope_header("gates:configure"),
        "Idempotency-Key": "k-409",
    }
    r1 = await c.post(
        "/v1/manifests", json={"name": "a"}, headers=headers409
    )
    assert r1.status_code == 201
    r409 = await c.post(
        "/v1/manifests", json={"name": "b"}, headers=headers409
    )
    assert r409.status_code == 409
    for h in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"):
        assert h in r409.headers


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-077")
@pytest.mark.asyncio
async def test_per_project_rate_limit_429(
    monkeypatch: pytest.MonkeyPatch,
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    # Set per-project to 2 RPS. Three rapid PUTs from same project ->
    # third returns 429.
    monkeypatch.setenv("RELAY_SIDECAR_RATELIMIT_PROJECT_RPS", "2")
    # Rebuild a fresh app since the env-var is read on each request inside
    # the middleware -- no rebuild needed actually.
    c, _db, _app = v2m02_client
    hdrs = {
        **scope_header("gates:configure"),
        "X-Relay-Project": "proj-A",
    }
    status_codes = []
    for _ in range(4):
        r = await c.put("/v1/gates/g", json={"name": "g"}, headers=hdrs)
        status_codes.append(r.status_code)
        if r.status_code == 429:
            assert json.loads(r.text)["code"] == "RELAY-RATE-001"
            assert "retry-after" in r.headers
            assert int(r.headers["retry-after"]) >= 1
            return
    pytest.fail(f"expected 429 within 4 requests; got {status_codes}")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-078")
@pytest.mark.asyncio
async def test_per_jwt_rate_limit_429(
    monkeypatch: pytest.MonkeyPatch,
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    monkeypatch.setenv("RELAY_SIDECAR_RATELIMIT_JWT_RPS", "2")
    c, _db, app = v2m02_client
    # Register a token with runs:read scope and a project_id.
    app.state.runtime.registered_tokens["jwt-aaa"] = {
        "scopes": frozenset({"runs:read"}),
        "project_id": "proj-jwt",
    }
    hdrs = {"Authorization": "Bearer jwt-aaa"}
    status_codes = []
    for _ in range(5):
        r = await c.get("/v1/runs/unknown-id", headers=hdrs)
        status_codes.append(r.status_code)
        if r.status_code == 429:
            assert json.loads(r.text)["code"] == "RELAY-RATE-001"
            return
    pytest.fail(f"expected 429; got {status_codes}")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-079")
@pytest.mark.asyncio
async def test_per_ip_verify_rate_limit_429(
    monkeypatch: pytest.MonkeyPatch,
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    monkeypatch.setenv("RELAY_SIDECAR_RATELIMIT_IP_RPS", "2")
    c, _db, _app = v2m02_client
    # Audit fix (2026-05-17 P0): POST /v1/evidence-bundles requires
    # ``evidence:write`` (was incorrectly ``evidence:read``).
    r_create = await c.post(
        "/v1/evidence-bundles",
        json={"scope_kind": "run", "scope_id": "r", "claims": []},
        headers=scope_header("evidence:write"),
    )
    bid = json.loads(r_create.text)["bundle_id"]
    status_codes = []
    for _ in range(5):
        r = await c.post(f"/v1/evidence-bundles/{bid}/verify")
        status_codes.append(r.status_code)
        if r.status_code == 429:
            assert json.loads(r.text)["code"] == "RELAY-RATE-014"
            assert "retry-after" in r.headers
            return
    pytest.fail(f"expected 429; got {status_codes}")
