"""V2 M02 W2.7 sidecar manifest endpoint tests.

Covers VAL-V2M02-057..060 (4 assertions):
  - 057 POST /v1/manifests upserts (201, commit_hash = sha256 prefix).
  - 058 POST enforces gates:configure scope.
  - 059 GET /v1/manifests/{id}/versions/{commit_hash} returns body, 404 path.
  - 060 GET enforces runs:read scope.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import pytest
from _v2m02_w25_helpers import (
    V2M02Client,
    no_scope_header,
    scope_header,
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-057")
@pytest.mark.asyncio
async def test_post_manifest_upserts(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    body = {"name": "manifest-x", "commands": [{"id": "test-plumbing"}]}
    r = await c.post(
        "/v1/manifests", json=body, headers=scope_header("gates:configure")
    )
    assert r.status_code == 201, r.text
    payload = json.loads(r.text)
    assert payload["manifest_id"]
    # Audit fix (2026-05-17 P0): canonical sha256 hyphen form +
    # manifest_versions CHECK constraint at migration 0006:75-76.
    assert payload["commit_hash"].startswith("sha256-")
    # Audit fix (2026-05-17 P0): parent Manifest envelope uses
    # ``relay.manifest_parent.v1`` per envelopes.yaml:847; the
    # ``relay.manifest.v1`` literal is reserved for ManifestVersion.
    assert payload["schema_version"] == "relay.manifest_parent.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-058")
@pytest.mark.asyncio
async def test_post_manifest_enforces_scope(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.post("/v1/manifests", json={}, headers=no_scope_header())
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-059")
@pytest.mark.asyncio
async def test_get_manifest_version_returns_body(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    body = {"name": "m-v", "commands": []}
    posted = await c.post(
        "/v1/manifests", json=body, headers=scope_header("gates:configure")
    )
    payload = json.loads(posted.text)
    mid = payload["manifest_id"]
    ch = payload["commit_hash"]
    r = await c.get(
        f"/v1/manifests/{mid}/versions/{ch}",
        headers=scope_header("runs:read"),
    )
    assert r.status_code == 200, r.text
    got = json.loads(r.text)
    assert got["manifest_id"] == mid
    assert got["commit_hash"] == ch
    assert got["body"]["name"] == "m-v"
    # 404 path: mismatched commit_hash (canonical hyphen-form).
    r404 = await c.get(
        f"/v1/manifests/{mid}/versions/sha256-{'9' * 64}",
        headers=scope_header("runs:read"),
    )
    assert r404.status_code == 404


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-060")
@pytest.mark.asyncio
async def test_get_manifest_version_enforces_scope(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.get(
        "/v1/manifests/x/versions/y", headers=no_scope_header()
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"
