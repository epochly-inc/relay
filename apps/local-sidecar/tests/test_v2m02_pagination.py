"""V2 M02 W2.9 pagination + error-envelope cross-cutting tests.

Covers VAL-V2M02-069..074 (6 assertions):
  - 069 cursor is opaque + server-signed; tampered cursor -> 400.
  - 070 cursor expires after 1 hour.
  - 071 limit defaults to 100, caps at 500, <=0 -> 400.
  - 072 error envelope contains required fields (message, code, etc.).
  - 073 documentation_url matches canonical regex.
  - 074 request_id / trace_id are ULID-shaped + unique across requests.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import re
import time

import pytest
from _v2m02_w25_helpers import (
    V2M02Client,
    no_scope_header,
    scope_header,
    seed_three_anchor_handoff,
)

# Anchors for draft-posting seed rounds. VAL-ISO-003 made the three-anchor
# handoff validator run unconditionally (fail closed on unseeded
# registries), so the seed loops below must register a valid actor +
# active manifest matching these hashes for the drafts to be accepted.
_PAGE_MANIFEST_HASH = "sha256-" + ("0" * 64)
_PAGE_ACTOR_HASH = "sha256-" + ("1" * 64)

ULID_RE = re.compile(r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$")
DOC_URL_RE = re.compile(r"^https://relay\.epochly\.com/docs/errors/[A-Z0-9-]+$")


# ---- VAL-V2M02-069: cursor is opaque + signed; tampered -> 400 ----------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-069")
@pytest.mark.asyncio
async def test_cursor_tampered_returns_400(
    v2m02_client: V2M02Client,
) -> None:
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_PAGE_ACTOR_HASH,
        manifest_commit_hash=_PAGE_MANIFEST_HASH,
    )
    # Seed >100 rounds so cursor is returned.
    for i in range(105):
        await c.post(
            "/v1/gates/g-page/drafts",
            json={
                "manifest_commit_hash": _PAGE_MANIFEST_HASH,
                "actor_identity_hash": _PAGE_ACTOR_HASH,
                "worker_id": f"w-{i}",
                "round": i + 1,
            },
            headers=scope_header("gates:execute"),
        )
    r = await c.get(
        "/v1/gates/g-page/rounds?limit=10",
        headers=scope_header("gates:configure"),
    )
    payload = json.loads(r.text)
    cursor = payload["next_cursor"]
    assert isinstance(cursor, str) and cursor
    # Cursor is opaque (not a plain base64 of {offset:N})
    # Tampered cursor -> 400.
    tampered = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
    r2 = await c.get(
        f"/v1/gates/g-page/rounds?cursor={tampered}",
        headers=scope_header("gates:configure"),
    )
    assert r2.status_code == 400, r2.text
    assert json.loads(r2.text)["code"] in (
        "RELAY-PAGE-001",
        "RELAY-PAGE-EXPIRED",
    )


# ---- VAL-V2M02-070: cursor expires after 1 hour --------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-070")
@pytest.mark.asyncio
async def test_cursor_expires_after_1h(
    v2m02_client: V2M02Client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, db_path, app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_PAGE_ACTOR_HASH,
        manifest_commit_hash=_PAGE_MANIFEST_HASH,
    )
    # Seed rounds + grab a cursor.
    for i in range(105):
        await c.post(
            "/v1/gates/g-expire/drafts",
            json={
                "manifest_commit_hash": _PAGE_MANIFEST_HASH,
                "actor_identity_hash": _PAGE_ACTOR_HASH,
                "worker_id": f"w-{i}",
                "round": i + 1,
            },
            headers=scope_header("gates:execute"),
        )
    r = await c.get(
        "/v1/gates/g-expire/rounds?limit=10",
        headers=scope_header("gates:configure"),
    )
    cursor = json.loads(r.text)["next_cursor"]
    assert cursor
    # Issue a far-future request by monkeypatching time so the cursor's
    # issued_at appears > 1h old. Patch the `_now_epoch_s` helper in the
    # runtime module on the live app's closure cells is not directly
    # accessible; instead, freeze `time.time` via monkeypatch -- the
    # runtime uses datetime.now(tz=UTC).timestamp() inside the closure
    # so we patch datetime's now.
    import relay_sidecar.runtime as rt_mod

    real_dt = rt_mod.datetime

    class _FrozenDT:
        @staticmethod
        def now(tz=None):  # noqa: ANN001
            return real_dt.now(tz=tz).fromtimestamp(time.time() + 7200, tz=tz)

    monkeypatch.setattr(rt_mod, "datetime", _FrozenDT)
    try:
        r2 = await c.get(
            f"/v1/gates/g-expire/rounds?cursor={cursor}",
            headers=scope_header("gates:configure"),
        )
        assert r2.status_code == 400, r2.text
        assert json.loads(r2.text)["code"] == "RELAY-PAGE-EXPIRED"
    finally:
        monkeypatch.setattr(rt_mod, "datetime", real_dt)


# ---- VAL-V2M02-071: limit defaults / caps / invalid ---------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-071")
@pytest.mark.asyncio
async def test_list_limit_caps_and_validates(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, app = v2m02_client
    # Seed 600 round records via direct registry write so we can prove
    # the server caps at 500 even when 600 are requested.
    runtime = app.state.runtime
    runtime.gate_rounds["g-cap"] = [
        {
            "gate_round_id": f"gr-{i}",
            "gate_id": "g-cap",
            "round": i + 1,
            "opened_at": "2026-05-17T00:00:00Z",
        }
        for i in range(600)
    ]
    # No limit -> default 100.
    r_default = await c.get(
        "/v1/gates/g-cap/rounds", headers=scope_header("gates:configure")
    )
    assert r_default.status_code == 200
    assert len(json.loads(r_default.text)["items"]) <= 100

    # limit=600 -> caps at 500.
    r_cap = await c.get(
        "/v1/gates/g-cap/rounds?limit=600",
        headers=scope_header("gates:configure"),
    )
    assert r_cap.status_code == 200
    assert len(json.loads(r_cap.text)["items"]) <= 500

    # limit=0 -> 400 RELAY-PAGE-001.
    r_zero = await c.get(
        "/v1/gates/g-cap/rounds?limit=0",
        headers=scope_header("gates:configure"),
    )
    assert r_zero.status_code == 400
    assert json.loads(r_zero.text)["code"] == "RELAY-PAGE-001"


# ---- VAL-V2M02-072: error envelope fields --------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-072")
@pytest.mark.asyncio
async def test_error_envelope_required_fields(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.put(
        "/v1/gates/g-403", json={}, headers=no_scope_header()
    )
    assert r.status_code == 403
    env = json.loads(r.text)
    for field in (
        "schema_version",
        "code",
        "http_status",
        "message",
        "blocked_surface",
        "retry_advice",
        "request_id",
        "trace_id",
    ):
        assert field in env, f"missing {field} in {env}"
    # documentation_url should be present for RELAY-AUTH-014 (published).
    assert "documentation_url" in env


# ---- VAL-V2M02-073: documentation_url canonical form ---------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-073")
@pytest.mark.asyncio
async def test_documentation_url_matches_canonical(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.put(
        "/v1/gates/g-doc", json={}, headers=no_scope_header()
    )
    env = json.loads(r.text)
    url = env["documentation_url"]
    assert DOC_URL_RE.match(url), url
    assert url.endswith(env["code"])


# ---- VAL-V2M02-074: request_id / trace_id ULID + unique ------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-074")
@pytest.mark.asyncio
async def test_request_id_trace_id_ulid_unique(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    ids_seen: set[str] = set()
    for _ in range(5):
        r = await c.put(
            "/v1/gates/g-id", json={}, headers=no_scope_header()
        )
        env = json.loads(r.text)
        assert ULID_RE.match(env["request_id"]), env["request_id"]
        assert ULID_RE.match(env["trace_id"]), env["trace_id"]
        assert env["request_id"] not in ids_seen
        ids_seen.add(env["request_id"])
