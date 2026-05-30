"""V3 M05 F03 RTL override + zero-width + BOM rejection at ID boundaries.

Fulfills VAL-V3M5-008 (spec section AI adversarial guards):

  Inbound HTTP ID fields (Idempotency-Key, run_id, gate_id, project_id) MUST
  be validated to reject U+202E (RIGHT-TO-LEFT OVERRIDE), U+200B (ZERO WIDTH
  SPACE), U+200C (ZERO WIDTH NON-JOINER), U+200D (ZERO WIDTH JOINER), and
  U+FEFF (ZERO WIDTH NO-BREAK SPACE / BOM) BEFORE any hashing or canonical
  processing.

These code points are the classic visually-invisible-or-misleading characters
used to smuggle IDs past naive string equality checks and to make the wire
form of an identifier render differently than its byte content. The sidecar's
ID validator rejects them at the HTTP boundary so the canonical hashing /
lookup layers never observe a value containing one of these code points.

Idempotency-Key is already covered by the V3M2 F03 Crockford-base32 ULID
grammar (``^[0-9A-HJKMNP-TV-Z]{26}$``) which excludes every non-ASCII code
point including the five banned ones; the test below confirms the existing
behavior keeps holding so the contract surface for Idempotency-Key remains
"400 rejection with no canonical hashing performed".

ASCII-only per CLAUDE.md "ASCII-Safe Source"; the banned code points are
spelled with explicit ``\\u`` escapes rather than literal glyphs.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from _v2m02_w25_helpers import V2M02Client, scope_header

# The five banned code points enumerated in VAL-V3M5-008 plus contract.md
# line 448. Spelled with explicit escapes so the source file stays ASCII.
_BANNED_CODEPOINTS: list[tuple[str, str]] = [
    ("rtl_override_u202e", "‮"),
    ("zero_width_space_u200b", "​"),
    ("zero_width_non_joiner_u200c", "‌"),
    ("zero_width_joiner_u200d", "‍"),
    ("bom_ufeff", "﻿"),
]

# A short ASCII identifier we splice the banned code point into. The
# splice happens mid-string so the value is *almost* a valid-looking ID
# (the prefix and suffix are unambiguous ASCII) and the only adversarial
# bit is the embedded invisible char. This mirrors the realistic attack
# of smuggling an invisible char into an otherwise-credible identifier.
_ASCII_STEM = "run-v3m5-id"


def _stem_with_banned(cp: str) -> str:
    """Return ``run-v3m5-i<BAD>d`` where ``<BAD>`` is the banned char."""
    return _ASCII_STEM[:-1] + cp + _ASCII_STEM[-1]


# Routes that consume the run_id / gate_id / project_id path parameter.
# Each tuple is (case_id, method, path_template, scopes_required).
# The path_template uses ``{id}`` as the placeholder we splice the
# (banned) value into per test.
_ID_ROUTES: list[tuple[str, str, str, str]] = [
    ("run_id_get_run", "GET", "/v1/runs/{id}", "runs:read"),
    ("run_id_get_run_trace", "GET", "/v1/runs/{id}/trace", "runs:read"),
    ("run_id_get_run_result", "GET", "/v1/runs/{id}/result", "runs:read"),
    ("run_id_get_run_explain", "GET", "/v1/runs/{id}/explain", "runs:read"),
    ("project_id_list_runs", "GET", "/v1/projects/{id}/runs", "runs:read"),
    ("gate_id_put_gate", "PUT", "/v1/gates/{id}", "gates:configure"),
    (
        "gate_id_post_draft",
        "POST",
        "/v1/gates/{id}/drafts",
        "gates:write",
    ),
    (
        "gate_id_get_rounds",
        "GET",
        "/v1/gates/{id}/rounds",
        "gates:read",
    ),
]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-008")
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("route_case", "method", "path_template", "scope"),
    _ID_ROUTES,
    ids=[r[0] for r in _ID_ROUTES],
)
@pytest.mark.parametrize(
    ("cp_case", "banned_cp"),
    _BANNED_CODEPOINTS,
    ids=[c[0] for c in _BANNED_CODEPOINTS],
)
async def test_banned_codepoint_in_path_id_rejected_400_relay_id_invalid(
    v2m02_client: V2M02Client,
    route_case: str,
    method: str,
    path_template: str,
    scope: str,
    cp_case: str,
    banned_cp: str,
) -> None:
    """Every (route, banned code point) pair returns HTTP 400 with code
    ``RELAY-ID-INVALID`` and the offending field + code point recorded in
    the structured details. The check MUST happen at the HTTP boundary
    BEFORE any hashing / canonical processing; verifying the status code
    + envelope code + details suffices because the ID never reaches a
    downstream handler that would canonicalize it.
    """
    c, _db, _app = v2m02_client
    bad_id = _stem_with_banned(banned_cp)
    path = path_template.format(id=bad_id)
    headers = scope_header(scope)
    # PUT /v1/gates/{gate_id} requires a JSON body; the other routes
    # tolerate an empty body for read-shaped endpoints.
    # Bag of optional request kwargs spread into c.request(**body_kwargs).
    # Typed as dict[str, Any] so the heterogeneous "json" payloads (and the
    # empty-body case) do not narrow to a value-type union that pyright then
    # tries -- and fails -- to match against every httpx.request parameter.
    body_kwargs: dict[str, Any]
    if method == "PUT":
        body_kwargs = {"json": {"name": "x", "scope_type": "run"}}
    elif method == "POST":
        body_kwargs = {"json": {"round": 1}}
    else:
        body_kwargs = {}
    r = await c.request(method, path, headers=headers, **body_kwargs)
    assert r.status_code == 400, (
        f"route={route_case!r} cp={cp_case!r}: expected 400 for "
        f"bad_id={bad_id!r}; got {r.status_code}: {r.text}"
    )
    payload = json.loads(r.text)
    assert payload["code"] == "RELAY-ID-INVALID", (
        f"route={route_case!r} cp={cp_case!r}: expected "
        f"RELAY-ID-INVALID; got {payload.get('code')!r}; body={payload!r}"
    )
    assert payload["http_status"] == 400
    # Structured details: which field and which code point were rejected.
    details = payload.get("details") or {}
    assert "field" in details, (
        f"route={route_case!r}: envelope details missing 'field'; "
        f"payload={payload!r}"
    )
    # The offending code point must be reported as a U+XXXX hex string so
    # callers can pinpoint the violation without re-encoding the raw byte
    # sequence themselves.
    assert "banned_codepoint" in details, (
        f"route={route_case!r}: envelope details missing "
        f"'banned_codepoint'; payload={payload!r}"
    )
    expected_hex = f"U+{ord(banned_cp):04X}"
    assert details["banned_codepoint"] == expected_hex, (
        f"route={route_case!r} cp={cp_case!r}: expected "
        f"banned_codepoint={expected_hex!r}; got "
        f"{details.get('banned_codepoint')!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-008")
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cp_case", "banned_cp"),
    _BANNED_CODEPOINTS,
    ids=[c[0] for c in _BANNED_CODEPOINTS],
)
async def test_banned_codepoint_in_idempotency_key_rejected_400(
    v2m02_client: V2M02Client,
    cp_case: str,
    banned_cp: str,
) -> None:
    """Idempotency-Key carrying any of the five banned code points is
    rejected at the HTTP boundary BEFORE any canonical hashing. The
    existing V3M2 ULID grammar (``^[0-9A-HJKMNP-TV-Z]{26}$``) already
    excludes every non-ASCII code point, so the rejection lands as
    ``RELAY-IDEMPOTENCY-014``. This test pins the contract surface so a
    regression that loosens the ULID grammar (and lets a banned code
    point through) fails here.

    Headers are passed as a list of (bytes, bytes) tuples so the raw
    UTF-8 octets survive httpx's str-header encoding check, mirroring
    real on-wire HTTP/1.1 octet semantics.
    """
    c, _db, _app = v2m02_client
    # A 26-char ASCII Crockford-base32 ULID with the banned code point
    # spliced mid-string -- still the right "length" in characters but
    # no longer 26 ASCII chars after encoding, so the grammar rejects.
    valid_ulid = "01HZX9F8K7M3N4P5Q6R7S8T9V0"
    bad_key = (valid_ulid[:13] + banned_cp + valid_ulid[13:]).encode("utf-8")
    scope_h = scope_header("gates:configure")
    headers: list[tuple[bytes, bytes]] = [
        (k.encode("ascii"), v.encode("ascii")) for k, v in scope_h.items()
    ]
    headers.append((b"Idempotency-Key", bad_key))
    body = {"name": "g", "scope_type": "run"}
    r = await c.put(
        "/v1/gates/01HZX9F8K7M3N4P5Q6R7S8T9VA",
        json=body,
        headers=headers,
    )
    assert r.status_code == 400, (
        f"cp={cp_case!r}: expected 400 for Idempotency-Key carrying "
        f"banned code point; got {r.status_code}: {r.text}"
    )
    payload = json.loads(r.text)
    # The existing V3M2 grammar produces RELAY-IDEMPOTENCY-014; the
    # contract is "Idempotency-Key with a banned code point is rejected
    # with HTTP 400" -- the precise code is a regression-detection anchor.
    assert payload["code"] == "RELAY-IDEMPOTENCY-014", (
        f"cp={cp_case!r}: expected RELAY-IDEMPOTENCY-014; got "
        f"{payload.get('code')!r}; body={payload!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-008")
@pytest.mark.asyncio
async def test_clean_ascii_id_is_accepted(
    v2m02_client: V2M02Client,
) -> None:
    """Positive control: a clean ASCII ``gate_id`` reaches the gate
    handler. Without this case the validator could trivially be written
    to reject every ID and pass the negative half of the matrix.
    """
    c, _db, _app = v2m02_client
    body = {"name": "g", "scope_type": "run"}
    headers = scope_header("gates:configure")
    r = await c.put("/v1/gates/gate-v3m5-positive", json=body, headers=headers)
    assert r.status_code in (200, 201), (
        f"clean ASCII gate_id must be accepted; got "
        f"{r.status_code}: {r.text}"
    )
