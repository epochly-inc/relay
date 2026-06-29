"""Fail-CLOSED regression tests for the mitmproxy replay addon (W7.1).

Pins a P1 fail-OPEN security bug in the generated mitmproxy addon
(``relay_replay_proxy.harness._MITMPROXY_ADDON_SOURCE``). Keystone
invariant #9 (cassette-first replay with DEFAULT-DENY egress) and #11
(integrity checks fail CLOSED) require that an intercepted agent request
NEVER reaches the live upstream provider on any miss / error / unconfigured
path.

The bug: a mitmproxy ``request`` hook that returns WITHOUT setting
``flow.response`` (or calling ``flow.kill()``) forwards the flow to the
LIVE upstream. The pre-fix addon did exactly that on two paths:

  * ``_server is None`` -> bare ``return`` (no response set).
  * ``_server.lookup(req)`` raising ``CassetteFormatError`` (corrupted /
    tampered cassette) -> exception propagates out of the hook; mitmproxy
    logs and forwards the flow to the live upstream.

Either way a corrupt / forged / missing cassette caused real network
egress to the provider and the live response was consumed as a "replay" --
the exact opposite of fail-closed.

These tests assert the fix two ways:

  1. The extracted, pure decision function
     ``relay_replay_proxy.cassette_server.decide_replay_response`` is TOTAL:
     it returns a ``ProxyDecision`` (never ``None``) on every path -- server
     ``None``, ``lookup`` raising (corruption / generic), a plain miss, and a
     hit -- and only the hit path is non-blocking.
  2. The ACTUAL shipped addon source string is exec'd against a fake
     mitmproxy module + fake flow, proving the real ``request`` hook ALWAYS
     assigns ``flow.response`` (a blocking envelope carrying an existing
     replay/cassette error code) and NEVER leaves it ``None``.

A real TLS-MITM end-to-end smoke test needs ``mitmdump`` on PATH (smoke
tier; not available on the lean plumbing CI matrix). The in-process driver
that plumbing tests use is a plain HTTP server that has no upstream-forward
capability, so it cannot reproduce the fail-OPEN behavior of a real MITM
proxy. We therefore exec the addon source directly with a fake mitmproxy
shim -- this exercises the exact bytes that mitmdump would import.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import sys
import types
from typing import Any

import pytest
from relay_replay_proxy import harness as harness_mod
from relay_replay_proxy.cassette_server import (
    CassetteServer,
    ProxyDecision,
    decide_replay_response,
)
from relay_replay_proxy.cert_authority import generate_ca
from relay_replay_proxy.errors import (
    RELAY_REPLAY_CASSETTE_CORRUPT,
    RELAY_REPLAY_PROXY_DOWN,
)
from relay_replay_proxy.harness import (
    _MITMPROXY_ADDON_SOURCE,
    _build_mitmdump_argv,
    _MitmProxyDriver,
)
from relay_sidecar.cassette import CassetteFormatError

pytestmark = pytest.mark.plumbing


# -----------------------------------------------------------------------------
# Test doubles
# -----------------------------------------------------------------------------


class _RaisingServer:
    """Cassette server whose ``lookup`` always raises ``exc``."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def lookup(self, request: Any) -> Any:  # noqa: ARG002 - signature parity
        raise self._exc


class _MissServer:
    """Cassette server whose ``lookup`` always misses (returns None)."""

    def lookup(self, request: Any) -> Any:  # noqa: ARG002 - signature parity
        return None


class _FakeResponse:
    """Minimal stand-in for a ``CassetteResponse`` (hit path)."""

    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body_bytes = body


class _HitServer:
    """Cassette server that returns a fixed ``_FakeResponse``."""

    def __init__(self, response: _FakeResponse) -> None:
        self._response = response

    def lookup(self, request: Any) -> Any:  # noqa: ARG002 - signature parity
        return self._response


# -----------------------------------------------------------------------------
# Pure decision function: total + fail-closed on every non-hit path
# -----------------------------------------------------------------------------


def test_decide_blocks_when_server_is_none() -> None:
    """``server is None`` MUST yield a blocking decision, never None."""
    decision = decide_replay_response(
        None,
        raw_body=b'{"model":"m"}',
        provider_header="openai",
        model_header="m",
    )
    assert isinstance(decision, ProxyDecision)
    assert decision.kind == "block"
    assert decision.status == 503
    envelope = json.loads(decision.body_bytes)
    assert envelope["code"] == RELAY_REPLAY_PROXY_DOWN


def test_decide_blocks_on_cassette_format_error() -> None:
    """A ``CassetteFormatError`` from lookup (corruption) MUST block."""
    exc = CassetteFormatError("response_digest mismatch for entry sequence=0", 2, "c")
    decision = decide_replay_response(
        _RaisingServer(exc),
        raw_body=b'{"model":"m"}',
        provider_header="openai",
        model_header="m",
    )
    assert decision.kind == "block"
    assert decision.status == 502
    envelope = json.loads(decision.body_bytes)
    assert envelope["code"] == RELAY_REPLAY_CASSETTE_CORRUPT


def test_decide_blocks_on_generic_lookup_exception() -> None:
    """ANY exception from lookup (not just CassetteFormatError) MUST block."""
    decision = decide_replay_response(
        _RaisingServer(RuntimeError("kaboom")),
        raw_body=b'{"model":"m"}',
        provider_header="openai",
        model_header="m",
    )
    assert decision.kind == "block"
    assert decision.status == 502
    envelope = json.loads(decision.body_bytes)
    assert envelope["code"] == RELAY_REPLAY_CASSETTE_CORRUPT


def test_decide_blocks_on_miss() -> None:
    """A plain lookup miss MUST block with the cassette-miss code."""
    decision = decide_replay_response(
        _MissServer(),
        raw_body=b'{"model":"m"}',
        provider_header="openai",
        model_header="m",
    )
    assert decision.kind == "block"
    assert decision.status == 404
    envelope = json.loads(decision.body_bytes)
    assert envelope["code"] == "RELAY-CASSETTE-MISS"


def test_decide_blocks_malformed_body() -> None:
    """A non-empty body that is not valid JSON MUST block (corrupt), not miss.

    Pre-fix this coerced to ``{}`` and fell through to lookup; a different /
    malformed request could then HIT an empty-object cassette entry.
    """
    decision = decide_replay_response(
        _MissServer(),
        raw_body=b"\xff\xfe not json",
        provider_header="",
        model_header="",
    )
    assert decision.kind == "block"
    assert decision.status == 502
    envelope = json.loads(decision.body_bytes)
    assert envelope["code"] == RELAY_REPLAY_CASSETTE_CORRUPT


def test_decide_malformed_body_never_matches_empty_entry() -> None:
    """REGRESSION: a malformed body MUST NOT match a ``{}`` cassette entry.

    ``_HitServer`` returns a hit for ANY lookup (including the empty-object
    digest). If the malformed body were coerced to ``{}`` and looked up, it
    would be served this hit. The fix blocks BEFORE lookup, so the result
    must be a block, never the hit.
    """
    resp = _FakeResponse(200, {"Content-Type": "application/json"}, b'{"id":"leak"}')
    decision = decide_replay_response(
        _HitServer(resp),
        raw_body=b"\xff\xfe not json",
        provider_header="openai",
        model_header="m",
    )
    assert decision.kind == "block", "malformed body leaked a cassette hit"
    assert decision.status == 502
    assert decision.body_bytes != b'{"id":"leak"}'


def test_decide_blocks_non_object_json_body() -> None:
    """Valid JSON that is not an object (list/scalar) MUST block, not coerce."""
    resp = _FakeResponse(200, {"Content-Type": "application/json"}, b'{"id":"leak"}')
    for raw in (b"[1,2,3]", b'"hi"', b"5", b"true", b"null"):
        decision = decide_replay_response(
            _HitServer(resp),
            raw_body=raw,
            provider_header="openai",
            model_header="m",
        )
        assert decision.kind == "block", f"non-object body {raw!r} leaked a hit"
        assert decision.status == 502
        envelope = json.loads(decision.body_bytes)
        assert envelope["code"] == RELAY_REPLAY_CASSETTE_CORRUPT


def test_decide_empty_body_still_looks_up() -> None:
    """A genuinely EMPTY body is legitimate (-> {}) and MUST reach lookup."""
    resp = _FakeResponse(200, {"Content-Type": "application/json"}, b'{"id":"ok"}')
    decision = decide_replay_response(
        _HitServer(resp),
        raw_body=b"",
        provider_header="openai",
        model_header="m",
    )
    assert decision.kind == "hit"
    assert decision.body_bytes == b'{"id":"ok"}'


def test_decide_hit_serves_recorded_response() -> None:
    """A matching entry yields a non-blocking 'hit' carrying the bytes."""
    resp = _FakeResponse(200, {"Content-Type": "application/json"}, b'{"id":"x"}')
    decision = decide_replay_response(
        _HitServer(resp),
        raw_body=b'{"model":"m"}',
        provider_header="openai",
        model_header="m",
    )
    assert decision.kind == "hit"
    assert decision.status == 200
    assert decision.body_bytes == b'{"id":"x"}'


# -----------------------------------------------------------------------------
# The ACTUAL shipped addon source: request() hook ALWAYS sets flow.response
# -----------------------------------------------------------------------------


class _FakeMitmResponse:
    """Captures the args mitmproxy's ``http.Response.make`` would receive."""

    def __init__(self, status_code: int, content: bytes, headers: Any) -> None:
        self.status_code = status_code
        self.content = content
        self.headers = headers

    @classmethod
    def make(
        cls,
        status_code: int = 200,
        content: bytes = b"",
        headers: Any = None,
    ) -> _FakeMitmResponse:
        return cls(status_code, content, headers or {})


class _FakeRequest:
    def __init__(self, raw: bytes, headers: dict[str, str]) -> None:
        self.raw_content = raw
        self.headers = headers


class _FakeFlow:
    """Fake mitmproxy flow: ``.request`` readable, ``.response`` settable."""

    def __init__(self, raw: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.request = _FakeRequest(raw, headers or {})
        self.response: Any = None
        self.killed = False

    def kill(self) -> None:
        self.killed = True


class _ExplodingFlow:
    """Flow whose ``.request`` access raises (exercises the last-resort guard)."""

    def __init__(self) -> None:
        self.response: Any = None

    @property
    def request(self) -> Any:
        raise RuntimeError("cannot read flow.request")


def _load_addon(server: Any) -> dict[str, Any]:
    """Exec the real addon source with a fake mitmproxy module injected.

    Returns the addon module namespace with ``_server`` set to ``server``.
    Restores ``sys.modules`` before returning; the exec'd namespace keeps
    its own references to the fake ``http`` / ``ctx`` it imported.
    """
    fake_mitm = types.ModuleType("mitmproxy")
    fake_mitm.http = types.SimpleNamespace(  # type: ignore[attr-defined]
        Response=_FakeMitmResponse, HTTPFlow=object
    )
    fake_mitm.ctx = types.SimpleNamespace(  # type: ignore[attr-defined]
        options=types.SimpleNamespace(relay_session_dir="")
    )
    saved = sys.modules.get("mitmproxy")
    sys.modules["mitmproxy"] = fake_mitm
    try:
        namespace: dict[str, Any] = {}
        exec(compile(_MITMPROXY_ADDON_SOURCE, "<relay-addon>", "exec"), namespace)
    finally:
        if saved is None:
            sys.modules.pop("mitmproxy", None)
        else:
            sys.modules["mitmproxy"] = saved
    namespace["_server"] = server
    return namespace


def test_addon_hook_blocks_when_server_none() -> None:
    """REGRESSION: ``_server is None`` previously fell through to live upstream."""
    addon = _load_addon(server=None)
    flow = _FakeFlow(raw=b'{"model":"m"}', headers={"X-Relay-Provider": "openai"})
    addon["request"](flow)
    assert flow.response is not None, (
        "fail-OPEN: request hook returned without setting flow.response; "
        "mitmproxy would forward this to the LIVE upstream"
    )
    assert flow.response.status_code == 503
    envelope = json.loads(flow.response.content)
    assert envelope["code"] == RELAY_REPLAY_PROXY_DOWN


def test_addon_hook_blocks_on_corrupt_cassette() -> None:
    """REGRESSION: lookup raising CassetteFormatError previously escaped to live."""
    exc = CassetteFormatError("response_digest mismatch for entry sequence=0", 2, "c")
    addon = _load_addon(server=_RaisingServer(exc))
    flow = _FakeFlow(raw=b'{"model":"m"}', headers={})
    addon["request"](flow)
    assert flow.response is not None, "fail-OPEN: corrupt cassette escaped to live upstream"
    assert flow.response.status_code == 502
    envelope = json.loads(flow.response.content)
    assert envelope["code"] == RELAY_REPLAY_CASSETTE_CORRUPT


def test_addon_hook_blocks_on_generic_lookup_exception() -> None:
    """Any unexpected lookup exception MUST also be blocked, not forwarded."""
    addon = _load_addon(server=_RaisingServer(RuntimeError("boom")))
    flow = _FakeFlow(raw=b'{"model":"m"}', headers={})
    addon["request"](flow)
    assert flow.response is not None
    assert flow.response.status_code == 502
    envelope = json.loads(flow.response.content)
    assert envelope["code"] == RELAY_REPLAY_CASSETTE_CORRUPT


def test_addon_hook_blocks_on_miss() -> None:
    """A miss still sets a blocking response (unchanged, must not regress)."""
    addon = _load_addon(server=_MissServer())
    flow = _FakeFlow(raw=b'{"model":"m"}', headers={})
    addon["request"](flow)
    assert flow.response is not None
    assert flow.response.status_code == 404
    envelope = json.loads(flow.response.content)
    assert envelope["code"] == "RELAY-CASSETTE-MISS"


def test_addon_hook_serves_hit() -> None:
    """A hit serves the recorded bytes through flow.response (happy path)."""
    resp = _FakeResponse(200, {"Content-Type": "application/json"}, b'{"id":"x"}')
    addon = _load_addon(server=_HitServer(resp))
    flow = _FakeFlow(raw=b'{"model":"m"}', headers={})
    addon["request"](flow)
    assert flow.response is not None
    assert flow.response.status_code == 200
    assert flow.response.content == b'{"id":"x"}'


def test_addon_hook_last_resort_guard_blocks() -> None:
    """If reading the flow itself raises, the hook STILL blocks (never forwards)."""
    addon = _load_addon(server=_MissServer())
    flow = _ExplodingFlow()
    addon["request"](flow)
    assert flow.response is not None, (
        "fail-OPEN: an exception before the decision left flow.response unset"
    )
    assert flow.response.status_code == 502
    envelope = json.loads(flow.response.content)
    assert envelope["code"] == RELAY_REPLAY_CASSETTE_CORRUPT


def test_addon_hook_blocks_malformed_body() -> None:
    """REGRESSION: a malformed body MUST be blocked, never matched to a hit."""
    resp = _FakeResponse(200, {"Content-Type": "application/json"}, b'{"id":"leak"}')
    addon = _load_addon(server=_HitServer(resp))
    flow = _FakeFlow(raw=b"\xff\xfe not json", headers={})
    addon["request"](flow)
    assert flow.response is not None
    assert flow.response.status_code == 502, "malformed body leaked a cassette hit"
    assert flow.response.content != b'{"id":"leak"}'


# -----------------------------------------------------------------------------
# Connection-layer egress hardening: the mitmdump launch must disable upstream
# certificate probing and eager upstream connect (keystone #9). Without these,
# mitmproxy contacts the LIVE upstream during TLS setup BEFORE the request hook
# runs -- a real outbound connection despite the hook always responding.
# -----------------------------------------------------------------------------


def _flag_pair_present(argv: list[str], flag: str, value: str) -> bool:
    """True if ``argv`` contains ``flag`` immediately followed by ``value``."""
    return any(
        argv[i] == flag and argv[i + 1] == value for i in range(len(argv) - 1)
    )


def test_build_mitmdump_argv_includes_egress_hardening(tmp_path: Any) -> None:
    """The built argv MUST disable upstream_cert and use the lazy strategy."""
    argv = _build_mitmdump_argv(
        binary="/usr/bin/mitmdump",
        port=8888,
        session_dir=tmp_path,
        addon_path=tmp_path / "_addon.py",
    )
    assert _flag_pair_present(argv, "--set", "upstream_cert=false"), argv
    assert _flag_pair_present(argv, "--set", "connection_strategy=lazy"), argv


def test_mitmdump_start_passes_egress_hardening_flags(
    cassette_root: Any,
    session_dir_with_cassette: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real ``_MitmProxyDriver.start`` MUST pass the hardening flags to Popen."""
    captured: dict[str, list[str]] = {}

    class _FakeProc:
        pid = 4321

        def poll(self) -> None:
            return None

    def _fake_popen(cmd: list[str], **_kwargs: Any) -> _FakeProc:
        captured["cmd"] = cmd
        return _FakeProc()

    monkeypatch.setattr(harness_mod.shutil, "which", lambda _name: "/usr/bin/mitmdump")
    monkeypatch.setattr(harness_mod.subprocess, "Popen", _fake_popen)

    ca = generate_ca(
        session_id=session_dir_with_cassette.name,
        session_dir=session_dir_with_cassette,
        cassette_root=cassette_root,
    )
    server = CassetteServer(session_dir_with_cassette)
    driver = _MitmProxyDriver()
    driver.start(port=12345, ca=ca, server=server)

    cmd = captured["cmd"]
    assert _flag_pair_present(cmd, "--set", "upstream_cert=false"), cmd
    assert _flag_pair_present(cmd, "--set", "connection_strategy=lazy"), cmd
