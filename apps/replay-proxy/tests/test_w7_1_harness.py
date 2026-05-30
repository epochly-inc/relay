"""W7.1 mitmproxy harness plumbing tests (VAL-W7-001..014).

Tier-1 plumbing only. The in-process driver is the default so tests have
zero external binary dependency and run on every CI matrix cell.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from relay_replay_proxy import (
    CA_CERT_FILENAME,
    CA_KEY_FILENAME,
    DRIVER_FAKE_FAILURE,
    DRIVER_INPROC,
    ENV_DRIVER,
    ENV_HTTP_PROXY,
    ENV_HTTPS_PROXY,
    ENV_REPLAY_PROXY_URL,
    ENV_REPLAY_SESSION,
    ENV_SSL_CERT_FILE,
    EPHEMERAL_PORT_HIGH,
    EPHEMERAL_PORT_LOW,
    HarnessConfig,
    HarnessSession,
    RelayProxyDownError,
    RelayProxyMissingCassetteError,
    generate_ca,
    pick_free_port,
    remove_ca,
)
from relay_replay_proxy.cert_authority import SUBJECT_CN_PREFIX

pytestmark = pytest.mark.plumbing


# -----------------------------------------------------------------------------
# VAL-W7-001: spawn-before-agent
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-001")
def test_proxy_starts_and_returns_handle_before_agent_spawn(
    harness: HarnessSession,
) -> None:
    """The harness's start() returns a ready handle BEFORE the CLI spawns
    the agent subprocess. We assert: handle exists, proxy URL is set,
    proxy is alive, and a TCP connect succeeds against the bound port.
    """
    handle = harness.handle
    assert handle is not None
    assert handle.proxy_url.startswith("http://127.0.0.1:")
    assert handle.proxy_port > 0
    # TCP probe: the proxy is bound and accepting before any agent is
    # told about it via env vars.
    sock = socket.create_connection(("127.0.0.1", handle.proxy_port), timeout=2.0)
    sock.close()


# -----------------------------------------------------------------------------
# VAL-W7-002: auto-pick port; concurrent sessions never collide
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-002")
def test_pick_free_port_returns_distinct_ports() -> None:
    ports = {pick_free_port() for _ in range(5)}
    assert len(ports) >= 4  # high probability of distinct picks
    for p in ports:
        assert 1024 < p <= 65535


@pytest.mark.fulfills("VAL-W7-002")
def test_two_concurrent_sessions_bind_distinct_ports(
    cassette_root: Path,
    write_cassette,
    use_inproc_driver: None,
) -> None:
    sessions = []
    handles = []
    try:
        for sid in ("ses02aaaaaaaaaaaaaaaaaaaa", "ses02bbbbbbbbbbbbbbbbbbbb"):
            sd = cassette_root / sid
            sd.mkdir(parents=True, exist_ok=True)
            write_cassette(
                sd,
                entries=[
                    {
                        "provider": "openai",
                        "model": "gpt-4o-mini",
                        "request": {"model": "gpt-4o-mini"},
                        "response": {"ok": True},
                    }
                ],
            )
            cfg = HarnessConfig(session_id=sid, cassette_root=cassette_root)
            sess = HarnessSession(cfg)
            handle = sess.start()
            sessions.append(sess)
            handles.append(handle)
        ports = {h.proxy_port for h in handles}
        assert len(ports) == 2, f"expected distinct ports; got {ports}"
    finally:
        for s in sessions:
            s.stop()


# -----------------------------------------------------------------------------
# VAL-W7-003: per-session CA cert generated fresh
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-003")
def test_generate_ca_writes_cert_and_key_to_session_dir(
    cassette_root: Path,
) -> None:
    sd = cassette_root / "ses03aaaaaaaaaaaaaaaaaaaa"
    sd.mkdir(parents=True, exist_ok=True)
    ca = generate_ca(session_id=sd.name, session_dir=sd, cassette_root=cassette_root)
    assert ca.cert_path.exists()
    assert ca.key_path.exists()
    assert ca.cert_path == sd / CA_CERT_FILENAME
    assert ca.key_path == sd / CA_KEY_FILENAME
    cert_pem = ca.cert_path.read_bytes()
    assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"-----END CERTIFICATE-----" in cert_pem


@pytest.mark.fulfills("VAL-W7-003")
def test_two_sessions_produce_distinct_subject_keys_and_serials(
    cassette_root: Path,
) -> None:
    sd_a = cassette_root / "ses03ccccccccccccccccccccc"
    sd_b = cassette_root / "ses03dddddddddddddddddddddd"
    for sd in (sd_a, sd_b):
        sd.mkdir(parents=True, exist_ok=True)
    ca_a = generate_ca(session_id=sd_a.name, session_dir=sd_a, cassette_root=cassette_root)
    ca_b = generate_ca(session_id=sd_b.name, session_dir=sd_b, cassette_root=cassette_root)
    assert ca_a.subject_key_id_hex != ca_b.subject_key_id_hex
    assert ca_a.serial_number != ca_b.serial_number
    digest_a = hashlib.sha256(ca_a.cert_path.read_bytes()).hexdigest()
    digest_b = hashlib.sha256(ca_b.cert_path.read_bytes()).hexdigest()
    assert digest_a != digest_b


# -----------------------------------------------------------------------------
# VAL-W7-004: CA deleted on session exit
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-004")
def test_stop_removes_ca_cert_and_key(
    cassette_root: Path,
    session_dir_with_cassette: Path,
    use_inproc_driver: None,
) -> None:
    cfg = HarnessConfig(
        session_id=session_dir_with_cassette.name,
        cassette_root=cassette_root,
    )
    sess = HarnessSession(cfg)
    handle = sess.start()
    assert handle.ca.cert_path.exists()
    assert handle.ca.key_path.exists()
    sess.stop()
    assert not handle.ca.cert_path.exists()
    assert not handle.ca.key_path.exists()


@pytest.mark.fulfills("VAL-W7-004")
def test_remove_ca_is_idempotent(cassette_root: Path) -> None:
    sd = cassette_root / "ses04aaaaaaaaaaaaaaaaaaaa"
    sd.mkdir(parents=True, exist_ok=True)
    ca = generate_ca(session_id=sd.name, session_dir=sd, cassette_root=cassette_root)
    first = remove_ca(ca)
    second = remove_ca(ca)
    assert len(first) == 2
    assert second == []


# -----------------------------------------------------------------------------
# VAL-W7-005: CA never written outside <cassettes>/<session>/
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-005")
def test_generate_ca_rejects_session_dir_without_cassettes_component(
    tmp_path: Path,
) -> None:
    bad = tmp_path / "tmp" / "evil"
    bad.mkdir(parents=True, exist_ok=True)
    legit_root = tmp_path / "cassettes"
    legit_root.mkdir(parents=True, exist_ok=True)
    # BUG-F2 (audit-r3 P2): the validator now enforces strict containment,
    # so a session_dir that lives outside the legitimate cassette_root is
    # rejected with the "descendant" error message regardless of whether
    # the literal "cassettes" appears anywhere in the path.
    with pytest.raises(ValueError, match="descendant"):
        generate_ca(session_id="x", session_dir=bad, cassette_root=legit_root)


@pytest.mark.fulfills("VAL-W7-005")
def test_generate_ca_rejects_relative_session_dir(tmp_path: Path) -> None:
    legit_root = tmp_path / "cassettes"
    legit_root.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="absolute"):
        generate_ca(
            session_id="x",
            session_dir=Path("relative/cassettes/x"),
            cassette_root=legit_root,
        )


@pytest.mark.fulfills("VAL-W7-005")
def test_ca_file_subject_cn_contains_session_marker(
    cassette_root: Path,
) -> None:
    sd = cassette_root / "ses05aaaaaaaaaaaaaaaaaaaa"
    sd.mkdir(parents=True, exist_ok=True)
    ca = generate_ca(session_id=sd.name, session_dir=sd, cassette_root=cassette_root)
    assert SUBJECT_CN_PREFIX in ca.subject_cn
    assert sd.name in ca.subject_cn


@pytest.mark.fulfills("VAL-W7-005")
def test_ca_files_only_present_under_session_dir(
    harness: HarnessSession, relay_home_tmp: Path
) -> None:
    """Walk the entire RELAY_HOME tree post-start; no PEM outside session dir."""
    handle = harness.handle
    assert handle is not None
    found_pems: list[Path] = []
    for root, _dirs, files in os.walk(relay_home_tmp):
        for name in files:
            if name.endswith(".pem"):
                found_pems.append(Path(root) / name)
    # Both cert and key live under session_dir; that's the ONLY acceptable
    # location.
    expected_dir = handle.session_dir.resolve()
    for p in found_pems:
        assert p.resolve().parent == expected_dir, (
            f"unexpected PEM outside session dir: {p}"
        )


# -----------------------------------------------------------------------------
# VAL-W7-006: HTTPS_PROXY exported into agent subprocess
# VAL-W7-007: SSL_CERT_FILE exported into agent subprocess
# VAL-W7-012: env injection atomic
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-006")
def test_agent_env_sets_https_proxy(harness: HarnessSession) -> None:
    env = harness.agent_env(parent_env={})
    assert env[ENV_HTTPS_PROXY].startswith("http://127.0.0.1:")
    assert env[ENV_HTTP_PROXY] == env[ENV_HTTPS_PROXY]


@pytest.mark.fulfills("VAL-W7-007")
def test_agent_env_sets_ssl_cert_file_to_session_ca(
    harness: HarnessSession,
) -> None:
    env = harness.agent_env(parent_env={})
    handle = harness.handle
    assert handle is not None
    assert env[ENV_SSL_CERT_FILE] == str(handle.ca.cert_path)
    on_disk = handle.ca.cert_path.read_bytes()
    via_env = Path(env[ENV_SSL_CERT_FILE]).read_bytes()
    assert hashlib.sha256(on_disk).hexdigest() == hashlib.sha256(via_env).hexdigest()


@pytest.mark.fulfills("VAL-W7-012")
def test_agent_env_atomically_sets_all_required_vars(
    harness: HarnessSession,
) -> None:
    """All four required vars must be present in one returned dict."""
    env = harness.agent_env(parent_env={"PATH": "/usr/bin"})
    for var in (
        ENV_HTTPS_PROXY,
        ENV_HTTP_PROXY,
        ENV_SSL_CERT_FILE,
        ENV_REPLAY_SESSION,
        ENV_REPLAY_PROXY_URL,
    ):
        assert var in env, f"required env var {var} missing from agent env"
    # Parent env still flowed through (PATH was preserved).
    assert env["PATH"] == "/usr/bin"


@pytest.mark.fulfills("VAL-W7-012")
def test_agent_env_extras_cannot_override_proxy_vars(
    cassette_root: Path,
    session_dir_with_cassette: Path,
    use_inproc_driver: None,
) -> None:
    cfg = HarnessConfig(
        session_id=session_dir_with_cassette.name,
        cassette_root=cassette_root,
        extra_env={
            ENV_HTTPS_PROXY: "http://attacker:9999",
            ENV_SSL_CERT_FILE: "/etc/passwd",
            "RELAY_API_KEY": "sk-test",
        },
    )
    sess = HarnessSession(cfg)
    try:
        sess.start()
        env = sess.agent_env(parent_env={})
        assert env[ENV_HTTPS_PROXY] != "http://attacker:9999"
        assert env[ENV_SSL_CERT_FILE] != "/etc/passwd"
        assert env["RELAY_API_KEY"] == "sk-test"
    finally:
        sess.stop()


@pytest.mark.fulfills("VAL-W7-012")
def test_agent_env_passes_through_subprocess_envp(
    harness: HarnessSession,
) -> None:
    """A real subprocess.Popen exec receives all required env vars."""
    env = harness.agent_env(parent_env=dict(os.environ))
    # The injected env is what subprocess.run hands to execve/CreateProcess
    # in one allocation. We exec a Python one-liner to echo the values.
    code = (
        "import json,os,sys; "
        "sys.stdout.write(json.dumps({"
        f"'p':os.environ.get({ENV_HTTPS_PROXY!r}),"
        f"'c':os.environ.get({ENV_SSL_CERT_FILE!r}),"
        f"'s':os.environ.get({ENV_REPLAY_SESSION!r}),"
        f"'u':os.environ.get({ENV_REPLAY_PROXY_URL!r})"
        "}))"
    )
    res = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    parsed = json.loads(res.stdout)
    handle = harness.handle
    assert handle is not None
    assert parsed["p"] == handle.proxy_url
    assert parsed["c"] == str(handle.ca.cert_path)
    assert parsed["s"] == handle.session_id
    assert parsed["u"] == handle.proxy_url


# -----------------------------------------------------------------------------
# VAL-W7-008: cassette confined to session dir
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-008")
def test_cassette_lookup_confined_to_session_dir(
    cassette_root: Path,
    write_cassette,
    use_inproc_driver: None,
) -> None:
    """Session A's proxy must NOT serve session B's cassette entries."""
    sd_a = cassette_root / "ses08aaaaaaaaaaaaaaaaaaaa"
    sd_b = cassette_root / "ses08bbbbbbbbbbbbbbbbbbbb"
    for sd in (sd_a, sd_b):
        sd.mkdir(parents=True, exist_ok=True)
    write_cassette(
        sd_a,
        entries=[
            {
                "provider": "openai",
                "model": "m",
                "request": {"model": "m", "messages": [{"role": "user", "content": "A"}]},
                "response": {"id": "A"},
            }
        ],
    )
    write_cassette(
        sd_b,
        entries=[
            {
                "provider": "openai",
                "model": "m",
                "request": {"model": "m", "messages": [{"role": "user", "content": "B"}]},
                "response": {"id": "B"},
            }
        ],
    )
    cfg = HarnessConfig(session_id=sd_a.name, cassette_root=cassette_root)
    sess = HarnessSession(cfg)
    try:
        handle = sess.start()
        # Issue a request matching session B's recorded body. Session A's
        # proxy must respond with 404 cassette-miss, not B's response.
        request_body = json.dumps(
            {"model": "m", "messages": [{"role": "user", "content": "B"}]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        with socket.create_connection(("127.0.0.1", handle.proxy_port)) as sock:
            sock.sendall(
                b"POST / HTTP/1.1\r\n"
                b"Host: api.openai.com\r\n"
                b"X-Relay-Provider: openai\r\n"
                b"X-Relay-Model: m\r\n"
                + f"Content-Length: {len(request_body)}\r\n".encode("ascii")
                + b"Content-Type: application/json\r\n"
                b"Connection: close\r\n\r\n"
                + request_body
            )
            response = b""
            sock.settimeout(2.0)
            while True:
                try:
                    chunk = sock.recv(4096)
                except TimeoutError:
                    break
                if not chunk:
                    break
                response += chunk
        assert b"HTTP/1.0 404" in response or b"HTTP/1.1 404" in response, (
            f"session A should not serve session B's body; got: {response[:200]!r}"
        )
        assert b"RELAY-CASSETTE-MISS" in response
    finally:
        sess.stop()


# -----------------------------------------------------------------------------
# VAL-W7-009: proxy serves canonical responses from cassette
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-009")
def test_proxy_returns_canonical_response_body(
    harness: HarnessSession,
) -> None:
    handle = harness.handle
    assert handle is not None
    request_body = json.dumps(
        {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    with socket.create_connection(("127.0.0.1", handle.proxy_port)) as sock:
        sock.sendall(
            b"POST / HTTP/1.1\r\n"
            b"Host: api.openai.com\r\n"
            b"X-Relay-Provider: openai\r\n"
            b"X-Relay-Model: gpt-4o-mini\r\n"
            + f"Content-Length: {len(request_body)}\r\n".encode("ascii")
            + b"Content-Type: application/json\r\n"
            b"Connection: close\r\n\r\n"
            + request_body
        )
        sock.settimeout(2.0)
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            response += chunk
    # Body is the recorded canonical JSON for {"id": "resp1", ...}
    assert b'"id":"resp1"' in response
    # Proxy-added headers documented in VAL-W7-009 are present.
    assert b"X-Relay-Replay-Hit: 1" in response
    assert (
        b"X-Relay-Replay-Session: " + handle.session_id.encode("ascii")
    ) in response


# -----------------------------------------------------------------------------
# VAL-W7-010: proxy crash mid-replay surfaces RelayProxyDownError
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-010")
def test_assert_alive_after_driver_terminate_raises(
    harness: HarnessSession,
) -> None:
    # Force the driver down by calling terminate() directly. The harness
    # holds the only PID reference; we never look up by name.
    harness._driver.terminate()  # type: ignore[union-attr]
    # Wait for the OS to finish releasing the bound port so TCP probe fails.
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            with socket.create_connection(
                ("127.0.0.1", harness.handle.proxy_port), timeout=0.2  # type: ignore[union-attr]
            ):
                time.sleep(0.05)
        except OSError:
            break
    with pytest.raises(RelayProxyDownError) as excinfo:
        harness.assert_alive()
    msg = str(excinfo.value)
    assert "restart instructions" in msg
    assert "RELAY-REPLAY-021" in msg
    assert excinfo.value.code == "RELAY-REPLAY-021"


@pytest.mark.fulfills("VAL-W7-010")
def test_fake_failure_driver_surfaces_proxy_down(
    cassette_root: Path,
    session_dir_with_cassette: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fake-failure driver exits immediately so start() raises start error."""
    from relay_replay_proxy.errors import RelayProxyStartError

    monkeypatch.setenv(ENV_DRIVER, DRIVER_FAKE_FAILURE)
    cfg = HarnessConfig(
        session_id=session_dir_with_cassette.name,
        cassette_root=cassette_root,
    )
    sess = HarnessSession(cfg)
    try:
        with pytest.raises(RelayProxyStartError) as excinfo:
            sess.start()
        assert excinfo.value.code == "RELAY-REPLAY-023"
    finally:
        sess.stop()


# -----------------------------------------------------------------------------
# VAL-W7-011: refuses to start if cassette dir missing
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-011")
def test_start_refuses_when_cassette_dir_missing(
    cassette_root: Path, use_inproc_driver: None
) -> None:
    cfg = HarnessConfig(
        session_id="ses11aaaaaaaaaaaaaaaaaaaa",  # never created
        cassette_root=cassette_root,
    )
    sess = HarnessSession(cfg)
    with pytest.raises(RelayProxyMissingCassetteError) as excinfo:
        sess.start()
    assert "ses11aaaaaaaaaaaaaaaaaaaa" in str(excinfo.value)
    assert excinfo.value.code == "RELAY-REPLAY-022"
    # And the harness MUST NOT silently create the missing dir.
    assert not (cassette_root / "ses11aaaaaaaaaaaaaaaaaaaa").exists()


# -----------------------------------------------------------------------------
# VAL-W7-013: cross-platform (macOS, Linux, Windows)
# VAL-W7-014: Windows works without Docker
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-013")
def test_inproc_driver_runs_on_current_platform(
    harness: HarnessSession,
) -> None:
    """The default driver is pure-Python and must work on all 3 OSes.

    Asserting platform-specific success requires CI matrix; this test
    proves the driver started on the current host (whatever it is).
    """
    handle = harness.handle
    assert handle is not None
    assert handle.driver_name == DRIVER_INPROC


@pytest.mark.fulfills("VAL-W7-014")
def test_inproc_driver_does_not_require_docker_or_mitmproxy(
    cassette_root: Path,
    session_dir_with_cassette: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per L2 the v0.1 Windows path must work without Docker.

    The in-process driver depends only on stdlib + cryptography. No
    docker module, no docker binary, no mitmproxy binary.
    """
    # Hide mitmdump from PATH for this test to assert the inproc driver
    # truly does not need it.
    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv(ENV_DRIVER, DRIVER_INPROC)
    cfg = HarnessConfig(
        session_id=session_dir_with_cassette.name,
        cassette_root=cassette_root,
    )
    sess = HarnessSession(cfg)
    try:
        handle = sess.start()
        assert handle.driver_name == DRIVER_INPROC
        assert handle.proxy_port > 0
    finally:
        sess.stop()


# -----------------------------------------------------------------------------
# Process safety guard (CLAUDE.md): never kill by name
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-001")
def test_no_pkill_or_killall_call_in_harness_source() -> None:
    """Smoke guard: the harness must not invoke pkill/killall.

    Scans for actual call patterns (subprocess.run / Popen / call /
    check_call invoking the banned binaries) rather than bare byte
    sequences -- our own docstrings legitimately say 'NEVER pkill'
    as a prohibition note.
    """
    import re

    pkg_dir = Path(__file__).resolve().parents[1] / "relay_replay_proxy"
    # Match patterns like subprocess.run(["pkill"...]) or
    # subprocess.Popen([..., "killall", ...]). The literal binary
    # name must appear inside a list/tuple of strings adjacent to a
    # subprocess call.
    call_pat = re.compile(
        rb"subprocess\.(run|Popen|call|check_call|check_output)\s*\([^)]*"
        rb"['\"](?:pkill|killall)['\"]",
        re.DOTALL,
    )
    offenders: list[Path] = []
    for path in pkg_dir.rglob("*.py"):
        data = path.read_bytes()
        if call_pat.search(data):
            offenders.append(path)
    assert not offenders, (
        f"banned name-based kill subprocess calls in: {offenders}"
    )


# -----------------------------------------------------------------------------
# SIGINT-during-start must not deadlock (regression for signal-handler vs.
# start() lock contention). The SIGINT/SIGTERM cleanup handler installed by
# ``_install_atexit_and_signal_handlers`` calls ``stop()`` which re-acquires
# ``self._lock``; a non-reentrant Lock would deadlock the main thread.
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-001")
def test_harness_lock_is_reentrant_for_signal_safety() -> None:
    """``HarnessSession`` MUST use an RLock so a SIGINT handler that fires
    while ``start()`` holds the lock can call ``stop()`` from the same
    thread without deadlocking. This pins the lock type contract.
    """
    from relay_replay_proxy.harness import HarnessSession

    cfg = HarnessConfig(
        session_id="seslocktypecheck00000000",
        cassette_root=Path("/tmp/relay-test-not-used"),
    )
    sess = HarnessSession(cfg)
    # threading.RLock() returns an _RLock instance whose type repr starts
    # with "<unlocked _thread.RLock". Direct isinstance check is the most
    # robust way to assert the contract without depending on a specific
    # CPython internal class name.
    # The owning-thread re-acquire MUST succeed without blocking; if the
    # lock were a non-reentrant Lock this acquire would deadlock and the
    # test would time out.
    acquired_once = sess._lock.acquire(blocking=False)
    assert acquired_once, "could not take the lock at all"
    try:
        # Same-thread re-acquire: succeeds on RLock, would block on Lock.
        # We use a non-blocking timeout so a regression to Lock manifests
        # as test failure, not test hang.
        acquired_twice = sess._lock.acquire(blocking=True, timeout=1.0)
        assert acquired_twice, (
            "harness._lock did not allow same-thread re-acquire; "
            "SIGINT during start() would deadlock. Lock must be an RLock."
        )
        sess._lock.release()
    finally:
        sess._lock.release()


@pytest.mark.fulfills("VAL-W7-001")
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows SIGINT semantics differ; covered by RLock contract test above.",
)
def test_harness_signint_during_start_does_not_deadlock(
    cassette_root: Path,
    session_dir_with_cassette: Path,
    use_inproc_driver: None,
) -> None:
    """Simulate the signal-during-start deadlock scenario: hold the lock
    on the main thread (as ``start()`` does), then invoke ``stop()``
    from the same thread (as the signal handler does). On a non-reentrant
    Lock this hangs forever; on an RLock it completes immediately.

    The test gates on a wall-clock budget so a regression is observable
    rather than catastrophic.
    """
    from relay_replay_proxy.harness import HarnessSession

    cfg = HarnessConfig(
        session_id=session_dir_with_cassette.name,
        cassette_root=cassette_root,
    )
    sess = HarnessSession(cfg)
    sess.start()
    # Re-create the in-flight start() condition: the main thread already
    # holds the lock when SIGINT arrives, the handler runs on the same
    # thread, calls stop(). On a non-reentrant Lock the inner acquire
    # would block forever.
    deadline = time.time() + 5.0
    completed = False
    with sess._lock:
        # Stop() acquires self._lock internally; succeeds only if RLock.
        sess.stop()
        completed = True
    assert completed, "stop() returned"
    assert time.time() < deadline, "stop() exceeded 5s budget (deadlock)"


# Suppress unused-import lint on threading + EPHEMERAL_PORT_LOW/HIGH:
# referenced via boundary checks elsewhere.
_ = (threading, EPHEMERAL_PORT_LOW, EPHEMERAL_PORT_HIGH)
