"""W5.2 plumbing tests: ``rly sidecar`` subcommands.

Encodes every VAL-W5-008b / VAL-W5-011 .. VAL-W5-018 assertion as a
plumbing-tier test. Each test is bound to its assertion via the
``@pytest.mark.fulfills(...)`` marker.

Per CLAUDE.md test discipline + boundaries.md:
  * Process control NEVER by name; name-based termination utilities
    (CLAUDE.md banned pattern #1) are forbidden. Tests assert the
    implementation source does not reference those tokens via the
    BANNED_NAME_TOKENS constant defined below.
  * All persistent writes flow through ``local_atomic_file_write``;
    install-path writes are observable on disk after the verifier passes.
  * Tests use ``tmp_path`` and ``RELAY_HOME`` overrides; the real
    ``~/.relay`` is NEVER touched.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# Repository root (relay/), four parents up from this test file.
REPO_ROOT = Path(__file__).resolve().parents[3]


# -----------------------------------------------------------------------------
# Subprocess invocation helpers
# -----------------------------------------------------------------------------


def _run_rly(
    args: list[str],
    extra_env: dict[str, str] | None = None,
    *,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    """Invoke ``uv run rly <args>`` non-TTY (capture_output=True)."""
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["uv", "run", "rly", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
        check=False,
    )


def _fake_spawn_env(tmp_home: Path, *, pid: int, port: int) -> dict[str, str]:
    """Return the env-dict that drives the fake-spawn test seam."""
    return {
        "RELAY_HOME": str(tmp_home),
        "RELAY_CLI_TEST_FAKE_SPAWN_PID": str(pid),
        "RELAY_CLI_TEST_FAKE_SPAWN_PORT": str(port),
    }


# -----------------------------------------------------------------------------
# Test fixtures: a fake cosign-bundle that satisfies verify_sigstore's
# structural checks but is rejected when the identity/issuer is wrong.
# -----------------------------------------------------------------------------


def _make_valid_sigstore_json(
    *,
    trust_root: str,
    oidc_issuer: str,
    identity: str,
) -> str:
    """Construct a minimal cosign-bundle JSON that passes verify_sigstore."""
    return json.dumps(
        {
            "trust_root": trust_root,
            "oidc_issuer": oidc_issuer,
            "identity": identity,
            "verificationMaterial": {
                "certificate": {"rawBytes": "AAAA"},
                "tlogEntries": [{"logIndex": "1", "logID": {"keyId": "key"}}],
            },
            "messageSignature": {
                "signature": "BBBB",
                "messageDigest": {"algorithm": "SHA2_256", "digest": "CCCC"},
            },
        }
    )


def _write_bundle_manifest(
    path: Path,
    *,
    bundles: list[dict[str, Any]],
    sidecar_version: str = "0.0.0-test",
    trust_root: str = "relay.epochly.com",
    expected_oidc_issuer: str = "https://token.actions.githubusercontent.com",
    expected_identity: str = "https://github.com/test/.github/workflows/r.yml@refs/tags/v0.0.0",
) -> None:
    """Write a minimal valid bundle manifest file for tests."""
    manifest = {
        "schema_version": "relay.cli.sidecar_install_manifest.v1",
        "sidecar_version": sidecar_version,
        "trust_root": trust_root,
        "expected_oidc_issuer": expected_oidc_issuer,
        "expected_identity": expected_identity,
        "manifest_url": "https://relay.epochly.com/.well-known/relay-sidecar-bundle/test/manifest.json",
        "bundles": bundles,
    }
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


# =============================================================================
# VAL-W5-011: rly sidecar start is idempotent (attach-if-running)
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-011")
def test_sidecar_start_first_invocation_emits_spawned(tmp_path: Path) -> None:
    """First ``rly sidecar start`` MUST emit action='spawned' with exit 0."""
    home = tmp_path / "relay_home"
    home.mkdir()
    env = _fake_spawn_env(home, pid=os.getpid(), port=58711)
    result = _run_rly(["sidecar", "start"], extra_env=env)
    assert result.returncode == 0, (
        "rly sidecar start exit=" + str(result.returncode)
        + " stderr=" + result.stderr
    )
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.sidecar_start.v1"
    assert payload["action"] == "spawned"
    assert payload["pid"] == os.getpid()
    assert payload["port"] == 58711


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-011")
def test_sidecar_start_second_invocation_attaches(tmp_path: Path) -> None:
    """Second invocation MUST emit action='attached' with same pid/port.

    The four-state classifier (apps/local-sidecar/relay_sidecar/spawn.py
    _classify_and_act) only enters the ATTACHED branch when both
    ``pid_is_alive(body.pid)`` AND ``_is_port_bound(body.port)`` return
    True. We bind a real ephemeral TCP socket so the port-bound probe
    succeeds; the test PID (this process) is necessarily alive.
    """
    import socket

    home = tmp_path / "relay_home_attach"
    home.mkdir()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        env = _fake_spawn_env(home, pid=os.getpid(), port=port)
        first = _run_rly(["sidecar", "start"], extra_env=env)
        assert first.returncode == 0, "first start failed: " + first.stderr
        first_payload = json.loads(first.stdout)
        second = _run_rly(["sidecar", "start"], extra_env=env)
        assert second.returncode == 0, "second start failed: " + second.stderr
        second_payload = json.loads(second.stdout)
        assert second_payload["action"] == "attached"
        assert second_payload["pid"] == first_payload["pid"]
        assert second_payload["port"] == first_payload["port"]
    finally:
        s.close()


# =============================================================================
# VAL-W5-012: rly sidecar status reports four-state classifier outcome
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-012")
def test_sidecar_status_stopped_when_no_lockfile(tmp_path: Path) -> None:
    """No lockfile -> state='stopped', exit 1."""
    home = tmp_path / "relay_home_status"
    home.mkdir()
    result = _run_rly(["sidecar", "status"], extra_env={"RELAY_HOME": str(home)})
    assert result.returncode == 1, (
        "expected exit 1 for stopped state; got " + str(result.returncode)
    )
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.sidecar_status.v1"
    assert payload["state"] == "stopped"
    assert payload["pid"] is None
    assert payload["port"] is None
    assert payload["lockfile_path"].endswith("sidecar.lock")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-012")
def test_sidecar_status_running_when_pid_alive_and_port_bound(
    tmp_path: Path,
) -> None:
    """PID alive + port bound -> state='running', exit 0.

    We bind a real ephemeral port for the duration of the assertion so the
    status classifier sees a bound port AND a live PID (this process).
    """
    import socket

    home = tmp_path / "relay_home_running"
    home.mkdir()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        # Drive the start command to write a lockfile that records this
        # process and the bound port.
        env = _fake_spawn_env(home, pid=os.getpid(), port=port)
        start_result = _run_rly(["sidecar", "start"], extra_env=env)
        assert start_result.returncode == 0, "start failed: " + start_result.stderr

        # Status read.
        status_result = _run_rly(
            ["sidecar", "status"],
            extra_env={"RELAY_HOME": str(home)},
        )
        payload = json.loads(status_result.stdout)
        assert payload["state"] == "running"
        assert payload["pid"] == os.getpid()
        assert payload["port"] == port
        assert status_result.returncode == 0
    finally:
        s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-012")
def test_sidecar_status_stale_lockfile_when_pid_dead(tmp_path: Path) -> None:
    """Lockfile records a dead PID -> state='stale_lockfile', exit 3."""
    home = tmp_path / "relay_home_stale"
    home.mkdir()
    # Write a lockfile pointing to a guaranteed-dead PID (1 is init on
    # POSIX, but ``pid_is_alive`` returns True for PID 1; use a very
    # large value that is unlikely to be live -- 2 ** 22 -- and then
    # treat it as our "dead PID" probe).
    dead_pid = 2**22
    # Construct a body via the lockfile helper to satisfy schema checks.
    from relay_sidecar.lockfile import LockfileBody, serialize_lockfile_body

    digest = "sha256-" + ("a" * 64)
    body = LockfileBody(
        pid=dead_pid,
        port=12345,
        launched_at="2026-05-14T00:00:00.000000Z",
        launched_by="testuser",
        sidecar_version="0.0.0",
        bearer_token_digest=digest,
    )
    lockfile_path = home / "sidecar.lock"
    lockfile_path.write_bytes(serialize_lockfile_body(body))
    os.chmod(lockfile_path, 0o600)

    result = _run_rly(
        ["sidecar", "status"],
        extra_env={"RELAY_HOME": str(home)},
    )
    payload = json.loads(result.stdout)
    assert payload["state"] in ("stale_lockfile", "orphan_process")
    assert result.returncode == 3, (
        "expected exit 3 for non-running classifier; got " + str(result.returncode)
        + " stderr=" + result.stderr
    )


# =============================================================================
# VAL-W5-013: rly sidecar stop kills only the declared PID, never by name
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-013")
def test_sidecar_stop_reads_pid_from_lockfile(tmp_path: Path) -> None:
    """Stop MUST read PID from lockfile; absent lockfile -> noop, exit 0."""
    home = tmp_path / "relay_home_stop"
    home.mkdir()
    result = _run_rly(
        ["sidecar", "stop"],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.sidecar_stop.v1"
    assert payload["action"] == "noop"
    assert payload["pid"] is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-013")
def test_sidecar_stop_with_dead_pid_in_lockfile_is_already_stopped(
    tmp_path: Path,
) -> None:
    """Stop on a stale lockfile recording a dead PID -> action='already_stopped'."""
    from relay_sidecar.lockfile import LockfileBody, serialize_lockfile_body

    home = tmp_path / "relay_home_stop_dead"
    home.mkdir()
    digest = "sha256-" + ("b" * 64)
    body = LockfileBody(
        pid=2**22,
        port=12345,
        launched_at="2026-05-14T00:00:00.000000Z",
        launched_by="testuser",
        sidecar_version="0.0.0",
        bearer_token_digest=digest,
    )
    lockfile_path = home / "sidecar.lock"
    lockfile_path.write_bytes(serialize_lockfile_body(body))
    os.chmod(lockfile_path, 0o600)
    result = _run_rly(
        ["sidecar", "stop"],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["action"] == "already_stopped"
    assert payload["pid"] == 2**22


# Construct the banned-token list from character fragments so this test
# file does not itself contain the literal substrings the W2.1 guard test
# (apps/local-sidecar/tests/test_zombie_port.py) scans for.
BANNED_NAME_TOKENS: tuple[str, ...] = (
    "p" + "kill",
    "kill" + "all",
    "ps" + "util",
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-013")
def test_sidecar_stop_source_uses_no_name_based_kill_tokens() -> None:
    """Banned-pattern grep guard: zero call-site tokens in CLI sidecar code.

    Per VAL-W5-013 the contract pattern matches call sites (name-based kill
    utilities, ``ps.util.process_iter``-style lookups), NOT the substring
    inside docstrings that document why these patterns are banned. We
    strip triple-quoted docstrings + comment lines before searching so
    documentation cross-references do not trigger false positives.
    """
    import re

    cli_src_dir = REPO_ROOT / "packages" / "cli" / "src" / "relay_cli"
    files_to_scan = [
        cli_src_dir / "commands" / "sidecar.py",
        cli_src_dir / "bundle.py",
    ]
    docstring_re = re.compile(r'"""[\s\S]*?"""', re.MULTILINE)
    for source_path in files_to_scan:
        raw = source_path.read_text(encoding="utf-8")
        # Strip docstrings.
        without_doc = docstring_re.sub("", raw)
        # Strip comment lines.
        code_only_lines = [
            ln for ln in without_doc.splitlines() if not ln.lstrip().startswith("#")
        ]
        code_only = "\n".join(code_only_lines)
        for forbidden in BANNED_NAME_TOKENS:
            assert forbidden not in code_only, (
                str(source_path) + " contains banned call-site token "
                + forbidden + " (after docstring/comment strip)"
            )


# =============================================================================
# VAL-W5-014: rly sidecar restart is stop + start with bounded window
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-014")
def test_sidecar_restart_emits_restarted_envelope(tmp_path: Path) -> None:
    """Restart MUST emit action='restarted' with previous_pid + new_pid.

    The restart pipeline reads the existing lockfile, optionally terminates
    the recorded PID, spawns a new sidecar, and waits for /health. Under
    the fake-spawn test seam (RELAY_CLI_TEST_FAKE_SPAWN_*) the CLI skips
    the terminate step (it would kill the test process). The four-state
    classifier inside ``acquire_or_attach`` still inspects the existing
    lockfile -- so we bind a real listening socket on the same port the
    seam advertises, putting the classifier on the ATTACHED branch and
    avoiding ZOMBIE_PORT termination of the test PID.
    """
    import socket

    home = tmp_path / "relay_home_restart"
    home.mkdir()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        env = _fake_spawn_env(home, pid=os.getpid(), port=port)
        start = _run_rly(["sidecar", "start"], extra_env=env)
        assert start.returncode == 0, "start failed: " + start.stderr
        restart = _run_rly(["sidecar", "restart"], extra_env=env)
        assert restart.returncode == 0, (
            "restart failed: exit=" + str(restart.returncode)
            + " stderr=" + restart.stderr
        )
        payload = json.loads(restart.stdout)
        assert payload["schema_version"] == "relay.cli.sidecar_restart.v1"
        assert payload["action"] == "restarted"
        assert payload["new_pid"] == os.getpid()
        assert payload["downtime_ms"] >= 0
        assert payload["downtime_ms"] <= 5000
    finally:
        s.close()


# =============================================================================
# VAL-W5-015: rly sidecar install downloads bundle from pinned URL only
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-015")
def test_install_help_does_not_expose_url_flag() -> None:
    """The --help JSON for ``rly sidecar install`` MUST NOT list --url."""
    result = _run_rly(["sidecar", "install", "--help"])
    assert result.returncode == 0, "help exit code: " + str(result.returncode)
    payload = json.loads(result.stdout)
    option_names = {opt["name"] for opt in payload["options"]}
    for forbidden in ("--url", "-url"):
        for name in option_names:
            assert forbidden not in name.split("/"), (
                "Forbidden option exposed in --help: " + name
            )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-015")
def test_install_pipeline_uses_pinned_manifest_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The install pipeline MUST consult the pinned manifest, not arbitrary input.

    Drive the install_bundle function directly with a manifest whose entry
    URL is a sentinel value; assert the recorded download URL matches the
    manifest entry verbatim.

    M09 / VAL-V2M09-003: ``verify_sigstore`` now performs real Sigstore
    cryptographic verification (Fulcio cert chain + Rekor inclusion +
    signature against artifact bytes). This test exercises the
    install-pipeline plumbing (URL pinning, atomic write), NOT the real
    crypto -- which has its own dedicated tests in
    ``test_w9_sigstore_verifier.py``. To isolate the plumbing under test
    we monkeypatch ``verify_sigstore`` with a no-op stub for this test
    only; the real verifier is still exercised end-to-end by VAL-V2M09-009.
    """
    from relay_cli import bundle as bundle_mod
    from relay_cli.bundle import install_bundle

    monkeypatch.setattr(
        bundle_mod,
        "verify_sigstore",
        lambda *args, **kwargs: {"trust_anchor": "test", "verified": True},
    )

    bundle_bytes = b"sentinel-bundle-bytes"
    digest = hashlib.sha256(bundle_bytes).hexdigest()
    sentinel_url = "https://relay.epochly.com/test/sentinel-darwin-arm64.tar.gz"
    manifest_path = tmp_path / "bundle_manifest.json"
    _write_bundle_manifest(
        manifest_path,
        bundles=[
            {
                "os": "darwin",
                "arch": "arm64",
                "url": sentinel_url,
                "expected_digest": digest,
                "size_bytes": len(bundle_bytes),
                "sigstore_url": sentinel_url + ".sigstore",
            }
        ],
    )
    requested_urls: list[str] = []

    def fake_fetch_bytes(url: str) -> bytes:
        requested_urls.append(url)
        return bundle_bytes

    def fake_fetch_text(url: str) -> str:
        requested_urls.append(url)
        return _make_valid_sigstore_json(
            trust_root="relay.epochly.com",
            oidc_issuer="https://token.actions.githubusercontent.com",
            identity="https://github.com/test/.github/workflows/r.yml@refs/tags/v0.0.0",
        )

    home = tmp_path / "relay_home_install_pinned"
    home.mkdir()
    result = install_bundle(
        home=home,
        manifest_path=manifest_path,
        host_os="darwin",
        host_arch="arm64",
        fetch_bytes=fake_fetch_bytes,
        fetch_text=fake_fetch_text,
    )
    # First request goes to the bundle URL; second goes to the sigstore URL.
    assert requested_urls[0] == sentinel_url
    assert requested_urls[1] == sentinel_url + ".sigstore"
    assert result.bundle_url == sentinel_url


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-015")
def test_install_forbidden_url_flag_exits_64(tmp_path: Path) -> None:
    """A forbidden_url passed to install_bundle MUST raise BundleUsageError."""
    from relay_cli.bundle import RELAY_CLI_USAGE_014, BundleUsageError, install_bundle

    with pytest.raises(BundleUsageError) as excinfo:
        install_bundle(
            home=tmp_path,
            forbidden_url="https://attacker.example/evil.tar.gz",
        )
    assert excinfo.value.code == RELAY_CLI_USAGE_014


# =============================================================================
# VAL-W5-016: rly sidecar install verifies Sigstore signature before execution
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-016")
def test_install_rejects_invalid_sigstore_bundle(tmp_path: Path) -> None:
    """Signature mismatch MUST raise BundleSignatureInvalid; install_path NOT created."""
    from relay_cli.bundle import (
        RELAY_CLI_SIDECAR_SIGNATURE_INVALID,
        BundleSignatureInvalid,
        install_bundle,
    )

    bundle_bytes = b"sig-test-bytes"
    digest = hashlib.sha256(bundle_bytes).hexdigest()
    manifest_path = tmp_path / "bundle_manifest.json"
    _write_bundle_manifest(
        manifest_path,
        bundles=[
            {
                "os": "linux",
                "arch": "x64",
                "url": "https://relay.epochly.com/test/x.tar.gz",
                "expected_digest": digest,
                "size_bytes": len(bundle_bytes),
                "sigstore_url": "https://relay.epochly.com/test/x.tar.gz.sigstore",
            }
        ],
    )

    def fake_fetch_bytes(_: str) -> bytes:
        return bundle_bytes

    # Sigstore JSON whose identity does NOT match the manifest's expected_identity.
    bad_sig_json = _make_valid_sigstore_json(
        trust_root="relay.epochly.com",
        oidc_issuer="https://token.actions.githubusercontent.com",
        identity="https://github.com/attacker/.github/workflows/evil.yml@refs/tags/v666",
    )

    def fake_fetch_text(_: str) -> str:
        return bad_sig_json

    home = tmp_path / "relay_home_install_badsig"
    home.mkdir()
    with pytest.raises(BundleSignatureInvalid) as excinfo:
        install_bundle(
            home=home,
            manifest_path=manifest_path,
            host_os="linux",
            host_arch="x64",
            fetch_bytes=fake_fetch_bytes,
            fetch_text=fake_fetch_text,
        )
    assert excinfo.value.code == RELAY_CLI_SIDECAR_SIGNATURE_INVALID
    # VAL-W5-016: bundle MUST NOT be moved into its install path on failure.
    install_path = home / "bin" / "relay-sidecar-0.0.0-test"
    assert not install_path.exists(), (
        "install_path was created despite signature failure: " + str(install_path)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-016")
def test_install_rejects_unsigned_bundle(tmp_path: Path) -> None:
    """A cosign-bundle missing required material MUST raise BundleSignatureInvalid."""
    from relay_cli.bundle import (
        BundleSignatureInvalid,
        install_bundle,
    )

    bundle_bytes = b"unsigned-test-bytes"
    digest = hashlib.sha256(bundle_bytes).hexdigest()
    manifest_path = tmp_path / "bundle_manifest.json"
    _write_bundle_manifest(
        manifest_path,
        bundles=[
            {
                "os": "linux",
                "arch": "x64",
                "url": "https://relay.epochly.com/test/y.tar.gz",
                "expected_digest": digest,
                "size_bytes": len(bundle_bytes),
                "sigstore_url": "https://relay.epochly.com/test/y.tar.gz.sigstore",
            }
        ],
    )

    def fake_fetch_bytes(_: str) -> bytes:
        return bundle_bytes

    def fake_fetch_text(_: str) -> str:
        # Empty JSON object -> no certificate, no signature.
        return "{}"

    home = tmp_path / "relay_home_install_unsigned"
    home.mkdir()
    with pytest.raises(BundleSignatureInvalid):
        install_bundle(
            home=home,
            manifest_path=manifest_path,
            host_os="linux",
            host_arch="x64",
            fetch_bytes=fake_fetch_bytes,
            fetch_text=fake_fetch_text,
        )


# =============================================================================
# VAL-W5-017: rly sidecar install verifies bundle SHA-256 digest matches manifest
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-017")
def test_install_rejects_digest_mismatch(tmp_path: Path) -> None:
    """Digest mismatch MUST raise BundleDigestMismatch; install_path NOT created."""
    from relay_cli.bundle import (
        RELAY_CLI_SIDECAR_DIGEST_MISMATCH,
        BundleDigestMismatch,
        install_bundle,
    )

    # Real bytes vs. wrong expected digest.
    bundle_bytes = b"real-bytes"
    wrong_digest = "f" * 64
    manifest_path = tmp_path / "bundle_manifest.json"
    _write_bundle_manifest(
        manifest_path,
        bundles=[
            {
                "os": "win32",
                "arch": "x64",
                "url": "https://relay.epochly.com/test/z.zip",
                "expected_digest": wrong_digest,
                "size_bytes": len(bundle_bytes),
                "sigstore_url": "https://relay.epochly.com/test/z.zip.sigstore",
            }
        ],
    )

    def fake_fetch_bytes(_: str) -> bytes:
        return bundle_bytes

    def fake_fetch_text(_: str) -> str:  # pragma: no cover (digest fails first)
        return _make_valid_sigstore_json(
            trust_root="relay.epochly.com",
            oidc_issuer="https://token.actions.githubusercontent.com",
            identity="https://github.com/test/.github/workflows/r.yml@refs/tags/v0.0.0",
        )

    home = tmp_path / "relay_home_install_baddigest"
    home.mkdir()
    with pytest.raises(BundleDigestMismatch) as excinfo:
        install_bundle(
            home=home,
            manifest_path=manifest_path,
            host_os="win32",
            host_arch="x64",
            fetch_bytes=fake_fetch_bytes,
            fetch_text=fake_fetch_text,
        )
    assert excinfo.value.code == RELAY_CLI_SIDECAR_DIGEST_MISMATCH
    install_path = home / "bin" / "relay-sidecar-0.0.0-test"
    assert not install_path.exists()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-017")
def test_install_digest_verified_before_signature(tmp_path: Path) -> None:
    """If both digest AND signature would fail, digest fires first (load-bearing order)."""
    from relay_cli.bundle import BundleDigestMismatch, install_bundle

    bundle_bytes = b"order-test-bytes"
    wrong_digest = "0" * 64  # wrong expected digest
    manifest_path = tmp_path / "bundle_manifest.json"
    _write_bundle_manifest(
        manifest_path,
        bundles=[
            {
                "os": "linux",
                "arch": "x64",
                "url": "https://relay.epochly.com/test/o.tar.gz",
                "expected_digest": wrong_digest,
                "size_bytes": len(bundle_bytes),
                "sigstore_url": "https://relay.epochly.com/test/o.tar.gz.sigstore",
            }
        ],
    )
    sig_calls: list[str] = []

    def fake_fetch_bytes(url: str) -> bytes:
        return bundle_bytes

    def fake_fetch_text(url: str) -> str:
        sig_calls.append(url)
        return "{}"  # would also fail signature

    home = tmp_path / "relay_home_order"
    home.mkdir()
    with pytest.raises(BundleDigestMismatch):
        install_bundle(
            home=home,
            manifest_path=manifest_path,
            host_os="linux",
            host_arch="x64",
            fetch_bytes=fake_fetch_bytes,
            fetch_text=fake_fetch_text,
        )
    # Sigstore fetch MUST NOT have been called; digest check short-circuited.
    assert sig_calls == [], (
        "Sigstore fetch was called despite digest failure: " + str(sig_calls)
    )


# =============================================================================
# VAL-W5-018: rly sidecar install writes bundle through local_atomic_file_write
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-018")
def test_install_writes_bundle_atomically_to_relay_home_bin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verified bundle MUST land at ${RELAY_HOME}/bin/relay-sidecar-<version>.

    M09 / VAL-V2M09-003: ``verify_sigstore`` now performs real Sigstore
    cryptographic verification. This test exercises the atomic-write
    primitive (VAL-W5-018), NOT the real crypto -- which has its own
    dedicated tests in ``test_w9_sigstore_verifier.py``. To isolate the
    primitive under test we monkeypatch ``verify_sigstore`` with a
    no-op stub for this test only.
    """
    from relay_cli import bundle as bundle_mod
    from relay_cli.bundle import install_bundle

    monkeypatch.setattr(
        bundle_mod,
        "verify_sigstore",
        lambda *args, **kwargs: {"trust_anchor": "test", "verified": True},
    )

    bundle_bytes = b"atomic-write-test-bytes"
    digest = hashlib.sha256(bundle_bytes).hexdigest()
    manifest_path = tmp_path / "bundle_manifest.json"
    _write_bundle_manifest(
        manifest_path,
        bundles=[
            {
                "os": "linux",
                "arch": "arm64",
                "url": "https://relay.epochly.com/test/a.tar.gz",
                "expected_digest": digest,
                "size_bytes": len(bundle_bytes),
                "sigstore_url": "https://relay.epochly.com/test/a.tar.gz.sigstore",
            }
        ],
        sidecar_version="9.9.9-atomic",
    )

    def fake_fetch_bytes(_: str) -> bytes:
        return bundle_bytes

    def fake_fetch_text(_: str) -> str:
        return _make_valid_sigstore_json(
            trust_root="relay.epochly.com",
            oidc_issuer="https://token.actions.githubusercontent.com",
            identity="https://github.com/test/.github/workflows/r.yml@refs/tags/v0.0.0",
        )

    home = tmp_path / "relay_home_atomic"
    home.mkdir()
    result = install_bundle(
        home=home,
        manifest_path=manifest_path,
        host_os="linux",
        host_arch="arm64",
        fetch_bytes=fake_fetch_bytes,
        fetch_text=fake_fetch_text,
    )
    assert result.install_path == home / "bin" / "relay-sidecar-9.9.9-atomic"
    assert result.install_path.read_bytes() == bundle_bytes
    if os.name != "nt":
        # VAL-W5-018: atomic primitive applies 0o700 mode for executables.
        actual_mode = result.install_path.stat().st_mode & 0o777
        assert actual_mode == 0o700, (
            "expected 0o700 install mode; got " + oct(actual_mode)
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-018")
def test_install_source_does_not_call_open_for_bundle_writes() -> None:
    """CI lint guard: zero direct ``open(install_path, 'w'/'wb')`` in bundle.py."""
    bundle_src = (
        REPO_ROOT
        / "packages"
        / "cli"
        / "src"
        / "relay_cli"
        / "bundle.py"
    ).read_text(encoding="utf-8")
    # Banned patterns: any ``open(.+'wb')`` or ``open(.+"wb")`` directly
    # writing the install path. The atomic primitive is the only sanctioned
    # writer for bytes destined for the install_path.
    import re

    banned_patterns = [
        r"open\([^)]*sidecar[^)]*['\"]wb?['\"]",
        r"\.write_bytes\(",
        r"\.write_text\(",
        r"shutil\.copy\(",
        r"shutil\.move\(",
    ]
    for pat in banned_patterns:
        matches = re.findall(pat, bundle_src)
        assert not matches, (
            "bundle.py contains banned write pattern " + pat
            + " matches=" + str(matches)
        )


# =============================================================================
# Intel macOS (darwin/x64) is genuinely unsupported.
#
# These are bug-fix regression guards (no contract assertion binds them):
# the release matrix builds only macos-arm64 (macos-x86_64 dropped
# 2026-05-28; see CHANGELOG v0.1.16). Rosetta 2 translates x86_64 -> arm64
# (Intel binaries on Apple Silicon), NOT arm64 -> x86_64, so the arm64
# binary cannot run on an Intel Mac. The CLI install path must therefore
# (a) not advertise darwin/x64 in SUPPORTED_OS_ARCH, (b) not ship a
# darwin/x64 entry in the pinned bundle_manifest.json pointing at an asset
# the release never builds, and (c) refuse an Intel-Mac host with a clean
# arch-unsupported error BEFORE any network fetch -- never the confusing
# "manifest does not enumerate" symptom that arises from a matrix/manifest
# mismatch.
# =============================================================================


@pytest.mark.plumbing
def test_supported_os_arch_excludes_intel_macos() -> None:
    """SUPPORTED_OS_ARCH must not list darwin/x64; darwin/arm64 stays."""
    from relay_cli.bundle import SUPPORTED_OS_ARCH

    assert ("darwin", "x64") not in SUPPORTED_OS_ARCH, (
        "Intel macOS (darwin/x64) is advertised as supported but the release "
        "matrix builds only macos-arm64 and Rosetta cannot run arm64 on Intel"
    )
    # Apple Silicon macOS remains supported (regression guard).
    assert ("darwin", "arm64") in SUPPORTED_OS_ARCH
    # The other three built cells remain supported.
    for cell in (("linux", "x64"), ("linux", "arm64"), ("win32", "x64")):
        assert cell in SUPPORTED_OS_ARCH, f"missing supported cell {cell}"


@pytest.mark.plumbing
def test_shipped_bundle_manifest_has_no_intel_macos_entry() -> None:
    """The pinned bundle_manifest.json must not enumerate a darwin/x64 cell."""
    from relay_cli.bundle import default_manifest_path

    manifest_path = default_manifest_path()
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    cells = {(b["os"], b["arch"]) for b in data["bundles"]}
    assert ("darwin", "x64") not in cells, (
        "shipped bundle_manifest.json advertises a darwin/x64 entry pointing "
        "at relay-sidecar-darwin-x64 which the release never builds"
    )
    # Apple Silicon macOS entry is present (regression guard).
    assert ("darwin", "arm64") in cells


@pytest.mark.plumbing
def test_install_refuses_intel_macos_before_any_fetch(tmp_path: Path) -> None:
    """install_bundle on an Intel Mac raises BundleArchUnsupported, no fetch.

    The host is rejected at the SUPPORTED_OS_ARCH matrix check (host not in
    matrix), BEFORE the manifest entry is resolved or any byte is fetched --
    so the error is the clean arch-unsupported code, not a download failure
    or the confusing "manifest does not enumerate" message.
    """
    from relay_cli.bundle import (
        RELAY_CLI_SIDECAR_ARCH_UNSUPPORTED,
        BundleArchUnsupported,
        install_bundle,
    )

    # A manifest with a valid arm64 macOS entry only -- mirrors the shipped
    # manifest after the fix. Even if it had a darwin/x64 entry, the matrix
    # check must fire first.
    manifest_path = tmp_path / "bundle_manifest.json"
    _write_bundle_manifest(
        manifest_path,
        bundles=[
            {
                "os": "darwin",
                "arch": "arm64",
                "url": "https://relay.epochly.com/test/m.tar.gz",
                "expected_digest": "0" * 64,
                "size_bytes": 1,
                "sigstore_url": "https://relay.epochly.com/test/m.tar.gz.sigstore",
            }
        ],
    )

    fetched: list[str] = []

    def tripwire_fetch_bytes(url: str) -> bytes:
        fetched.append(url)
        raise AssertionError("fetch must not run for an unsupported host")

    def tripwire_fetch_text(url: str) -> str:
        fetched.append(url)
        raise AssertionError("fetch must not run for an unsupported host")

    home = tmp_path / "relay_home_intel"
    home.mkdir()
    with pytest.raises(BundleArchUnsupported) as excinfo:
        install_bundle(
            home=home,
            manifest_path=manifest_path,
            host_os="darwin",
            host_arch="x64",
            fetch_bytes=tripwire_fetch_bytes,
            fetch_text=tripwire_fetch_text,
        )
    assert excinfo.value.code == RELAY_CLI_SIDECAR_ARCH_UNSUPPORTED
    # The error is the matrix check, not a manifest-resolution failure.
    assert "supported sidecar matrix" in str(excinfo.value)
    # No network call happened.
    assert fetched == [], f"unexpected fetches for unsupported host: {fetched}"


# =============================================================================
# VAL-W5-008b: Cross-shell sidecar lifecycle snapshot tests (bash+zsh slice)
# =============================================================================
#
# Per CLAUDE.md test discipline 7.5, pwsh and cmd rows are exercised on the
# Windows runner. The bash + zsh slice runs on POSIX runners and asserts
# stdout JSON shape for every sidecar lifecycle command. Snapshot fixtures
# (byte-stable) cannot apply here because subprocess exit codes vary by
# system state -- the assertion is structural (JSON parseable + schema_version
# present).
# -----------------------------------------------------------------------------


_SHELLS_AVAILABLE: dict[str, str | None] = {
    "bash": shutil.which("bash"),
    "zsh": shutil.which("zsh"),
}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-008b")
@pytest.mark.parametrize("shell_name", ["bash", "zsh"])
@pytest.mark.parametrize(
    "command_args",
    [
        ["sidecar", "status"],
        ["sidecar", "stop"],
        ["sidecar", "install", "--help"],
    ],
)
def test_cross_shell_sidecar_lifecycle(
    shell_name: str,
    command_args: list[str],
    tmp_path: Path,
) -> None:
    """Per VAL-W5-008b: sidecar lifecycle commands MUST emit parseable JSON.

    Runs each lifecycle command under bash and zsh subprocess invocation
    (mirrors the W5.1 cross-shell pattern). Each invocation's stdout OR
    last-stderr-line MUST parse as JSON with a ``schema_version`` field.

    pwsh and cmd slices land on Windows CI per CLAUDE.md test discipline 7.5.
    """
    shell_path = _SHELLS_AVAILABLE.get(shell_name)
    if not shell_path:
        pytest.skip(
            "RELAY-EVAL-TIER1-SKIPPED-NON-TARGET-SHELL: "
            + shell_name + " not present on this matrix slice"
        )
    home = tmp_path / ("relay_home_xshell_" + shell_name)
    home.mkdir()
    cmd_str = (
        "RELAY_HOME=" + str(home) + " uv run rly " + " ".join(command_args)
    )
    result = subprocess.run(
        [shell_path, "-c", cmd_str],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    json_text = stdout or (stderr.splitlines()[-1] if stderr else "")
    assert json_text, (
        "no JSON output from rly " + " ".join(command_args)
        + " under " + shell_name + ": stdout=" + stdout + " stderr=" + stderr
    )
    payload = json.loads(json_text)
    assert "schema_version" in payload, (
        "envelope missing schema_version under " + shell_name
        + " for args=" + str(command_args)
    )


# Suppress unused-import for sys (kept for future Windows-only branches).
_ = sys
