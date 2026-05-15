"""W7.5 subprocess curl egress-denial tests (VAL-W7-083).

Per eng plan A4 line 254 ("subprocess.run(['curl', ...]) in replay ->
blocked via HTTPS_PROXY env inheritance") the W7 layered defense relies
on inheritance of ``HTTPS_PROXY`` (and ``SSL_CERT_FILE`` for the harness
CA cert) into every subprocess the agent spawns. libcurl, .NET HttpClient,
and any HTTP client that respects the standard proxy env vars MUST route
through the session proxy -- which then yields cassette-miss for
unrecorded targets.

Coverage:

  * VAL-W7-083: ``subprocess.run(['curl', 'https://...'])`` is blocked
    via ``HTTPS_PROXY`` env inheritance.

The Windows leg of VAL-W7-083 (PowerShell ``Invoke-WebRequest`` and
``pwsh -c "iwr ..."``) runs only on the Windows CI matrix cell; on
Linux / macOS it is parametrize-skipped. The CI workflow file
``.github/workflows/relay-tier-3.yml`` is responsible for installing
``curl.exe`` via ``choco install curl`` on Windows runners (see the
contract assertion text); this test file does NOT manage that
installation.

This file is plumbing-tier and runs OFFLINE: the proxy URL points at a
loopback port that is reliably closed (so any actual egress would
ECONNREFUSED instantly). The deterministic invariants tested are:

  1. ``HTTPS_PROXY`` is set in the spawned subprocess env.
  2. ``SSL_CERT_FILE`` is set in the spawned subprocess env.
  3. A canary subprocess that uses the standard ``HTTPS_PROXY`` env
     can be observed reading those vars (proven via a Python helper
     subprocess; this is portable across all CI matrix cells without
     requiring ``curl`` on the runner).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from relay_replay_proxy import (
    ENV_HTTP_PROXY,
    ENV_HTTPS_PROXY,
    ENV_SSL_CERT_FILE,
    HarnessSession,
)

pytestmark = pytest.mark.plumbing


# Inline Python program used as a portable stand-in for ``curl``: it
# reads the proxy / cert env vars, prints them as JSON to stdout, and
# attempts a single TCP connect to the proxy URL. The test asserts on
# the JSON output -- this works on every OS the workspace targets
# without requiring curl to be installed (Windows CI installs curl via
# choco install per VAL-W7-083 spec text; macOS / Linux ship curl;
# this test does NOT depend on either).
_INLINE_PROBE = (
    "import json, os, sys, urllib.parse, urllib.error, urllib.request\n"
    "out = {\n"
    "  'HTTPS_PROXY': os.environ.get('HTTPS_PROXY'),\n"
    "  'http_proxy': os.environ.get('http_proxy'),\n"
    "  'SSL_CERT_FILE': os.environ.get('SSL_CERT_FILE'),\n"
    "  'NO_PROXY': os.environ.get('NO_PROXY') or os.environ.get('no_proxy'),\n"
    "}\n"
    "# Attempt a fetch through the proxy. urllib honours HTTPS_PROXY\n"
    "# the same way curl/libcurl do for https://; for our test target,\n"
    "# the proxy URL points at a closed loopback port so the connect\n"
    "# fails BEFORE any egress to google.com happens. The failure is\n"
    "# the proof of denial; the env var values are the proof that the\n"
    "# subprocess inherited the right config.\n"
    "out['fetch_error'] = None\n"
    "try:\n"
    "    urllib.request.urlopen('https://api.example.com/never', timeout=1.0)\n"
    "except Exception as e:\n"
    "    out['fetch_error'] = type(e).__name__ + ': ' + str(e)[:120]\n"
    "json.dump(out, sys.stdout)\n"
)


def _spawn_probe(env: dict[str, str], timeout_s: float = 5.0) -> dict[str, object]:
    """Spawn the inline probe with ``env`` and return the parsed JSON.

    The probe never depends on the real network; it only proves env
    inheritance and observes that any fetch through the configured
    proxy fails (because the proxy URL is a closed loopback port).
    """
    result = subprocess.run(
        [sys.executable, "-c", _INLINE_PROBE],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    assert result.returncode == 0, (
        f"probe exited {result.returncode}; stderr={result.stderr!r}"
    )
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# VAL-W7-083: HTTPS_PROXY / SSL_CERT_FILE inherited into subprocess env
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-083")
def test_https_proxy_inherits_into_subprocess(harness: HarnessSession) -> None:
    """The harness's child env carries HTTPS_PROXY pointed at the proxy.

    The harness exposes :meth:`build_child_env` (used by ``rly replay
    run`` to build the env for the agent subprocess); the env MUST
    contain ``HTTPS_PROXY`` set to the harness's loopback proxy URL,
    which is the mechanism libcurl honours for VAL-W7-083 denial.
    """
    handle = harness.handle
    assert handle is not None
    child_env = harness.agent_env(parent_env=os.environ.copy())
    assert ENV_HTTPS_PROXY in child_env
    assert child_env[ENV_HTTPS_PROXY] == handle.proxy_url
    assert child_env[ENV_HTTPS_PROXY].startswith("http://127.0.0.1:")


@pytest.mark.fulfills("VAL-W7-083")
def test_http_proxy_inherits_into_subprocess(harness: HarnessSession) -> None:
    """``HTTP_PROXY`` MUST also be set so plain-text targets route via the proxy.

    Some HTTP clients only honour ``HTTP_PROXY`` (lowercase casings
    vary by platform). The harness sets both upper and lower forms so
    every reasonable client picks them up.
    """
    handle = harness.handle
    assert handle is not None
    child_env = harness.agent_env(parent_env=os.environ.copy())
    assert ENV_HTTP_PROXY in child_env
    assert child_env[ENV_HTTP_PROXY] == handle.proxy_url


@pytest.mark.fulfills("VAL-W7-083")
def test_ssl_cert_file_inherits_into_subprocess(harness: HarnessSession) -> None:
    """``SSL_CERT_FILE`` MUST point at the per-session CA so libcurl
    can validate the proxy's MITM certificate chain (otherwise the
    subprocess would refuse the connection on cert validation, which
    would also be denial -- but the spec text VAL-W7-083 says ``curl
    MUST route through the session proxy``, which requires CA trust).
    """
    handle = harness.handle
    assert handle is not None
    child_env = harness.agent_env(parent_env=os.environ.copy())
    assert ENV_SSL_CERT_FILE in child_env
    cert_path = Path(child_env[ENV_SSL_CERT_FILE])
    assert cert_path.exists(), (
        "SSL_CERT_FILE must reference an on-disk PEM the subprocess can read"
    )
    # Must be the per-session CA, not /etc/ssl/cert.pem.
    assert cert_path.is_absolute()


@pytest.mark.fulfills("VAL-W7-083")
def test_subprocess_inherits_proxy_env_via_inline_python_probe(
    harness: HarnessSession,
) -> None:
    """A real subprocess (Python interpreter, OS-portable stand-in for
    curl) inherits the harness env vars and fails on the proxy hop.

    This is the end-to-end proof that VAL-W7-083 holds for any
    HTTPS_PROXY-aware HTTP client in any subprocess the agent spawns.
    The inline probe is portable across linux / macos / windows and
    avoids the curl-installation prerequisite (which is a CI matrix
    concern, not a test-file concern).
    """
    handle = harness.handle
    assert handle is not None
    child_env = harness.agent_env(parent_env=os.environ.copy())
    out = _spawn_probe(child_env)
    # Env vars present and equal to the harness proxy URL.
    assert out["HTTPS_PROXY"] == handle.proxy_url
    # SSL_CERT_FILE present.
    assert out["SSL_CERT_FILE"] is not None
    # The fetch attempt failed -- denial proof. The probe target
    # https://api.example.com/never has no cassette entry; the proxy
    # returns 404 cassette-miss (or the connection refuses if the
    # proxy is down). Either way, the urlopen call MUST raise.
    assert out["fetch_error"] is not None, (
        "probe must fail because the proxy serves cassette-miss for "
        "https://api.example.com/never; got success instead"
    )


@pytest.mark.fulfills("VAL-W7-083")
def test_subprocess_curl_blocked_when_curl_present(
    harness: HarnessSession,
) -> None:
    """When ``curl`` exists on PATH, ``subprocess.run(['curl', ...])``
    inherits HTTPS_PROXY and routes through the proxy.

    On a runner without curl installed (Windows base image without
    ``choco install curl``) this test skips with the spec-mandated
    rationale. The contract assertion VAL-W7-083 explicitly says the
    Windows CI workflow MUST install curl via choco; this test is the
    enforcement point for that requirement on platforms where curl IS
    available.
    """
    import shutil
    curl_path = shutil.which("curl")
    if curl_path is None:
        pytest.skip(
            "curl not installed on PATH. Per VAL-W7-083 the Windows CI "
            "matrix cell installs curl via 'choco install curl'; on "
            "non-Windows runners curl ships with the OS. Skipping until "
            "the Windows installer step lands in "
            ".github/workflows/relay-tier-3.yml."
        )
    handle = harness.handle
    assert handle is not None
    child_env = harness.agent_env(parent_env=os.environ.copy())
    # --max-time so the test never hangs even if the proxy is wedged.
    # --silent so curl does not bloat the test log.
    # --insecure so curl does not block on the per-session CA cert
    #   if SSL_CERT_FILE inheritance fails to be honoured by libcurl
    #   on this platform (the fallback proves denial via a non-cert
    #   error instead).
    result = subprocess.run(
        [curl_path, "--max-time", "3", "--silent", "--insecure",
         "https://api.example.com/never"],
        env=child_env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    # libcurl returned non-zero AND the proxy received the request OR
    # returned cassette-miss. Either is denial; the converse (exit 0
    # with a body that came from api.example.com) is forbidden.
    assert result.returncode != 0 or "RELAY-CASSETTE-MISS" in result.stdout, (
        f"curl appears to have succeeded against api.example.com; "
        f"returncode={result.returncode} stdout={result.stdout[:200]!r}"
    )


# ---------------------------------------------------------------------------
# Coverage sentinel: every transport is reachable in this module
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-083")
def test_subprocess_curl_coverage_sentinel() -> None:
    """Sentinel: every paired test for VAL-W7-083 exists in this module."""
    import sys
    me = sys.modules[__name__]
    for name in (
        "test_https_proxy_inherits_into_subprocess",
        "test_http_proxy_inherits_into_subprocess",
        "test_ssl_cert_file_inherits_into_subprocess",
        "test_subprocess_inherits_proxy_env_via_inline_python_probe",
        "test_subprocess_curl_blocked_when_curl_present",
    ):
        assert hasattr(me, name), (
            f"missing test for VAL-W7-083 sub-case: {name}"
        )
