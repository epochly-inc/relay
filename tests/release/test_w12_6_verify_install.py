"""W12.6 ``rly verify-install`` plumbing tests.

Covers contract assertions VAL-W12-028..034:

  * 028 - Python package signature verification on a clean machine
  * 029 - npm package signature verification on a clean machine
  * 030 - sidecar binary signature verification on a clean machine
  * 031 - composite exit code + structured JSON output
  * 032 - default JWKS at relay.epochly.com per CLAUDE.md keystone #11
  * 033 - offline mode against cached JWKS + cached bundles
  * 034 - structured fail when Sigstore Rekor reachable but artifact NOT
          in log (transparency-log absence)

Per CLAUDE.md TDD discipline: tests use ``@pytest.mark.fulfills`` to
bind to contract assertions. ASCII-only source per CLAUDE.md.

Test seams (avoid network egress):

  * ``RLY_VERIFY_INSTALL_PYTHON_RECORD`` / ``--python-record``
  * ``RLY_VERIFY_INSTALL_NPM_RECORD``    / ``--npm-record``
  * ``RLY_VERIFY_INSTALL_SIDECAR_RECORD``/ ``--sidecar-record``
  * ``RLY_VERIFY_INSTALL_OFFLINE``       / ``--offline``
  * ``--trust-anchor URL``
  * ``RLY_VERIFY_INSTALL_HOME``          / ``--home``  (jwks cache root)
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.plumbing

REPO_ROOT: Path = Path(__file__).resolve().parents[2]

DEFAULT_JWKS_URL = "https://relay.epochly.com/.well-known/jwks.json"
DEFAULT_TRUST_ROOT = "relay.epochly.com"
DEFAULT_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
DEFAULT_OIDC_IDENTITY = (
    "https://github.com/epochly-inc/relay/.github/workflows/release-pypi.yml@refs/heads/main"
)

# Shared xfail reason for the verify-install tests that depend on the
# (now fail-closed) sigstore + Rekor verifiers. See
# packages/cli/tests/test_verifier_crypto_failclosed.py for the
# fail-closed invariants. Re-enable each test once the corresponding
# `*_CRYPTO_IMPLEMENTED` flag is True and the fixture builder produces
# a real Sigstore bundle (Fulcio-signed) with a verifiable Rekor proof.
_SIGSTORE_REKOR_XFAIL_REASON = (
    "verify-install relies on verify_sigstore + _verify_rekor_inclusion, "
    "both of which are fail-closed until real Sigstore cryptographic "
    "verification (sigstore-python) and Rekor inclusion proof "
    "verification are wired. See test_verifier_crypto_failclosed.py "
    "(P0 verifier crypto gap)."
)


# ---------------------------------------------------------------------------
# Invocation helpers (no network; pure subprocess).
# ---------------------------------------------------------------------------


def _run_rly(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess:
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    # Invoke via the installed ``rly`` console script in the active venv.
    # This mirrors how end-users (and the cross-platform-test surface) run
    # the CLI; ``python -m relay_cli`` is not exposed.
    venv_bin = Path(sys.executable).parent
    rly_exe = venv_bin / ("rly.exe" if os.name == "nt" else "rly")
    return subprocess.run(
        [str(rly_exe), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(cwd) if cwd else None,
        env=full_env,
    )


# ---------------------------------------------------------------------------
# Fixture builders.
# ---------------------------------------------------------------------------


def _make_sigstore_bundle_json(
    *,
    trust_root: str = DEFAULT_TRUST_ROOT,
    oidc_issuer: str = DEFAULT_OIDC_ISSUER,
    identity: str = DEFAULT_OIDC_IDENTITY,
    include_tlog: bool = True,
    include_inclusion_proof: bool = True,
) -> str:
    """Build a structurally-valid cosign-bundle JSON for testing."""
    tlog_entries = []
    if include_tlog:
        entry: dict = {
            "logIndex": "1234",
            "integratedTime": "1700000000",
            "logId": {"keyId": "AAA"},
            "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
            "canonicalizedBody": "eyJraW5kIjogImhhc2hlZHJla29yZCJ9",
        }
        if include_inclusion_proof:
            entry["inclusionProof"] = {
                "logIndex": "1234",
                "rootHash": "deadbeef",
                "treeSize": "5000",
                "hashes": ["abc", "def"],
                "checkpoint": {"envelope": "rekor.sigstore.dev - 1234\n"},
            }
        tlog_entries.append(entry)
    return json.dumps(
        {
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "verificationMaterial": {
                "certificate": {"rawBytes": "MIIBxz..."},
                "tlogEntries": tlog_entries,
            },
            "messageSignature": {
                "signature": "MEUCIQ...==",
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": "00",
                },
            },
            "trust_root": trust_root,
            "oidc_issuer": oidc_issuer,
            "identity": identity,
        }
    )


def _write_artifact_and_record(
    base: Path,
    *,
    artifact_name: str,
    kind: str,
    sigstore_kwargs: dict | None = None,
) -> Path:
    """Create a fake installed artifact and an install record pointing at it."""
    sigstore_kwargs = dict(sigstore_kwargs or {})
    artifact_path = base / artifact_name
    artifact_path.write_bytes(b"FAKE-ARTIFACT-PAYLOAD-" + kind.encode("ascii"))
    sig_path = base / (artifact_name + ".sigstore")
    sig_path.write_text(_make_sigstore_bundle_json(**sigstore_kwargs))
    record = {
        "schema_version": "relay.cli.install_record.v1",
        "kind": kind,
        "artifact_path": str(artifact_path),
        "expected_sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
        "sigstore_bundle_path": str(sig_path),
        "oidc_issuer": sigstore_kwargs.get("oidc_issuer", DEFAULT_OIDC_ISSUER),
        "oidc_identity": sigstore_kwargs.get("identity", DEFAULT_OIDC_IDENTITY),
        "trust_root": sigstore_kwargs.get("trust_root", DEFAULT_TRUST_ROOT),
        "package_name": {
            "python": "epochly-relay",
            "npm": "@epochly/relay",
            "sidecar": "@epochly/relay-sidecar-bundle",
        }[kind],
        "version": "0.1.0",
    }
    record_path = base / f"{kind}_record.json"
    record_path.write_text(json.dumps(record))
    return record_path


def _seed_jwks_cache(
    home: Path, *, trust_anchor_url: str = DEFAULT_JWKS_URL
) -> Path:
    """Pre-seed the JWKS cache so --offline runs find a hit."""
    from urllib.parse import urlparse

    host = urlparse(trust_anchor_url).hostname or "relay.epochly.com"
    cache_dir = home / "jwks-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"{host}.json"
    cache_file.write_text(
        json.dumps(
            {
                "schema_version": "relay.cli.jwks_cache.v1",
                "trust_anchor_url": trust_anchor_url,
                "fetched_at": "2026-05-15T00:00:00Z",
                "jwks": {
                    "keys": [
                        {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "kid": "rly-test",
                            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        }
                    ]
                },
            }
        )
    )
    return cache_file


# ---------------------------------------------------------------------------
# VAL-W12-028: Python package verification
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W12-028")
@pytest.mark.xfail(strict=True, reason=_SIGSTORE_REKOR_XFAIL_REASON)
def test_verify_install_python_passes_with_valid_record(tmp_path: Path) -> None:
    record = _write_artifact_and_record(
        tmp_path, artifact_name="epochly_relay-0.1.0.whl", kind="python"
    )
    home = tmp_path / "home"
    home.mkdir()
    _seed_jwks_cache(home)
    result = _run_rly(
        ["verify-install", "--python", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_PYTHON_RECORD": str(record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
        },
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.verify_install.v1"
    assert payload["python_check"]["status"] == "pass"


@pytest.mark.fulfills("VAL-W12-028")
def test_verify_install_python_tamper_yields_release_028(tmp_path: Path) -> None:
    record = _write_artifact_and_record(
        tmp_path, artifact_name="epochly_relay-0.1.0.whl", kind="python"
    )
    # Tamper the installed artifact AFTER recording the expected digest.
    record_data = json.loads(record.read_text())
    Path(record_data["artifact_path"]).write_bytes(b"TAMPERED")
    home = tmp_path / "home"
    home.mkdir()
    _seed_jwks_cache(home)
    result = _run_rly(
        ["verify-install", "--python", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_PYTHON_RECORD": str(record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
        },
    )
    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["python_check"]["status"] == "fail"
    assert payload["python_check"]["error_code"] == "RELAY-RELEASE-028"
    assert "artifact_path" in payload["python_check"].get("detail", {})


# ---------------------------------------------------------------------------
# VAL-W12-029: npm package verification
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W12-029")
@pytest.mark.xfail(strict=True, reason=_SIGSTORE_REKOR_XFAIL_REASON)
def test_verify_install_npm_passes_with_valid_record(tmp_path: Path) -> None:
    record = _write_artifact_and_record(
        tmp_path, artifact_name="epochly-relay-0.1.0.tgz", kind="npm"
    )
    home = tmp_path / "home"
    home.mkdir()
    _seed_jwks_cache(home)
    result = _run_rly(
        ["verify-install", "--npm", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_NPM_RECORD": str(record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
        },
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    payload = json.loads(result.stdout)
    assert payload["npm_check"]["status"] == "pass"


@pytest.mark.fulfills("VAL-W12-029")
def test_verify_install_npm_tamper_yields_release_029(tmp_path: Path) -> None:
    record = _write_artifact_and_record(
        tmp_path, artifact_name="epochly-relay-0.1.0.tgz", kind="npm"
    )
    record_data = json.loads(record.read_text())
    Path(record_data["artifact_path"]).write_bytes(b"TAMPERED")
    home = tmp_path / "home"
    home.mkdir()
    _seed_jwks_cache(home)
    result = _run_rly(
        ["verify-install", "--npm", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_NPM_RECORD": str(record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
        },
    )
    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["npm_check"]["status"] == "fail"
    assert payload["npm_check"]["error_code"] == "RELAY-RELEASE-029"


# ---------------------------------------------------------------------------
# VAL-W12-030: sidecar binary verification
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W12-030")
@pytest.mark.xfail(strict=True, reason=_SIGSTORE_REKOR_XFAIL_REASON)
def test_verify_install_sidecar_passes_with_valid_record(tmp_path: Path) -> None:
    record = _write_artifact_and_record(
        tmp_path,
        artifact_name="relay-sidecar-darwin-arm64-v0.1.0",
        kind="sidecar",
    )
    home = tmp_path / "home"
    home.mkdir()
    _seed_jwks_cache(home)
    result = _run_rly(
        ["verify-install", "--sidecar", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_SIDECAR_RECORD": str(record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
        },
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    payload = json.loads(result.stdout)
    assert payload["sidecar_check"]["status"] == "pass"


@pytest.mark.fulfills("VAL-W12-030")
def test_verify_install_sidecar_tamper_yields_release_030(tmp_path: Path) -> None:
    record = _write_artifact_and_record(
        tmp_path,
        artifact_name="relay-sidecar-darwin-arm64-v0.1.0",
        kind="sidecar",
    )
    record_data = json.loads(record.read_text())
    # Single-byte flip in the binary.
    orig = Path(record_data["artifact_path"]).read_bytes()
    flipped = bytes([orig[0] ^ 0x01]) + orig[1:]
    Path(record_data["artifact_path"]).write_bytes(flipped)
    home = tmp_path / "home"
    home.mkdir()
    _seed_jwks_cache(home)
    result = _run_rly(
        ["verify-install", "--sidecar", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_SIDECAR_RECORD": str(record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
        },
    )
    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["sidecar_check"]["status"] == "fail"
    assert payload["sidecar_check"]["error_code"] == "RELAY-RELEASE-030"
    # Digest-check happens BEFORE Sigstore (per spec orchestrator pin).
    assert (
        payload["sidecar_check"].get("detail", {}).get("reason")
        == "digest_mismatch"
    )


# ---------------------------------------------------------------------------
# VAL-W12-031: composite exit code + structured JSON
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W12-031")
@pytest.mark.xfail(strict=True, reason=_SIGSTORE_REKOR_XFAIL_REASON)
def test_verify_install_no_flags_runs_all_three_checks(tmp_path: Path) -> None:
    py_record = _write_artifact_and_record(
        tmp_path, artifact_name="epochly_relay-0.1.0.whl", kind="python"
    )
    npm_record = _write_artifact_and_record(
        tmp_path, artifact_name="epochly-relay-0.1.0.tgz", kind="npm"
    )
    sidecar_record = _write_artifact_and_record(
        tmp_path,
        artifact_name="relay-sidecar-darwin-arm64-v0.1.0",
        kind="sidecar",
    )
    home = tmp_path / "home"
    home.mkdir()
    _seed_jwks_cache(home)
    result = _run_rly(
        ["verify-install", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_PYTHON_RECORD": str(py_record),
            "RLY_VERIFY_INSTALL_NPM_RECORD": str(npm_record),
            "RLY_VERIFY_INSTALL_SIDECAR_RECORD": str(sidecar_record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
        },
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    payload = json.loads(result.stdout)
    # All three keys required.
    for key in ("python_check", "npm_check", "sidecar_check"):
        assert key in payload, f"missing key {key!r}: {payload!r}"
        assert payload[key]["status"] == "pass"
    assert payload["overall_status"] == "pass"


@pytest.mark.fulfills("VAL-W12-031")
@pytest.mark.xfail(strict=True, reason=_SIGSTORE_REKOR_XFAIL_REASON)
def test_verify_install_composite_fail_returns_nonzero(tmp_path: Path) -> None:
    py_record = _write_artifact_and_record(
        tmp_path, artifact_name="epochly_relay-0.1.0.whl", kind="python"
    )
    npm_record = _write_artifact_and_record(
        tmp_path, artifact_name="epochly-relay-0.1.0.tgz", kind="npm"
    )
    sidecar_record = _write_artifact_and_record(
        tmp_path,
        artifact_name="relay-sidecar-darwin-arm64-v0.1.0",
        kind="sidecar",
    )
    # Tamper one of three.
    record_data = json.loads(py_record.read_text())
    Path(record_data["artifact_path"]).write_bytes(b"TAMPERED")
    home = tmp_path / "home"
    home.mkdir()
    _seed_jwks_cache(home)
    result = _run_rly(
        ["verify-install", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_PYTHON_RECORD": str(py_record),
            "RLY_VERIFY_INSTALL_NPM_RECORD": str(npm_record),
            "RLY_VERIFY_INSTALL_SIDECAR_RECORD": str(sidecar_record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
        },
    )
    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["python_check"]["status"] == "fail"
    assert payload["npm_check"]["status"] == "pass"
    assert payload["sidecar_check"]["status"] == "pass"
    assert payload["overall_status"] == "fail"


@pytest.mark.fulfills("VAL-W12-031")
def test_verify_install_output_is_rfc8259_json(tmp_path: Path) -> None:
    py_record = _write_artifact_and_record(
        tmp_path, artifact_name="epochly_relay-0.1.0.whl", kind="python"
    )
    home = tmp_path / "home"
    home.mkdir()
    _seed_jwks_cache(home)
    result = _run_rly(
        ["verify-install", "--python", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_PYTHON_RECORD": str(py_record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
        },
    )
    # Must parse without error (machine-parseable JSON).
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)


# ---------------------------------------------------------------------------
# VAL-W12-032: default trust anchor JWKS URL
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W12-032")
def test_verify_install_prints_default_trust_anchor() -> None:
    result = _run_rly(["verify-install", "--print-trust-anchor"])
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    assert result.stdout.strip() == DEFAULT_JWKS_URL


@pytest.mark.fulfills("VAL-W12-032")
def test_verify_install_default_jwks_constant_grep() -> None:
    """Exactly one occurrence of the literal in the verify_install module."""
    src = (
        REPO_ROOT
        / "packages/cli/src/relay_cli/commands/verify_install.py"
    ).read_text()
    occurrences = src.count(DEFAULT_JWKS_URL)
    # The verify_install module re-uses the canonical constant from the
    # verifier package; the literal should appear ZERO times in this
    # module (it lives in relay_verifier.constants). The print-trust-anchor
    # command imports the constant and prints it.
    assert occurrences == 0, (
        f"verify_install.py contains {occurrences} occurrences of the "
        f"default JWKS literal; expected 0 (must import from "
        f"relay_verifier.constants)"
    )


# ---------------------------------------------------------------------------
# VAL-W12-033: offline mode against cached JWKS + cached bundles
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W12-033")
@pytest.mark.xfail(strict=True, reason=_SIGSTORE_REKOR_XFAIL_REASON)
def test_verify_install_offline_succeeds_with_cache(tmp_path: Path) -> None:
    record = _write_artifact_and_record(
        tmp_path, artifact_name="epochly_relay-0.1.0.whl", kind="python"
    )
    home = tmp_path / "home"
    home.mkdir()
    _seed_jwks_cache(home)
    result = _run_rly(
        ["verify-install", "--python", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_PYTHON_RECORD": str(record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
            # Force-block egress: any HTTP attempt would fail because no
            # fetcher is wired in this test. Offline mode MUST NOT attempt
            # any HTTP call when the cache is populated.
            "RLY_VERIFY_INSTALL_BLOCK_NETWORK": "1",
        },
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    payload = json.loads(result.stdout)
    assert payload["python_check"]["status"] == "pass"
    assert payload.get("offline_mode") is True


@pytest.mark.fulfills("VAL-W12-033")
def test_verify_install_offline_fails_when_cache_absent(tmp_path: Path) -> None:
    record = _write_artifact_and_record(
        tmp_path, artifact_name="epochly_relay-0.1.0.whl", kind="python"
    )
    home = tmp_path / "home"
    home.mkdir()
    # NO _seed_jwks_cache call.
    result = _run_rly(
        ["verify-install", "--python", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_PYTHON_RECORD": str(record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
            "RLY_VERIFY_INSTALL_BLOCK_NETWORK": "1",
        },
    )
    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["python_check"]["status"] == "fail"
    assert payload["python_check"]["error_code"] == "RELAY-RELEASE-033"


@pytest.mark.fulfills("VAL-W12-033")
def test_verify_install_help_documents_cache_path() -> None:
    result = _run_rly(["verify-install", "--help"])
    # Help must document the cache path so auditors know where to inspect.
    assert "jwks-cache" in result.stdout or "JWKS" in result.stdout


@pytest.mark.fulfills("VAL-W12-032")
def test_verify_install_online_fails_when_no_jwks_resolvable(
    tmp_path: Path,
) -> None:
    """Online mode (no --offline) with no cached JWKS and network blocked
    MUST fail-closed with RELAY-VERIFY-JWKS-UNAVAILABLE, not silently
    skip the JWKS check.

    Regression: prior implementation returned (None, None) from
    _resolve_jwks on online cache miss without ENV_BLOCK_NETWORK set,
    which let the verify pass with no trust anchor anchored to the
    bundle signature path.
    """
    record = _write_artifact_and_record(
        tmp_path, artifact_name="epochly_relay-0.1.0.whl", kind="python"
    )
    home = tmp_path / "home"
    home.mkdir()
    # NO _seed_jwks_cache call -- cache is empty.
    result = _run_rly(
        ["verify-install", "--python", "--json"],  # NO --offline
        env={
            "RLY_VERIFY_INSTALL_PYTHON_RECORD": str(record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
            # Force-block the network so the would-be fetch fails; cache
            # is empty; check MUST fail-closed.
            "RLY_VERIFY_INSTALL_BLOCK_NETWORK": "1",
        },
    )
    assert result.returncode != 0, (
        "online verify-install with no cache + blocked network must fail; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    payload = json.loads(result.stdout)
    assert payload["overall_status"] == "fail"
    assert payload["python_check"]["status"] == "fail"
    assert payload["python_check"]["error_code"] == "RELAY-VERIFY-JWKS-UNAVAILABLE"
    detail = payload["python_check"].get("detail", {})
    assert "JWKS" in detail.get("message", "") or "jwks" in detail.get(
        "reason", ""
    )


# ---------------------------------------------------------------------------
# VAL-W12-034: Rekor reachable but artifact NOT in log -> RELAY-RELEASE-034
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W12-034")
@pytest.mark.xfail(
    strict=True,
    reason=(
        "_verify_rekor_inclusion is fail-closed; every input (including "
        "fork-style bundles with omitted tlog entries) returns reason "
        "'rekor_crypto_not_implemented' rather than the 'transparency log' "
        "substring this test asserts. The error_code RELAY-RELEASE-034 is "
        "still emitted correctly, but the human-readable reason changed. "
        "See test_verifier_crypto_failclosed.py (P0 verifier crypto gap)."
    ),
)
def test_verify_install_no_rekor_inclusion_proof_yields_release_034(
    tmp_path: Path,
) -> None:
    # Fork-style bundle: tlog entries omitted entirely (no Rekor entry).
    record = _write_artifact_and_record(
        tmp_path,
        artifact_name="epochly_relay-0.1.0.whl",
        kind="python",
        sigstore_kwargs={"include_tlog": False},
    )
    home = tmp_path / "home"
    home.mkdir()
    _seed_jwks_cache(home)
    result = _run_rly(
        ["verify-install", "--python", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_PYTHON_RECORD": str(record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
        },
    )
    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["python_check"]["status"] == "fail"
    assert payload["python_check"]["error_code"] == "RELAY-RELEASE-034"
    assert "transparency log" in payload["python_check"]["detail"]["reason"]


@pytest.mark.fulfills("VAL-W12-034")
def test_verify_install_missing_inclusion_proof_yields_release_034(
    tmp_path: Path,
) -> None:
    # tlog entries present but missing inclusionProof -> transparency-log
    # absence per spec section AO.1.
    record = _write_artifact_and_record(
        tmp_path,
        artifact_name="epochly_relay-0.1.0.whl",
        kind="python",
        sigstore_kwargs={"include_tlog": True, "include_inclusion_proof": False},
    )
    home = tmp_path / "home"
    home.mkdir()
    _seed_jwks_cache(home)
    result = _run_rly(
        ["verify-install", "--python", "--offline", "--json"],
        env={
            "RLY_VERIFY_INSTALL_PYTHON_RECORD": str(record),
            "RLY_VERIFY_INSTALL_HOME": str(home),
        },
    )
    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["python_check"]["error_code"] == "RELAY-RELEASE-034"


# ---------------------------------------------------------------------------
# Sanity: --help renders and command is wired into rly tree.
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W12-031")
def test_verify_install_help_exits_zero() -> None:
    result = _run_rly(["verify-install", "--help"])
    assert result.returncode == 0
    assert "verify-install" in result.stdout
