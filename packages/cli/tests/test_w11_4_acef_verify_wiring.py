"""W11.4 CLI wiring: ``rly evidence verify`` routes ACEF bundles to the
Relay-OWNED fail-closed ACEF verifier (VAL-CRYPTO-001/004/005).

These tests prove the Relay-owned ACEF bundle verifier is NOT dead code:
``_cmd_evidence_verify`` detects an ACEF bundle (ACEF Core schema_version
"v0.3" / x-relay namespace shape) and routes it through
``relay_acef.bundle_verifier.verify_acef_bundle`` instead of the
Relay-native ``verify_bundle``.

  * VAL-CRYPTO-001: a tampered ACEF bundle (record mutated, original
    signature retained) exits non-zero via RELAY-EVID-014; a valid
    ACEF bundle exits 0.
  * VAL-CRYPTO-004: an ACEF bundle signed by an attacker key whose jwk is
    embedded in the JWS header, with that kid absent from the trusted
    (cached) JWKS, is rejected.
  * VAL-CRYPTO-005: the verify envelope reports the count of
    cryptographically-VERIFIED signatures and the verified algorithms.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from relay_acef.bundle_verifier import (
    jwk_from_ec_p256_public_key,
    jwk_from_ed25519_public_key,
    sign_acef_bundle_ed25519,
    sign_acef_bundle_es256,
)
from relay_cli.commands.evidence import DEFAULT_TRUST_ANCHOR_URL
from relay_cli.jwks_cache import store_jwks_in_cache
from relay_extensions import (
    ACEF_CORE_SCHEMA_VERSION_PIN,
    RELAY_EXTENSIONS_SCHEMA_VERSION,
    X_RELAY_NAMESPACE_KEY,
)

pytestmark = pytest.mark.plumbing


def _base_acef_bundle() -> dict[str, Any]:
    return {
        "schema_version": ACEF_CORE_SCHEMA_VERSION_PIN,
        "claims": [
            {
                "evidence_claim_id": "claim-001",
                "kind": "contract_gate_result",
                "value": "pass",
            },
        ],
        "namespaces": {
            X_RELAY_NAMESPACE_KEY: {
                "schema_version": RELAY_EXTENSIONS_SCHEMA_VERSION,
                "manifest_commit_hash": "a" * 64,
                "scope_kind": "run",
                "scope_id": "11111111-2222-3333-4444-555555555555",
                "actor_kind": "control_plane",
                "actor_identity_hash": "b" * 64,
                "written_by": "control_plane",
                "redaction_policy_version": "v1.0",
            }
        },
    }


def _write_bundle(home: Path, bundle_id: str, bundle: dict[str, Any]) -> Path:
    target = home / "evidence" / f"{bundle_id}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle), encoding="utf-8")
    return target


def _invoke_verify(bundle_path: Path, home: Path) -> tuple[int, dict[str, Any], str]:
    """Run ``_cmd_evidence_verify`` in-process; return (exit, stdout, stderr)."""
    from relay_cli.commands.evidence import _cmd_evidence_verify

    out_buf = io.StringIO()
    err_buf = io.StringIO()
    exit_code: int = -1
    with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
        try:
            _cmd_evidence_verify(
                bundle_arg=str(bundle_path),
                trust_anchor="",
                home=str(home),
            )
        except SystemExit as exc:
            exit_code = int(exc.code) if exc.code is not None else 0
        except Exception as exc:  # noqa: BLE001 -- typer.Exit -> click Exit
            from click.exceptions import Exit as ClickExit

            assert isinstance(exc, ClickExit), repr(exc)
            exit_code = int(exc.exit_code)
    stdout = out_buf.getvalue()
    parsed = json.loads(stdout) if stdout.strip() else {}
    return exit_code, parsed, err_buf.getvalue()


@pytest.mark.fulfills("VAL-CRYPTO-001")
def test_cli_routes_valid_acef_bundle_and_exits_zero(tmp_path: Path) -> None:
    home = tmp_path / "relay_home"
    home.mkdir()
    priv = ec.generate_private_key(ec.SECP256R1())
    kid = "relay-acef-es"
    store_jwks_in_cache(
        DEFAULT_TRUST_ANCHOR_URL,
        {"keys": [jwk_from_ec_p256_public_key(priv.public_key(), kid=kid)]},
        home=home,
    )
    bundle = _base_acef_bundle()
    bundle["signatures"] = [sign_acef_bundle_es256(bundle, priv, kid=kid)]
    bundle_path = _write_bundle(home, str(uuid.uuid4()), bundle)

    exit_code, out, _ = _invoke_verify(bundle_path, home)
    assert exit_code == 0
    assert out["bundle_kind"] == "acef"
    assert out["digest_ok"] is True
    assert out["signatures_ok"] is True
    assert out["structure_ok"] is True
    assert out["verified_signature_count"] == 1
    assert out["verified_algorithms"] == ["ES256"]


@pytest.mark.fulfills("VAL-CRYPTO-001")
def test_cli_rejects_tampered_acef_bundle(tmp_path: Path) -> None:
    home = tmp_path / "relay_home"
    home.mkdir()
    priv = ed25519.Ed25519PrivateKey.generate()
    kid = "relay-acef-ed"
    store_jwks_in_cache(
        DEFAULT_TRUST_ANCHOR_URL,
        {"keys": [jwk_from_ed25519_public_key(priv.public_key(), kid=kid)]},
        home=home,
    )
    bundle = _base_acef_bundle()
    bundle["signatures"] = [sign_acef_bundle_ed25519(bundle, priv, kid=kid)]
    tampered = copy.deepcopy(bundle)
    tampered["claims"][0]["value"] = "fail"  # mutate after signing
    bundle_path = _write_bundle(home, str(uuid.uuid4()), tampered)

    exit_code, out, err = _invoke_verify(bundle_path, home)
    assert exit_code != 0
    assert out["bundle_kind"] == "acef"
    assert out["signatures_ok"] is False
    assert out["verified_signature_count"] == 0
    err_envelope = json.loads(err.splitlines()[-1])
    assert err_envelope["code"] == "RELAY-EVID-014"


@pytest.mark.fulfills("VAL-CRYPTO-004")
def test_cli_rejects_header_embedded_attacker_key(tmp_path: Path) -> None:
    home = tmp_path / "relay_home"
    home.mkdir()
    # Trusted JWKS holds a legitimate key; the attacker kid is absent.
    legit = ed25519.Ed25519PrivateKey.generate()
    store_jwks_in_cache(
        DEFAULT_TRUST_ANCHOR_URL,
        {"keys": [jwk_from_ed25519_public_key(legit.public_key(), kid="relay-prod")]},
        home=home,
    )
    # Attacker signs with their own key; the signer embeds the attacker
    # public jwk in the JWS header. The kid is NOT in the trusted JWKS.
    attacker = ed25519.Ed25519PrivateKey.generate()
    bundle = _base_acef_bundle()
    bundle["signatures"] = [
        sign_acef_bundle_ed25519(bundle, attacker, kid="attacker-001")
    ]
    bundle_path = _write_bundle(home, str(uuid.uuid4()), bundle)

    exit_code, out, _ = _invoke_verify(bundle_path, home)
    assert exit_code != 0
    assert out["bundle_kind"] == "acef"
    assert out["signatures_ok"] is False
    assert out["verified_signature_count"] == 0
