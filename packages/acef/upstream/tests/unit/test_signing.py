"""Tests for acef.signing — JWS signing and verification with RS256 and ES256."""

from __future__ import annotations

import json

import pytest

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization

from acef.errors import ACEFSigningError
from acef.signing import (
    _detect_algorithm,
    create_detached_jws,
    verify_detached_jws,
)


@pytest.fixture
def rsa_key_pair():
    """Generate an RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def ec_key_pair():
    """Generate an EC (P-256) key pair for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def rsa_key_pair_alt():
    """Generate a second RSA key pair (for wrong-key tests)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def ec_key_pair_alt():
    """Generate a second EC key pair (for wrong-key tests)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


class TestDetectAlgorithm:
    """Test algorithm detection from key type."""

    def test_rsa_detected(self, rsa_key_pair):
        private_key, _ = rsa_key_pair
        assert _detect_algorithm(private_key) == "RS256"

    def test_ec_detected(self, ec_key_pair):
        private_key, _ = ec_key_pair
        assert _detect_algorithm(private_key) == "ES256"

    def test_unsupported_key_raises(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        ed_key = ed25519.Ed25519PrivateKey.generate()
        with pytest.raises(ACEFSigningError, match="Unsupported key type"):
            _detect_algorithm(ed_key)

    def test_unsupported_key_code(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        ed_key = ed25519.Ed25519PrivateKey.generate()
        with pytest.raises(ACEFSigningError) as exc_info:
            _detect_algorithm(ed_key)
        assert exc_info.value.code == "ACEF-013"


class TestCreateDetachedJWS:
    """Test JWS creation for RS256 and ES256."""

    def test_rs256_produces_valid_jws(self, rsa_key_pair):
        private_key, _ = rsa_key_pair
        payload = b'{"test": "data"}'
        jws = create_detached_jws(payload, private_key)

        parts = jws.split(".")
        assert len(parts) == 3
        # Detached: empty payload section
        assert parts[1] == ""

    def test_es256_produces_valid_jws(self, ec_key_pair):
        private_key, _ = ec_key_pair
        payload = b"test payload"
        jws = create_detached_jws(payload, private_key)

        parts = jws.split(".")
        assert len(parts) == 3
        assert parts[1] == ""

    def test_jws_header_contains_alg(self, rsa_key_pair):
        private_key, _ = rsa_key_pair
        jws = create_detached_jws(b"data", private_key)
        import base64
        header_b64 = jws.split(".")[0]
        header_b64_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64_padded))
        assert header["alg"] == "RS256"

    def test_jws_header_with_kid(self, rsa_key_pair):
        private_key, _ = rsa_key_pair
        jws = create_detached_jws(b"data", private_key, kid="test-key-1")
        import base64
        header_b64 = jws.split(".")[0]
        header_b64_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64_padded))
        assert header["kid"] == "test-key-1"


class TestVerifyDetachedJWS:
    """Test JWS verification."""

    def test_rs256_verify_succeeds(self, rsa_key_pair):
        private_key, public_key = rsa_key_pair
        payload = b'{"content": "hashes"}'
        jws = create_detached_jws(payload, private_key)
        header = verify_detached_jws(jws, payload, public_key)
        assert header["alg"] == "RS256"

    def test_es256_verify_succeeds(self, ec_key_pair):
        private_key, public_key = ec_key_pair
        payload = b"test data"
        jws = create_detached_jws(payload, private_key)
        header = verify_detached_jws(jws, payload, public_key)
        assert header["alg"] == "ES256"

    def test_rs256_wrong_key_fails(self, rsa_key_pair, rsa_key_pair_alt):
        private_key, _ = rsa_key_pair
        _, wrong_public = rsa_key_pair_alt
        payload = b"secure data"
        jws = create_detached_jws(payload, private_key)
        with pytest.raises(ACEFSigningError, match="verification failed"):
            verify_detached_jws(jws, payload, wrong_public)

    def test_es256_wrong_key_fails(self, ec_key_pair, ec_key_pair_alt):
        private_key, _ = ec_key_pair
        _, wrong_public = ec_key_pair_alt
        payload = b"secure data"
        jws = create_detached_jws(payload, private_key)
        with pytest.raises(ACEFSigningError, match="verification failed"):
            verify_detached_jws(jws, payload, wrong_public)

    def test_tampered_payload_fails(self, rsa_key_pair):
        private_key, public_key = rsa_key_pair
        payload = b"original"
        jws = create_detached_jws(payload, private_key)
        with pytest.raises(ACEFSigningError):
            verify_detached_jws(jws, b"tampered", public_key)

    def test_verify_with_key_data(self, rsa_key_pair):
        private_key, public_key = rsa_key_pair
        payload = b"data"
        jws = create_detached_jws(payload, private_key)

        key_data = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        header = verify_detached_jws(jws, payload, key_data=key_data)
        assert header["alg"] == "RS256"


class TestRejectNonAllowedAlgorithms:
    """Test that non-RS256/ES256 algorithms are rejected per ACEF-013."""

    def test_reject_hs256_in_header(self, rsa_key_pair):
        import base64
        # Forge a JWS with HS256 header
        header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(b"fake_sig").rstrip(b"=").decode()
        jws = f"{header}..{sig}"

        _, public_key = rsa_key_pair
        with pytest.raises(ACEFSigningError, match="Unsupported JWS algorithm") as exc_info:
            verify_detached_jws(jws, b"data", public_key)
        assert exc_info.value.code == "ACEF-013"

    def test_reject_none_algorithm(self, rsa_key_pair):
        import base64
        header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
        jws = f"{header}..abc"

        _, public_key = rsa_key_pair
        with pytest.raises(ACEFSigningError, match="Unsupported JWS algorithm"):
            verify_detached_jws(jws, b"data", public_key)

    def test_invalid_jws_format(self, rsa_key_pair):
        _, public_key = rsa_key_pair
        with pytest.raises(ACEFSigningError, match="Invalid JWS format"):
            verify_detached_jws("not.a.valid.jws.with.too.many.parts", b"data", public_key)
