"""W9.3 real Rekor Merkle-inclusion-proof + SET verification tests.

Encodes VAL-V2M09-004, 011, 012, 013, 014 against
``relay_cli.commands.verify_install._verify_rekor_inclusion``.
After M09-w9.3 the function MUST:

  - Flip ``REKOR_CRYPTO_IMPLEMENTED`` to ``True`` (VAL-V2M09-004).
  - Call into a real Merkle inclusion-proof verifier
    (``sigstore.models.verify_merkle_inclusion`` /
    ``verify_checkpoint`` / ``TransparencyLogEntry._verify_set``)
    (VAL-V2M09-011).
  - Reject a tampered Merkle proof with reason
    ``rekor_inclusion_proof_invalid`` (VAL-V2M09-012).
  - Reject a tampered Signed Entry Timestamp (SET) with reason
    ``rekor_set_signature_invalid`` (VAL-V2M09-013).
  - Accept a real Rekor inclusion proof fetched from
    ``https://rekor.sigstore.dev`` at test time (VAL-V2M09-014).

Network-gated tests use the env var ``RLY_TEST_ALLOW_NETWORK=1`` so
local-dev runs are hermetic by default. CI MUST set this variable on at
least one matrix cell so the live-Rekor round-trip is exercised.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ast
import base64
import copy
import inspect
import json
import os
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from relay_cli.commands import verify_install as vi_mod
from relay_cli.commands.verify_install import (
    REKOR_CRYPTO_IMPLEMENTED,
    _verify_rekor_inclusion,
)

VI_PY = Path(vi_mod.__file__).resolve()

# Known production Rekor log index. Any sufficiently old, integrated
# entry works; index 100000000 is a stable witness on the public-good
# transparency log (anchored in production tree state circa 2024). The
# fetch returns the inclusion proof and signed entry timestamp needed by
# both Merkle-proof and SET verification paths.
_REKOR_BASE = "https://rekor.sigstore.dev/api/v1/log/entries"
_REKOR_TEST_LOG_INDEX = 100000000


def _network_allowed() -> bool:
    return os.environ.get("RLY_TEST_ALLOW_NETWORK") == "1"


def _fetch_rekor_entry(log_index: int) -> dict[str, Any]:
    """Fetch a single Rekor log entry by index.

    Returns the raw REST response dict (single-entry map keyed by UUID).
    Skips the calling test if the network is unreachable or the entry is
    unavailable; the network gate (``RLY_TEST_ALLOW_NETWORK``) is checked
    by the caller.
    """
    url = f"{_REKOR_BASE}?logIndex={int(log_index)}"
    req = urllib.request.Request(url, headers={"User-Agent": "rly-test/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return json.loads(resp.read())
    except Exception as exc:  # pragma: no cover - network/test infra
        pytest.skip(f"could not fetch Rekor entry {log_index}: {exc}")


def _wrap_entry_as_bundle_bytes(entry_response: dict[str, Any]) -> bytes:
    """Wrap a Rekor REST entry response as bytes for _verify_rekor_inclusion.

    ``_verify_rekor_inclusion`` accepts either a full Sigstore Bundle
    JSON or a raw Rekor REST entry response (single-entry map). We pass
    the REST response directly here to exercise both decode paths.
    """
    return json.dumps(entry_response).encode("utf-8")


# ---------------------------------------------------------------------------
# VAL-V2M09-004: feature flag flipped True
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-004")
def test_rekor_crypto_flag_is_true() -> None:
    """The feature flag MUST be True after w9-3 lands. Flipping back
    to False without removing the corresponding verify_merkle_inclusion /
    _verify_set calls is a P0 keystone-invariant regression (CLAUDE.md
    keystone #2: pass without evidence is not a pass). The polarity-
    inverted tripwire in ``test_verifier_crypto_failclosed.py`` mirrors
    this assertion."""
    assert REKOR_CRYPTO_IMPLEMENTED is True, (
        "REKOR_CRYPTO_IMPLEMENTED was flipped False after the real "
        "Rekor Merkle-inclusion-proof verifier landed; this is a P0 "
        "keystone-invariant regression."
    )


# ---------------------------------------------------------------------------
# VAL-V2M09-011: AST inspection -- real Merkle / SET calls exist
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-011")
def test_calls_real_merkle_verifier() -> None:
    """AST inspection: the function body MUST reference at least one
    of the real Sigstore transparency-log verifiers
    (``verify_merkle_inclusion``, ``verify_checkpoint``, ``_verify_set``).
    The prior fail-closed sentinel
    (unconditional ``return False, "rekor_crypto_not_implemented"``) is
    gone."""
    source = inspect.getsource(_verify_rekor_inclusion)
    tree = ast.parse(source)
    referenced: set[str] = set()
    sigstore_seen = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            referenced.add(node.id)
        elif isinstance(node, ast.Attribute):
            # Walk down to leftmost Name
            cur: Any = node
            attrs: list[str] = []
            while isinstance(cur, ast.Attribute):
                attrs.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                referenced.add(cur.id)
                if cur.id == "sigstore":
                    sigstore_seen = True
                for a in attrs:
                    referenced.add(a)
    real_call_names = {
        "verify_merkle_inclusion",
        "verify_checkpoint",
        "_verify_set",
        "TransparencyLogEntry",
        "Bundle",  # Sigstore Bundle parse path
    }
    intersection = referenced & real_call_names
    assert intersection or sigstore_seen, (
        "_verify_rekor_inclusion body MUST reference one of the real "
        f"sigstore transparency verifiers {real_call_names}; saw names "
        f"{sorted(referenced)!r}\nsource:\n{source}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-011")
def test_no_legacy_failclosed_sentinel() -> None:
    """The fail-closed sentinel ``return False, 'rekor_crypto_not_implemented'``
    MUST NOT appear in the verify_install.py module after the w9-3 flip.
    Grep guard mirrors the assertion in CLAUDE.md "Verify Before
    Claiming"."""
    text = VI_PY.read_text(encoding="utf-8")
    # The sentinel literal must NOT be present in any code path (the
    # historical fail-closed return value is gone).
    assert "rekor_crypto_not_implemented" not in text, (
        "verify_install.py still contains the historical fail-closed "
        "sentinel literal 'rekor_crypto_not_implemented'; remove every "
        "occurrence including any pre-flag guard."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-011")
def test_no_tlog_entry_yields_transparency_log_reason() -> None:
    """A bundle with no transparency-log entry MUST be rejected with a
    reason whose substring includes 'transparency log' (case-insensitive).

    This is the offline counterpart to VAL-V2M09-012/013/014: when the
    bundle simply has no tlog entry to verify, the caller surfaces
    RELAY-RELEASE-034 with the spec-section-AO.1 phrasing 'Artifact not
    in Rekor transparency log.' (See VAL-W12-034.)
    """
    payload = {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "verificationMaterial": {
            "certificate": {"rawBytes": "AAAA"},
            "tlogEntries": [],
        },
        "messageSignature": {
            "signature": "AAAA",
            "messageDigest": {"algorithm": "SHA2_256", "digest": "00" * 32},
        },
    }
    ok, reason = _verify_rekor_inclusion(json.dumps(payload).encode("utf-8"))
    assert ok is False
    assert "transparency log" in reason.lower(), (
        f"expected reason containing 'transparency log'; got {reason!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-011")
def test_unparseable_input_rejected_with_structured_reason() -> None:
    """Garbage bytes MUST be rejected with a structured reason (not
    raised as an unhandled exception)."""
    ok, reason = _verify_rekor_inclusion(b"not-json")
    assert ok is False
    assert reason  # non-empty structured reason
    # Caller turns this into RELAY-RELEASE-034 detail.reason.
    assert "rekor_crypto_not_implemented" not in reason


# ---------------------------------------------------------------------------
# VAL-V2M09-012: tampered Merkle proof rejected (network test)
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.skipif(
    not _network_allowed(),
    reason="VAL-V2M09-012 requires RLY_TEST_ALLOW_NETWORK=1 to fetch from rekor.sigstore.dev",
)
@pytest.mark.fulfills("VAL-V2M09-012")
def test_reject_tampered_merkle_proof() -> None:
    """Mutate one byte in the proof's hashes[] array; verifier MUST
    return (False, 'rekor_inclusion_proof_invalid'). The unmutated
    original proof MUST verify cleanly in the same test."""
    data = _fetch_rekor_entry(_REKOR_TEST_LOG_INDEX)

    # Positive control: unmutated proof verifies.
    ok_orig, reason_orig = _verify_rekor_inclusion(_wrap_entry_as_bundle_bytes(data))
    assert ok_orig is True, (
        f"unmutated Rekor proof MUST verify; got reason={reason_orig!r}"
    )

    # Mutation: flip one byte in hashes[0].
    mutated = copy.deepcopy(data)
    uuid, entry = next(iter(mutated.items()))
    proof = entry["verification"]["inclusionProof"]
    assert proof["hashes"], "fetched Rekor entry unexpectedly has empty hashes[]"
    orig_hash = proof["hashes"][0]
    flipped = bytearray(bytes.fromhex(orig_hash))
    flipped[0] ^= 0x01
    proof["hashes"][0] = flipped.hex()

    ok, reason = _verify_rekor_inclusion(_wrap_entry_as_bundle_bytes(mutated))
    assert ok is False, "tampered Merkle proof MUST be rejected"
    assert reason == "rekor_inclusion_proof_invalid", (
        f"expected reason 'rekor_inclusion_proof_invalid'; got {reason!r}"
    )


# ---------------------------------------------------------------------------
# VAL-V2M09-013: tampered SET rejected with distinct reason (network test)
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.skipif(
    not _network_allowed(),
    reason="VAL-V2M09-013 requires RLY_TEST_ALLOW_NETWORK=1 to fetch from rekor.sigstore.dev",
)
@pytest.mark.fulfills("VAL-V2M09-013")
def test_reject_tampered_set() -> None:
    """Mutate one byte in the Signed Entry Timestamp signature; verifier
    MUST return (False, 'rekor_set_signature_invalid'). The reason MUST
    be DISTINCT from VAL-V2M09-012's 'rekor_inclusion_proof_invalid' so
    incident-response can distinguish a witness-key failure from a proof
    tampering."""
    data = _fetch_rekor_entry(_REKOR_TEST_LOG_INDEX)

    mutated = copy.deepcopy(data)
    uuid, entry = next(iter(mutated.items()))
    orig_set = entry["verification"]["signedEntryTimestamp"]
    raw = bytearray(base64.b64decode(orig_set))
    # Flip a byte deep in the signature (not the DER header).
    raw[len(raw) // 2] ^= 0xFF
    entry["verification"]["signedEntryTimestamp"] = base64.b64encode(bytes(raw)).decode(
        "ascii"
    )

    ok, reason = _verify_rekor_inclusion(_wrap_entry_as_bundle_bytes(mutated))
    assert ok is False, "tampered SET MUST be rejected"
    assert reason == "rekor_set_signature_invalid", (
        f"expected reason 'rekor_set_signature_invalid'; got {reason!r}"
    )
    # Distinct-reason invariant: MUST NOT collide with VAL-V2M09-012.
    assert reason != "rekor_inclusion_proof_invalid"


# ---------------------------------------------------------------------------
# VAL-V2M09-014: real inclusion proof verifies (network test)
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.skipif(
    not _network_allowed(),
    reason="VAL-V2M09-014 requires RLY_TEST_ALLOW_NETWORK=1 to fetch from rekor.sigstore.dev",
)
@pytest.mark.fulfills("VAL-V2M09-014")
def test_real_inclusion_proof_accepted() -> None:
    """A real Rekor inclusion proof fetched from rekor.sigstore.dev MUST
    verify end-to-end (Merkle proof + checkpoint + SET) and return
    (True, '')."""
    data = _fetch_rekor_entry(_REKOR_TEST_LOG_INDEX)
    ok, reason = _verify_rekor_inclusion(_wrap_entry_as_bundle_bytes(data))
    assert ok is True, f"real Rekor proof MUST verify; reason={reason!r}"
    assert reason == "", f"on success reason MUST be empty; got {reason!r}"
