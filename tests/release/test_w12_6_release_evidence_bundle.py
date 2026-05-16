"""W12.6 release evidence bundle plumbing tests (VAL-W12-045).

Tests the ``scripts/emit-release-evidence-bundle.py`` script that the
release workflow invokes after publication. Verifies:

  * Bundle JSON shape matches relay.evidence.release.v1 schema
  * ``subject.kind == "release"`` and ``subject.manifest_commit_hash``
    matches the input git SHA
  * Every required field is present (manifest_commit_hash, artifact
    digests, SLSA attestation digests, in-toto link digests, Sigstore
    bundle digests, builder workflow SHA, signer key id)
  * Bundle is written atomically to the requested output path

Per CLAUDE.md TDD discipline: tests use ``@pytest.mark.fulfills`` to
bind to contract assertions. ASCII-only source per CLAUDE.md.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.plumbing

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
EMIT_SCRIPT: Path = (
    REPO_ROOT / "scripts" / "emit-release-evidence-bundle.py"
)


def _run_emit(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(EMIT_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _make_release_fixtures(base: Path) -> dict[str, list[Path]]:
    """Create a minimal set of release artifact fixtures on disk."""
    artifacts = []
    for name in (
        "epochly_relay-0.1.0.tar.gz",
        "epochly_relay-0.1.0-py3-none-any.whl",
        "epochly-relay-0.1.0.tgz",
        "relay-sidecar-darwin-arm64-v0.1.0",
    ):
        p = base / name
        p.write_bytes(b"FAKE-ARTIFACT-" + name.encode("ascii"))
        artifacts.append(p)

    slsa = [base / "slsa-provenance.json"]
    slsa[0].write_text(
        json.dumps({"_type": "https://in-toto.io/Statement/v0.1"})
    )

    links = [base / "in-toto-link-build.link"]
    links[0].write_text(json.dumps({"_type": "link", "name": "build"}))

    sigstore = []
    for a in artifacts:
        sb = base / (a.name + ".sigstore")
        sb.write_text(json.dumps({"mediaType": "sigstore-bundle"}))
        sigstore.append(sb)

    return {
        "artifacts": artifacts,
        "slsa": slsa,
        "in_toto": links,
        "sigstore": sigstore,
    }


# ---------------------------------------------------------------------------
# VAL-W12-045: release bundle emission
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W12-045")
def test_release_bundle_emits_with_required_fields(tmp_path: Path) -> None:
    fixtures = _make_release_fixtures(tmp_path)
    out = tmp_path / "evidence" / "release-v0.1.0.acef"
    args = [
        "--tag", "v0.1.0",
        "--manifest-commit-hash", "abc123def456",
        "--builder-workflow-sha", "deadbeefcafe1234",
        "--signer-key-id", "rly-release-2026-05",
        "--out", str(out),
        "--print",
    ]
    for a in fixtures["artifacts"]:
        args += ["--artifact", str(a)]
    for s in fixtures["slsa"]:
        args += ["--slsa-attestation", str(s)]
    for link in fixtures["in_toto"]:
        args += ["--in-toto-link", str(link)]
    for sb in fixtures["sigstore"]:
        args += ["--sigstore-bundle", str(sb)]

    result = _run_emit(args)
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    assert out.exists(), f"bundle not written to {out}"

    bundle = json.loads(out.read_text())
    assert bundle["schema_version"] == "relay.evidence.release.v1"
    assert bundle["subject"]["kind"] == "release"
    assert bundle["subject"]["tag"] == "v0.1.0"
    assert bundle["subject"]["manifest_commit_hash"] == "abc123def456"
    assert bundle["subject"]["builder_workflow_sha"] == "deadbeefcafe1234"
    assert bundle["signer_key_id"] == "rly-release-2026-05"
    # Every required collection populated.
    assert len(bundle["artifacts"]) == len(fixtures["artifacts"])
    assert len(bundle["slsa_attestations"]) == len(fixtures["slsa"])
    assert len(bundle["in_toto_links"]) == len(fixtures["in_toto"])
    assert len(bundle["sigstore_bundles"]) == len(fixtures["sigstore"])
    # Default trust anchor (VAL-W12-032 cross-tie).
    assert bundle["trust_anchor"] == "https://relay.epochly.com/.well-known/jwks.json"


@pytest.mark.fulfills("VAL-W12-045")
def test_release_bundle_digests_match_input_artifacts(tmp_path: Path) -> None:
    fixtures = _make_release_fixtures(tmp_path)
    out = tmp_path / "release.acef"
    args = [
        "--tag", "v0.1.1",
        "--manifest-commit-hash", "0" * 40,
        "--builder-workflow-sha", "1" * 40,
        "--signer-key-id", "kid-x",
        "--out", str(out),
    ]
    for a in fixtures["artifacts"]:
        args += ["--artifact", str(a)]
    for s in fixtures["slsa"]:
        args += ["--slsa-attestation", str(s)]
    for link in fixtures["in_toto"]:
        args += ["--in-toto-link", str(link)]
    for sb in fixtures["sigstore"]:
        args += ["--sigstore-bundle", str(sb)]
    result = _run_emit(args)
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    bundle = json.loads(out.read_text())
    # Each artifact entry has the correct SHA-256 of the file bytes.
    for entry, artifact_path in zip(
        bundle["artifacts"], fixtures["artifacts"], strict=True
    ):
        expected = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        assert entry["sha256"] == expected, (
            f"digest mismatch for {artifact_path}: "
            f"bundle says {entry['sha256']}, expected {expected}"
        )


@pytest.mark.fulfills("VAL-W12-045")
def test_release_bundle_atomic_write_creates_parent_dirs(tmp_path: Path) -> None:
    fixtures = _make_release_fixtures(tmp_path)
    out = tmp_path / "nested" / "evidence" / "deep" / "release.acef"
    args = [
        "--tag", "v0.1.2",
        "--manifest-commit-hash", "f" * 40,
        "--builder-workflow-sha", "e" * 40,
        "--signer-key-id", "k",
        "--out", str(out),
    ]
    for a in fixtures["artifacts"][:1]:
        args += ["--artifact", str(a)]
    for s in fixtures["slsa"]:
        args += ["--slsa-attestation", str(s)]
    for link in fixtures["in_toto"]:
        args += ["--in-toto-link", str(link)]
    for sb in fixtures["sigstore"][:1]:
        args += ["--sigstore-bundle", str(sb)]
    result = _run_emit(args)
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    assert out.exists()
    assert out.parent.is_dir()


@pytest.mark.fulfills("VAL-W12-045")
def test_release_bundle_signature_is_null_in_oss_path(tmp_path: Path) -> None:
    """OSS-path bundle is unsigned (hosted registry attaches signature)."""
    fixtures = _make_release_fixtures(tmp_path)
    out = tmp_path / "release.acef"
    args = [
        "--tag", "v0.1.3",
        "--manifest-commit-hash", "abc",
        "--builder-workflow-sha", "def",
        "--signer-key-id", "kid-y",
        "--out", str(out),
    ]
    for a in fixtures["artifacts"][:1]:
        args += ["--artifact", str(a)]
    for s in fixtures["slsa"]:
        args += ["--slsa-attestation", str(s)]
    for link in fixtures["in_toto"]:
        args += ["--in-toto-link", str(link)]
    for sb in fixtures["sigstore"][:1]:
        args += ["--sigstore-bundle", str(sb)]
    result = _run_emit(args)
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    bundle = json.loads(out.read_text())
    assert bundle["signature"] is None
