#!/usr/bin/env python3
"""Emit a Relay-format release evidence bundle (VAL-W12-045).

Per spec section K (every release is an evidence subject) and contract
assertion VAL-W12-045, the release pipeline MUST emit a Relay-format
evidence bundle (kind ``release``) binding the published artifacts to:

  * ``manifest_commit_hash`` -- the git commit SHA the release was cut
    from (RFC 8785 JCS over the manifest is out of scope here; the
    release evidence binds to the source git SHA per the contract).
  * artifact digests -- SHA-256 of every published artifact (sdist,
    wheel, npm tarball, sidecar binaries per OS/arch).
  * SLSA attestation digests -- SHA-256 of the SLSA L3 provenance JSON.
  * in-toto link digests -- SHA-256 of every in-toto link document.
  * Sigstore bundle digests -- SHA-256 of each ``*.sigstore`` bundle.
  * builder workflow SHA -- the workflow ref + commit of the runner.
  * signer key id -- the kid that signed the release bundle itself.

The bundle is written to ``${RELAY_HOME}/evidence/release-<tag>.acef``
on the OSS path. When the hosted evidence registry is available the
release workflow ALSO POSTs the same bundle to the registry endpoint;
that step is implemented in ``relay-platform/`` and is out of scope for
this OSS script.

Bundle JSON shape (relay.evidence.release.v1):

    {
      "schema_version": "relay.evidence.release.v1",
      "evidence_bundle_id": "<uuid>",
      "subject": {
        "kind": "release",
        "tag": "<v0.1.0>",
        "manifest_commit_hash": "<sha>",
        "builder_workflow_sha": "<sha>"
      },
      "artifacts": [
        {"path": "<rel-or-abs>", "sha256": "<hex>", "kind": "<...>"}, ...
      ],
      "slsa_attestations": [{"path": "...", "sha256": "..."}, ...],
      "in_toto_links":     [{"path": "...", "sha256": "..."}, ...],
      "sigstore_bundles":  [{"path": "...", "sha256": "..."}, ...],
      "signer_key_id": "<kid>",
      "trust_anchor": "<jwks url>",
      "created_at": "<RFC3339-Z>",
      "signature": { "alg": "EdDSA", ... } | null
    }

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Final

# Default trust anchor: imported from the verifier package so the script
# has ZERO copies of the literal URL. VAL-W12-032 grep guard depends on
# this. The verifier package's constants module is the canonical site.
sys.path.insert(
    0,
    str(
        Path(__file__).resolve().parent.parent
        / "packages"
        / "verifier"
        / "src"
    ),
)
from relay_verifier.constants import DEFAULT_JWKS_URL  # noqa: E402

RELEASE_BUNDLE_SCHEMA: Final[str] = "relay.evidence.release.v1"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_hex(path.read_bytes())


def _utc_iso_z() -> str:
    return (
        _dt.datetime.now(_dt.UTC)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _digest_entries(paths: list[Path], kind: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for p in paths:
        if not p.exists():
            raise FileNotFoundError(f"artifact for digest not found: {p}")
        out.append({"path": str(p), "sha256": _sha256_file(p), "kind": kind})
    return out


def build_release_bundle(
    *,
    tag: str,
    manifest_commit_hash: str,
    builder_workflow_sha: str,
    artifacts: list[Path],
    slsa_attestations: list[Path],
    in_toto_links: list[Path],
    sigstore_bundles: list[Path],
    signer_key_id: str,
    trust_anchor: str = DEFAULT_JWKS_URL,
    evidence_bundle_id: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build the canonical release evidence bundle payload (unsigned).

    Returns a dict ready for ``json.dumps``. The ``signature`` field is
    ``None`` for the OSS path; a hosted release workflow attaches an
    EdDSA signature against the canonical-JSON bytes before pushing to
    the evidence registry.
    """
    bundle_id = evidence_bundle_id or str(uuid.uuid4())
    when = created_at or _utc_iso_z()

    artifact_entries = _digest_entries(artifacts, "release_artifact")
    # Override the generic kind for items whose suffix tells us more.
    for entry in artifact_entries:
        suffix = Path(entry["path"]).suffix.lower()
        if suffix in (".whl",):
            entry["kind"] = "python_wheel"
        elif suffix in (".gz", ".tgz"):
            entry["kind"] = (
                "python_sdist"
                if "tar.gz" in entry["path"].lower()
                else "npm_tarball"
            )
        elif Path(entry["path"]).name.startswith("relay-sidecar-"):
            entry["kind"] = "sidecar_binary"

    return {
        "schema_version": RELEASE_BUNDLE_SCHEMA,
        "evidence_bundle_id": bundle_id,
        "subject": {
            "kind": "release",
            "tag": tag,
            "manifest_commit_hash": manifest_commit_hash,
            "builder_workflow_sha": builder_workflow_sha,
        },
        "artifacts": artifact_entries,
        "slsa_attestations": _digest_entries(
            slsa_attestations, "slsa_attestation"
        ),
        "in_toto_links": _digest_entries(in_toto_links, "in_toto_link"),
        "sigstore_bundles": _digest_entries(
            sigstore_bundles, "sigstore_bundle"
        ),
        "signer_key_id": signer_key_id,
        "trust_anchor": trust_anchor,
        "created_at": when,
        "signature": None,
    }


def write_release_bundle(
    bundle: dict[str, Any],
    *,
    out_path: Path,
) -> Path:
    """Atomically write the release bundle to ``out_path``.

    Uses ``local_atomic_file_write`` so the on-disk artifact never
    appears partially written (CLAUDE.md keystone invariant #8).
    """
    # Import locally so the script does not require relay_sidecar at
    # parse time; the primitive lives in apps/local-sidecar.
    sys.path.insert(
        0,
        str(
            Path(__file__).resolve().parent.parent
            / "apps"
            / "local-sidecar"
            / "src"
        ),
    )
    from relay_sidecar.primitives import local_atomic_file_write  # noqa: E402

    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(bundle, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
    local_atomic_file_write(out_path, payload, mode=0o600)
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Emit a Relay-format release evidence bundle "
            "(VAL-W12-045)."
        )
    )
    parser.add_argument("--tag", required=True, help="Release tag (e.g., v0.1.0)")
    parser.add_argument(
        "--manifest-commit-hash",
        required=True,
        help="Git SHA the release was cut from.",
    )
    parser.add_argument(
        "--builder-workflow-sha",
        required=True,
        help="Builder workflow commit SHA (GitHub Actions runner identity).",
    )
    parser.add_argument(
        "--signer-key-id",
        required=True,
        help="kid of the key that will sign this bundle.",
    )
    parser.add_argument(
        "--trust-anchor",
        default=DEFAULT_JWKS_URL,
        help="JWKS URL the verifier should use (default: spec-pinned).",
    )
    parser.add_argument(
        "--artifact",
        action="append",
        type=Path,
        default=[],
        help="Path to a published artifact (repeatable).",
    )
    parser.add_argument(
        "--slsa-attestation",
        action="append",
        type=Path,
        default=[],
        help="Path to a SLSA L3 attestation JSON (repeatable).",
    )
    parser.add_argument(
        "--in-toto-link",
        action="append",
        type=Path,
        default=[],
        help="Path to an in-toto link document (repeatable).",
    )
    parser.add_argument(
        "--sigstore-bundle",
        action="append",
        type=Path,
        default=[],
        help="Path to a Sigstore bundle (repeatable).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help=(
            "Output path for the release bundle "
            "(typically ~/.relay/evidence/release-<tag>.acef)."
        ),
    )
    parser.add_argument(
        "--print",
        action="store_true",
        help="Also print the bundle JSON on stdout after writing.",
    )
    args = parser.parse_args(argv)

    bundle = build_release_bundle(
        tag=args.tag,
        manifest_commit_hash=args.manifest_commit_hash,
        builder_workflow_sha=args.builder_workflow_sha,
        artifacts=list(args.artifact),
        slsa_attestations=list(args.slsa_attestation),
        in_toto_links=list(args.in_toto_link),
        sigstore_bundles=list(args.sigstore_bundle),
        signer_key_id=args.signer_key_id,
        trust_anchor=args.trust_anchor,
    )
    out = write_release_bundle(bundle, out_path=args.out)
    if args.print:
        sys.stdout.write(
            json.dumps(bundle, separators=(",", ":"), ensure_ascii=True) + "\n"
        )
    sys.stderr.write(f"[OK] release bundle written: {out}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
