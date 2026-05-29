#!/usr/bin/env python3
"""Assemble the aggregated, wrapper-facing release manifest (VAL-CRYPTO-003).

The npx wrapper (``packages/sdk-typescript/src/bin/manifest.ts``) fetches a
SINGLE aggregated ``manifest.json`` from the pinned manifest URL and trusts
its per-entry ``sha256`` digests and ``trust_root`` claim to decide which
sidecar bundle to download and run. That manifest is therefore the trust
root for the whole bundle-launch chain, so the release pipeline signs it
(``manifest.json.sigstore``) and the wrapper verifies the signature over the
exact manifest bytes BEFORE trusting any field.

This script produces that aggregated manifest in the wire schema the wrapper
parses (``relay.sidecar_bundle_manifest.v1``; see ``parseReleaseManifest``):

    {
      "schema_version": "relay.sidecar_bundle_manifest.v1",
      "emitted_at":      "<RFC 3339 UTC>",
      "sidecar_version": "<version>",
      "trust_root":      "<host>",
      "bundles": [
        {"os": "darwin"|"linux"|"win32", "arch": "x64"|"arm64",
         "url": "https://.../<asset>", "sha256": "<64 hex>",
         "size_bytes": <int>, "sigstore_url": "https://.../<asset>.sigstore"}
      ]
    }

It discovers the per-cell binary artifacts under ``--dist-root`` (the
``relay-sidecar-<os>-<arch>[.exe]`` files the build matrix produced and the
sign job downloaded), maps the build OS/arch slugs to the wrapper's
``process.platform`` / ``process.arch`` vocabulary, computes each digest +
size, and derives the published release-asset download URLs.

Exit codes:
    0  manifest written
    1  no binary artifacts discovered / matrix incomplete
    2  invalid invocation

Per CLAUDE.md "ASCII-Safe Source": ASCII-only output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

# Map the build-driver OS/arch slugs (scripts/build-sidecar-bundle.py
# CANONICAL_MATRIX) to the wrapper's process.platform / process.arch
# vocabulary (packages/sdk-typescript/src/bin/types.ts SUPPORTED_OS_ARCH).
_OS_MAP: dict[str, str] = {
    "macos": "darwin",
    "linux": "linux",
    "windows": "win32",
}
_ARCH_MAP: dict[str, str] = {
    "x86_64": "x64",
    "arm64": "arm64",
}

# Canonical four-arch matrix (build-driver slugs). Mirrors
# build-sidecar-bundle.py CANONICAL_MATRIX. A complete release manifest
# enumerates every cell; a partial set fails closed.
_CANONICAL_SLUGS: tuple[str, ...] = (
    "macos-arm64",
    "linux-x86_64",
    "linux-arm64",
    "windows-x86_64",
)

_SCHEMA_VERSION = "relay.sidecar_bundle_manifest.v1"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _slug_for_artifact(name: str) -> str | None:
    """Return the ``<os>-<arch>`` slug for a binary artifact filename.

    The build matrix names binaries ``relay-sidecar-<os>-<arch>`` (POSIX) or
    ``relay-sidecar-<os>-<arch>.exe`` (Windows). Anything else returns None.
    """
    if not name.startswith("relay-sidecar-"):
        return None
    rest = name[len("relay-sidecar-") :]
    if rest.endswith(".exe"):
        rest = rest[: -len(".exe")]
    return rest if rest in _CANONICAL_SLUGS else None


def discover_artifacts(dist_root: Path) -> dict[str, Path]:
    """Discover one binary artifact per canonical cell under ``dist_root``.

    Returns a ``slug -> path`` mapping. Signature bundles (``*.sigstore``),
    SLSA attestations (``*.intoto.jsonl``), the manifest, and any non-binary
    file are excluded. A duplicate slug (the same cell discovered twice)
    fails closed.
    """
    found: dict[str, Path] = {}
    for path in sorted(dist_root.rglob("relay-sidecar-*")):
        if not path.is_file():
            continue
        if path.name.endswith((".sigstore", ".intoto.jsonl", ".json", ".zip")):
            continue
        slug = _slug_for_artifact(path.name)
        if slug is None:
            continue
        if slug in found:
            print(
                f"FAIL: duplicate artifact for cell '{slug}': "
                f"{found[slug]} and {path}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        found[slug] = path
    return found


def build_manifest(
    *,
    dist_root: Path,
    sidecar_version: str,
    trust_root: str,
    asset_base_url: str,
    emitted_at: str | None = None,
) -> dict[str, object]:
    artifacts = discover_artifacts(dist_root)
    if not artifacts:
        print(
            f"FAIL: no relay-sidecar-* binary artifacts found under {dist_root}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    missing = [slug for slug in _CANONICAL_SLUGS if slug not in artifacts]
    if missing:
        print(
            "FAIL: release manifest is incomplete; missing cells: "
            + ", ".join(missing),
            file=sys.stderr,
        )
        raise SystemExit(1)

    base = asset_base_url.rstrip("/")
    bundles: list[dict[str, object]] = []
    for slug in _CANONICAL_SLUGS:
        path = artifacts[slug]
        build_os, _, build_arch = slug.partition("-")
        wrapper_os = _OS_MAP.get(build_os)
        wrapper_arch = _ARCH_MAP.get(build_arch)
        if wrapper_os is None or wrapper_arch is None:
            print(
                f"FAIL: cannot map build cell '{slug}' to a wrapper os/arch",
                file=sys.stderr,
            )
            raise SystemExit(1)
        asset_name = path.name
        bundles.append(
            {
                "os": wrapper_os,
                "arch": wrapper_arch,
                "url": f"{base}/{asset_name}",
                "sha256": _sha256(path),
                "size_bytes": path.stat().st_size,
                "sigstore_url": f"{base}/{asset_name}.sigstore",
            }
        )

    return {
        "schema_version": _SCHEMA_VERSION,
        "emitted_at": emitted_at
        or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sidecar_version": sidecar_version,
        "trust_root": trust_root,
        "bundles": bundles,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assemble the aggregated wrapper-facing release manifest.",
    )
    parser.add_argument(
        "--dist-root",
        required=True,
        help="Directory tree holding the per-cell relay-sidecar-* binaries.",
    )
    parser.add_argument(
        "--sidecar-version",
        required=True,
        help="Sidecar version this manifest describes (e.g. '0.1.21').",
    )
    parser.add_argument(
        "--trust-root",
        default="relay.epochly.com",
        help="Trust root host claim (default: relay.epochly.com).",
    )
    parser.add_argument(
        "--asset-base-url",
        default=None,
        help=(
            "Base URL the published bundle assets resolve to. Default: the "
            "canonical Relay sidecar-bundle release-asset prefix."
        ),
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Path to write the aggregated manifest JSON.",
    )
    parser.add_argument(
        "--emitted-at",
        default=None,
        help="Override emitted_at (RFC 3339 UTC); default: now. Test seam.",
    )
    args = parser.parse_args(argv)

    asset_base_url = args.asset_base_url or (
        "https://relay.epochly.com/.well-known/relay-sidecar-bundle"
    )

    manifest = build_manifest(
        dist_root=Path(args.dist_root),
        sidecar_version=args.sidecar_version,
        trust_root=args.trust_root,
        asset_base_url=asset_base_url,
        emitted_at=args.emitted_at,
    )
    payload = json.dumps(manifest, indent=2, sort_keys=True)
    Path(args.out).write_text(payload + "\n", encoding="utf-8")
    print(f"PASS: wrote aggregated release manifest to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
