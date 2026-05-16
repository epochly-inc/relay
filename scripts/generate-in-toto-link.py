#!/usr/bin/env python3
"""W12.4 in-toto link metadata emitter.

Emits a single ``<step-name>.<key-id>.link`` JSON file recording the
materials (inputs with sha256 digests), products (outputs with sha256
digests), command, and byproducts of a build step.

The output filename follows the in-toto v0.1 grammar
``<step-name>.<key-id>.link``. The on-disk JSON envelope uses the
``signed`` / ``signatures`` shape so the offline verifier
(``scripts/check-in-toto-attestations.py``) can index the file by step
name AND so the relay-platform signing service can countersign the link
without rewriting its body.

Per CLAUDE.md banned pattern #14, this OSS script DOES NOT hold any
signing key material. Links emitted by this script carry an empty
``signatures[]`` list when run outside the canonical
``epochly-inc/relay`` repository (fork-friendly dry-run-unsigned mode);
the relay-platform signing service stamps the signature in a separate
job that is not committed here. Tests use the
``RELAY_LINK_KEY_ID`` env var to pin the keyid for deterministic
filenames.

Per CLAUDE.md keystone invariant #8 the script writes its single output
file via the ``local_atomic_file_write`` primitive (writes-to-tmp +
fsync + atomic-rename) -- this is a single-file artifact emitter and
the per-write atomicity is sufficient (no cross-file invariants).

Per CLAUDE.md "ASCII-Safe Source": ASCII-only output and source.

Exit codes:
    0  link emitted successfully
    2  input file (material glob) missing or unreadable
    3  invalid invocation
"""

from __future__ import annotations

import argparse
import errno
import glob
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

# Default key id used when neither --key-id nor RELAY_LINK_KEY_ID is set.
# This is the OSS placeholder; production runs are signed by the
# relay-platform service which substitutes the canonical layout key id.
DEFAULT_KEY_ID = "RELAY-FUNCTIONARY-CI-RUNNER"

# in-toto link wire-format version. Tracks the layout schema in
# packages/schemas/raw/relay-error-codes.yaml; bumps require a layout
# version bump in tests/release/fixtures/release.layout.
LINK_TYPE = "link"
LINK_SCHEMA_VERSION = "relay-link-v0.1"


def _sha256_file(path: Path) -> str:
    """Stream a file through sha256 in 1 MiB chunks; return lowercase hex."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _build_artifact_entry(
    *,
    repo_root: Path,
    abs_path: Path,
) -> dict[str, Any]:
    """Build a single in-toto materials/products entry for a real file
    on disk. The ``uri`` is the path relative to ``repo_root`` so links
    are reproducible across runners (no leading /home/runner/...)."""
    try:
        rel = abs_path.relative_to(repo_root)
    except ValueError:
        rel = abs_path
    return {
        "uri": str(rel).replace(os.sep, "/"),
        "digest": {"sha256": _sha256_file(abs_path)},
    }


def _entries_from_glob(
    *,
    repo_root: Path,
    pattern: str,
    allow_empty: bool,
) -> list[dict[str, Any]]:
    """Resolve a glob to a sorted list of materials/products entries."""
    matched = sorted(glob.glob(str(repo_root / pattern), recursive=True))
    if not matched and not allow_empty:
        print(
            f"FAIL: glob pattern '{pattern}' matched no files (use "
            f"--allow-empty-* to permit)",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return [
        _build_artifact_entry(repo_root=repo_root, abs_path=Path(p))
        for p in matched
    ]


def _entries_from_git_sha(*, sha: str) -> list[dict[str, Any]]:
    """A source-tree material/product is represented by the git commit
    SHA itself: a single entry whose digest{sha256} field is the
    SHA-256 of the canonicalized commit SHA string. This produces a
    stable, reproducible digest that any verifier can re-derive from
    the public commit SHA without needing the working tree."""
    if not sha or len(sha) < 7:
        print(
            f"FAIL: git SHA '{sha}' is not a valid commit reference",
            file=sys.stderr,
        )
        raise SystemExit(3)
    digest = hashlib.sha256(f"git-commit:{sha.lower()}".encode("ascii")).hexdigest()
    return [
        {
            "uri": f"git+commit://{sha.lower()}",
            "digest": {"sha256": digest},
        }
    ]


def _entries_from_link_products(*, link_path: Path) -> list[dict[str, Any]]:
    """Extract the products[] list from a previously-emitted link file
    and return them as materials[] entries (uri + digest passthrough).
    Used by the upload-release-artifacts step which consumes products
    from every preceding build step."""
    try:
        with link_path.open("r", encoding="utf-8") as f:
            link = json.load(f)
    except FileNotFoundError:
        print(
            f"FAIL: --materials-from-link-products: link file not found at "
            f"{link_path}",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    except json.JSONDecodeError as exc:
        print(
            f"FAIL: --materials-from-link-products: link JSON unparseable: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    signed = link.get("signed")
    if not isinstance(signed, dict):
        return []
    products = signed.get("products", [])
    if not isinstance(products, list):
        return []
    out: list[dict[str, Any]] = []
    for p in products:
        if not isinstance(p, dict):
            continue
        uri = p.get("uri")
        digest = p.get("digest")
        if not isinstance(uri, str) or not isinstance(digest, dict):
            continue
        out.append({"uri": uri, "digest": dict(digest)})
    return out


def _parse_byproduct(token: str) -> tuple[str, str]:
    """--byproduct k=v parser. The '=' MUST be present."""
    if "=" not in token:
        print(
            f"FAIL: --byproduct expects 'key=value', got {token!r}",
            file=sys.stderr,
        )
        raise SystemExit(3)
    key, _, value = token.partition("=")
    if not key:
        print(
            f"FAIL: --byproduct key is empty in {token!r}",
            file=sys.stderr,
        )
        raise SystemExit(3)
    return key, value


def _atomic_write_text(path: Path, text: str) -> None:
    """Write text atomically: write to <path>.tmp.<pid>, fsync, rename.

    Per CLAUDE.md keystone invariant #8: persistent file writes go
    through an atomic-rename pattern. This script's single output is
    independent of any cross-file invariants, so the local primitive is
    sufficient (no need for the locked-write helper).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp.{os.getpid()}"
    try:
        with tmp.open("w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        # Best-effort cleanup if rename failed mid-flight.
        try:
            tmp.unlink()
        except OSError as exc:
            if exc.errno != errno.ENOENT:  # noqa: PERF203
                # Surface unexpected unlink errors but do not mask the
                # original write failure.
                print(
                    f"WARN: temp file cleanup failed: {exc}",
                    file=sys.stderr,
                )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Emit in-toto link metadata for a single build step. The "
            "output filename follows '<step-name>.<key-id>.link' and the "
            "on-disk JSON uses the signed/signatures envelope shape."
        )
    )
    parser.add_argument(
        "--step-name",
        type=str,
        required=True,
        help=(
            "Layout step name; must match a name in "
            "tests/release/fixtures/release.layout's signed.steps[]."
        ),
    )
    parser.add_argument(
        "--command",
        type=str,
        required=True,
        help=(
            "Verbatim command string the runner executed for this step "
            "(stored in signed.command, used by the verifier to compare "
            "against the layout's expected_command)."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output path, e.g. links/<step-name>.<key-id>.link.",
    )

    # Materials sources. Multiple --material-* flags compose; entries
    # are deduplicated by sha256 digest before serialization.
    materials_group = parser.add_argument_group("materials")
    materials_group.add_argument(
        "--no-materials",
        action="store_true",
        help=(
            "Step has no input materials (e.g. source-checkout). Mutually "
            "exclusive with the other --material-* flags."
        ),
    )
    materials_group.add_argument(
        "--material-glob",
        type=str,
        action="append",
        default=[],
        help="Glob pattern (relative to repo root) of input materials.",
    )
    materials_group.add_argument(
        "--material-from-git-sha",
        type=str,
        default=None,
        help=(
            "Use the git commit SHA as the canonical source-tree material "
            "(deterministic uri+digest from the SHA itself)."
        ),
    )
    materials_group.add_argument(
        "--materials-from-link-products",
        type=Path,
        action="append",
        default=[],
        help=(
            "Extract products[] from a previously-emitted link file and "
            "use them as materials[] entries; pass once per upstream link."
        ),
    )
    materials_group.add_argument(
        "--allow-empty-materials",
        action="store_true",
        help=(
            "Permit a step whose --material-glob expands to zero files "
            "(used by sidecar-bundle-source=w12.5 pre-build placeholder)."
        ),
    )

    # Products sources.
    products_group = parser.add_argument_group("products")
    products_group.add_argument(
        "--no-products",
        action="store_true",
        help=(
            "Step has no output products (e.g. upload-release-artifacts "
            "publishes externally and does not produce files we hash)."
        ),
    )
    products_group.add_argument(
        "--product-glob",
        type=str,
        action="append",
        default=[],
        help="Glob pattern (relative to repo root) of output products.",
    )
    products_group.add_argument(
        "--product-from-git-sha",
        type=str,
        default=None,
        help=(
            "Use the git commit SHA as the canonical source-tree product "
            "(emits a single entry whose digest is sha256(git-commit:<sha>))."
        ),
    )
    products_group.add_argument(
        "--allow-empty-products",
        action="store_true",
        help="Permit a step whose --product-glob expands to zero files.",
    )

    parser.add_argument(
        "--byproduct",
        type=str,
        action="append",
        default=[],
        help="Free-form 'key=value' byproducts (runner, env, etc.).",
    )
    parser.add_argument(
        "--key-id",
        type=str,
        default=None,
        help=(
            "Functionary key id used in the link filename and in "
            "signatures[].keyid. Defaults to RELAY_LINK_KEY_ID env var "
            f"or '{DEFAULT_KEY_ID}'."
        ),
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help=(
            "Repository root; defaults to current working directory. All "
            "--material-glob / --product-glob patterns resolve relative "
            "to this root."
        ),
    )

    args = parser.parse_args(argv)

    repo_root = (args.repo_root or Path.cwd()).resolve()
    key_id = (
        args.key_id
        or os.environ.get("RELAY_LINK_KEY_ID")
        or DEFAULT_KEY_ID
    )

    # Validate --no-materials / --no-products mutually-exclusive sanity.
    if args.no_materials and (
        args.material_glob
        or args.material_from_git_sha is not None
        or args.materials_from_link_products
    ):
        print(
            "FAIL: --no-materials is mutually exclusive with --material-* flags",
            file=sys.stderr,
        )
        return 3
    if args.no_products and (
        args.product_glob or args.product_from_git_sha is not None
    ):
        print(
            "FAIL: --no-products is mutually exclusive with --product-* flags",
            file=sys.stderr,
        )
        return 3

    # Compose materials.
    materials: list[dict[str, Any]] = []
    if not args.no_materials:
        for pat in args.material_glob:
            materials.extend(
                _entries_from_glob(
                    repo_root=repo_root,
                    pattern=pat,
                    allow_empty=args.allow_empty_materials,
                )
            )
        if args.material_from_git_sha is not None:
            materials.extend(
                _entries_from_git_sha(sha=args.material_from_git_sha)
            )
        for link_path in args.materials_from_link_products:
            materials.extend(_entries_from_link_products(link_path=link_path))

    # Compose products.
    products: list[dict[str, Any]] = []
    if not args.no_products:
        for pat in args.product_glob:
            products.extend(
                _entries_from_glob(
                    repo_root=repo_root,
                    pattern=pat,
                    allow_empty=args.allow_empty_products,
                )
            )
        if args.product_from_git_sha is not None:
            products.extend(
                _entries_from_git_sha(sha=args.product_from_git_sha)
            )

    # Deduplicate by sha256 digest while preserving order.
    def _dedup(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for e in entries:
            digest = e.get("digest", {})
            sha = digest.get("sha256") if isinstance(digest, dict) else None
            if not isinstance(sha, str):
                continue
            if sha in seen:
                continue
            seen.add(sha)
            out.append(e)
        return out

    materials = _dedup(materials)
    products = _dedup(products)

    # Compose byproducts.
    byproducts: dict[str, str] = {}
    for token in args.byproduct:
        k, v = _parse_byproduct(token)
        byproducts[k] = v

    # Build the in-toto link envelope. The functionary key id chosen
    # above is recorded in signed.key_id_hint so that the relay-platform
    # signing service knows which key to apply when it stamps the
    # signatures[] array out-of-band; the OSS-path signatures[] remains
    # empty until that out-of-band signing happens.
    envelope: dict[str, Any] = {
        "signed": {
            "_type": LINK_TYPE,
            "schema_version": LINK_SCHEMA_VERSION,
            "name": args.step_name,
            "command": args.command,
            "materials": materials,
            "products": products,
            "byproducts": byproducts,
            "environment": {},
            "key_id_hint": key_id,
        },
        # Empty signatures[] in OSS path; relay-platform signing service
        # populates this list when run in the canonical repo.
        "signatures": [],
    }

    text = json.dumps(envelope, indent=2, sort_keys=False) + "\n"
    _atomic_write_text(args.output, text)
    print(f"wrote {args.output} ({len(materials)} materials, {len(products)} products)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
