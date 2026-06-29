"""Offline-verifier dependency-surface guards.

The verifier is the canonical OSS-portable, air-gapped evidence verifier
(spec AO.4, keystone invariant #11). Its README promises "strict
offline-first semantics" and "a bundled JWKS snapshot inside the wheel so
air-gapped auditors can [verify offline]". To honour that, the verifier
deliberately VENDORS its own error-code constants (e.g.
``bundle_paths.RELAY_EVID_024``, ``tsa.RELAY_EVID_031`` /
``RELAY_EVID_038``) and the one schema-id string it writes
(``local_signer.py`` -> ``relay.evidence_bundle.v1``) rather than importing
them from ``relay_schemas`` -- so ``pip install epochly-relay-verifier``
pulls the smallest possible dependency tree (cryptography, asn1crypto,
rfc3161-client) and never drags in ``relay_schemas`` / pydantic.

This module locks that minimal-footprint surface:

1. The verifier MUST NOT runtime-depend on ANY first-party ``epochly-relay-*``
   package. An offline auditor's install must stand alone.
2. ``epochly-relay-schemas`` belongs in the ``test`` extra: the
   VAL-V3M1-016 cross-package deprecation guard imports
   ``relay_schemas.envelopes`` (the process-level deprecation tracker), so
   the workspace test environment still resolves it.
3. No production module may import ``relay_schemas`` at runtime.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
VERIFIER_DIR = REPO_ROOT / "packages" / "verifier"
VERIFIER_PYPROJECT = VERIFIER_DIR / "pyproject.toml"
VERIFIER_SRC = VERIFIER_DIR / "src" / "relay_verifier"


def _names(entries: list[str]) -> set[str]:
    out: set[str] = set()
    for entry in entries:
        name = entry
        for sep in ("[", ";", "<", ">", "=", "!", "~", "(", " "):
            name = name.split(sep, 1)[0]
        out.add(name.strip().lower())
    return out


def _runtime_deps() -> list[str]:
    data = tomllib.loads(VERIFIER_PYPROJECT.read_text(encoding="utf-8"))
    return list(data["project"]["dependencies"])


def _test_extra() -> list[str]:
    data = tomllib.loads(VERIFIER_PYPROJECT.read_text(encoding="utf-8"))
    return list(data["project"].get("optional-dependencies", {}).get("test", []))


@pytest.mark.plumbing
def test_verifier_has_no_first_party_runtime_deps() -> None:
    """The offline verifier MUST NOT runtime-depend on any Relay package.

    Encodes the air-gapped / minimal-footprint design: an auditor install
    stands alone on third-party crypto libs only.
    """
    first_party = sorted(
        n for n in _names(_runtime_deps()) if n.startswith("epochly-relay")
    )
    assert not first_party, (
        "offline verifier must not runtime-depend on any first-party "
        f"epochly-relay-* package; found {first_party!r}"
    )


@pytest.mark.plumbing
def test_schemas_is_declared_in_test_extra() -> None:
    """``epochly-relay-schemas`` MUST be a test-only extra.

    The VAL-V3M1-016 deprecation guard imports relay_schemas.envelopes.
    """
    assert "epochly-relay-schemas" in _names(_test_extra()), (
        "epochly-relay-schemas must be declared under "
        f"[project.optional-dependencies.test]; got {_test_extra()!r}"
    )


@pytest.mark.plumbing
def test_verifier_production_does_not_import_relay_schemas() -> None:
    """No production verifier module may import ``relay_schemas`` at runtime."""
    offenders: list[str] = []
    for py in sorted(VERIFIER_SRC.rglob("*.py")):
        for lineno, raw in enumerate(
            py.read_text(encoding="utf-8").splitlines(), start=1
        ):
            stripped = raw.strip()
            if stripped.startswith("#"):
                continue
            if re.match(r"^(import relay_schemas|from relay_schemas)(\s|\.|$)", stripped):
                offenders.append(f"{py.relative_to(REPO_ROOT)}:{lineno}: {stripped}")
    assert not offenders, (
        "production verifier code must not import relay_schemas at runtime "
        "(it vendors its own error-code / schema-id constants for the offline "
        "air-gapped surface); found:\n" + "\n".join(offenders)
    )
