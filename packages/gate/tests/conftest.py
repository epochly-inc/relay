"""Shared fixtures for the W8.1 gate-engine plumbing tests.

The pure helpers (provider implementations + builders + constants) live
in ``_w8_1_helpers``; this file only declares pytest fixtures that wire
them together. Splitting fixtures from helpers avoids the cross-package
``conftest`` module-name collision that pytest's prepend import mode
produces (sibling test directories at ``apps/replay-proxy/tests/`` and
``apps/local-sidecar/tests/`` ALSO declare ``conftest.py`` modules
under the same bare name).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from _w8_1_helpers import (
    InMemoryEvidenceProvider,
    InMemoryManifestResolver,
)
from relay_gate_engine import (
    AntiBypassGuard,
    GateEvaluator,
)


@pytest.fixture
def evidence_provider() -> InMemoryEvidenceProvider:
    return InMemoryEvidenceProvider()


@pytest.fixture
def manifest_resolver() -> InMemoryManifestResolver:
    # Pre-load benign commands so the happy-path tests need no per-test
    # manifest setup; tests exercising bypass paths add their own dirty
    # commands via .add(...).
    return InMemoryManifestResolver({
        "sha256-clean": "uv run pytest -m plumbing",
        "sha256-also-clean": "npm run typecheck",
    })


@pytest.fixture
def anti_bypass_guard() -> AntiBypassGuard:
    return AntiBypassGuard()


@pytest.fixture
def evaluator(
    evidence_provider: InMemoryEvidenceProvider,
    manifest_resolver: InMemoryManifestResolver,
    anti_bypass_guard: AntiBypassGuard,
) -> GateEvaluator:
    return GateEvaluator(
        evidence_provider=evidence_provider,
        manifest_resolver=manifest_resolver,
        anti_bypass=anti_bypass_guard,
    )
