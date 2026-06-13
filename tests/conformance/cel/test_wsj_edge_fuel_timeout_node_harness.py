"""CI wiring (roborev MED): subprocess-run the WS-J edge fuel-timeout node-harness
(``packages/cel-wasm/conformance/harness/wsj_edge_fuel_timeout.test.mjs``) and
assert exit 0, so regressions in the TS/edge ``.mjs`` loader's fuel forwarding --
including the fail-closed range guard -- are caught by a gate CI ALREADY runs.

The node harness is the ``node --test`` runner that drives the real TS/edge loader
(``packages/cel-wasm/typescript/relay-cel-wasm.mjs``) against the real pinned
``.wasm``. Before this wiring it was a MANUAL command only (``node --test ...``),
so a regression in fuel forwarding (e.g. a future edit dropping the
``Number.isSafeInteger`` fail-closed guard, or breaking the RELAY-CEL-003 timeout
path) would NOT trip any normal gate. Wrapping it in a pytest plumbing test puts
it on the tier-1 path the CI plumbing gate runs every commit.

This mirrors how the cross-host fuel-exhaustion harness is invoked from pytest
(``test_fuel_exhaustion_cross_host_envelope_parity.py``): resolve the SAME pinned
wasm via the canonical resolver, hand it to the node subprocess via ``$CEL_WASM``,
and fail LOUD (with the harness diagnostics) on a non-zero exit -- a silent skip
would let a fuel-forwarding regression ship undetected.

tier-1 plumbing (offline, against the committed pinned wasm). ASCII-only per
CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# Repo root: this file lives at relay/tests/conformance/cel/test_*.py
REPO_ROOT = Path(__file__).resolve().parents[3]

# The WS-J edge fuel-timeout node-harness (node --test runner) that exercises the
# real TS/edge .mjs loader's fuel surface end to end (forwarding, the
# RELAY-CEL-003 timeout path, and the fail-closed out-of-u64 range guard).
NODE_HARNESS = (
    REPO_ROOT
    / "packages"
    / "cel-wasm"
    / "conformance"
    / "harness"
    / "wsj_edge_fuel_timeout.test.mjs"
)

# The (gitignored) crate/target build -- the local-dev fallback when neither
# $CEL_WASM nor the committed package-data wasm is present.
CRATE_TARGET_WASM = (
    REPO_ROOT
    / "packages"
    / "cel-wasm"
    / "crate"
    / "target"
    / "wasm32-unknown-unknown"
    / "release"
    / "relay_cel_wasm.wasm"
)

# Make the canonical wasm resolver importable (relay_contracts IS installed
# editable; the explicit insert keeps the import robust to invocation cwd).
sys.path.insert(0, str(REPO_ROOT / "packages" / "contracts" / "src"))

from relay_contracts.wasm_artifact import (  # noqa: E402  -- after sys.path
    WASM_PINNED_SHA256,
    resolve_packaged_wasm_path,
    sha256_of_path,
)


def _wasm_path() -> str:
    """The pinned wasm the node harness loads (the SAME bytes both hosts use).

    Resolution precedence:
      1. $CEL_WASM when set -- the explicit CI override.
      2. The COMMITTED, git-tracked PACKAGE-DATA wasm via the canonical resolver.
         Defense-in-depth: its sha256 MUST equal WASM_PINNED_SHA256, so a
         stale/tampered vendored wasm FAILS LOUD here rather than running the
         harness against the wrong bytes.
      3. The (gitignored) crate/target build -- a LOCAL-DEV fallback only.
    """
    override = os.environ.get("CEL_WASM")
    if override:
        return override
    packaged = resolve_packaged_wasm_path()
    if packaged is not None:
        actual = sha256_of_path(packaged)
        assert actual == WASM_PINNED_SHA256, (
            "the committed package-data wasm at "
            f"{packaged} hashes to {actual}, NOT the pinned "
            f"{WASM_PINNED_SHA256}; refusing to run the node harness on a "
            "stale/tampered wasm."
        )
        return str(packaged)
    return str(CRATE_TARGET_WASM)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P7EDGE-006")
def test_wsj_edge_fuel_timeout_node_harness_passes() -> None:
    """The node --test harness for the TS/edge loader fuel surface exits 0.

    Drives the harness as a subprocess against the pinned wasm. A non-zero exit
    fails this test WITH the harness diagnostics (stdout/stderr), so a fuel
    forwarding regression -- a dropped fail-closed range guard, a broken
    RELAY-CEL-003 timeout, or a no-field/0-sentinel regression -- is caught on the
    tier-1 CI path rather than only by a manual command."""
    node = shutil.which("node")
    assert node is not None, (
        "node executable not found on PATH; the cel-wasm gate requires Node "
        "(the manifest declares Node as a required tool)."
    )
    assert NODE_HARNESS.exists(), (
        f"missing the WS-J edge fuel-timeout node harness at {NODE_HARNESS}."
    )
    env = dict(os.environ)
    env["CEL_WASM"] = _wasm_path()
    proc = subprocess.run(
        [node, "--test", str(NODE_HARNESS)],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(
            "the WS-J edge fuel-timeout node harness exited "
            f"{proc.returncode} (a fuel-forwarding / fail-closed-guard regression "
            "in the TS/edge .mjs loader). Build the wasm via "
            "`make -C packages/cel-wasm build` or set $CEL_WASM.\n"
            f"  stdout: {proc.stdout[-3000:]}\n  stderr: {proc.stderr[-2000:]}"
        )
