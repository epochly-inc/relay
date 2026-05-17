"""W9.5 plumbing test: ``rly verify-self`` post-M09 invariant set.

Covers contract assertion VAL-V2M09-025:

  After M09 lands, ``uv run rly verify-self --json`` exits 0 with the
  five pre-M09 invariants PLUS three new crypto-implemented invariants:

    * sigstore-verifier-implemented
    * rekor-verifier-implemented
    * tsa-verifier-implemented

  Every invariant has status "pass" (the runner's "ok" equivalent).

Per CLAUDE.md TDD discipline this test was written FIRST and asserts the
shape the runner must produce after the three new checkers are
registered.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

# Repository root (relay/), four parents up from this test file:
# packages/cli/tests/test_verify_self_post_m09.py -> relay/
REPO_ROOT: Path = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.plumbing

# Required invariant check names that MUST be present in the runner output
# after M09 lands. The first five existed before M09; the last three were
# added by w9-5 to bind the M09 crypto flip into the canonical self-check.
REQUIRED_CHECKS_POST_M09 = (
    "atomic-primitives-only",
    "no-todo-fixme",
    "control-plane-write-only",
    "gate-engine-invariants",
    "no-mocks-in-prod",
    "sigstore-verifier-implemented",
    "rekor-verifier-implemented",
    "tsa-verifier-implemented",
)


@pytest.mark.fulfills("VAL-V2M09-025")
def test_post_m09_invariants_all_green() -> None:
    """``rly verify-self`` exit 0 with three M09 crypto invariants reported pass.

    Asserts:

      1. Process exit code is 0.
      2. JSON envelope ``overall == "pass"``.
      3. Every required check name in :data:`REQUIRED_CHECKS_POST_M09`
         appears in the ``checks`` array with ``status == "pass"``.
      4. ``failures == 0`` and ``invariants_checked >= 8``.
    """
    env = os.environ.copy()
    # Pin the repo root so the runner doesn't accidentally walk into a
    # parent directory if the test is invoked from a different cwd.
    env["RELAY_VERIFY_SELF_REPO_ROOT"] = str(REPO_ROOT)
    result = subprocess.run(
        ["uv", "run", "rly", "verify-self", "--json"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, (
        f"verify-self exited {result.returncode}; stdout={result.stdout!r}; "
        f"stderr={result.stderr!r}"
    )
    payload = json.loads(result.stdout)
    assert payload["overall"] == "pass", (
        f"expected overall=pass, got {payload.get('overall')!r}: "
        f"checks={payload.get('checks')!r}"
    )
    assert int(payload.get("failures", -1)) == 0, (
        f"failures={payload.get('failures')!r}: {payload!r}"
    )
    checks_by_name = {c["name"]: c for c in payload.get("checks", [])}
    missing = [
        name for name in REQUIRED_CHECKS_POST_M09 if name not in checks_by_name
    ]
    assert not missing, (
        f"verify-self output is missing required post-M09 checks: {missing!r}; "
        f"present: {sorted(checks_by_name.keys())!r}"
    )
    for name in REQUIRED_CHECKS_POST_M09:
        status = checks_by_name[name]["status"]
        assert status == "pass", (
            f"post-M09 invariant {name!r} expected status=pass, got "
            f"{status!r}; details={checks_by_name[name].get('details')!r}"
        )
    assert int(payload.get("invariants_checked", 0)) >= len(
        REQUIRED_CHECKS_POST_M09
    ), (
        f"invariants_checked={payload.get('invariants_checked')!r}; "
        f"expected at least {len(REQUIRED_CHECKS_POST_M09)}"
    )


@pytest.mark.fulfills("VAL-V2M09-025")
def test_post_m09_crypto_flags_all_true() -> None:
    """The three crypto-implemented flags are True after M09.

    Spec: §AO.1 lines 6117-6119 (three layers of the Relay trust anchor).
    The verify-self invariants depend on these constants; assert them
    directly so a regression of the flag flip is caught immediately
    without parsing CLI output.
    """
    from relay_cli.bundle import VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED
    from relay_cli.commands.verify_install import REKOR_CRYPTO_IMPLEMENTED
    from relay_verifier.tsa import TSA_CRYPTO_IMPLEMENTED

    assert VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED is True
    assert REKOR_CRYPTO_IMPLEMENTED is True
    assert TSA_CRYPTO_IMPLEMENTED is True
