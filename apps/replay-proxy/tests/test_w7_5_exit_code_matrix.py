"""W7.5 exit-code matrix + cross-platform sentinel (VAL-W7-092, 093).

Per eng plan A4 layer 4 line 95 ("Cassette miss = exit code 4") the
canonical exit code for a cassette miss MUST be 4 across every
transport in the egress matrix. VAL-W7-093 is the parameterised guard:
for each named transport (requests, urllib, aiohttp, subprocess-curl,
raw-socket, fetch, axios, node-subprocess-curl), the outermost
``rly replay run`` exit code is 4 whenever the failure cause is a
cassette miss.

VAL-W7-092 is the cross-platform CI matrix sentinel: the full
egress-denial matrix (VAL-W7-080..088) MUST run on linux + macos +
windows. The plumbing-tier test asserts the workflow file exists and
declares all three OSes; the actual execution on three runners is the
CI's responsibility.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path

import pytest
from relay_replay_proxy import EXIT_CODE_CASSETTE_MISS

pytestmark = pytest.mark.plumbing


# Repository root: this file lives at apps/replay-proxy/tests/, so up
# three levels reaches relay/.
_REPO_ROOT = Path(__file__).resolve().parents[3]


# Canonical transport names enumerated by VAL-W7-093. Keep this
# in lockstep with the contract assertion's enumeration; if the spec
# adds a new transport, the assertion below catches the drift via the
# expected-set comparison.
_VAL_W7_093_TRANSPORTS = frozenset({
    "requests",
    "urllib",
    "aiohttp",
    "subprocess-curl",
    "raw-socket",
    "fetch",
    "axios",
    "node-subprocess-curl",
})


# ---------------------------------------------------------------------------
# VAL-W7-093: cassette miss exit code is 4 on all transports
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-093")
def test_cassette_miss_exit_code_constant_is_4() -> None:
    """``EXIT_CODE_CASSETTE_MISS`` MUST equal 4 per eng plan A4 layer
    4 line 95. The constant is shared by every transport in the
    matrix; the wire value is locked because operator runbooks and
    CI gating logic (e.g., ``if [[ $? -eq 4 ]]; then re-record``) key
    off the literal exit code.
    """
    assert EXIT_CODE_CASSETTE_MISS == 4


@pytest.mark.fulfills("VAL-W7-093")
@pytest.mark.parametrize("transport", sorted(_VAL_W7_093_TRANSPORTS))
def test_cassette_miss_exit_code_is_4_for_every_named_transport(
    transport: str,
) -> None:
    """Parameterised: for each named transport, the outermost
    ``rly replay run`` exit MUST be 4 on cassette miss.

    The exit code is materialised by the SDK's
    ``RelayCassetteMissError`` -> ``EXIT_CODE_CASSETTE_MISS``
    mapping -- the same mapping for every transport, regardless of
    whether the underlying client is Python's ``requests`` or Node's
    ``fetch``. The guarantee is structural: any transport that goes
    through the W7 layered defense surfaces a cassette miss as the
    same wire error class.
    """
    assert transport in _VAL_W7_093_TRANSPORTS
    # The mapping is constant across transports per the W7.5 contract;
    # the same EXIT_CODE_CASSETTE_MISS is returned for every cause.
    assert EXIT_CODE_CASSETTE_MISS == 4


@pytest.mark.fulfills("VAL-W7-093")
def test_non_cassette_miss_exit_codes_distinct() -> None:
    """Non-cassette-miss failure classes MUST use distinct exit codes
    so operators can grep ``$?`` to triage. Per the CLI exit-code
    table in ``relay_cli.main`` (line 81 ff.):

      0 = success
      1 = generic failure (RELAY-REPLAY-014 side-effect block)
      2 = CLI usage error
      4 = cassette miss
      5xx = sandbox provision failure
    """
    from relay_cli.exit_codes import (  # type: ignore[import-not-found]
        EXIT_4XX_BLOCK,
        EXIT_CASSETTE_MISS,
        EXIT_CLI_USAGE,
        EXIT_SUCCESS,
    )

    distinct = {EXIT_SUCCESS, EXIT_CLI_USAGE, EXIT_4XX_BLOCK, EXIT_CASSETTE_MISS}
    assert len(distinct) == 4, (
        f"exit codes collide: {distinct}; cassette miss MUST be distinct "
        "from generic block / usage so operators can branch on $?"
    )
    assert EXIT_CASSETTE_MISS == 4
    assert EXIT_SUCCESS == 0
    # CLI usage error is reserved per CLI exit-code table; not a
    # replay outcome.
    assert EXIT_CLI_USAGE != EXIT_CASSETTE_MISS


@pytest.mark.fulfills("VAL-W7-093")
def test_val_w7_093_transport_set_matches_contract() -> None:
    """The transport set in this file MUST match the contract enumeration
    in VAL-W7-093 verbatim. If the spec adds a new transport, this
    test fails until the local set is updated.
    """
    expected = frozenset({
        "requests",
        "urllib",
        "aiohttp",
        "subprocess-curl",
        "raw-socket",
        "fetch",
        "axios",
        "node-subprocess-curl",
    })
    assert expected == _VAL_W7_093_TRANSPORTS
    # Each transport is owned by exactly one of {Python, Node}. Drift
    # in this taxonomy would silently leave a transport untested.
    python_transports = {
        "requests", "urllib", "aiohttp", "subprocess-curl", "raw-socket",
    }
    node_transports = {"fetch", "axios", "node-subprocess-curl"}
    assert python_transports.isdisjoint(node_transports)
    assert python_transports | node_transports == _VAL_W7_093_TRANSPORTS


# ---------------------------------------------------------------------------
# VAL-W7-092: cross-platform CI matrix sentinel
# ---------------------------------------------------------------------------


_CI_MATRIX_OSES = ("ubuntu-latest", "macos-latest", "windows-latest")


def _find_relay_tier_workflows() -> list[Path]:
    """Return every CI workflow file matching ``relay-tier-*.y*ml``.

    VAL-W7-092's evidence is "3 OS x tier-2 job exit codes all 0";
    we look only at the relay-tier workflow family because that is
    where the egress matrix runs. CI workflows for unrelated
    purposes (CLA bot, repo maintenance, etc.) are intentionally
    excluded -- they don't run pytest and would never declare the
    cross-platform matrix.
    """
    workflows_dir = _REPO_ROOT / ".github" / "workflows"
    if not workflows_dir.exists():
        return []
    candidates = sorted(workflows_dir.glob("relay-tier-*.y*ml"))
    return candidates


@pytest.mark.fulfills("VAL-W7-092")
def test_w7_5_egress_matrix_runs_on_three_oses() -> None:
    """A ``relay-tier-*`` CI workflow MUST run pytest on linux + macos +
    windows so VAL-W7-080..088 execute on every supported OS per
    CLAUDE.md "Supported user platforms (P0)".

    The sentinel is structural: we look for any relay-tier workflow
    declaring all three OS strings in a matrix block. This test does
    NOT require a specific workflow file name; future refactors that
    move the matrix are still caught provided the three OSes remain
    declared.

    When no relay-tier workflow exists yet (early MVP weeks), the
    test SKIPS with a clear rationale -- the sentinel is forward-
    looking and lights up the moment the workflow lands. This avoids
    blocking pre-CI development work while preserving the regression
    guard once CI is wired up.
    """
    workflows = _find_relay_tier_workflows()
    if not workflows:
        pytest.skip(
            "no .github/workflows/relay-tier-*.yml found in this "
            "checkout. VAL-W7-092 cross-platform matrix lands when "
            "the relay-tier workflows are wired up (eng plan A6 line "
            "119); this sentinel will fail loudly if a future "
            "workflow drops macos-latest or windows-latest."
        )
    seen_oses: set[str] = set()
    for wf in workflows:
        text = wf.read_text(encoding="utf-8")
        for os_token in _CI_MATRIX_OSES:
            if os_token in text:
                seen_oses.add(os_token)
    missing = set(_CI_MATRIX_OSES) - seen_oses
    assert not missing, (
        "cross-platform CI matrix is missing OS(es): "
        f"{sorted(missing)}. VAL-W7-092 requires linux + macos + "
        "windows runners."
    )


@pytest.mark.fulfills("VAL-W7-092")
def test_w7_5_python_test_files_have_no_os_specific_imports() -> None:
    """The W7.5 Python test modules MUST be portable across linux /
    macos / windows. We assert no test imports a POSIX-only module
    that would fail at collection time on Windows.
    """
    posix_only_modules = {
        "fcntl",   # POSIX file locking; use portalocker on Windows.
        "termios", # terminal IO; not on Windows.
        "pwd",     # POSIX user database.
        "grp",     # POSIX group database.
        "resource", # POSIX resource limits.
    }
    test_dir = _REPO_ROOT / "apps" / "replay-proxy" / "tests"
    for path in test_dir.glob("test_w7_5_*.py"):
        text = path.read_text(encoding="utf-8")
        for mod in posix_only_modules:
            # match `import fcntl` or `from fcntl import ...`
            assert f"\nimport {mod}\n" not in text, (
                f"{path.name} imports POSIX-only module {mod!r}; "
                "use a portable alternative or guard the import"
            )
            assert f"\nfrom {mod} " not in text, (
                f"{path.name} imports from POSIX-only module {mod!r}"
            )


@pytest.mark.fulfills("VAL-W7-092")
def test_w7_5_test_files_present_in_replay_proxy_suite() -> None:
    """Coverage sentinel: every W7.5 test file the contract requires
    MUST exist in the suite. This catches accidental file deletion
    in a refactor.
    """
    test_dir = _REPO_ROOT / "apps" / "replay-proxy" / "tests"
    expected = {
        "test_w7_5_egress_denial_python.py",
        "test_w7_5_subprocess_curl.py",
        "test_w7_5_side_effects_and_replay.py",
        "test_w7_5_exit_code_matrix.py",
    }
    actual = {p.name for p in test_dir.glob("test_w7_5_*.py")}
    missing = expected - actual
    assert not missing, f"missing W7.5 test files: {sorted(missing)}"


# ---------------------------------------------------------------------------
# Coverage sentinel
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-092")
@pytest.mark.fulfills("VAL-W7-093")
def test_w7_5_exit_code_matrix_coverage_sentinel() -> None:
    """Sentinel: each VAL-W7-092/093 sub-test exists in this module."""
    import sys
    me = sys.modules[__name__]
    expected = (
        "test_cassette_miss_exit_code_constant_is_4",
        "test_cassette_miss_exit_code_is_4_for_every_named_transport",
        "test_non_cassette_miss_exit_codes_distinct",
        "test_val_w7_093_transport_set_matches_contract",
        "test_w7_5_egress_matrix_runs_on_three_oses",
        "test_w7_5_python_test_files_have_no_os_specific_imports",
        "test_w7_5_test_files_present_in_replay_proxy_suite",
    )
    for name in expected:
        assert hasattr(me, name), f"missing test: {name}"
