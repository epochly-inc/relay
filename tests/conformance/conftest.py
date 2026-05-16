"""W17.4 conformance suite fault-injection hook (VAL-W17-020).

Lives at ``tests/conformance/conftest.py`` (not under any specific
suite) because pytest's conftest discovery scopes a conftest to its
own subtree. To make the fault-injection hook engage for ALL FOUR
conformance suites (jcs/, jws/, cel-spec/, cel/), the conftest MUST
sit at their common parent.

The release-block negative test (``test_w17_4_release_block.py``)
needs a deterministic way to make a single suite's first test fail
when run under a specific environment variable. This conftest
implements ``pytest_collection_modifyitems`` to detect the
``RELAY_CONFORMANCE_FAULT_INJECT`` env var and override the first
collected item for the named suite so its runtest raises
``AssertionError``.

Supported suite names (matching the four conformance sub-features):

  - ``w17.1`` -> tests/conformance/jcs/
  - ``w17.2`` -> tests/conformance/jws/
  - ``w17.3`` -> tests/conformance/cel-spec/
  - ``w17.4`` -> tests/conformance/cel/test_w17_4_*

Setting ``RELAY_CONFORMANCE_FAULT_INJECT=w17.4`` and running the
w17.4 test suite causes the first test from that suite to fail with
``RELAY_CONFORMANCE_FAULT_INJECT`` in the message. Unsetting the
variable restores normal behavior (the hook short-circuits before
mutating any item).

Design note: we DO NOT use ``pytest.mark.xfail`` here. xfail would
convert the AssertionError into an XFAIL outcome (exit 0), defeating
the negative test that asserts pytest exits non-zero on injection.
Only ``item.runtest`` is overridden.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import os

import pytest

# Suite-name -> path fragment that, if present in an item's nodeid,
# identifies that item as belonging to the suite.
_SUITE_NODEID_FRAGMENTS: dict[str, str] = {
    "w17.1": "tests/conformance/jcs/",
    "w17.2": "tests/conformance/jws/",
    "w17.3": "tests/conformance/cel-spec/",
    "w17.4": "tests/conformance/cel/test_w17_4_",
}


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Override the first item of the named suite with a forced failure.

    Activated only when ``RELAY_CONFORMANCE_FAULT_INJECT`` env var is
    set to one of the supported suite names. The hook replaces the
    first matching item's ``runtest`` with a callable that raises
    ``AssertionError``. This produces a hard pytest failure (non-zero
    exit) -- not an XFAIL -- so the release-block negative test can
    assert the injection caused a real failure.
    """

    suite = os.environ.get("RELAY_CONFORMANCE_FAULT_INJECT", "").strip()
    if not suite:
        return
    fragment = _SUITE_NODEID_FRAGMENTS.get(suite)
    if fragment is None:
        return
    # Normalise nodeids to forward-slashes for cross-platform matching.
    for item in items:
        nodeid_norm = item.nodeid.replace(os.sep, "/")
        if fragment in nodeid_norm:
            def _forced_fail(suite_name: str = suite) -> None:
                raise AssertionError(
                    f"RELAY_CONFORMANCE_FAULT_INJECT={suite_name}: "
                    "fault-injected failure (W17.4 release-block negative test)"
                )

            item.runtest = _forced_fail  # type: ignore[method-assign]
            # Only the first matching item should fail; break after
            # patching so the suite still reports the rest as normal.
            break


__all__ = ["pytest_collection_modifyitems"]
