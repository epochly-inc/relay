"""Guard test: exit code 7 is removed from the CLI's canonical tables.

VAL-V2M07-029: a grep guard test asserts that recursive
``grep -rn "code.*[^0-9]7[^0-9]" packages/cli/src/`` finds no exit-code-7
declarations in the CLI source. The test fails if code 7 reappears in
any of the canonical-table-bearing files.

The historical OSS exit code 7 (EXIT_GATE_TTL_EXPIRED, RELAY-GATE-024)
was a divergence from the spec §P.1 canonical table. Per VAL-V2M07-028
the CLI's table now omits this row; RELAY-GATE-024 maps to exit 4
(transient) per VAL-V2M07-016. The SDK retains EXIT_GATE_TTL_EXPIRED=7
for cross-language parity at the SDK layer.

Re-introducing the row in the CLI tables would re-create the divergence;
this guard ensures any such PR is caught by CI.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# File lives at <repo>/tests/contract/cli/test_exit_code_7_removed.py;
# parents[0]=cli, [1]=contract, [2]=tests, [3]=<repo root>.
REPO_ROOT = Path(__file__).resolve().parents[3]
CLI_SRC = REPO_ROOT / "packages" / "cli" / "src" / "relay_cli"

# Pattern: a "7" surrounded by non-digit characters, after a "code"-prefix
# context. Matches `"code": 7,` and `"code":7,` and `"code": 7}` etc.,
# but does NOT match `"code": 70` or `"code": 130` (digits adjacent).
# Mirrors the grep the contract specifies: `code.*[^0-9]7[^0-9]`.
_CODE_7_RE = re.compile(r"code.*[^0-9]7[^0-9]")


def _strip_docstrings_and_comments(source: str) -> str:
    """Drop triple-quoted strings and single-line # comments from source."""
    stripped = re.sub(
        r'("""(?:\\.|(?!""").)*"""|\'\'\'(?:\\.|(?!\'\'\').)*\'\'\')',
        "",
        source,
        flags=re.MULTILINE | re.DOTALL,
    )
    stripped = re.sub(r"#.*$", "", stripped, flags=re.MULTILINE)
    return stripped


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-029")
def test_no_exit_code_7_in_cli_runtime_tables() -> None:
    """Recursive grep of CLI source for exit-code-7 declarations.

    Strips docstrings + comments first so prose mentions of "exit code 7"
    or "EXIT_GATE_TTL_EXPIRED" in module-level documentation do not
    trigger a false positive.
    """
    if not CLI_SRC.exists():
        pytest.fail(
            f"CLI source root not found at {CLI_SRC}; cannot run guard"
        )
    offenders: list[tuple[str, int, str]] = []
    for py in CLI_SRC.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        stripped = _strip_docstrings_and_comments(text)
        for idx, line in enumerate(stripped.splitlines(), start=1):
            if _CODE_7_RE.search(line):
                offenders.append((str(py.relative_to(REPO_ROOT)), idx, line.strip()))
    assert not offenders, (
        "VAL-V2M07-029: exit code 7 (RELAY-GATE-024 / "
        "EXIT_GATE_TTL_EXPIRED) MUST NOT appear in CLI canonical tables; "
        f"found {len(offenders)} occurrence(s): {offenders}"
    )
