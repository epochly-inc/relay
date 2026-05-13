"""Minimal error-code constant generator (W1.4 stopgap).

Reads ``packages/schemas/raw/relay-error-codes.yaml`` and emits:

  - ``packages/schemas/python/relay_schemas/error_codes.py``
    (RelayErrorCode dataclass-style constant container)
  - ``packages/schemas/typescript/src/error_codes.ts``
    (RelayErrorCode object literal + TS type)

The W1.5 codegen pipeline (datamodel-code-generator + openapi-typescript)
will replace this minimal generator with a full pipeline + drift check.
The YAML format here is intentionally compatible: a flat ``codes: [...]``
list of ``RELAY-{AREA}-NNN`` tokens. The generator turns each token into a
constant by replacing hyphens with underscores.

ASCII-only per CLAUDE.md "ASCII-Safe Source". Re-runnable; deterministic
output for a given input YAML.

Usage::

    uv run python packages/schemas/scripts/gen_error_codes.py

Exit code 0 = generated outputs in sync. Exit code 1 = YAML parse failure
or invalid token format.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
YAML_PATH = REPO_ROOT / "packages" / "schemas" / "raw" / "relay-error-codes.yaml"
PY_OUT_PATH = (
    REPO_ROOT / "packages" / "schemas" / "python" / "relay_schemas" / "error_codes.py"
)
TS_OUT_PATH = (
    REPO_ROOT / "packages" / "schemas" / "typescript" / "src" / "error_codes.ts"
)

# Per VAL-W1-029, every code MUST match this pattern. The generator refuses
# to emit a constant for any token violating it. This catches typos in the
# canonical YAML at generator-run time.
_TOKEN_PATTERN = r"^RELAY-[A-Z]+-[0-9]{3}$"


def _load_codes() -> list[str]:
    import re

    text = YAML_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or "codes" not in data:
        raise SystemExit(
            f"FAIL: {YAML_PATH} missing top-level 'codes' key"
        )
    codes = data["codes"]
    if not isinstance(codes, list) or not all(isinstance(c, str) for c in codes):
        raise SystemExit(
            f"FAIL: {YAML_PATH}: codes MUST be a list of strings"
        )
    pattern = re.compile(_TOKEN_PATTERN)
    for code in codes:
        if not pattern.match(code):
            raise SystemExit(
                f"FAIL: code {code!r} does not match {_TOKEN_PATTERN}"
            )
    # Sort for deterministic output independent of YAML ordering.
    return sorted(set(codes))


def _to_constant_name(token: str) -> str:
    """Convert ``RELAY-ING-031`` -> ``RELAY_ING_031``."""
    return token.replace("-", "_")


PY_HEADER = '''"""Generated Relay error-code constants (DO NOT EDIT BY HAND).

Source: ``packages/schemas/raw/relay-error-codes.yaml``.
Generator: ``packages/schemas/scripts/gen_error_codes.py``.

W1.5 will replace this minimal generator with the full codegen pipeline
(datamodel-code-generator + openapi-typescript + drift check). Until then,
re-run ``python packages/schemas/scripts/gen_error_codes.py`` after editing
the YAML.

ASCII-only per CLAUDE.md "ASCII-Safe Source".

VAL-W1-030 evidence: every documented RELAY-* code from spec section B.4
appears as a constant on ``RelayErrorCode``.
"""

from __future__ import annotations

from typing import Final


class RelayErrorCode:
    """Container for canonical Relay error-code string constants.

    Each constant value is the wire-format token (e.g., ``"RELAY-ING-031"``).
    Attribute names mirror the wire token with hyphens replaced by
    underscores (e.g., ``RelayErrorCode.RELAY_ING_031``).

    Per VAL-W1-029, every token matches ``^RELAY-[A-Z]+-[0-9]{3}$``. The
    generator refuses to emit constants for tokens violating that pattern.
    """

'''

TS_HEADER = """/**
 * Generated Relay error-code constants (DO NOT EDIT BY HAND).
 *
 * Source: packages/schemas/raw/relay-error-codes.yaml.
 * Generator: packages/schemas/scripts/gen_error_codes.py.
 *
 * W1.5 will replace this minimal generator with the full codegen pipeline.
 * Until then, re-run `python packages/schemas/scripts/gen_error_codes.py`
 * after editing the YAML.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 *
 * VAL-W1-030 evidence: every documented RELAY-* code from spec section B.4
 * appears as a constant on `RelayErrorCode`.
 */

"""


def _render_python(codes: list[str]) -> str:
    lines: list[str] = [PY_HEADER]
    for code in codes:
        name = _to_constant_name(code)
        lines.append(f'    {name}: Final[str] = "{code}"\n')
    lines.append("\n")
    # Frozenset of all known codes for membership checks at runtime.
    lines.append("    @classmethod\n")
    lines.append("    def all(cls) -> frozenset[str]:\n")
    lines.append('        """Return the frozenset of every known wire-format code."""\n')
    lines.append("        return _ALL_CODES\n")
    lines.append("\n\n")
    lines.append("_ALL_CODES: Final[frozenset[str]] = frozenset({\n")
    for code in codes:
        lines.append(f'    "{code}",\n')
    lines.append("})\n")
    lines.append("\n")
    lines.append(
        "__all__ = [\"RelayErrorCode\"]\n"
    )
    return "".join(lines)


def _render_typescript(codes: list[str]) -> str:
    lines: list[str] = [TS_HEADER]
    lines.append("export const RelayErrorCode = {\n")
    for code in codes:
        name = _to_constant_name(code)
        lines.append(f'  {name}: "{code}",\n')
    lines.append("} as const;\n\n")
    lines.append(
        "export type RelayErrorCodeToken = "
        "(typeof RelayErrorCode)[keyof typeof RelayErrorCode];\n\n"
    )
    lines.append("export const RELAY_ERROR_CODE_SET: ReadonlySet<string> = new Set<string>([\n")
    for code in codes:
        lines.append(f'  "{code}",\n')
    lines.append("]);\n")
    return "".join(lines)


def main() -> int:
    codes = _load_codes()
    py_text = _render_python(codes)
    ts_text = _render_typescript(codes)
    PY_OUT_PATH.write_text(py_text, encoding="utf-8")
    TS_OUT_PATH.write_text(ts_text, encoding="utf-8")
    print(f"OK: wrote {len(codes)} codes to {PY_OUT_PATH.name} and {TS_OUT_PATH.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
