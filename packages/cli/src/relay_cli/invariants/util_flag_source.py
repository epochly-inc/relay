"""Source-file flag parsing for the crypto-implemented invariants.

VAL-ISO-005: the ``*-verifier-implemented`` checks must read the
``*_CRYPTO_IMPLEMENTED`` flag from the SOURCE FILE under the operator's
``repo_root`` rather than importing the installed package on ``sys.path``.
This module owns the single shared parser used by ``sigstore_verifier``,
``rekor_verifier``, and ``tsa_verifier`` so the three checks share one
deterministic, import-free implementation.

The parser is pure: it reads a file's text and walks its AST. It does NOT
import or execute the module under test, so a flag flipped to ``False`` in
a checked-out source tree is observed even when the installed wheel ships
``True``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ast
from pathlib import Path

__all__ = ["resolve_bool_flag_from_source"]


def _bool_from_node(node: ast.expr) -> bool | None:
    """Return the boolean value of a literal ``True``/``False`` node.

    Returns ``None`` for any non-boolean expression (e.g. a name, a call,
    a non-bool constant). Only an explicit boolean literal counts as a
    resolved flag value; anything else is treated as unresolved so the
    caller fails closed.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def resolve_bool_flag_from_source(
    source_path: Path, flag_name: str
) -> bool | None:
    """Parse the value of a module-level ``flag_name = <bool>`` assignment.

    Handles both annotated (``flag_name: Final[bool] = True``) and plain
    (``flag_name = True``) module-level assignments. Returns:

      * ``True`` / ``False`` when the assignment is found and its
        right-hand side is a boolean literal,
      * ``None`` when the source file is absent/unreadable, cannot be
        parsed, the assignment is missing, or the value is not a boolean
        literal.

    The caller treats ``None`` as a fail-closed finding: an absent or
    non-literal canonical flag declaration is itself a regression of the
    verified surface.

    Only module-level (top-level) assignments are considered, so a
    same-named local inside a function or a class attribute cannot shadow
    the canonical constant.
    """
    if not source_path.is_file():
        return None
    try:
        text = source_path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None

    for stmt in tree.body:
        # Annotated assignment: ``NAME: Final[bool] = <value>``.
        if isinstance(stmt, ast.AnnAssign):
            target = stmt.target
            if (
                isinstance(target, ast.Name)
                and target.id == flag_name
                and stmt.value is not None
            ):
                return _bool_from_node(stmt.value)
        # Plain assignment: ``NAME = <value>`` (or ``NAME = OTHER = ...``).
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == flag_name:
                    return _bool_from_node(stmt.value)
    return None
