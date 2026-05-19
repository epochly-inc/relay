"""V3 M02 F04 pagination coverage check (VAL-V3M2-008).

Enumerates every ``@app.get(...)`` route in
``apps/local-sidecar/relay_sidecar/runtime.py`` whose 200-status response
body is a JSON object containing at least one list-valued field, and
asserts the response body also exposes a ``next_cursor`` field plus
declares a ``cursor`` query parameter.

A route is classified as a *list endpoint* when its handler's body
contains a successful ``JSONResponse(status_code=200, content={...})``
(or an implicit-200 dict return) whose top-level dict literal contains
at least one key whose value is one of:

  * a ``List`` / ``Tuple`` / ``Set`` literal,
  * a list / set / dict comprehension,
  * a Name reference whose binding within the same function is a
    ``List``/``ListComp``/``GeneratorExp``/`list(...)` call.

The following keys are NEVER considered "collections" because they are
metadata, not first-class list payloads: ``next_cursor``, ``cursor``,
``has_more``, ``rate_limit``, ``trust_anchor``, ``headers``, ``hypotheses``
counts (anything ending in ``_count``).

Exit codes:
  0 -- every list endpoint exposes ``next_cursor`` + ``cursor`` query param.
  1 -- one or more list endpoints lack pagination coverage. Offending
       routes printed to stdout as JSON.
  2 -- infrastructure error (runtime.py not found / parse failure).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_PATH = (
    REPO_ROOT / "apps" / "local-sidecar" / "relay_sidecar" / "runtime.py"
)

# Top-level keys that are pagination/transport metadata, not collection
# payloads. A response whose only list-like key is one of these is NOT
# classified as a list endpoint.
META_KEYS = frozenset(
    {
        "next_cursor",
        "cursor",
        "has_more",
        "rate_limit",
        "trust_anchor",
        "headers",
    }
)

# Routes that are intentionally not paginated even though they return
# collections. Each entry MUST come with a written justification so the
# allowlist does not silently grow.
ALLOWLIST: dict[str, str] = {
    # /diagnostics/db returns a small, bounded ``readers`` array whose
    # length is the SidecarDatabase reader-pool size (typically 2-4,
    # capped by the pool config). The endpoint is an in-process
    # introspection surface used by VAL-W2-023 + runbooks, not a
    # user-facing collection. Paginating it would force test fixtures
    # and operators to iterate a single-page-worth of static rows for
    # no benefit, and would add cursor signing to a path that runs
    # before the cursor-signing key is necessarily initialised in
    # some recovery scenarios.
    "/diagnostics/db": (
        "bounded reader-pool diagnostic (size <= reader_count), not a "
        "user-facing list payload"
    ),
}


def _is_app_get(decorator: ast.expr) -> str | None:
    """Return the route path string if ``decorator`` is ``@app.get(<path>)``.

    Returns None otherwise.
    """
    if not isinstance(decorator, ast.Call):
        return None
    func = decorator.func
    if not isinstance(func, ast.Attribute):
        return None
    if func.attr != "get":
        return None
    if not isinstance(func.value, ast.Name) or func.value.id != "app":
        return None
    if not decorator.args:
        return None
    first = decorator.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def _collect_local_bindings(
    func: ast.AsyncFunctionDef | ast.FunctionDef,
) -> dict[str, ast.expr]:
    """Collect ``name -> value-expression`` for assignments local to ``func``.

    For each ``x = <expr>`` (and ``x: T = <expr>`` annotated assigns) at
    any depth inside the function body, record the last binding seen.
    Multi-target assignments (``a = b = ...``) bind every target. This
    is a single-pass best-effort flow-insensitive scan; we use it to
    decide whether a Name referenced inside a content dict ultimately
    points at a list/list-comprehension.
    """
    bindings: dict[str, ast.expr] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and node.value is not None
            and isinstance(node.target, ast.Name)
        ):
            bindings[node.target.id] = node.value
    return bindings


def _looks_like_list(
    expr: ast.expr, bindings: dict[str, ast.expr], _depth: int = 0
) -> bool:
    """Return True if ``expr`` looks like a JSON-array value at response time."""
    if _depth > 8:
        return False
    if isinstance(expr, ast.List | ast.Tuple | ast.Set):
        return True
    if isinstance(expr, ast.ListComp | ast.SetComp | ast.GeneratorExp):
        return True
    if isinstance(expr, ast.DictComp):
        return False
    if isinstance(expr, ast.Call):
        func = expr.func
        if isinstance(func, ast.Name) and func.id in {"list", "tuple", "sorted"}:
            return True
        return isinstance(func, ast.Attribute) and func.attr in {
            "fetchall",
            "split",
            "values",
            "items",
            "keys",
        }
    if isinstance(expr, ast.Subscript):
        # Slicing a list/tuple yields a list/tuple.
        return _looks_like_list(expr.value, bindings, _depth + 1)
    if isinstance(expr, ast.Name):
        # Resolve through the local binding table once.
        bound = bindings.get(expr.id)
        if bound is not None and bound is not expr:
            return _looks_like_list(bound, bindings, _depth + 1)
        # Names commonly used for list payloads in this file.
        return expr.id in {"items", "spans", "hypotheses", "rounds", "rows"}
    return False


def _iter_jsonresponse_dict_contents(
    func: ast.AsyncFunctionDef | ast.FunctionDef,
) -> Iterable[ast.Dict]:
    """Yield each dict literal passed as ``content=`` to a successful response.

    Successful means ``status_code`` is omitted (FastAPI default 200) or
    explicitly ``200``/``201``/``202``. Error envelopes (4xx/5xx) are
    skipped because they never carry collection payloads.
    """
    for node in ast.walk(func):
        # Plain ``return {...}`` (FastAPI infers 200).
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            yield node.value
            continue
        if not isinstance(node, ast.Call):
            continue
        func_expr = node.func
        if isinstance(func_expr, ast.Name):
            name = func_expr.id
        elif isinstance(func_expr, ast.Attribute):
            name = func_expr.attr
        else:
            continue
        if name != "JSONResponse":
            continue
        # Detect status code (default 200).
        status_value: int | None = 200
        for kw in node.keywords:
            if kw.arg == "status_code":
                if isinstance(kw.value, ast.Constant) and isinstance(
                    kw.value.value, int
                ):
                    status_value = kw.value.value
                else:
                    status_value = None
                break
        if status_value is None or not (200 <= status_value < 300):
            continue
        # Find content=
        content_expr: ast.expr | None = None
        for kw in node.keywords:
            if kw.arg == "content":
                content_expr = kw.value
                break
        if content_expr is None and node.args:
            # Positional: JSONResponse(<content>, status_code=...)
            content_expr = node.args[0]
        if isinstance(content_expr, ast.Dict):
            yield content_expr


def _dict_top_keys(d: ast.Dict) -> dict[str, ast.expr]:
    """Return ``{constant_str_key: value_expr}`` for a Dict literal."""
    out: dict[str, ast.expr] = {}
    for k, v in zip(d.keys, d.values, strict=True):
        if (
            isinstance(k, ast.Constant)
            and isinstance(k.value, str)
            and v is not None
        ):
            out[k.value] = v
    return out


def _has_cursor_param(func: ast.AsyncFunctionDef | ast.FunctionDef) -> bool:
    """Return True iff handler declares a ``cursor`` query parameter."""
    args = func.args
    candidates: list[ast.arg] = []
    candidates.extend(args.args)
    candidates.extend(args.kwonlyargs)
    return any(a.arg == "cursor" for a in candidates)


def analyze(source: str) -> tuple[list[dict], list[dict]]:
    """Return ``(list_endpoints, offenders)`` from ``runtime.py`` source."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:  # pragma: no cover - infrastructure failure
        print(
            json.dumps(
                {
                    "error": "RELAY-PAGE-COVERAGE-PARSE",
                    "message": f"failed to parse runtime.py: {exc}",
                }
            )
        )
        sys.exit(2)

    list_endpoints: list[dict] = []
    offenders: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            continue
        # Find any @app.get(<path>) decorator (could be one of several).
        path: str | None = None
        for dec in node.decorator_list:
            p = _is_app_get(dec)
            if p is not None:
                path = p
                break
        if path is None:
            continue

        bindings = _collect_local_bindings(node)
        is_list = False
        has_next_cursor = False
        list_keys_found: list[str] = []
        for content_dict in _iter_jsonresponse_dict_contents(node):
            keys = _dict_top_keys(content_dict)
            if "next_cursor" in keys:
                has_next_cursor = True
            for key, value in keys.items():
                if key in META_KEYS:
                    continue
                if key.endswith("_count"):
                    continue
                if _looks_like_list(value, bindings):
                    is_list = True
                    list_keys_found.append(key)

        if not is_list:
            continue

        record = {
            "route": f"GET {path}",
            "handler": node.name,
            "list_keys": sorted(set(list_keys_found)),
            "has_next_cursor": has_next_cursor,
            "has_cursor_param": _has_cursor_param(node),
        }
        list_endpoints.append(record)

        if path in ALLOWLIST:
            continue
        if not has_next_cursor or not _has_cursor_param(node):
            offenders.append(
                {
                    **record,
                    "reason": (
                        "missing next_cursor field in response"
                        if not has_next_cursor
                        else "missing cursor query param on handler"
                    ),
                }
            )

    return list_endpoints, offenders


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify every GET list endpoint in runtime.py exposes "
            "next_cursor (VAL-V3M2-008)."
        )
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON report on stdout",
    )
    parser.add_argument(
        "--runtime",
        type=Path,
        default=RUNTIME_PATH,
        help="path to runtime.py (default: apps/local-sidecar/...)",
    )
    args = parser.parse_args(argv)

    if not args.runtime.is_file():
        print(
            json.dumps(
                {
                    "error": "RELAY-PAGE-COVERAGE-MISSING-RUNTIME",
                    "path": str(args.runtime),
                }
            )
        )
        return 2

    source = args.runtime.read_text(encoding="utf-8")
    list_endpoints, offenders = analyze(source)

    if args.json:
        print(
            json.dumps(
                {
                    "list_endpoints": list_endpoints,
                    "offenders": offenders,
                    "total_list_endpoints": len(list_endpoints),
                    "total_offenders": len(offenders),
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        offender_paths = {o["route"] for o in offenders}
        print(f"list endpoints discovered: {len(list_endpoints)}")
        for r in list_endpoints:
            paginated = r["has_next_cursor"] and r["has_cursor_param"]
            route_path = r["route"].split(" ", 1)[1]
            if paginated:
                mark = "OK"
            elif route_path in ALLOWLIST:
                mark = "SKIP"
            elif r["route"] in offender_paths:
                mark = "FAIL"
            else:
                mark = "OK"
            print(
                f"  [{mark}] {r['route']} "
                f"(keys={r['list_keys']}, "
                f"cursor_param={r['has_cursor_param']}, "
                f"next_cursor={r['has_next_cursor']})"
            )
        if offenders:
            print("")
            print(f"PAGINATION COVERAGE FAILED: {len(offenders)} offender(s)")
            for o in offenders:
                print(f"  - {o['route']}: {o['reason']}")

    return 1 if offenders else 0


if __name__ == "__main__":
    sys.exit(main())
