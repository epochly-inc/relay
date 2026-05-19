#!/usr/bin/env python3
"""VAL-V3M2-001/002/003 OpenAPI route coverage + structural validity.

Enumerates every FastAPI route registered by the sidecar runtime
(``apps/local-sidecar/relay_sidecar/runtime.py`` plus the routers it
include_router()s and the health-route helper it composes) and asserts:

  VAL-V3M2-001  Set-equality between the FastAPI route set and the
                ``paths:`` section of ``packages/schemas/raw/openapi.yaml``.
                Every registered (method, path) pair MUST have a matching
                OpenAPI operation; every OpenAPI operation MUST resolve to
                a real FastAPI route. No extras, no missing entries.

  VAL-V3M2-002  Each OpenAPI operation entry declares the minimum
                contract surface the spec requires:
                  * ``summary`` (non-empty string)
                  * ``responses`` with at least one 2xx status code AND
                    at least one 4xx/5xx status code
                  * ``requestBody`` declared for POST/PUT/PATCH operations
                If ``openapi-spec-validator`` is importable it is also
                run for full OpenAPI 3.x structural validation; otherwise
                we surface a single warning and rely on the in-script
                checks (which cover the spec's enumerated requirements).

  VAL-V3M2-003  ``operationId`` is globally unique across the document.

The script enumerates routes via Python AST so it does not need the
FastAPI runtime stack (and therefore does not import sidecar modules
that have heavy import-time side effects). The decorator forms it
recognises are::

    @app.get("/v1/foo")
    @app.post("/v1/foo")
    @app.put("/v1/foo")
    @app.delete("/v1/foo")
    @app.patch("/v1/foo")
    @router.<verb>(...)        # via include_router()

Routes whose path starts with ``/v1`` or ``/diagnostics`` are in scope.
The ``/health`` + ``/health/nonce`` routes registered by
``_register_health_routes`` are out of scope per the contract (which
restricts coverage to the OpenAPI ``paths:`` surface; health is a
non-versioned liveness contract).

Exit code 0 on success, 1 on any drift.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]

# Files we AST-scan to enumerate the FastAPI route surface. The list is
# explicit so a new router source added to the sidecar must be wired
# into this script in the same PR.
SOURCE_FILES = (
    REPO_ROOT / "apps" / "local-sidecar" / "relay_sidecar" / "runtime.py",
    REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "relay_sidecar"
    / "state_engine"
    / "http_endpoint.py",
)

OPENAPI_PATH = REPO_ROOT / "packages" / "schemas" / "raw" / "openapi.yaml"

# Path prefixes considered "in scope" for the OpenAPI route-coverage
# contract. /health is excluded per the rationale in the module docstring.
SCOPED_PREFIXES = ("/v1", "/diagnostics")

HTTP_VERBS = frozenset({"get", "post", "put", "delete", "patch"})

MUTATING_VERBS = frozenset({"post", "put", "patch"})


def _decorator_method_and_path(
    decorator: ast.expr,
) -> tuple[str, str] | None:
    """Return (method, path) for a recognised FastAPI route decorator.

    Recognises ``@app.<verb>(path)`` and ``@router.<verb>(path)`` where
    ``<verb>`` is one of get/post/put/delete/patch and ``path`` is a
    string literal. Returns None for anything else (including dynamic
    paths, which the contract does not permit).
    """
    if not isinstance(decorator, ast.Call):
        return None
    func = decorator.func
    if not isinstance(func, ast.Attribute):
        return None
    method = func.attr.lower()
    if method not in HTTP_VERBS:
        return None
    # The decorator target object (app / router) is recorded by name
    # but we deliberately do not constrain it: include_router'd routers
    # carry their own variable name. Constraining to {app, router}
    # would create false negatives if the codebase ever renames.
    if not decorator.args:
        return None
    arg0 = decorator.args[0]
    if not isinstance(arg0, ast.Constant) or not isinstance(arg0.value, str):
        return None
    return method, arg0.value


def _enumerate_routes(source_files: Iterable[Path]) -> set[tuple[str, str]]:
    """Walk each source file's AST and collect (method, path) tuples.

    Iterates all function and async-function defs (including nested
    defs inside factory functions like ``build_runtime_app``) and
    inspects their ``decorator_list``. Filters to SCOPED_PREFIXES.
    """
    routes: set[tuple[str, str]] = set()
    for path in source_files:
        if not path.exists():
            raise FileNotFoundError(
                f"AST-scan source not found: {path.relative_to(REPO_ROOT)}"
            )
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for dec in node.decorator_list:
                pair = _decorator_method_and_path(dec)
                if pair is None:
                    continue
                method, route_path = pair
                if not route_path.startswith(SCOPED_PREFIXES):
                    continue
                routes.add((method, route_path))
    return routes


def _enumerate_openapi_paths(doc: dict[str, Any]) -> set[tuple[str, str]]:
    """Collect (method, path) tuples from the openapi.yaml paths: block."""
    pairs: set[tuple[str, str]] = set()
    paths = doc.get("paths") or {}
    if not isinstance(paths, dict):
        raise TypeError(
            f"openapi.yaml paths: must be a mapping, got {type(paths).__name__}"
        )
    for route_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method in methods:
            if method.lower() in HTTP_VERBS:
                pairs.add((method.lower(), route_path))
    return pairs


def _collect_operation_ids(doc: dict[str, Any]) -> list[str]:
    """Return all operationId values across the document."""
    ids: list[str] = []
    paths = doc.get("paths") or {}
    if not isinstance(paths, dict):
        return ids
    for _route_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in HTTP_VERBS:
                continue
            if not isinstance(operation, dict):
                continue
            op_id = operation.get("operationId")
            if isinstance(op_id, str):
                ids.append(op_id)
    return ids


def _validate_operation_shape(
    method: str, route_path: str, operation: dict[str, Any]
) -> list[str]:
    """Return a list of per-operation defects (empty list = clean).

    Enforces VAL-V3M2-002's minimum surface:
      * summary present and non-empty
      * responses present with >=1 2xx AND >=1 4xx/5xx status
      * requestBody present for POST/PUT/PATCH
      * operationId present and non-empty (required for VAL-V3M2-003)
    """
    defects: list[str] = []
    label = f"{method.upper()} {route_path}"

    summary = operation.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        defects.append(f"{label}: missing or empty 'summary'")

    op_id = operation.get("operationId")
    if not isinstance(op_id, str) or not op_id.strip():
        defects.append(f"{label}: missing or empty 'operationId'")

    responses = operation.get("responses")
    if not isinstance(responses, dict) or not responses:
        defects.append(f"{label}: missing or empty 'responses'")
    else:
        status_codes = [str(code) for code in responses]
        has_2xx = any(code.startswith("2") for code in status_codes)
        has_err = any(code.startswith(("4", "5")) for code in status_codes)
        if not has_2xx:
            defects.append(
                f"{label}: responses lacks any 2xx status code (found {status_codes})"
            )
        if not has_err:
            defects.append(
                f"{label}: responses lacks any 4xx/5xx status code (found {status_codes})"
            )

    if method in MUTATING_VERBS and "requestBody" not in operation:
        defects.append(f"{label}: {method.upper()} operation missing 'requestBody'")

    return defects


def _run_openapi_spec_validator(doc: dict[str, Any]) -> tuple[bool, str]:
    """Run openapi-spec-validator if importable.

    Returns (ok, message). When the package is not installed the tool
    is skipped and we return (True, "<skipped>"). When the package is
    installed and the document is invalid we return (False, error).
    """
    try:
        from openapi_spec_validator import (  # type: ignore[import-not-found]
            validate_spec,
        )
    except Exception:  # noqa: BLE001 -- import-time issues are best-effort
        return True, "openapi-spec-validator not installed (skipped)"
    try:
        validate_spec(doc)
    except Exception as exc:  # noqa: BLE001 -- the validator raises many subtypes
        return False, f"openapi-spec-validator error: {exc}"
    return True, "openapi-spec-validator: ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--openapi",
        type=Path,
        default=OPENAPI_PATH,
        help="Path to openapi.yaml (default: packages/schemas/raw/openapi.yaml)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-failure output; exit code is authoritative.",
    )
    args = parser.parse_args(argv)

    fastapi_routes = _enumerate_routes(SOURCE_FILES)
    doc = yaml.safe_load(args.openapi.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        print(
            f"FAIL: {args.openapi} did not parse as a mapping document",
            file=sys.stderr,
        )
        return 1

    openapi_routes = _enumerate_openapi_paths(doc)

    failures: list[str] = []

    # VAL-V3M2-001: set equality between FastAPI registration and OpenAPI doc.
    missing_in_openapi = sorted(fastapi_routes - openapi_routes)
    extra_in_openapi = sorted(openapi_routes - fastapi_routes)
    for method, route_path in missing_in_openapi:
        failures.append(
            f"VAL-V3M2-001: route {method.upper()} {route_path} "
            "is registered in FastAPI but missing from openapi.yaml"
        )
    for method, route_path in extra_in_openapi:
        failures.append(
            f"VAL-V3M2-001: route {method.upper()} {route_path} "
            "is declared in openapi.yaml but has no matching FastAPI handler"
        )

    # VAL-V3M2-002: per-operation shape (summary + responses + requestBody).
    paths = doc.get("paths") or {}
    if isinstance(paths, dict):
        for route_path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if method.lower() not in HTTP_VERBS:
                    continue
                if not isinstance(operation, dict):
                    failures.append(
                        f"VAL-V3M2-002: {method.upper()} {route_path}: "
                        f"operation must be a mapping, got {type(operation).__name__}"
                    )
                    continue
                defects = _validate_operation_shape(
                    method.lower(), route_path, operation
                )
                for d in defects:
                    failures.append(f"VAL-V3M2-002: {d}")

    # VAL-V3M2-003: operationId uniqueness.
    op_ids = _collect_operation_ids(doc)
    duplicates = [op_id for op_id, count in Counter(op_ids).items() if count > 1]
    for op_id in sorted(duplicates):
        failures.append(
            f"VAL-V3M2-003: operationId '{op_id}' is declared on more than one operation"
        )

    # Optional reinforcement: full OpenAPI 3.x structural validation.
    spec_validator_ok, spec_validator_msg = _run_openapi_spec_validator(doc)
    if not spec_validator_ok:
        failures.append(f"VAL-V3M2-002: {spec_validator_msg}")

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        print(
            f"FAIL: {len(failures)} OpenAPI coverage/shape defect(s); "
            f"FastAPI routes={len(fastapi_routes)}, OpenAPI routes={len(openapi_routes)}",
            file=sys.stderr,
        )
        return 1

    if not args.quiet:
        print(
            "PASS: OpenAPI route coverage "
            f"({len(fastapi_routes)} FastAPI routes == {len(openapi_routes)} OpenAPI ops); "
            f"{len(op_ids)} operationIds unique; {spec_validator_msg}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
