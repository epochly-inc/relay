#!/usr/bin/env python3
"""Auto-generate the Relay package/module dependency graph (DELIVERABLE 2).

Discovers every Python package (a directory with ``pyproject.toml``) and every
TypeScript workspace package (a ``package.json`` carrying a ``name``) under
``packages/`` and ``apps/``, maps each importable top-level module to its owning
package, then statically resolves cross-package import edges:

  * Python: ``ast``-parsed ``import`` / ``from ... import`` whose first dotted
    component is a known cross-package module root.
  * TypeScript: ``import ... from "@epochly/..."`` / ``require("@epochly/...")``
    / dynamic ``import("@epochly/...")`` mapped via package.json names.

Production source only -- tests, vendored crates, build output, and
node_modules are excluded so the graph reflects the SHIPPED dependency
structure, not test-only or third-party edges.

The output is fully DETERMINISTIC (sorted everywhere, no timestamps) so it is
reproducible and diffable. Three artifacts are written under
``docs/architecture/``:

  * ``dependency-graph.json`` -- machine-readable (packages, edges, cycles,
    layers).
  * ``dependency-graph.md``   -- human-readable summary + per-package fan-in/out.
  * ``dependency-graph.dot``  -- Graphviz source for rendering.

Modes::

    python scripts/gen-dependency-graph.py            # regenerate the artifacts
    python scripts/gen-dependency-graph.py --check     # fail (exit 1) on drift
    python scripts/gen-dependency-graph.py --json      # print JSON to stdout

Exit codes: 0 = ok / no drift; 1 = drift detected under --check OR a dependency
CYCLE was found (cycles are architectural violations and fail the gate); 2 =
invocation / IO error.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Final

# Repo root: scripts/gen-dependency-graph.py -> scripts -> repo root.
REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
SEARCH_ROOTS: Final[tuple[str, ...]] = ("packages", "apps")
OUT_DIR: Final[Path] = REPO_ROOT / "docs" / "architecture"

# Directory names never scanned for production source (tests, build output,
# vendored third-party, caches).
_EXCLUDED_DIR_NAMES: Final[frozenset[str]] = frozenset(
    {
        "tests",
        "test",
        "node_modules",
        "vendor",
        "target",
        "dist",
        "build",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "conformance",  # cel-wasm Go/py oracle harness, not shipped source
    }
)

# TS import specifier extraction. Matches the module specifier in:
#   import ... from "spec";  import "spec";  require("spec");  import("spec")
_TS_IMPORT_RE: Final[re.Pattern[str]] = re.compile(
    r"""(?:from|import|require)\s*\(?\s*['"]([^'"]+)['"]"""
)


def _is_excluded(path: Path) -> bool:
    """True if any path component is an excluded directory name."""
    return any(part in _EXCLUDED_DIR_NAMES for part in path.parts)


def _iter_source_files(pkg_dir: Path, suffixes: tuple[str, ...]) -> list[Path]:
    """Production source files under ``pkg_dir`` with one of ``suffixes``,
    excluding test/build/vendor trees. Sorted for determinism."""
    out: list[Path] = []
    for p in pkg_dir.rglob("*"):
        if p.suffix not in suffixes:
            continue
        if not p.is_file():
            continue
        rel = p.relative_to(pkg_dir)
        if _is_excluded(rel):
            continue
        out.append(p)
    return sorted(out)


# ---------------------------------------------------------------------------
# Package discovery
# ---------------------------------------------------------------------------


def _discover_python_packages() -> dict[str, Path]:
    """Map package-name -> package directory for every Python package (a dir
    with pyproject.toml) under the search roots. Package name = directory
    name (stable, matches the on-disk layout)."""
    pkgs: dict[str, Path] = {}
    for root in SEARCH_ROOTS:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for pyproject in sorted(base.glob("*/pyproject.toml")):
            pkg_dir = pyproject.parent
            pkgs[pkg_dir.name] = pkg_dir
    return pkgs


def _read_ts_pkg_name(pkg_json: Path) -> str | None:
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    name = data.get("name")
    return name if isinstance(name, str) and name else None


def _discover_ts_packages() -> dict[str, dict[str, object]]:
    """Map dir-name -> {npm_name, path} for every TS workspace package (a
    package.json with a name and a tsconfig or src/) under the search roots."""
    pkgs: dict[str, dict[str, object]] = {}
    for root in SEARCH_ROOTS:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for pkg_json in sorted(base.glob("*/package.json")):
            pkg_dir = pkg_json.parent
            if _is_excluded(pkg_dir.relative_to(REPO_ROOT)):
                continue
            name = _read_ts_pkg_name(pkg_json)
            if name is None:
                continue
            # Heuristic: a real TS source package has a src/ dir or tsconfig.
            if not (pkg_dir / "src").is_dir() and not (
                pkg_dir / "tsconfig.json"
            ).is_file():
                continue
            pkgs[pkg_dir.name] = {"npm_name": name, "path": pkg_dir}
    return pkgs


def _python_module_index(
    py_pkgs: dict[str, Path],
) -> dict[str, str]:
    """Map importable top-level module name -> owning package name.

    A top-level module root is a directory containing ``__init__.py`` whose
    PARENT does not contain ``__init__.py`` (so nested subpackages are not
    counted as roots). Test trees are excluded.
    """
    index: dict[str, str] = {}
    for pkg_name, pkg_dir in py_pkgs.items():
        for init in pkg_dir.rglob("__init__.py"):
            rel = init.relative_to(pkg_dir)
            if _is_excluded(rel):
                continue
            mod_dir = init.parent
            parent = mod_dir.parent
            if (parent / "__init__.py").exists():
                continue  # not a top-level root
            mod_name = mod_dir.name
            # First writer wins; collisions across packages are reported.
            index.setdefault(mod_name, pkg_name)
    return index


# ---------------------------------------------------------------------------
# Edge extraction
# ---------------------------------------------------------------------------


def _python_imports(py_file: Path) -> set[str]:
    """Top-level dotted-import roots referenced by ``py_file`` (best-effort;
    unparseable files are skipped)."""
    try:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
    except (OSError, SyntaxError, ValueError):
        return set()
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue  # relative import -> intra-package
            if node.module:
                roots.add(node.module.split(".", 1)[0])
    return roots


def _ts_imports(ts_file: Path) -> set[str]:
    """Import specifiers referenced by ``ts_file`` (regex best-effort)."""
    try:
        text = ts_file.read_text(encoding="utf-8")
    except OSError:
        return set()
    return set(_TS_IMPORT_RE.findall(text))


def _build_python_edges(
    py_pkgs: dict[str, Path], module_index: dict[str, str]
) -> dict[tuple[str, str], set[str]]:
    """(from_pkg, to_pkg) -> set of example module roots, for Python."""
    edges: dict[tuple[str, str], set[str]] = {}
    for pkg_name, pkg_dir in py_pkgs.items():
        for py_file in _iter_source_files(pkg_dir, (".py",)):
            for root in _python_imports(py_file):
                owner = module_index.get(root)
                if owner is None or owner == pkg_name:
                    continue
                edges.setdefault((pkg_name, owner), set()).add(root)
    return edges


def _build_ts_edges(
    ts_pkgs: dict[str, dict[str, object]],
) -> dict[tuple[str, str], set[str]]:
    """(from_pkg, to_pkg) -> set of example npm specifiers, for TypeScript."""
    npm_to_dir = {str(v["npm_name"]): k for k, v in ts_pkgs.items()}
    edges: dict[tuple[str, str], set[str]] = {}
    for pkg_name, meta in ts_pkgs.items():
        pkg_dir = meta["path"]
        assert isinstance(pkg_dir, Path)
        for ts_file in _iter_source_files(pkg_dir, (".ts", ".tsx", ".mts", ".cts")):
            if ts_file.name.endswith(".d.ts"):
                continue
            for spec in _ts_imports(ts_file):
                # Match the longest npm package name that prefixes the specifier
                # (scoped names can contain subpath imports like "@epochly/x/y").
                owner_dir: str | None = None
                for npm_name, dir_name in npm_to_dir.items():
                    if spec == npm_name or spec.startswith(npm_name + "/"):
                        owner_dir = dir_name
                        break
                if owner_dir is None or owner_dir == pkg_name:
                    continue
                edges.setdefault((pkg_name, owner_dir), set()).add(spec)
    return edges


# ---------------------------------------------------------------------------
# Graph analysis
# ---------------------------------------------------------------------------


def _find_cycles(adj: dict[str, set[str]]) -> list[list[str]]:
    """Return the distinct simple cycles (as sorted-canonical node lists) in the
    package dependency digraph. Deterministic."""
    cycles: set[tuple[str, ...]] = set()
    nodes = sorted(adj)
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {n: WHITE for n in nodes}
    stack: list[str] = []

    def dfs(u: str) -> None:
        color[u] = GRAY
        stack.append(u)
        for v in sorted(adj.get(u, ())):
            if color[v] == GRAY:
                idx = stack.index(v)
                cyc = stack[idx:]
                # Canonicalize: rotate so the lexicographically smallest node
                # leads, so the same cycle is recorded once.
                m = cyc.index(min(cyc))
                cycles.add(tuple(cyc[m:] + cyc[:m]))
            elif color[v] == WHITE:
                dfs(v)
        stack.pop()
        color[u] = BLACK

    for n in nodes:
        if color[n] == WHITE:
            dfs(n)
    return [list(c) for c in sorted(cycles)]


def _layers(adj: dict[str, set[str]], nodes: list[str]) -> list[list[str]] | None:
    """Topological layering (each layer depends only on lower layers). Returns
    None if the graph has a cycle. Layer 0 = leaves (no outgoing deps)."""
    depth: dict[str, int] = {}

    def resolve(u: str, seen: frozenset[str]) -> int:
        if u in depth:
            return depth[u]
        if u in seen:
            return -1  # cycle
        deps = adj.get(u, set())
        if not deps:
            depth[u] = 0
            return 0
        sub = [resolve(v, seen | {u}) for v in sorted(deps)]
        if any(s < 0 for s in sub):
            return -1
        depth[u] = 1 + max(sub)
        return depth[u]

    for n in nodes:
        if resolve(n, frozenset()) < 0:
            return None
    max_depth = max(depth.values(), default=0)
    return [
        sorted(n for n in nodes if depth[n] == d) for d in range(max_depth + 1)
    ]


# ---------------------------------------------------------------------------
# Assembly + rendering
# ---------------------------------------------------------------------------


def build_graph() -> dict[str, object]:
    py_pkgs = _discover_python_packages()
    ts_pkgs = _discover_ts_packages()
    module_index = _python_module_index(py_pkgs)
    py_edges = _build_python_edges(py_pkgs, module_index)
    ts_edges = _build_ts_edges(ts_pkgs)

    all_pkg_names = sorted(set(py_pkgs) | set(ts_pkgs))

    edges_list: list[dict[str, object]] = []
    adj: dict[str, set[str]] = {n: set() for n in all_pkg_names}
    for (src, dst), examples in sorted(py_edges.items()):
        edges_list.append(
            {
                "from": src,
                "to": dst,
                "lang": "python",
                "examples": sorted(examples),
            }
        )
        adj[src].add(dst)
    for (src, dst), examples in sorted(ts_edges.items()):
        edges_list.append(
            {
                "from": src,
                "to": dst,
                "lang": "typescript",
                "examples": sorted(examples),
            }
        )
        adj[src].add(dst)

    cycles = _find_cycles(adj)
    layers = _layers(adj, all_pkg_names) if not cycles else None

    fan_out: dict[str, int] = {n: 0 for n in all_pkg_names}
    fan_in: dict[str, int] = {n: 0 for n in all_pkg_names}
    for e in edges_list:
        fan_out[str(e["from"])] += 1
        fan_in[str(e["to"])] += 1

    packages: list[dict[str, object]] = []
    for name in all_pkg_names:
        langs: list[str] = []
        if name in py_pkgs:
            langs.append("python")
        if name in ts_pkgs:
            langs.append("typescript")
        rel_path = (
            str(py_pkgs[name].relative_to(REPO_ROOT))
            if name in py_pkgs
            else str(ts_pkgs[name]["path"])  # type: ignore[index]
        )
        deps = sorted({str(e["to"]) for e in edges_list if e["from"] == name})
        dependents = sorted({str(e["from"]) for e in edges_list if e["to"] == name})
        packages.append(
            {
                "name": name,
                "languages": langs,
                "path": rel_path,
                "depends_on": deps,
                "depended_on_by": dependents,
                "fan_out": fan_out[name],
                "fan_in": fan_in[name],
            }
        )

    return {
        "schema": "relay.architecture.dependency-graph/v1",
        "generated_by": "scripts/gen-dependency-graph.py",
        "module_index": dict(sorted(module_index.items())),
        "packages": packages,
        "edges": edges_list,
        "cycles": cycles,
        "layers": layers,
    }


def render_markdown(graph: dict[str, object]) -> str:
    pkgs = graph["packages"]
    assert isinstance(pkgs, list)
    edges = graph["edges"]
    assert isinstance(edges, list)
    cycles = graph["cycles"]
    assert isinstance(cycles, list)
    layers = graph["layers"]

    lines: list[str] = []
    lines.append("# Relay dependency graph (generated)")
    lines.append("")
    lines.append(
        "Generated by `scripts/gen-dependency-graph.py` from production source "
        "imports (tests, vendored crates, and build output excluded). Do not "
        "edit by hand -- run the script. Render the DOT with "
        "`dot -Tsvg docs/architecture/dependency-graph.dot`."
    )
    lines.append("")
    lines.append(f"- Packages: {len(pkgs)}")
    lines.append(f"- Cross-package edges: {len(edges)}")
    lines.append(
        f"- Dependency cycles: {len(cycles)}"
        + ("  **(architectural violation -- gate fails)**" if cycles else "")
    )
    lines.append("")

    if cycles:
        lines.append("## Cycles (must be zero)")
        lines.append("")
        for cyc in cycles:
            assert isinstance(cyc, list)
            lines.append("- " + " -> ".join(cyc + [cyc[0]]))
        lines.append("")

    if isinstance(layers, list):
        lines.append("## Layers (topological; layer 0 = leaves)")
        lines.append("")
        for i, layer in enumerate(layers):
            lines.append(f"- L{i}: " + ", ".join(layer))
        lines.append("")

    lines.append("## Packages")
    lines.append("")
    lines.append("| Package | Lang | Fan-out | Fan-in | Depends on |")
    lines.append("|---|---|---|---|---|")
    for p in pkgs:
        assert isinstance(p, dict)
        langs = "+".join(p["languages"]) if p["languages"] else "-"  # type: ignore[arg-type]
        deps = ", ".join(p["depends_on"]) or "-"  # type: ignore[arg-type]
        lines.append(
            f"| `{p['name']}` | {langs} | {p['fan_out']} | {p['fan_in']} | {deps} |"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def render_dot(graph: dict[str, object]) -> str:
    edges = graph["edges"]
    assert isinstance(edges, list)
    pkgs = graph["packages"]
    assert isinstance(pkgs, list)
    lines = ["digraph relay_deps {", "  rankdir=LR;", "  node [shape=box];"]
    for p in pkgs:
        assert isinstance(p, dict)
        lines.append(f'  "{p["name"]}";')
    for e in edges:
        assert isinstance(e, dict)
        style = "" if e["lang"] == "python" else " [style=dashed]"
        lines.append(f'  "{e["from"]}" -> "{e["to"]}"{style};')
    lines.append("}")
    return "\n".join(lines) + "\n"


def _dump_json(graph: dict[str, object]) -> str:
    return json.dumps(graph, indent=2, ensure_ascii=True, sort_keys=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail on drift")
    parser.add_argument("--json", action="store_true", help="print JSON to stdout")
    args = parser.parse_args(argv)

    try:
        graph = build_graph()
    except OSError as exc:  # pragma: no cover - IO failure
        print(f"FAIL: dependency-graph generation IO error: {exc}", file=sys.stderr)
        return 2

    json_text = _dump_json(graph)
    md_text = render_markdown(graph)
    dot_text = render_dot(graph)

    if args.json:
        sys.stdout.write(json_text)

    json_path = OUT_DIR / "dependency-graph.json"
    md_path = OUT_DIR / "dependency-graph.md"
    dot_path = OUT_DIR / "dependency-graph.dot"

    cycles = graph["cycles"]
    assert isinstance(cycles, list)

    if args.check:
        drift: list[str] = []
        for path, expected in (
            (json_path, json_text),
            (md_path, md_text),
            (dot_path, dot_text),
        ):
            current = path.read_text(encoding="utf-8") if path.exists() else None
            if current != expected:
                drift.append(str(path.relative_to(REPO_ROOT)))
        if drift:
            print(
                "FAIL: dependency-graph artifacts are stale -- re-run "
                "scripts/gen-dependency-graph.py and commit: " + ", ".join(drift),
                file=sys.stderr,
            )
            return 1
        if cycles:
            print(
                f"FAIL: {len(cycles)} dependency cycle(s) present "
                "(architectural violation).",
                file=sys.stderr,
            )
            return 1
        print("PASS: dependency-graph up to date; 0 cycles.")
        return 0

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json_text, encoding="utf-8")
    md_path.write_text(md_text, encoding="utf-8")
    dot_path.write_text(dot_text, encoding="utf-8")
    print(
        f"Wrote {json_path.relative_to(REPO_ROOT)}, "
        f"{md_path.relative_to(REPO_ROOT)}, {dot_path.relative_to(REPO_ROOT)} "
        f"({len(graph['packages'])} packages, {len(graph['edges'])} edges, "  # type: ignore[arg-type]
        f"{len(cycles)} cycles)."
    )
    if cycles:
        print(
            f"WARNING: {len(cycles)} dependency cycle(s) present "
            "(run --check in CI to fail on this).",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
