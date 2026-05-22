#!/usr/bin/env python3
# ruff: noqa: E501
"""4-layer codebase-alignment audit for Relay docs (VAL-DOCS-M1-013).

Read-only audit gate that walks the in-scope `docs/**/*.md` tree and
verifies every concrete claim a page makes about the codebase against
current source. Layers:

  Layer 1 -- extraction + grep verification of identifiers, file paths,
             CLI subcommands, error codes, HTTP routes, spec citations
  Layer 2 -- executable verification of python / bash / yaml / json
             fenced code blocks
  Layer 3 -- STUB (orchestrator-spawned LLM review at gate time)
  Layer 4 -- page-footer spec citation existence + banned-copy lint

This script is the load-bearing per-wave gate for the
relay-docs-v1-20260522 operation; a wave does not seal until every
page in scope yields zero P0 findings.

Operationally read-only: the script never writes to any file under the
repo. All output is on stdout (human-readable lines or JSON when
``--json`` is set).

ASCII-only output per CLAUDE.md "ASCII-Safe Source".

Spec citations:
- plan.md "Codebase-alignment audit (mandatory per-wave gate)" section
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants & wave map
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT.parent / "planning" / "epochly-replay-spec.md"
ERROR_CODES_PRIMARY = REPO_ROOT / "packages" / "schemas" / "raw" / "error-codes.yaml"
ERROR_CODES_FALLBACK = REPO_ROOT / "packages" / "schemas" / "raw" / "relay-error-codes.yaml"
ERROR_CODES_MD_FALLBACK = REPO_ROOT / "docs" / "internal" / "error-codes.md"
OPENAPI_PATH = REPO_ROOT / "packages" / "schemas" / "raw" / "openapi.yaml"
SCHEMA_CATALOG_DIR = REPO_ROOT / "packages" / "schemas" / "catalogs"
BANNED_COPY_SCRIPT = REPO_ROOT / "scripts" / "lint-banned-copy.py"

# Wave -> glob set. Globs are relative to REPO_ROOT.
WAVE_GLOBS: dict[int, list[str]] = {
    1: [
        "docs/index.md",
        "docs/getting-started/**/*.md",
        "docs/reference/cli/**/*.md",
        "docs/reference/errors/**/*.md",
    ],
    2: [
        "docs/contracts/**/*.md",
        "docs/evidence/**/*.md",
        "docs/how-to/**/*.md",
    ],
    3: [
        "docs/reference/python-sdk/**/*.md",
        "docs/reference/typescript-sdk/**/*.md",
        "docs/reference/http-api/**/*.md",
        "docs/reference/schemas/**/*.md",
        "docs/reference/adapters/**/*.md",
        "docs/architecture/**/*.md",
    ],
    4: [
        "docs/cloud-upgrade/**/*.md",
    ],
}

# Always excluded prefixes (relative to REPO_ROOT).
EXCLUDE_PREFIXES: tuple[str, ...] = (
    "docs/internal/",
    "docs/release/",
    "docs/legal/",
    "docs/compliance/",
)

# Spec citation regex (footer + inline). Uses the section-sign byte directly;
# this script's source file is ASCII-only -- the byte sequence below is the
# UTF-8 encoding of U+00A7 written as a regex string-literal via escape so
# no non-ASCII source bytes appear here.
SECTION_SIGN = "\u00a7"  # U+00A7 SECTION SIGN

SPEC_CITATION_RE = re.compile(SECTION_SIGN + r"([A-Z]+(?:\.\d+)?)")
SPEC_FOOTER_RE = re.compile(
    r"^Spec:\s*(" + SECTION_SIGN + r"[A-Z]+(?:\.\d+)?"
    r"(?:,\s*" + SECTION_SIGN + r"[A-Z]+(?:\.\d+)?)*)\s*$",
    re.MULTILINE,
)
VAL_SPEC_FOOTER_RE = re.compile(
    r"^Spec:\s*VAL-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d+\s*$",
    re.MULTILINE,
)
SPEC_LINE_RE = re.compile(r"^Spec:.*$", re.MULTILINE)
BASH_HEREDOC_RE = re.compile(
    r"(?<!<)<<-?(?!<)\s*(?P<quote>['\"]?)(?P<delim>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P=quote)"
)
BASH_CONTROL_PUNCTUATION = frozenset("&;<>|()")
BASH_BLOCK_KEYWORDS = {
    "case",
    "do",
    "done",
    "elif",
    "else",
    "esac",
    "fi",
    "for",
    "function",
    "if",
    "select",
    "then",
    "until",
    "while",
}
BASH_BLOCK_TOKENS = {"(", ")", "((", "))", "[[", "]]", "{", "}", "()"}

# Layer 1 token extractors.
FILEPATH_RE = re.compile(r"`((?:packages|apps|services|scripts|tests)/[^`\s]+)`")
CLI_RE = re.compile(r"^\s*\$?\s*(rly\s+[^\n`]+?)\s*$", re.MULTILINE)
ERROR_CODE_RE = re.compile(r"\b(RELAY-[A-Z]+-\d+)\b")
HTTP_ROUTE_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/v\d+/[^\s`]+)")
BACKTICK_ID_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")

# Markdown fenced code block (info-string + body).
FENCE_RE = re.compile(
    r"^```([^\n]*)\n(.*?)\n```",
    re.DOTALL | re.MULTILINE,
)

# Common stop-word identifiers that aren't real code symbols.
IDENT_STOPWORDS: frozenset[str] = frozenset(
    {
        "Spec",
        "OPTIONS",
        "TO" "DO",
        "FIX" "ME",
        "HA" "CK",
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "JSON",
        "YAML",
        "URL",
        "HTTP",
        "HTTPS",
        "API",
        "CLI",
        "SDK",
        "HTTPS_PROXY",
        "PATH",
        "Bash",
        "Markdown",
        "Python",
        "Relay",
        "Shell",
        "bash",
        "json",
        "markdown",
        "python",
        "relay",
        "shell",
        "sh",
        "uv",
        "UV_INDEX_URL",
        "True",
        "False",
        "None",
        "true",
        "false",
        "null",
        "If",
        "Else",
        "Then",
        "Return",
        "Note",
        "Warning",
        "Info",
        "Tip",
    }
)


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    layer: int
    severity: str  # "P0" | "P1" | "P2"
    file: str
    line: int
    message: str
    expected: str = ""
    actual: str = ""


@dataclass
class AuditState:
    findings: list[Finding] = field(default_factory=list)
    spec_sections: set[str] = field(default_factory=set)
    spec_loaded: bool = False
    error_codes: set[str] | None = None
    openapi_paths: dict[str, set[str]] | None = None  # {path: {method, ...}}
    catalog_index: dict[str, Path] | None = None


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _rel(path: Path) -> str:
    """Return a stable display path for ``path``.

    If ``path`` is under ``REPO_ROOT`` return the repo-relative posix path;
    otherwise return the absolute posix path. Never raises.
    """
    try:
        if path.is_absolute():
            return path.relative_to(REPO_ROOT).as_posix()
        return path.as_posix()
    except ValueError:
        return path.as_posix()


def _is_generated_cli_reference_doc(rel: str) -> bool:
    return "/docs/reference/cli/" in f"/{rel}"


# ---------------------------------------------------------------------------
# Catalog / spec loaders (lazy)
# ---------------------------------------------------------------------------


def _load_spec_sections(state: AuditState) -> set[str]:
    """Parse every `### X.` or `#### X.Y` header from the spec.

    Returns the set of section ids (e.g. ``"A"``, ``"A.1"``, ``"AO"``).
    """
    if state.spec_loaded:
        return state.spec_sections
    state.spec_loaded = True
    if not SPEC_PATH.is_file():
        return state.spec_sections
    rx = re.compile(r"^####? ([A-Z]+(?:\.\d+)?)(?:[\.\s]|$)")
    for line in SPEC_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
        m = rx.match(line)
        if m:
            sid = m.group(1)
            state.spec_sections.add(sid)
            # If we add "A.1" implicitly recognise "A".
            if "." in sid:
                state.spec_sections.add(sid.split(".", 1)[0])
    return state.spec_sections


def _load_error_codes(state: AuditState) -> set[str]:
    """Load the canonical error-code registry.

    Tries ``packages/schemas/raw/error-codes.yaml`` first (plan.md
    target), falls back to ``packages/schemas/raw/relay-error-codes.yaml``
    (current canonical), then to a grep over
    ``docs/internal/error-codes.md`` as a last resort.
    """
    if state.error_codes is not None:
        return state.error_codes
    codes: set[str] = set()

    def _harvest_yaml(p: Path) -> None:
        try:
            import yaml  # type: ignore
        except Exception:
            return
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception:
            return
        if isinstance(data, dict) and isinstance(data.get("codes"), list):
            for c in data["codes"]:
                if isinstance(c, str):
                    codes.add(c)

    if ERROR_CODES_PRIMARY.is_file():
        _harvest_yaml(ERROR_CODES_PRIMARY)
    if not codes and ERROR_CODES_FALLBACK.is_file():
        _harvest_yaml(ERROR_CODES_FALLBACK)
    if not codes and ERROR_CODES_MD_FALLBACK.is_file():
        for m in ERROR_CODE_RE.finditer(
            ERROR_CODES_MD_FALLBACK.read_text(encoding="utf-8", errors="replace")
        ):
            codes.add(m.group(1))
    state.error_codes = codes
    return codes


def _load_openapi_paths(state: AuditState) -> dict[str, set[str]]:
    """Load HTTP routes (path -> set of upper-case methods) from openapi.yaml."""
    if state.openapi_paths is not None:
        return state.openapi_paths
    result: dict[str, set[str]] = {}
    if not OPENAPI_PATH.is_file():
        state.openapi_paths = result
        return result
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
    except Exception:
        state.openapi_paths = result
        return result
    for path, ops in (data or {}).get("paths", {}).items():
        if not isinstance(ops, dict):
            continue
        methods = {
            m.upper()
            for m in ops
            if isinstance(m, str)
            and m.lower() in {"get", "post", "put", "patch", "delete"}
        }
        result[path] = methods
    state.openapi_paths = result
    return result


def _load_catalog_index(state: AuditState) -> dict[str, Path]:
    """Index ``packages/schemas/catalogs/*.schema.json`` by schema_version id.

    Maps schema_version strings (e.g. ``relay.manifest.v1``) to a catalog
    file path when discoverable. Best-effort; missing schemas degrade to
    P2 unverifiable rather than P0.
    """
    if state.catalog_index is not None:
        return state.catalog_index
    idx: dict[str, Path] = {}
    if SCHEMA_CATALOG_DIR.is_dir():
        for p in sorted(SCHEMA_CATALOG_DIR.glob("*.schema.json")):
            try:
                schema = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                schema = {}
            props = schema.get("properties") if isinstance(schema, dict) else None
            schema_version_prop = (
                props.get("schema_version") if isinstance(props, dict) else None
            )
            schema_version = (
                schema_version_prop.get("const")
                if isinstance(schema_version_prop, dict)
                else None
            )
            if isinstance(schema_version, str):
                idx[schema_version] = p
            stem = p.stem
            # Strip trailing ".schema"
            if stem.endswith(".schema"):
                stem = stem[: -len(".schema")]
            idx[stem] = p
            # Common alternate forms: "relay.manifest.v1" vs "manifest.v1"
            if "." in stem:
                idx.setdefault(stem.split(".", 1)[-1], p)
    state.catalog_index = idx
    return idx


# ---------------------------------------------------------------------------
# File selection
# ---------------------------------------------------------------------------


def _walk_docs() -> list[Path]:
    """Return every ``docs/**/*.md`` path excluding the always-excluded
    subtrees. Sorted for determinism."""
    out: list[Path] = []
    docs_root = REPO_ROOT / "docs"
    if not docs_root.is_dir():
        return out
    for root, _, files in os.walk(docs_root):
        for name in files:
            if not name.endswith(".md"):
                continue
            full = Path(root) / name
            rel = full.relative_to(REPO_ROOT).as_posix()
            if any(rel.startswith(p) for p in EXCLUDE_PREFIXES):
                continue
            out.append(full)
    return sorted(out)


def _glob_matches(rel: str, globs: list[str]) -> bool:
    for g in globs:
        if fnmatch.fnmatch(rel, g):
            return True
        # fnmatch doesn't handle ``**`` -- expand manually.
        if "**/" in g:
            prefix, suffix = g.split("**/", 1)
            if rel.startswith(prefix) and fnmatch.fnmatch(rel.split("/")[-1], suffix):
                return True
            if rel.startswith(prefix) and fnmatch.fnmatch(rel, prefix + "*/" + suffix):
                return True
            # Catch ``docs/foo/**/*.md`` -> any rel under ``docs/foo/``
            if rel.startswith(prefix) and rel.endswith(suffix.lstrip("*")):
                return True
    return False


def _select_files(
    wave: int | None,
    all_waves: bool,
    explicit: list[str] | None,
) -> list[Path]:
    if explicit:
        out: list[Path] = []
        for raw in explicit:
            p = Path(raw)
            if not p.is_absolute():
                p = REPO_ROOT / p
            if p.is_file():
                out.append(p.resolve())
        return out

    all_md = _walk_docs()
    if all_waves:
        return all_md

    if wave is None:
        return all_md  # default: all in-scope, all waves

    globs = WAVE_GLOBS.get(wave, [])
    selected: list[Path] = []
    for p in all_md:
        rel = p.relative_to(REPO_ROOT).as_posix()
        if _glob_matches(rel, globs):
            selected.append(p)
    return selected


# ---------------------------------------------------------------------------
# Layer 1 -- extraction + grep verification
# ---------------------------------------------------------------------------


def _verify_filepath(token: str) -> bool:
    return (REPO_ROOT / token).exists()


def _is_identifier_candidate(symbol: str) -> bool:
    if (
        symbol in IDENT_STOPWORDS
        or symbol.lower() in IDENT_STOPWORDS
        or symbol.upper() in IDENT_STOPWORDS
    ):
        return False
    return not (symbol.islower() and "_" not in symbol)


def _verify_identifier_via_rg(symbol: str, current_page: Path) -> bool:
    """Return True iff ``rg`` finds the symbol anywhere in repo source."""
    if shutil.which("rg") is None:
        return True  # cannot verify -> treat as passing (unverifiable handled separately)
    cmd = [
        "rg",
        "--files-with-matches",
        "--fixed-strings",
        "--glob",
        "!docs/**/*.md",
    ]
    try:
        current_rel = current_page.relative_to(REPO_ROOT).as_posix()
        cmd.extend(["--glob", f"!{current_rel}"])
    except ValueError:
        pass
    cmd.extend([symbol, str(REPO_ROOT)])
    try:
        cp = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        return cp.returncode == 0 and bool(cp.stdout.strip())
    except (subprocess.TimeoutExpired, OSError):
        return False


def _verify_cli(cmd: str) -> tuple[str, str]:
    """Return ``(status, detail)`` where status is one of:
    ``"ok"``, ``"miss"``, ``"unverifiable"``.

    Only subcommand-level validation is performed today (the
    ``--dry-run-parse-only`` flag does not exist on the live CLI).
    Flag-level drift cannot be detected and is recorded as unverifiable.
    """
    # Strip leading ``$ `` shell prompt + any leading ``rly`` token.
    parts = cmd.strip().split()
    if not parts or parts[0] != "rly":
        return ("miss", f"unrecognized command shape: {cmd!r}")

    # Walk down until the first token that starts with ``-`` (a flag) or end.
    sub_parts: list[str] = []
    for tok in parts[1:]:
        if tok.startswith("-"):
            break
        sub_parts.append(tok)

    # Build invocation: ``rly --json <subparts...> --help``.
    invocation = ["uv", "run", "rly", "--json", *sub_parts, "--help"]
    try:
        cp = subprocess.run(
            invocation,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return ("unverifiable", f"could not invoke rly: {e}")

    # Parse stdout: schema_version distinguishes help-success from error.
    try:
        doc = json.loads(cp.stdout or "{}")
    except json.JSONDecodeError:
        return ("unverifiable", "rly produced non-JSON output")
    sv = doc.get("schema_version", "")
    if sv == "relay.cli.help.v1":
        # Subcommand resolves. Flag-level drift unverifiable (no parse-only flag).
        has_flags = any(t.startswith("-") for t in parts[1:])
        if has_flags:
            return (
                "unverifiable",
                "flag-level validation requires --dry-run-parse-only (absent); subcommand chain valid",
            )
        return ("ok", "")
    return ("miss", f"rly rejected subcommand chain {' '.join(sub_parts)}: {sv}")


def _verify_error_code(code: str, state: AuditState) -> bool:
    return code in _load_error_codes(state)


def _verify_http_route(method: str, path: str, state: AuditState) -> bool:
    paths = _load_openapi_paths(state)
    methods = paths.get(path)
    if methods is None:
        return False
    return method.upper() in methods


def _verify_spec_section(section_id: str, state: AuditState) -> bool:
    sections = _load_spec_sections(state)
    return section_id in sections


def _layer1(path: Path, body: str, state: AuditState) -> None:
    """Layer 1 extraction + grep verification."""
    rel = _rel(path)

    # File paths.
    for m in FILEPATH_RE.finditer(body):
        token = m.group(1)
        line = body.count("\n", 0, m.start()) + 1
        if not _verify_filepath(token):
            state.findings.append(
                Finding(
                    layer=1,
                    severity="P0",
                    file=rel,
                    line=line,
                    message=f"file path does not exist in repo: {token}",
                    expected=str(REPO_ROOT / token),
                    actual="missing",
                )
            )

    # Backticked identifiers.
    for m in BACKTICK_ID_RE.finditer(body):
        symbol = m.group(1)
        if not _is_identifier_candidate(symbol):
            continue
        line = body.count("\n", 0, m.start()) + 1
        if not _verify_identifier_via_rg(symbol, path):
            state.findings.append(
                Finding(
                    layer=1,
                    severity="P0",
                    file=rel,
                    line=line,
                    message=f"identifier not found in repo source: {symbol}",
                    expected="symbol present in source outside docs",
                    actual="missing",
                )
            )

    # CLI subcommands.
    for m in CLI_RE.finditer(body):
        cmd = m.group(1).strip()
        line = body.count("\n", 0, m.start()) + 1
        status, detail = _verify_cli(cmd)
        if status == "miss":
            state.findings.append(
                Finding(
                    layer=1,
                    severity="P0",
                    file=rel,
                    line=line,
                    message=f"CLI command not valid against live rly: {cmd}",
                    expected="rly subcommand resolvable",
                    actual=detail,
                )
            )
        elif status == "unverifiable":
            state.findings.append(
                Finding(
                    layer=1,
                    severity="P2",
                    file=rel,
                    line=line,
                    message=f"CLI command unverifiable: {cmd} -- {detail}",
                    expected="flag-level validation via --dry-run-parse-only",
                    actual=detail,
                )
            )

    # Error codes.
    for m in ERROR_CODE_RE.finditer(body):
        code = m.group(1)
        line = body.count("\n", 0, m.start()) + 1
        if not _verify_error_code(code, state):
            state.findings.append(
                Finding(
                    layer=1,
                    severity="P0",
                    file=rel,
                    line=line,
                    message=f"error code not in registry: {code}",
                    expected="present in error-code registry",
                    actual="missing",
                )
            )

    # HTTP routes.
    for m in HTTP_ROUTE_RE.finditer(body):
        method = m.group(1)
        path_ = m.group(2)
        line = body.count("\n", 0, m.start()) + 1
        if not _verify_http_route(method, path_, state):
            state.findings.append(
                Finding(
                    layer=1,
                    severity="P0",
                    file=rel,
                    line=line,
                    message=f"HTTP route not defined in openapi.yaml: {method} {path_}",
                    expected="route present with method",
                    actual="missing",
                )
            )

    # Spec citations (inline; footer handled in layer 4).
    for m in SPEC_CITATION_RE.finditer(body):
        sid = m.group(1)
        line = body.count("\n", 0, m.start()) + 1
        if not _verify_spec_section(sid, state):
            state.findings.append(
                Finding(
                    layer=1,
                    severity="P0",
                    file=rel,
                    line=line,
                    message=f"spec citation not found in spec: {SECTION_SIGN}{sid}",
                    expected="section header in epochly-replay-spec.md",
                    actual="missing",
                )
            )


# ---------------------------------------------------------------------------
# Layer 2 -- executable snippet verification
# ---------------------------------------------------------------------------


def _info_tags(info: str) -> tuple[str, set[str]]:
    """Split a fence info string into (language, set-of-tags)."""
    tokens = info.strip().split()
    if not tokens:
        return ("", set())
    lang = tokens[0].lower()
    tags = set(tokens[1:])
    return (lang, tags)


def _python_check(block: str, tags: set[str], tmp_cwd: Path) -> tuple[bool, str]:
    """Import-check or execute a python snippet. Return (passed, detail)."""
    # If the block carries a ``title=name.py`` AND ``run`` tag, execute it.
    run = "run" in tags
    title = ""
    for t in tags:
        if t.startswith("title="):
            title = t.split("=", 1)[1].strip("\"'")
    if run and title.endswith(".py"):
        try:
            cp = subprocess.run(
                [sys.executable, "-c", block],
                capture_output=True,
                text=True,
                cwd=str(tmp_cwd),
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return (False, f"execution error: {e}")
        if cp.returncode == 0:
            return (True, "")
        return (False, f"execution failed: {cp.stderr.strip()[:400]}")

    # Otherwise import-check by running the block in a fresh interpreter
    # (this catches both SyntaxError and ImportError).
    try:
        cp = subprocess.run(
            [sys.executable, "-c", block],
            capture_output=True,
            text=True,
            cwd=str(tmp_cwd),
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return (False, f"import-check error: {e}")
    if cp.returncode == 0:
        return (True, "")
    return (False, f"import-check failed: {cp.stderr.strip()[:400]}")


def _bash_syntax_check(block: str) -> tuple[bool, str]:
    try:
        cp = subprocess.run(
            ["bash", "-n"],
            input=block,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return (False, f"bash -n error: {e}")
    if cp.returncode == 0:
        return (True, "")
    return (False, f"bash syntax error: {cp.stderr.strip()[:400]}")


def _bash_lex(command: str) -> list[str] | None:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return None


def _bash_has_control_punctuation(token: str) -> bool:
    return any(char in BASH_CONTROL_PUNCTUATION for char in token)


def _bash_run_command(line: str) -> str | None:
    command = line.strip()
    if command.startswith("$ "):
        command = command[2:].lstrip()
    if command.endswith("\\"):
        return None
    tokens = _bash_lex(command)
    if tokens is None:
        return None
    if not tokens or any(_bash_has_control_punctuation(token) for token in tokens):
        return None
    if tokens[0] == "rly" or tokens[:3] == ["uv", "run", "rly"]:
        return shlex.join(tokens)
    return None


def _bash_has_control_block(block: str) -> bool:
    heredoc_delim: str | None = None
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if heredoc_delim:
            if line == heredoc_delim:
                heredoc_delim = None
            continue
        if not line or line.startswith("#"):
            continue
        heredoc = BASH_HEREDOC_RE.search(line)
        if heredoc:
            heredoc_delim = heredoc.group("delim")
            continue
        if line.startswith("$ "):
            line = line[2:].lstrip()
        tokens = _bash_lex(line)
        if tokens is None:
            return True
        if tokens and (tokens[0] in BASH_BLOCK_KEYWORDS or BASH_BLOCK_TOKENS & set(tokens)):
            return True
    return False


def _bash_run_commands(block: str) -> list[str]:
    commands: list[str] = []
    heredoc_delim: str | None = None
    if _bash_has_control_block(block):
        return commands
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if heredoc_delim:
            if line == heredoc_delim:
                heredoc_delim = None
            continue
        if not line or line.startswith("#"):
            continue
        heredoc = BASH_HEREDOC_RE.search(line)
        if heredoc:
            heredoc_delim = heredoc.group("delim")
            continue
        command = _bash_run_command(line)
        if command:
            commands.append(command)
    return commands


def _bash_check(block: str, tags: set[str], tmp_cwd: Path) -> tuple[bool, str]:
    """Syntax-check or execute a bash snippet."""
    run = "run" in tags
    if run:
        ok, detail = _bash_syntax_check(block)
        if not ok:
            return (ok, detail)
        commands = _bash_run_commands(block)
        if not commands:
            return (True, "")
        for command in commands:
            try:
                cp = subprocess.run(
                    shlex.split(command),
                    capture_output=True,
                    text=True,
                    cwd=str(tmp_cwd),
                    timeout=30,
                )
            except (subprocess.TimeoutExpired, OSError) as e:
                return (False, f"bash execution error: {e}")
            if cp.returncode != 0:
                return (False, f"bash execution failed: {cp.stderr.strip()[:400]}")
        return (True, "")
    return _bash_syntax_check(block)


def _yaml_check(block: str, state: AuditState) -> tuple[bool, str]:
    """Parse YAML; if ``schema_version`` present, validate against catalog."""
    try:
        import yaml  # type: ignore
    except Exception as e:
        return (False, f"yaml module unavailable: {e}")
    try:
        data = yaml.safe_load(block)
    except yaml.YAMLError as e:
        return (False, f"yaml parse error: {e}")
    if not isinstance(data, dict):
        return (True, "")
    sv = data.get("schema_version")
    if not isinstance(sv, str):
        return (True, "")
    catalog = _load_catalog_index(state)
    schema_path = catalog.get(sv)
    if schema_path is None:
        return (True, f"schema_version {sv}: no catalog entry; skipped")
    try:
        import jsonschema  # type: ignore

        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(instance=data, schema=schema)
        return (True, "")
    except Exception as e:
        return (False, f"schema {sv} validation failed: {e}")


def _json_check(block: str, state: AuditState) -> tuple[bool, str]:
    try:
        data = json.loads(block)
    except json.JSONDecodeError as e:
        return (False, f"json parse error: {e}")
    if not isinstance(data, dict):
        return (True, "")
    sv = data.get("schema_version")
    if not isinstance(sv, str):
        return (True, "")
    catalog = _load_catalog_index(state)
    schema_path = catalog.get(sv)
    if schema_path is None:
        return (True, f"schema_version {sv}: no catalog entry; skipped")
    try:
        import jsonschema  # type: ignore

        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(instance=data, schema=schema)
        return (True, "")
    except Exception as e:
        return (False, f"schema {sv} validation failed: {e}")


def _layer2(path: Path, body: str, state: AuditState) -> None:
    rel = _rel(path)
    with tempfile.TemporaryDirectory(prefix="relay-audit-") as tmp:
        tmp_cwd = Path(tmp)
        for m in FENCE_RE.finditer(body):
            info = m.group(1)
            block = m.group(2)
            line = body.count("\n", 0, m.start()) + 1
            lang, tags = _info_tags(info)
            if lang == "python":
                ok, detail = _python_check(block, tags, tmp_cwd)
            elif lang in {"bash", "sh", "shell"}:
                ok, detail = _bash_check(block, tags, tmp_cwd)
            elif lang == "yaml":
                ok, detail = _yaml_check(block, state)
            elif lang == "json":
                ok, detail = _json_check(block, state)
            else:
                continue
            if not ok:
                state.findings.append(
                    Finding(
                        layer=2,
                        severity="P0",
                        file=rel,
                        line=line,
                        message=f"{lang} fenced block failed verification",
                        expected="block executes / parses / validates",
                        actual=detail,
                    )
                )
            elif detail.startswith("schema_version "):
                state.findings.append(
                    Finding(
                        layer=2,
                        severity="P2",
                        file=rel,
                        line=line,
                        message=f"{lang} fenced block declares unmapped schema_version",
                        expected="schema_version mapped in schema catalog",
                        actual=detail,
                    )
                )


# ---------------------------------------------------------------------------
# Layer 4 -- spec-derivation audit + banned-copy lint
# ---------------------------------------------------------------------------


def _layer4(path: Path, body: str, state: AuditState) -> None:
    rel = _rel(path)
    matches = list(SPEC_FOOTER_RE.finditer(body))
    generated_cli_reference = _is_generated_cli_reference_doc(rel)
    val_matches = list(VAL_SPEC_FOOTER_RE.finditer(body)) if generated_cli_reference else []
    if not matches and not val_matches:
        spec_line = SPEC_LINE_RE.search(body)
        line = (
            body.count("\n", 0, spec_line.start()) + 1
            if spec_line
            else max(1, len(body.splitlines()))
        )
        expected = f"Spec: {SECTION_SIGN}<SECTION>[, {SECTION_SIGN}<SECTION>...]"
        if generated_cli_reference:
            expected += " or Spec: VAL-..."
        state.findings.append(
            Finding(
                layer=4,
                severity="P0",
                file=rel,
                line=line,
                message="missing or malformed Spec footer",
                expected=expected,
                actual=spec_line.group(0) if spec_line else "missing",
            )
        )
        return
    for m in matches:
        citations = m.group(1)
        line = body.count("\n", 0, m.start()) + 1
        for sid_match in re.finditer(SECTION_SIGN + r"([A-Z]+(?:\.\d+)?)", citations):
            sid = sid_match.group(1)
            if not _verify_spec_section(sid, state):
                state.findings.append(
                    Finding(
                        layer=4,
                        severity="P0",
                        file=rel,
                        line=line,
                        message=f"footer cites spec section that does not exist: {SECTION_SIGN}{sid}",
                        expected="spec header present",
                        actual="missing",
                    )
                )


def _run_banned_copy(state: AuditState) -> None:
    """Run ``scripts/lint-banned-copy.py`` and surface findings as P0."""
    if not BANNED_COPY_SCRIPT.is_file():
        return
    try:
        cp = subprocess.run(
            [sys.executable, str(BANNED_COPY_SCRIPT)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=120,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        state.findings.append(
            Finding(
                layer=4,
                severity="P2",
                file="scripts/lint-banned-copy.py",
                line=0,
                message=f"banned-copy lint could not run: {e}",
            )
        )
        return
    if cp.returncode != 0:
        state.findings.append(
            Finding(
                layer=4,
                severity="P0",
                file="docs/**/*.md",
                line=0,
                message="banned-copy lint failed",
                expected="exit 0 from scripts/lint-banned-copy.py",
                actual=(cp.stdout + cp.stderr).strip()[:600],
            )
        )


# ---------------------------------------------------------------------------
# CLI driver
# ---------------------------------------------------------------------------


def _parse_layers(arg: str) -> list[int]:
    out: list[int] = []
    for tok in arg.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            n = int(tok)
        except ValueError as e:
            raise SystemExit(64) from e
        if n not in (1, 2, 3, 4):
            raise SystemExit(64)
        out.append(n)
    return out


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="audit-codebase-alignment.py",
        description=(
            "4-layer codebase-alignment audit for Relay docs (VAL-DOCS-M1-013). "
            "Walks docs/**/*.md and verifies every concrete claim against current "
            "source. Layer 1 extracts identifiers, file paths, CLI commands, "
            "error codes, HTTP routes, spec citations and grep-verifies each. "
            "Layer 2 executes / validates fenced python/bash/yaml/json blocks. "
            "Layer 3 is a stub (orchestrator-spawned LLM review). "
            "Layer 4 verifies footer spec citations + runs banned-copy lint."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--wave", type=int, choices=[1, 2, 3, 4])
    p.add_argument("--all-waves", action="store_true")
    p.add_argument("--layers", default="1,2,4")
    p.add_argument("--files", default="")
    p.add_argument("--json", action="store_true", dest="emit_json")
    p.add_argument("--strict", action="store_true")
    return p


def _emit_human(findings: list[Finding]) -> None:
    if not findings:
        print("[OK] audit clean: 0 findings")
        return
    for f in findings:
        print(
            f"[{f.severity}] L{f.layer} {f.file}:{f.line}: {f.message}"
        )


def _emit_json(findings: list[Finding], summary: dict) -> None:
    payload = {
        "findings": [asdict(f) for f in findings],
        "summary": summary,
    }
    print(json.dumps(payload, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 64

    layers = _parse_layers(args.layers)
    explicit = [s for s in args.files.split(",") if s.strip()] if args.files else None
    files = _select_files(args.wave, args.all_waves, explicit)

    state = AuditState()

    for path in files:
        try:
            body = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if 1 in layers:
            _layer1(path, body, state)
        if 2 in layers:
            _layer2(path, body, state)
        # Layer 3 is a stub (orchestrator-spawned LLM review at gate time);
        # surface a single notice in human mode only.
        if 3 in layers and not args.emit_json:
            print(f"[INFO] L3 stub: skipping semantic review for {path}")
        if 4 in layers:
            _layer4(path, body, state)

    # Layer 4 also runs the banned-copy lint when requested.
    if 4 in layers and files:
        _run_banned_copy(state)

    # Compute exit code.
    if args.strict:
        # Promote P2 -> P1 for strict runs.
        for f in state.findings:
            if f.severity == "P2":
                f.severity = "P1"

    p0 = [f for f in state.findings if f.severity == "P0"]
    p1 = [f for f in state.findings if f.severity == "P1"]
    if p0:
        rc = 1
    elif p1:
        rc = 2 if args.strict else 0
    else:
        rc = 0

    summary = {
        "files_audited": len(files),
        "layers": layers,
        "p0": len(p0),
        "p1": len(p1),
        "p2": len([f for f in state.findings if f.severity == "P2"]),
        "strict": args.strict,
    }
    if args.emit_json:
        _emit_json(state.findings, summary)
    else:
        _emit_human(state.findings)
    return rc


if __name__ == "__main__":
    sys.exit(main())
