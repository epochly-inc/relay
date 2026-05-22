#!/usr/bin/env python3
# ruff: noqa: E501
"""CLI-reference generator for Relay docs (VAL-DOCS-M1-008).

Walks every subcommand reachable via ``rly --json help`` (and its nested
``--json <group> --help`` / ``--json <group> <leaf> --help`` invocations)
and writes one Markdown page per command under ``docs/reference/cli/``.

Each page carries the banner

    > Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

so machine consumers and human reviewers know to regenerate via this
script rather than hand-edit.

The CLI emits the canonical ``relay.cli.help.v1`` JSON envelope on
``--help`` when stdout is non-TTY; we exploit that envelope to produce
deterministic, drift-checkable output. See
``packages/cli/src/relay_cli/main.py:117-179`` (``_RelayTyperGroup`` /
``_RelayTyperCommand``) for the source of truth on the envelope shape.

Surface:

    python scripts/docs/build-cli-reference.py [--check] [--out DIR]

      --check    Compare generated pages against existing pages on disk;
                 exit non-zero on drift; do not write.
      --out DIR  Output directory (default: docs/reference/cli).

Exit codes:

    0  -- success (wrote pages) OR ``--check`` found no drift
    1  -- ``--check`` found drift between generated and on-disk content
    64 -- usage error

Idempotency: byte-identical output across consecutive runs against the
same CLI source. We sort all option/subcommand lists, normalize line
endings to ``\\n``, and never embed timestamps or random tokens.

ASCII-only output per CLAUDE.md "ASCII-Safe Source"; markdown body uses
plain headings and pipe tables only.

Spec citations:
- plan.md "Wave 1 deliverable 5" (CLI reference auto-generated)
- contract.md VAL-DOCS-M1-008
- ``packages/cli/src/relay_cli/main.py`` lines 117-239 (JSON help envelope)
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = REPO_ROOT / "docs" / "reference" / "cli"
SOURCE_PATH = "packages/cli/src/relay_cli/main.py"
BANNER = (
    "> Generated from packages/cli/src/relay_cli/main.py. "
    "Do not edit by hand."
)

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_USAGE = 64

# Recursion guard: the rly CLI tree depth is small (root -> group -> leaf),
# but a defensive ceiling prevents runaway recursion if a future subcommand
# layout introduces a cycle.
MAX_DEPTH = 5


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CliCommand:
    """One node in the CLI tree.

    ``command_path`` is the dotted Click command path as the CLI reports it
    (e.g., ``"rly"``, ``"rly contract"``, ``"rly contract publish"``).
    """

    command_path: str
    help_text: str
    options: tuple[dict[str, Any], ...]
    subcommands: tuple[dict[str, Any], ...]
    exit_codes: tuple[dict[str, Any], ...]
    is_leaf: bool


# ---------------------------------------------------------------------------
# CLI tree discovery
# ---------------------------------------------------------------------------


def _rly_binary() -> list[str]:
    """Resolve the ``rly`` invocation used to harvest help envelopes.

    Prefers the installed ``rly`` binary on PATH (matches the documented
    install path); falls back to ``python -m relay_cli`` so the generator
    still works in a fresh editable install before ``uv pip install`` has
    placed the console script.
    """
    on_path = shutil.which("rly")
    if on_path:
        return [on_path]
    # Module form. ``relay_cli.__main__`` re-exports ``run``.
    return [sys.executable, "-m", "relay_cli"]


def _fetch_help(command_tokens: list[str]) -> dict[str, Any]:
    """Run ``rly --json <tokens...> --help`` and parse the JSON envelope.

    ``command_tokens`` is the list of subcommand tokens after ``rly`` and
    before ``--help`` (e.g., ``[]`` for the root, ``["contract"]`` for a
    group, ``["contract", "publish"]`` for a leaf).

    The CLI's JSON-help override (see main.py:139-153) detects non-TTY
    stdout via ``should_emit_json``; because subprocess pipes are non-TTY,
    JSON is emitted by default. We still pass ``--json`` for belt-and-
    braces in case the helper is later strengthened to require the flag.
    """
    argv = [*_rly_binary(), "--json", *command_tokens, "--help"]
    env = dict(os.environ)
    # Force the canonical JSON path even when the env happens to disable it.
    env.pop("RELAY_OUTPUT_FORMAT", None)
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    # ``--help`` exits 0 on success; we treat any non-zero as a generator
    # error so the calling tooling sees the failure rather than silently
    # producing an incomplete tree.
    if result.returncode != 0:
        raise RuntimeError(
            f"rly help failed for tokens={command_tokens!r} "
            f"(exit={result.returncode}); stderr={result.stderr!r}"
        )
    raw = result.stdout.strip()
    if not raw:
        raise RuntimeError(
            f"rly help produced empty stdout for tokens={command_tokens!r}"
        )
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"rly help did not produce valid JSON for tokens={command_tokens!r}: "
            f"{exc}; stdout={raw!r}"
        ) from exc
    schema = envelope.get("schema_version")
    if schema != "relay.cli.help.v1":
        raise RuntimeError(
            f"unexpected help schema_version={schema!r} for tokens={command_tokens!r}; "
            "expected 'relay.cli.help.v1'"
        )
    return envelope


def _walk_tree(command_tokens: list[str], depth: int = 0) -> list[CliCommand]:
    """Recurse through the CLI tree starting at ``command_tokens``.

    Returns commands in deterministic order (sorted by command_path) so
    the generator's output stays byte-stable across runs and across
    machines.
    """
    if depth > MAX_DEPTH:
        raise RuntimeError(
            f"CLI tree depth exceeded MAX_DEPTH={MAX_DEPTH} at tokens={command_tokens!r}; "
            "increase MAX_DEPTH or investigate a cycle in the CLI surface."
        )
    envelope = _fetch_help(command_tokens)
    command_path = str(envelope.get("command") or "rly").strip()
    options = tuple(_normalize_options(envelope.get("options") or []))
    subcommands_raw = tuple(_normalize_subcommands(envelope.get("subcommands") or []))
    exit_codes = tuple(envelope.get("exit_codes") or [])
    # If the help envelope offers subcommands, this node is a group; else
    # it's a leaf command.
    is_leaf = len(subcommands_raw) == 0
    # Pull the long ``help`` text from the parent envelope's matching
    # subcommands entry (the root self-help has it under a different key);
    # fall back to whatever the envelope itself carries. For the root the
    # CLI does not include a top-level help string in the envelope, so we
    # derive a stable description from the Typer ``app`` constructor
    # (main.py:182-195).
    help_text = _resolve_help_text(envelope, command_tokens)
    node = CliCommand(
        command_path=command_path,
        help_text=help_text,
        options=options,
        subcommands=subcommands_raw,
        exit_codes=exit_codes,
        is_leaf=is_leaf,
    )
    collected: list[CliCommand] = [node]
    for sub in subcommands_raw:
        sub_name = sub.get("name")
        if not isinstance(sub_name, str) or not sub_name:
            continue
        collected.extend(_walk_tree([*command_tokens, sub_name], depth=depth + 1))
    return collected


def _normalize_options(opts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Coerce option entries into a stable shape.

    The envelope already populates ``name`` / ``type`` / ``required`` /
    ``help``; we strip Nones, default missing strings to ``""`` and bool
    fields to ``False``, and sort by ``name`` so rendering is order-
    independent. Sorted output is mandatory for idempotency.
    """
    normalized: list[dict[str, Any]] = []
    for raw in opts:
        if not isinstance(raw, dict):
            continue
        normalized.append(
            {
                "name": str(raw.get("name") or "").strip(),
                "type": str(raw.get("type") or "string").strip(),
                "required": bool(raw.get("required", False)),
                "help": str(raw.get("help") or "").strip(),
            }
        )
    normalized.sort(key=lambda d: d["name"])
    return normalized


def _normalize_subcommands(subs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Coerce subcommand entries into a stable shape (sorted by name)."""
    normalized: list[dict[str, Any]] = []
    for raw in subs:
        if not isinstance(raw, dict):
            continue
        normalized.append(
            {
                "name": str(raw.get("name") or "").strip(),
                "help": str(raw.get("help") or "").strip(),
            }
        )
    normalized.sort(key=lambda d: d["name"])
    return normalized


def _resolve_help_text(envelope: dict[str, Any], tokens: list[str]) -> str:
    """Extract a human-language description for the current node.

    The JSON envelope itself does not currently carry the top-level help
    string for a group; that text lives on the *parent* envelope's
    matching ``subcommands`` entry. The walker compensates by storing
    parent help on the child node via a second helper call below.

    For the root ``rly`` invocation we fall back to a stable canned
    description (the Typer ``app`` help string at main.py:185-189).
    """
    if not tokens:
        return (
            "Relay control surface (rly). Apache 2.0 CLI for the Relay agent "
            "reliability OS. JSON output by default when piped; human-readable "
            "text on a TTY. Exit codes follow the canonical Relay exit-code "
            "table (see --help for the full list)."
        )
    # Parent envelope lookup: fetch the parent's help once more and grab
    # the matching subcommands entry. This is one extra subprocess call
    # per non-root node; the CLI tree is small (<=20 nodes today) so this
    # is acceptable.
    parent_tokens = tokens[:-1]
    parent_env = _fetch_help(parent_tokens)
    last = tokens[-1]
    for entry in parent_env.get("subcommands") or []:
        if isinstance(entry, dict) and entry.get("name") == last:
            return str(entry.get("help") or "").strip()
    return ""


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _filename_for(command_path: str) -> str:
    """Map a dotted command path to its on-disk filename.

    ``rly`` -> ``index.md``
    ``rly contract`` -> ``contract.md``
    ``rly contract publish`` -> ``contract/publish.md``
    """
    parts = command_path.split()
    if parts == ["rly"]:
        return "index.md"
    # Drop the ``rly`` prefix; the remainder defines directory + file.
    tail = parts[1:]
    if len(tail) == 1:
        return f"{tail[0]}.md"
    # Group + leaf: directory-per-group, leaf-as-file.
    return os.path.join(*tail[:-1], f"{tail[-1]}.md")


def _render_page(node: CliCommand) -> str:
    """Render a single command's Markdown page.

    Output layout (stable, ASCII-only):

      # <command path>
      <banner blockquote>

      <help text paragraph>

      ## Usage
      ```
      <command path> [OPTIONS] [SUBCOMMAND]
      ```

      ## Options
      | Name | Type | Required | Description |
      ...

      ## Subcommands  (groups only)
      | Name | Description |
      ...

      ## Exit codes
      | Code | Meaning |
      ...

      ---
      Spec: VAL-DOCS-M1-008
    """
    lines: list[str] = []
    title = node.command_path.strip()
    lines.append(f"# `{title}`")
    lines.append("")
    lines.append(BANNER)
    lines.append("")
    if node.help_text:
        for paragraph in _split_paragraphs(node.help_text):
            lines.append(paragraph)
            lines.append("")
    # Usage line: groups take [SUBCOMMAND], leaves take [ARGS].
    usage_tail = "[OPTIONS] [SUBCOMMAND]" if not node.is_leaf else "[OPTIONS]"
    lines.append("## Usage")
    lines.append("")
    lines.append("```")
    lines.append(f"{title} {usage_tail}")
    lines.append("```")
    lines.append("")
    lines.append("## Options")
    lines.append("")
    if node.options:
        lines.append("| Name | Type | Required | Description |")
        lines.append("| --- | --- | --- | --- |")
        for opt in node.options:
            name = _escape_pipe(opt["name"]) or "(positional)"
            type_ = _escape_pipe(opt["type"]) or "string"
            req = "yes" if opt["required"] else "no"
            help_ = _escape_pipe(_oneline(opt["help"])) or "-"
            lines.append(f"| `{name}` | `{type_}` | {req} | {help_} |")
    else:
        lines.append("_No options._")
    lines.append("")
    if not node.is_leaf and node.subcommands:
        lines.append("## Subcommands")
        lines.append("")
        lines.append("| Name | Description |")
        lines.append("| --- | --- |")
        for sub in node.subcommands:
            sub_name = _escape_pipe(sub["name"])
            sub_help = _escape_pipe(_oneline(sub["help"])) or "-"
            sub_file = _subcommand_link(node.command_path, sub["name"])
            lines.append(f"| [`{sub_name}`]({sub_file}) | {sub_help} |")
        lines.append("")
    if node.exit_codes:
        lines.append("## Exit codes")
        lines.append("")
        lines.append("| Code | Meaning |")
        lines.append("| --- | --- |")
        for row in node.exit_codes:
            code = row.get("code", "")
            meaning = _escape_pipe(_oneline(str(row.get("meaning") or ""))) or "-"
            lines.append(f"| `{code}` | {meaning} |")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"Source: `{SOURCE_PATH}`")
    lines.append("")
    lines.append("Spec: VAL-DOCS-M1-008")
    lines.append("")
    return "\n".join(lines)


def _split_paragraphs(text: str) -> list[str]:
    """Split a help string into paragraphs preserving deterministic order.

    The CLI help text often embeds ``\\n`` newlines for line breaks but no
    paragraph markers. We collapse runs of whitespace and treat a blank
    line as a paragraph boundary.
    """
    paragraphs: list[str] = []
    current: list[str] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        stripped = line.strip()
        if not stripped:
            if current:
                paragraphs.append(" ".join(current))
                current = []
            continue
        current.append(stripped)
    if current:
        paragraphs.append(" ".join(current))
    return paragraphs


def _oneline(text: str) -> str:
    """Collapse a help string into a single line for use inside a table cell."""
    return " ".join(text.replace("\r\n", " ").replace("\n", " ").split())


def _escape_pipe(text: str) -> str:
    """Escape pipe characters that would otherwise break a Markdown table row."""
    return text.replace("|", "\\|")


def _subcommand_link(parent_path: str, child_name: str) -> str:
    """Return the relative href used in the parent's subcommands table.

    A group at ``docs/reference/cli/contract.md`` linking to its leaf at
    ``docs/reference/cli/contract/publish.md`` uses ``contract/publish.md``.
    The root index linking to a top-level group uses ``contract.md``.
    """
    parent_parts = parent_path.split()
    if parent_parts == ["rly"]:
        return f"{child_name}.md"
    tail = parent_parts[1:]
    return os.path.join(*tail, f"{child_name}.md")


# ---------------------------------------------------------------------------
# Generation + check
# ---------------------------------------------------------------------------


def _generate_pages() -> dict[Path, str]:
    """Walk the CLI tree and render every page.

    Returns a mapping from output-relative-path to page content. The
    caller is responsible for placing the contents under the chosen
    output root.
    """
    nodes = _walk_tree([])
    # De-duplicate by command_path (the tree walk visits each node once,
    # but defensive de-dup keeps the output stable if a CLI ever exposes
    # the same node via two paths).
    seen: dict[str, CliCommand] = {}
    for node in nodes:
        seen.setdefault(node.command_path, node)
    pages: dict[Path, str] = {}
    for command_path in sorted(seen):
        node = seen[command_path]
        rel = Path(_filename_for(command_path))
        pages[rel] = _render_page(node)
    return pages


def _write_pages(pages: dict[Path, str], out_root: Path) -> None:
    """Write every rendered page to disk under ``out_root``.

    Removes any existing ``*.md`` artifacts under ``out_root`` first to
    avoid stale leftovers from previously-deleted subcommands. The
    ``.gitkeep`` sentinel under the production output dir is preserved by
    only deleting files with a ``.md`` suffix.
    """
    out_root.mkdir(parents=True, exist_ok=True)
    # Sweep stale .md files so removed subcommands do not linger.
    for existing in out_root.rglob("*.md"):
        try:
            existing.unlink()
        except OSError:
            # A read-only or vanished file is non-fatal; the write below
            # will fail loudly if the directory itself is bad.
            pass
    for rel, content in pages.items():
        target = out_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        # Write bytes so newline handling stays deterministic across OSes;
        # the file always ends with a single trailing newline.
        body = content if content.endswith("\n") else content + "\n"
        with open(target, "wb") as fp:
            fp.write(body.encode("utf-8"))


def _diff_pages(
    pages: dict[Path, str], out_root: Path
) -> tuple[bool, list[Path], str]:
    """Compare generated pages against on-disk content.

    Returns ``(has_drift, drifting_files, unified_diff_first)``.

    ``unified_diff_first`` is the diff body for the *first* drifting file
    (path-sorted) so callers can print a focused failure message; if no
    drift is present it is the empty string.
    """
    drifting: list[Path] = []
    first_diff = ""
    expected_paths = sorted(pages.keys(), key=lambda p: str(p))
    # Walk expected files first so the "first drift" we report is the
    # earliest-by-path mismatch.
    for rel in expected_paths:
        target = out_root / rel
        expected_body = pages[rel]
        if not expected_body.endswith("\n"):
            expected_body += "\n"
        if not target.exists():
            drifting.append(rel)
            if not first_diff:
                first_diff = _format_missing(rel, expected_body)
            continue
        on_disk = target.read_text(encoding="utf-8")
        if on_disk != expected_body:
            drifting.append(rel)
            if not first_diff:
                first_diff = _format_diff(rel, on_disk, expected_body)
    # Surface unexpected stale files (present on disk but not in the
    # current generation). These also count as drift because the next
    # generate will delete them.
    expected_set = {str(rel) for rel in expected_paths}
    for stale in sorted(out_root.rglob("*.md")):
        rel_str = str(stale.relative_to(out_root))
        if rel_str not in expected_set:
            drifting.append(Path(rel_str))
            if not first_diff:
                first_diff = (
                    f"--- {rel_str}\n+++ /dev/null\n"
                    f"unexpected stale page on disk\n"
                )
    return (bool(drifting), drifting, first_diff)


def _format_diff(rel: Path, on_disk: str, expected: str) -> str:
    """Return a unified diff string for one file."""
    return "".join(
        difflib.unified_diff(
            on_disk.splitlines(keepends=True),
            expected.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
    )


def _format_missing(rel: Path, expected: str) -> str:
    """Return a synthetic diff describing a missing-on-disk page."""
    return "".join(
        difflib.unified_diff(
            "".splitlines(keepends=True),
            expected.splitlines(keepends=True),
            fromfile="/dev/null",
            tofile=f"b/{rel}",
        )
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build-cli-reference.py",
        description=(
            "Generate Markdown CLI reference pages under docs/reference/cli/ "
            "from `rly --json help`. Use --check in CI to detect drift."
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Compare generated content against existing pages on disk; "
            "exit 1 on drift and print a unified diff of the first drifting "
            "file. Does not write."
        ),
    )
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUT_DIR),
        help=(
            "Output directory (default: docs/reference/cli/ relative to "
            "the repo root)."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits with code 2 on usage errors; remap to the
        # canonical CLI-usage exit code.
        code = int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE
        if code == 0:
            return EXIT_OK
        return EXIT_USAGE
    out_root = Path(args.out).resolve()
    try:
        pages = _generate_pages()
    except RuntimeError as exc:
        print(f"build-cli-reference: ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.check:
        has_drift, drifting, diff = _diff_pages(pages, out_root)
        if not has_drift:
            return EXIT_OK
        print(
            "build-cli-reference: drift detected in "
            f"{len(drifting)} file(s); first drift: {drifting[0]}",
            file=sys.stderr,
        )
        if diff:
            sys.stderr.write(diff)
            if not diff.endswith("\n"):
                sys.stderr.write("\n")
        return EXIT_DRIFT
    _write_pages(pages, out_root)
    print(
        f"build-cli-reference: wrote {len(pages)} page(s) to {out_root}",
        file=sys.stdout,
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
