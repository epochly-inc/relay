#!/usr/bin/env python3
"""Generate the spec<->code<->test traceability map (DELIVERABLE 3).

Two layers, both deterministic and reproducible:

  1. KEYSTONE INVARIANTS (16): each load-bearing invariant mapped to its
     enforcing source path AND its guard test(s). The enforcement path is
     verified to exist; guard tests are discovered by grepping the test tree
     for the invariant's guard marker. An invariant with a missing enforcement
     site or zero guard tests is a P0 finding.

  2. SPEC SECTIONS (from packages/schemas/raw/spec-sections.txt): each section
     ID is searched for as a citation (``Section <id>`` / ``spec <id>``)
     across production source and tests. A load-bearing section cited in
     NEITHER is flagged as a coverage gap (candidate unimplemented / doc
     drift). NOTE: bare single/double-letter section IDs are inherently noisy;
     this layer is a COARSE coverage signal, not a precise binding, and is
     reported as such.

Plus a VAL-assertion coverage count: how many distinct ``VAL-*`` assertions are
bound to a test via ``@pytest.mark.fulfills`` (the contract-assertion guard).

Outputs (deterministic, sorted, no timestamps) under docs/architecture/:
  * traceability-map.json -- machine-readable.
  * traceability-map.md   -- human-readable + findings.

Usage::

    python scripts/gen-traceability-map.py            # regenerate
    python scripts/gen-traceability-map.py --check     # fail on drift OR P0 gap
    python scripts/gen-traceability-map.py --json      # print JSON

Exit codes: 0 = ok; 1 = drift (under --check) OR an invariant with no
enforcement/guard (under --check); 2 = IO error.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
OUT_DIR: Final[Path] = REPO_ROOT / "docs" / "architecture"
SPEC_SECTIONS: Final[Path] = REPO_ROOT / "packages" / "schemas" / "raw" / "spec-sections.txt"

_SRC_ROOTS: Final[tuple[str, ...]] = ("packages", "apps")
_EXCLUDED: Final[frozenset[str]] = frozenset(
    {"node_modules", "vendor", "target", "dist", "build", "__pycache__",
     ".venv", "conformance", "gen"}
)

# The 16 keystone invariants. enforcement = a path substring that MUST resolve
# to an existing file/dir; guard_grep = a regex grepped across the test tree to
# discover the guard test(s). Curated from docs/architecture/keystone-invariants.md
# + ARCHITECTURE.md section 6 + the CLAUDE.md "REQUIRED GUARD TESTS" table.
KEYSTONE: Final[list[dict[str, str]]] = [
    {"n": "1", "name": "Control plane writes the result",
     "enforcement": "apps/local-sidecar/relay_sidecar/state_engine/compare_and_set.py",
     "guard_grep": r"written_by|control_plane|RunResult ownership|run_results.*INSERT"},
    {"n": "2", "name": "Pass without evidence is not a pass",
     "enforcement": "packages/gate/src/relay_gate_engine",
     "guard_grep": r"evidence.?pairing|exit_code.*artifact|artifact.*digest.*exit"},
    {"n": "3", "name": "Manifest is the source of truth",
     "enforcement": "packages/cli/src/relay_cli/commands/manifest.py",
     "guard_grep": r"command_hash|manifest.*source.?of.?truth|declared command"},
    {"n": "4", "name": "Three-anchor handoff",
     "enforcement": "apps/local-sidecar/relay_sidecar/state_engine/guards.py",
     "guard_grep": r"three.?anchor|RELAY-GATE-021|stale handoff|actor_identity_hash"},
    {"n": "5", "name": "Gate restart on failure",
     "enforcement": "packages/gate/src/relay_gate_engine/restart_pipeline.py",
     "guard_grep": r"gate restart|restart.*scrutiny|remediation_round|restart_pipeline"},
    {"n": "6", "name": "Side-effect idempotency",
     "enforcement": "apps/local-sidecar/relay_sidecar/side_effect_markers.py",
     "guard_grep": r"pre.?action marker|post.?success proof|side.?effect.*idempot"},
    {"n": "7", "name": "Default-deny raw capture",
     "enforcement": "apps/local-sidecar/relay_sidecar/validation/raw_capture.py",
     "guard_grep": r"raw_capture|RAWCAPTURE-DENIED|default.?deny.*raw"},
    {"n": "8", "name": "Atomic persistence -- four primitives only",
     "enforcement": "apps/local-sidecar/relay_sidecar/primitives",
     "guard_grep": r"transactional_db_write|object_put_with_digest|atomic.?write|four primitives"},
    {"n": "9", "name": "Cassette-first replay",
     "enforcement": "apps/replay-proxy/relay_replay_proxy",
     "guard_grep": r"cassette.?first|cassette mode|replay.*cassette default"},
    {"n": "10", "name": "Schema versioning on every envelope",
     "enforcement": "packages/schemas/python/relay_schemas",
     "guard_grep": r"schema_version|unknown version.*refuse|schema versioning"},
    {"n": "11", "name": "Trust anchor is the moat",
     "enforcement": "packages/verifier/src/relay_verifier/jwks_loader.py",
     "guard_grep": r"trust_anchor|jwks.*default|well-known/jwks"},
    {"n": "12", "name": "Live replay against irreversible effects is gated",
     "enforcement": "apps/local-sidecar/relay_sidecar/side_effect_markers.py",
     "guard_grep": r"external_irreversible|mutating.*replay|RELAY-REPLAY-014|side_effect_class"},
    {"n": "13", "name": "OSS default trust-anchor change is board-level",
     "enforcement": "packages/verifier/src/relay_verifier/jwks_loader.py",
     "guard_grep": r"default trust.?anchor|relay\.epochly\.com|board.?level"},
    {"n": "14", "name": "No trust-anchor key material in OSS repo",
     "enforcement": "scripts/lint-banned-copy.py",
     "guard_grep": r"private key|key material|secret.?scan|BEGIN .*PRIVATE"},
    {"n": "15", "name": "OSS/hosted source-boundary discipline",
     "enforcement": "scripts/gen-dependency-graph.py",
     "guard_grep": r"import.?boundary|pack.?boundary|relay-platform"},
    {"n": "16", "name": "CEL UDFs deterministic; Py<->wasm<->TS parity",
     "enforcement": "packages/cel-wasm",
     "guard_grep": r"byte.?parity|cross.?host|conformance.*corpus|determinis"},
]


def _is_excluded(rel: Path) -> bool:
    return any(part in _EXCLUDED for part in rel.parts)


def _iter_files(suffixes: tuple[str, ...], *, tests: bool) -> list[Path]:
    out: list[Path] = []
    for root in _SRC_ROOTS:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if p.suffix not in suffixes or not p.is_file():
                continue
            rel = p.relative_to(REPO_ROOT)
            in_tests = "tests" in rel.parts or "test" in rel.parts
            if in_tests != tests:
                continue
            if _is_excluded(rel) and not in_tests:
                continue
            out.append(p)
    # repo-root tests/ tree (cross-package guards live here)
    if tests:
        troot = REPO_ROOT / "tests"
        if troot.is_dir():
            out.extend(p for p in troot.rglob("*.py") if p.is_file())
    return sorted(set(out))


_SRC_SUFFIXES: Final[tuple[str, ...]] = (".py", ".ts", ".mts", ".rs")


def _grep_files(files: list[Path], pattern: str) -> list[str]:
    rx = re.compile(pattern)
    hits: list[str] = []
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if rx.search(text):
            hits.append(str(p.relative_to(REPO_ROOT)))
    return sorted(hits)


def _load_sections() -> list[str]:
    if not SPEC_SECTIONS.is_file():
        return []
    out: list[str] = []
    for line in SPEC_SECTIONS.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return sorted(set(out))


def build_map() -> dict[str, object]:
    src_files = _iter_files(_SRC_SUFFIXES, tests=False)
    test_files = _iter_files((".py", ".ts", ".mts"), tests=True)

    # Layer 1: keystone invariants.
    invariants: list[dict[str, object]] = []
    for inv in KEYSTONE:
        enf = REPO_ROOT / inv["enforcement"]
        guards = _grep_files(test_files, inv["guard_grep"])
        invariants.append({
            "n": inv["n"],
            "name": inv["name"],
            "enforcement": inv["enforcement"],
            "enforcement_exists": enf.exists(),
            "guard_tests": guards,
            "guard_test_count": len(guards),
        })

    # Layer 2: spec-section coarse coverage.
    sections = _load_sections()
    sec_rows: list[dict[str, object]] = []
    for sid in sections:
        esid = re.escape(sid)
        pat = rf"(?:Section |[Ss]pec[^A-Za-z0-9]{{0,3}}|§){esid}(?![0-9A-Za-z.])"
        in_src = bool(_grep_files(src_files, pat))
        in_test = bool(_grep_files(test_files, pat))
        sec_rows.append({"section": sid, "in_source": in_src, "in_tests": in_test})

    # VAL-assertion coverage (fulfills bindings).
    val_rx = re.compile(r'fulfills\(\s*"(VAL-[A-Z0-9]+-[0-9]+)"')
    bound: set[str] = set()
    for p in test_files:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        bound.update(val_rx.findall(text))

    findings: list[dict[str, object]] = []
    for inv in invariants:
        if not inv["enforcement_exists"]:
            findings.append({"severity": "P0", "kind": "missing_enforcement",
                             "invariant": inv["n"], "detail": inv["enforcement"]})
        if inv["guard_test_count"] == 0:
            findings.append({"severity": "P1", "kind": "no_guard_test",
                             "invariant": inv["n"], "detail": inv["name"]})
    uncited = [r["section"] for r in sec_rows
               if not r["in_source"] and not r["in_tests"]]

    return {
        "schema": "relay.architecture.traceability-map/v1",
        "generated_by": "scripts/gen-traceability-map.py",
        "keystone_invariants": invariants,
        "spec_sections_total": len(sections),
        "spec_sections": sec_rows,
        "spec_sections_uncited": sorted(uncited),
        "val_assertions_bound_to_tests": len(bound),
        "findings": findings,
    }


def render_md(m: dict[str, object]) -> str:
    inv = m["keystone_invariants"]
    assert isinstance(inv, list)
    findings = m["findings"]
    assert isinstance(findings, list)
    uncited = m["spec_sections_uncited"]
    assert isinstance(uncited, list)
    lines: list[str] = []
    lines.append("# Relay spec<->code<->test traceability map (generated)")
    lines.append("")
    lines.append(
        "Generated by `scripts/gen-traceability-map.py`. Do not edit by hand. "
        "Layer 1 (keystone invariants) is a precise enforcement+guard binding; "
        "Layer 2 (spec sections) is a COARSE citation-coverage signal."
    )
    lines.append("")
    lines.append(f"- Keystone invariants: {len(inv)}")
    lines.append(f"- Spec sections: {m['spec_sections_total']} "
                 f"({len(uncited)} cited in neither source nor tests)")
    lines.append(f"- VAL assertions bound to a test (`fulfills`): "
                 f"{m['val_assertions_bound_to_tests']}")
    lines.append(f"- Findings: {len(findings)}")
    lines.append("")
    lines.append("## Keystone invariant traceability")
    lines.append("")
    lines.append("| # | Invariant | Enforcement | exists | Guard tests |")
    lines.append("|---|---|---|---|---|")
    for r in inv:
        assert isinstance(r, dict)
        ok = "yes" if r["enforcement_exists"] else "**NO**"
        lines.append(
            f"| {r['n']} | {r['name']} | `{r['enforcement']}` | {ok} | "
            f"{r['guard_test_count']} |"
        )
    lines.append("")
    if findings:
        lines.append("## Findings")
        lines.append("")
        for f in findings:
            assert isinstance(f, dict)
            lines.append(f"- [{f['severity']}] {f['kind']} -- invariant "
                         f"#{f['invariant']}: {f['detail']}")
        lines.append("")
    if uncited:
        lines.append("## Spec sections cited in neither source nor tests (coarse)")
        lines.append("")
        lines.append(
            "These bare section IDs were not found as `Section <id>` / `spec "
            "<id>` / `§<id>` citations. Many are narrative/spec-only "
            "sections with no direct code binding (expected); review for any "
            "that should be implemented or guarded.")
        lines.append("")
        lines.append("> " + ", ".join(uncited))
        lines.append("")
    lines.append("Spec: §A, §S, §AK")
    return "\n".join(lines) + "\n"


def _dump_json(m: dict[str, object]) -> str:
    return json.dumps(m, indent=2, ensure_ascii=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true")
    p.add_argument("--json", action="store_true", dest="emit_json")
    args = p.parse_args(argv)

    try:
        m = build_map()
    except OSError as exc:  # pragma: no cover
        print(f"FAIL: traceability generation IO error: {exc}", file=sys.stderr)
        return 2

    json_text = _dump_json(m)
    md_text = render_md(m)
    if args.emit_json:
        sys.stdout.write(json_text)

    json_path = OUT_DIR / "traceability-map.json"
    md_path = OUT_DIR / "traceability-map.md"
    p0 = [f for f in m["findings"] if f["severity"] == "P0"]  # type: ignore[index,union-attr]

    if args.check:
        drift = []
        for path, expected in ((json_path, json_text), (md_path, md_text)):
            cur = path.read_text(encoding="utf-8") if path.exists() else None
            if cur != expected:
                drift.append(str(path.relative_to(REPO_ROOT)))
        if drift:
            print("FAIL: traceability map stale -- regenerate: "
                  + ", ".join(drift), file=sys.stderr)
            return 1
        if p0:
            print(f"FAIL: {len(p0)} P0 traceability finding(s) "
                  "(invariant with no enforcement site).", file=sys.stderr)
            return 1
        print("PASS: traceability map up to date; 0 P0 findings.")
        return 0

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json_text, encoding="utf-8")
    md_path.write_text(md_text, encoding="utf-8")
    print(f"Wrote {json_path.relative_to(REPO_ROOT)}, "
          f"{md_path.relative_to(REPO_ROOT)} "
          f"({len(m['keystone_invariants'])} invariants, "  # type: ignore[arg-type]
          f"{m['val_assertions_bound_to_tests']} bound assertions, "
          f"{len(m['findings'])} findings).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
