"""W15.1 doc-content tests for `docs/architecture/sandbox-threat-model.md`.

Plumbing-tier tests that bind each VAL-W15-NNN contract assertion to a
parser-driven check against the committed doc. Per CLAUDE.md TDD discipline,
each test carries `@pytest.mark.fulfills("VAL-W15-NNN")` so the gate engine
can trace test-to-assertion coverage.

The tests intentionally operate offline (no HTTP probes): per CLAUDE.md
"TESTING DISCIPLINE", tier-1 plumbing tests run without network access.
Repo-relative link resolution and intra-doc anchor checks run unconditionally
(VAL-W15-013). External HTTPS link probing is gated on the opt-in environment
variable ``RELAY_W15_LINKCHECK=1`` so CI plumbing remains offline while local
or nightly link-check runs can verify 2xx status when desired.

Spec citations:
- CEO plan T-F threat model (cherry-pick); CEO plan D10 (local-docker P0)
- Spec E.3 (side-effect classes), E.4 lines 3939-4005 (sandbox driver / NetworkPolicy)
- Eng plan A4 (layered proxy), L1 (spec hygiene TODO), L2 (no-Docker degraded mode)
- CW-005 action; C-GAP-006; C-GAP-007 whole-file banned-copy scan
- OV-16 disposition
"""

from __future__ import annotations

import os
import re
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml
from markdown_it import MarkdownIt

# ---------------------------------------------------------------------------
# Doc location + content load.
# ---------------------------------------------------------------------------

# tests/docs/test_*.py -> tests/docs -> tests -> repo root
REPO_ROOT: Path = Path(__file__).resolve().parents[2]
DOC_REL_PATH = "docs/architecture/sandbox-threat-model.md"
DOC_PATH: Path = REPO_ROOT / DOC_REL_PATH


# Banned product copy per CLAUDE.md J.5 / banned pattern #9. The list is
# case-insensitive and applies to the entire file (body AND front-matter),
# closing the C-GAP-007 front-matter evasion path.
BANNED_TERMS: tuple[str, ...] = (
    "compliant",
    "certified",
    "AI Act-approved",
    "guaranteed AI Act compliance",
)


# Required H2 headings (canonical order, exact match) per VAL-W15-003.
REQUIRED_H2: tuple[str, ...] = (
    "Threat Model (T)",
    "Failure Modes (F)",
    "Local-Docker Sandbox (P0)",
    "No-Docker Degraded Mode",
    "Spec Hygiene TODO (§E.4 contradiction)",
)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _read_raw() -> str:
    """Read the whole doc file (front-matter + body) as text."""
    assert DOC_PATH.exists(), f"W15 doc missing at {DOC_PATH}"
    return DOC_PATH.read_text(encoding="utf-8")


_FRONT_MATTER_RE = re.compile(r"\A---\s*\n(?P<yaml>.*?)\n---\s*\n(?P<body>.*)\Z", re.DOTALL)


def _split_front_matter(raw: str) -> tuple[dict[str, Any], str]:
    """Return (front_matter_dict, body_markdown). Raises if not well-formed."""
    m = _FRONT_MATTER_RE.match(raw)
    if not m:
        raise AssertionError(
            "W15 doc must begin with a YAML front-matter block delimited by '---'."
        )
    fm_raw = m.group("yaml")
    body = m.group("body")
    parsed = yaml.safe_load(fm_raw)
    if not isinstance(parsed, dict):
        raise AssertionError("W15 front-matter must parse as a YAML mapping.")
    return parsed, body


def _h2_headings(body: str) -> list[str]:
    """Extract H2 headings (text only) in document order.

    Uses markdown-it-py so fenced code blocks and other constructs are
    correctly skipped (a literal '## ...' inside a fenced block must not be
    counted as an H2).
    """
    md = MarkdownIt("commonmark")
    tokens = md.parse(body)
    out: list[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.type == "heading_open" and t.tag == "h2":
            inline = tokens[i + 1]
            text = inline.content.strip()
            out.append(text)
        i += 1
    return out


def _all_headings_with_levels(body: str) -> list[tuple[int, str]]:
    """Return list of (level, text) for every ATX heading in body order."""
    md = MarkdownIt("commonmark")
    tokens = md.parse(body)
    out: list[tuple[int, str]] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.type == "heading_open":
            level = int(t.tag[1:])
            inline = tokens[i + 1]
            out.append((level, inline.content.strip()))
        i += 1
    return out


def _markdown_links(body: str) -> list[tuple[str, str]]:
    """Extract (label, target) for every markdown link in body order."""
    md = MarkdownIt("commonmark")
    tokens = md.parse(body)
    out: list[tuple[str, str]] = []
    for tok in tokens:
        if tok.type != "inline" or tok.children is None:
            continue
        children = tok.children
        i = 0
        while i < len(children):
            c = children[i]
            if c.type == "link_open":
                href = c.attrs.get("href", "") if c.attrs else ""
                label_parts: list[str] = []
                j = i + 1
                while j < len(children) and children[j].type != "link_close":
                    if children[j].type == "text":
                        label_parts.append(children[j].content)
                    j += 1
                out.append(("".join(label_parts), str(href)))
                i = j + 1
            else:
                i += 1
    return out


def _slugify(text: str) -> str:
    """GitHub-style heading slug: lowercase, non-alphanum -> hyphen, collapse, strip."""
    s = text.lower()
    s = re.sub(r"[^\w\s-]", "", s, flags=re.UNICODE)
    s = re.sub(r"\s+", "-", s).strip("-")
    return s


def _is_rfc3339_date(value: object) -> bool:
    """Accept YYYY-MM-DD (RFC 3339 full-date) or full RFC 3339 datetime string."""
    if isinstance(value, date):
        return True
    if not isinstance(value, str):
        return False
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", value)
    if m:
        try:
            date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            return True
        except ValueError:
            return False
    m = re.match(
        r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$",
        value,
    )
    if not m:
        return False
    try:
        date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# Module-level cached parses (parsed once per test session).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def raw_doc() -> str:
    return _read_raw()


@pytest.fixture(scope="module")
def parsed(raw_doc: str) -> tuple[dict[str, Any], str]:
    return _split_front_matter(raw_doc)


@pytest.fixture(scope="module")
def front_matter(parsed: tuple[dict[str, Any], str]) -> dict[str, Any]:
    return parsed[0]


@pytest.fixture(scope="module")
def body(parsed: tuple[dict[str, Any], str]) -> str:
    return parsed[1]


# ===========================================================================
# VAL-W15-001  Doc exists at canonical path, non-empty body >= 600 words.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-001")
def test_w15_001_doc_exists_with_minimum_body_word_count(body: str) -> None:
    """File present, parses, and body >= 600 words after stripping front-matter."""
    word_count = len(body.split())
    assert word_count >= 600, (
        f"W15 doc body must be >= 600 words; got {word_count}. "
        f"VAL-W15-001 binds doc length to minimum substantive content threshold."
    )


# ===========================================================================
# VAL-W15-002  Status / Approval front-matter block present.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-002")
def test_w15_002_front_matter_has_required_keys_and_valid_values(
    front_matter: dict[str, Any],
) -> None:
    """Front-matter contains status, last-reviewed-by, last-reviewed-on,
    next-review-due. last-reviewed-on and next-review-due must be RFC 3339.
    """
    required_keys = {
        "status",
        "last-reviewed-by",
        "last-reviewed-on",
        "next-review-due",
    }
    missing = required_keys - set(front_matter.keys())
    assert not missing, f"W15 front-matter missing keys: {sorted(missing)}"

    status = front_matter["status"]
    assert isinstance(status, str) and status.strip(), (
        "W15 front-matter status must be a non-empty string"
    )

    reviewer = front_matter["last-reviewed-by"]
    assert isinstance(reviewer, str) and reviewer.strip(), (
        "W15 front-matter last-reviewed-by must be a non-empty string"
    )

    assert _is_rfc3339_date(front_matter["last-reviewed-on"]), (
        f"W15 front-matter last-reviewed-on must be RFC 3339; "
        f"got {front_matter['last-reviewed-on']!r}"
    )
    assert _is_rfc3339_date(front_matter["next-review-due"]), (
        f"W15 front-matter next-review-due must be RFC 3339; "
        f"got {front_matter['next-review-due']!r}"
    )


# ===========================================================================
# VAL-W15-003  Required H2 headings present in canonical order.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-003")
def test_w15_003_required_h2_headings_in_canonical_order(body: str) -> None:
    """The canonical H2 sequence must appear in order. Other H2 sections may
    intersperse (the contract permits extra sections such as Overview,
    Cross-References, No Legal Advice) but the canonical five must appear in
    the canonical order."""
    found = _h2_headings(body)
    # Filter found headings down to the canonical set, preserving order.
    canonical_seen = [h for h in found if h in REQUIRED_H2]
    assert canonical_seen == list(REQUIRED_H2), (
        f"W15 canonical H2 headings must appear in canonical order with no "
        f"duplicates or omissions.\n"
        f"  expected order: {list(REQUIRED_H2)}\n"
        f"  observed (filtered): {canonical_seen}\n"
        f"  all H2s in doc: {found}"
    )


# ===========================================================================
# VAL-W15-004  Threat actor types (T) enumerated.
# ===========================================================================


def _section_body(body: str, h2_name: str) -> str:
    """Return the body text under H2 `h2_name` up to the next H2."""
    lines = body.splitlines()
    out: list[str] = []
    capturing = False
    in_fence = False
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            if capturing:
                out.append(line)
            continue
        if not in_fence and stripped.startswith("## "):
            heading = stripped[3:].strip()
            if capturing and heading != h2_name:
                break
            capturing = heading == h2_name
            continue
        if capturing:
            out.append(line)
    return "\n".join(out)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-004")
def test_w15_004_threat_actor_types_enumerated(body: str) -> None:
    """Threat Model (T) section enumerates: trusted local-dev customer code
    (in-scope), untrusted third-party agent code (out-of-scope), network-side
    adversary (egress-deny), compromised tool destination (side-effect-class
    policy), host kernel-level adversary (not defended)."""
    section = _section_body(body, "Threat Model (T)")
    assert section.strip(), "Threat Model (T) section is empty"
    lower = section.lower()

    # (a) trusted local-dev customer code, in-scope for P0
    assert "trusted local-dev" in lower, (
        "Threat Model must enumerate 'trusted local-dev customer code' actor class"
    )
    assert "in-scope" in lower, (
        "Threat Model must mark trusted local-dev as in-scope"
    )

    # (b) untrusted third-party agent code, explicitly out-of-scope for P0
    assert "untrusted third-party" in lower, (
        "Threat Model must enumerate 'untrusted third-party agent code' actor class"
    )
    assert "out-of-scope" in lower, (
        "Threat Model must mark untrusted third-party as out-of-scope for P0"
    )

    # (c) network-side adversary, egress-deny defended
    assert "network-side adversary" in lower, (
        "Threat Model must enumerate 'network-side adversary' actor class"
    )
    assert "egress" in lower and ("deny" in lower or "default-deny" in lower), (
        "Threat Model must describe egress-deny defense for network-side adversary"
    )

    # (d) compromised tool destination, side-effect-class policy defended
    assert "compromised tool" in lower, (
        "Threat Model must enumerate 'compromised tool destination' actor class"
    )
    assert "side-effect" in lower, (
        "Threat Model must cite side-effect-class policy defense"
    )

    # (e) host kernel-level adversary, explicitly NOT defended by local-docker
    assert "kernel-level adversary" in lower or "host kernel-level" in lower, (
        "Threat Model must enumerate 'host kernel-level adversary' actor class"
    )
    not_defended_present = (
        "not defended" in lower
        or "not in scope" in lower
        or "outside the trust boundary" in lower
        or "does not provide" in lower
    )
    assert not_defended_present, (
        "Threat Model must explicitly state kernel-level adversary is NOT defended"
    )


# ===========================================================================
# VAL-W15-005  Failure modes (F) enumerated.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-005")
def test_w15_005_failure_modes_enumerated(body: str) -> None:
    """Failure Modes (F) section enumerates: provision failure, egress leak,
    side-effect tool call leak, cassette tamper / fixture digest mismatch,
    Docker absent on host, kernel-level escape (not in P0 scope)."""
    section = _section_body(body, "Failure Modes (F)")
    assert section.strip(), "Failure Modes (F) section is empty"
    lower = section.lower()

    # (a) sandbox provision failure
    assert "provision failure" in lower or "provision-failed" in lower, (
        "Failure Modes must enumerate sandbox provision failure"
    )

    # (b) network egress leak
    assert "egress leak" in lower, (
        "Failure Modes must enumerate network egress leak"
    )

    # (c) side-effect tool call leak
    assert "side-effect" in lower and "leak" in lower, (
        "Failure Modes must enumerate side-effect tool-call leak"
    )

    # (d) cassette tamper / fixture digest mismatch
    cassette_phrase = (
        "cassette tamper" in lower
        or "fixture digest mismatch" in lower
        or ("cassette" in lower and "digest" in lower)
    )
    assert cassette_phrase, (
        "Failure Modes must enumerate cassette tamper / fixture digest mismatch"
    )

    # (e) Docker absent on host (Windows / minimal Linux)
    assert "docker absent" in lower or "docker" in lower and "windows" in lower, (
        "Failure Modes must enumerate Docker absent on host"
    )

    # (f) kernel-level escape (explicitly not in P0 scope)
    assert "kernel-level escape" in lower, (
        "Failure Modes must enumerate kernel-level escape"
    )
    not_in_scope_present = (
        "not in p0 scope" in lower
        or "not in scope" in lower
        or "outside the trust boundary" in lower
        or "explicitly not" in lower
    )
    assert not_in_scope_present, (
        "Failure Modes must explicitly state kernel-level escape is not in P0 scope"
    )


# ===========================================================================
# VAL-W15-006  Local-docker P0 elevation explicitly stated.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-006")
def test_w15_006_local_docker_p0_elevation(body: str) -> None:
    """Local-Docker Sandbox (P0) section states: v0.1 P0 driver is
    local-docker (per CEO plan D10); e2b remains documented opt-in;
    docker resource isolation + network policy enforcement are the in-scope
    defense surface; kernel-level isolation is explicitly NOT provided."""
    section = _section_body(body, "Local-Docker Sandbox (P0)")
    assert section.strip(), "Local-Docker Sandbox (P0) section is empty"
    lower = section.lower()

    # local-docker named as P0
    assert "local-docker" in lower, (
        "Local-Docker Sandbox section must name 'local-docker' as P0 driver"
    )

    # e2b named as documented opt-in
    assert "e2b" in lower and "opt-in" in lower, (
        "Local-Docker Sandbox section must state 'e2b' remains a documented opt-in"
    )

    # network policy enforcement named
    assert "network policy" in lower, (
        "Local-Docker Sandbox section must name network policy enforcement"
    )

    # kernel-level isolation explicitly NOT provided
    kernel_negation_present = (
        ("kernel-level isolation" in lower)
        and ("not provided" in lower or "does not" in lower or "explicitly does not" in lower)
    )
    assert kernel_negation_present, (
        "Local-Docker Sandbox section must explicitly state kernel-level "
        "isolation is NOT provided"
    )


# ===========================================================================
# VAL-W15-007  No-Docker degraded mode pathway + W7 implementation-timing footnote.
# ===========================================================================


# Literal substring required by VAL-W15-007 (CW-005 action + C-GAP-006).
W7_TIMING_FOOTNOTE = (
    "A4 layered proxy is implemented in W7; "
    "this doc establishes the doc-first design"
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-007")
def test_w15_007_no_docker_degraded_mode_and_w7_footnote(body: str) -> None:
    """No-Docker Degraded Mode section documents: rly replay run works
    without sandbox, A4 layered proxy is default enforcement (mitmproxy +
    HTTPS_PROXY + socket deny + undici interceptor), sandbox driver is only
    required for verify-self and tier-3 evals, Windows users without Docker
    get this degraded mode. AND the literal W7 timing footnote substring
    must appear.

    Updated to expect bare `verify-self` rather than the prior
    `verify-self --sandbox-check` form because the `--sandbox-check` flag
    was never implemented on the CLI surface (`rly verify-self --help`
    exposes only --repo-root / --json / --home / --help). Earlier review
    iteration corrected the doc; this test now matches the corrected wording.
    """
    section = _section_body(body, "No-Docker Degraded Mode")
    assert section.strip(), "No-Docker Degraded Mode section is empty"
    lower = section.lower()

    # "without" Docker / sandbox
    assert "without" in lower and ("docker" in lower or "sandbox" in lower), (
        "No-Docker Degraded Mode must state rly replay run works WITHOUT a "
        "Docker-based sandbox"
    )

    # A4 layered proxy named
    assert "a4 layered proxy" in lower, (
        "No-Docker Degraded Mode must name 'A4 layered proxy' as default enforcement"
    )

    # mitmproxy named
    assert "mitmproxy" in lower, (
        "No-Docker Degraded Mode must name 'mitmproxy' transport"
    )

    # verify-self named (the prior `--sandbox-check` flag was never
    # implemented on the CLI; doc updated to bare `verify-self` and this
    # assertion follows). Scoped to the No-Docker Degraded Mode section
    # via _section_body extraction above.
    assert "verify-self" in lower, (
        "No-Docker Degraded Mode must cite 'verify-self' as the diagnostic"
    )

    # tier-3 evals named
    assert "tier-3 eval" in lower, (
        "No-Docker Degraded Mode must cite 'tier-3 evals'"
    )

    # CW-005 / C-GAP-006 literal W7 timing footnote
    assert W7_TIMING_FOOTNOTE in body, (
        f"No-Docker Degraded Mode section (or doc body) MUST contain the "
        f"literal substring: {W7_TIMING_FOOTNOTE!r}. Required by CW-005 + "
        f"C-GAP-006 to make the forward reference acceptable as doc-first "
        f"design rather than drift."
    )


# ===========================================================================
# VAL-W15-008  Spec E.4 contradiction TODO explicitly flagged (L1).
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-008")
def test_w15_008_spec_e4_contradiction_todo_flagged(body: str) -> None:
    """Spec Hygiene TODO section explicitly states: spec E.4 lines 3939-4005
    lists e2b as P0; D10 elevates local-docker to P0; spec hygiene TODO is
    filed; this doc resolves the contradiction for v0.1 in favor of
    local-docker P0."""
    section = _section_body(body, "Spec Hygiene TODO (§E.4 contradiction)")
    assert section.strip(), "Spec Hygiene TODO section is empty"
    lower = section.lower()

    # Spec section cite
    assert "§e.4" in lower, "Spec Hygiene TODO must cite spec section '§E.4'"

    # Stable line range form per C-MIN-005 reconciliation
    assert "lines 3939-4005" in lower, (
        "Spec Hygiene TODO must cite the stable line range 'lines 3939-4005' "
        "per C-MIN-005 reconciliation (dropping 'line ~3941' hedging)"
    )

    # e2b and local-docker contrast
    assert "e2b" in lower, "Spec Hygiene TODO must name 'e2b'"
    assert "local-docker" in lower, "Spec Hygiene TODO must name 'local-docker'"

    # D10 cite
    assert "d10" in lower, "Spec Hygiene TODO must cite CEO plan D10"

    # spec hygiene TODO is filed
    assert "spec hygiene todo" in lower, (
        "Spec Hygiene TODO section must contain the literal 'spec hygiene TODO' phrase"
    )

    # Resolution statement
    resolution_present = (
        "resolves" in lower or "resolution" in lower or "in favor of" in lower
    )
    assert resolution_present, (
        "Spec Hygiene TODO must state this doc resolves the contradiction in "
        "favor of local-docker P0 for v0.1"
    )


# ===========================================================================
# VAL-W15-009  Out-of-scope use cases explicitly stated.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-009")
def test_w15_009_out_of_scope_use_cases(body: str) -> None:
    """Doc explicitly states the local-docker P0 sandbox is NOT appropriate
    for: (a) running untrusted third-party agent code, (b) multi-tenant
    sandbox-as-a-service, (c) security-critical isolation against malicious
    code."""
    lower = body.lower()

    # (a) untrusted third-party agent code
    assert "untrusted third-party" in lower, (
        "Doc must state local-docker P0 is NOT appropriate for untrusted "
        "third-party agent code"
    )

    # (b) multi-tenant sandbox-as-a-service
    assert "multi-tenant sandbox-as-a-service" in lower or (
        "multi-tenant" in lower and "sandbox-as-a-service" in lower
    ), (
        "Doc must state local-docker P0 is NOT appropriate for multi-tenant "
        "sandbox-as-a-service"
    )

    # (c) security-critical isolation against malicious code
    assert "security-critical isolation" in lower, (
        "Doc must state local-docker P0 is NOT appropriate for "
        "security-critical isolation against malicious code"
    )
    assert "malicious code" in lower, (
        "Doc must reference 'malicious code' in the security-critical "
        "isolation out-of-scope statement"
    )


# ===========================================================================
# VAL-W15-010  Side-effect blocking mechanism cited (driver-level, not kernel).
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-010")
def test_w15_010_side_effect_blocking_driver_level(body: str) -> None:
    """Doc explicitly states side-effect blocking per spec E.3 operates at
    the DRIVER level (intercepting tool calls and applying side-effect-class
    policy), NOT via kernel-level confinement."""
    lower = body.lower()

    # E.3 cite
    assert "§e.3" in lower, "Doc must cite spec E.3 for side-effect blocking"

    # driver level (vs kernel level)
    assert "driver level" in lower, (
        "Doc must state side-effect blocking operates at the 'driver level'"
    )

    # side-effect class
    assert "side-effect class" in lower or "side_effect_class" in lower, (
        "Doc must cite 'side-effect class' (or side_effect_class)"
    )

    # kernel-level negation
    kernel_negation = (
        "not via kernel-level" in lower
        or "not at the kernel level" in lower
        or "not kernel-level" in lower
        or "not kernel level" in lower
        or "not the kernel level" in lower
    )
    assert kernel_negation, (
        "Doc must explicitly state side-effect blocking is NOT kernel-level"
    )


# ===========================================================================
# VAL-W15-011  Banned product copy returns zero matches (whole file, case-insensitive).
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-011")
def test_w15_011_banned_product_copy_absent_whole_file(raw_doc: str) -> None:
    """Whole-file case-insensitive scan for banned product copy per
    CLAUDE.md J.5 / banned pattern #9. C-GAP-007 whole-file scan closes the
    front-matter evasion path."""
    haystack = raw_doc.lower()
    offenders = [term for term in BANNED_TERMS if term.lower() in haystack]
    assert not offenders, (
        f"W15 file contains banned product copy: {offenders}. "
        "Banned per CLAUDE.md J.5 / banned pattern #9. Scan is whole-file "
        "(front-matter + body) per C-GAP-007."
    )


# ===========================================================================
# VAL-W15-012  Cross-references to W13 and E.4 architecture present.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-012")
def test_w15_012_cross_references_w13_and_e4(body: str) -> None:
    """Doc body cites: spec E.4 (replay sandbox driver interface), spec E.3
    (side-effect class), AND contains a Markdown link to
    ../legal/trust-anchor-governance.md (W13)."""
    assert "§E.4" in body, (
        "Doc must cite spec section §E.4 (replay sandbox driver interface)"
    )
    assert "§E.3" in body, (
        "Doc must cite spec section §E.3 (side-effect class)"
    )
    # Link to W13 doc
    links = _markdown_links(body)
    targets = [t for _, t in links]
    w13_link_present = any(
        "legal/trust-anchor-governance.md" in t for t in targets
    )
    assert w13_link_present, (
        "Doc must contain a Markdown link to ../legal/trust-anchor-governance.md "
        "(W13 sibling doc). Observed link targets: " + str(targets)
    )


# ===========================================================================
# VAL-W15-013  Internal + external links resolve.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W15-013")
def test_w15_013_links_resolve(body: str) -> None:
    """Every Markdown link in the W15 doc resolves: repo-relative links point
    to existing files, anchor links point to existing slug-ified headings,
    external HTTPS links are well-formed. Network HEAD probing gated on
    RELAY_W15_LINKCHECK=1 to keep plumbing tier offline."""
    links = _markdown_links(body)
    assert links, "W15 doc must contain at least one markdown link."

    # Collect headings for anchor resolution.
    headings = _all_headings_with_levels(body)
    heading_slugs = {_slugify(text) for _, text in headings}

    errors: list[str] = []

    for label, target in links:
        if not target:
            errors.append(f"empty link target for label {label!r}")
            continue

        # Pure anchor link e.g. '#threat-model-t'
        if target.startswith("#"):
            slug = target[1:]
            if slug not in heading_slugs:
                errors.append(
                    f"anchor target {target!r} not found among {sorted(heading_slugs)}"
                )
            continue

        parsed = urllib.parse.urlparse(target)

        # External http(s) link.
        if parsed.scheme in ("http", "https"):
            if not parsed.netloc:
                errors.append(f"external link {target!r} missing netloc")
                continue
            # Plumbing tier: skip network. Opt-in network check.
            if os.environ.get("RELAY_W15_LINKCHECK") == "1":
                req = urllib.request.Request(target, method="HEAD")
                try:
                    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                        status = resp.status
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"external link {target!r} HEAD failed: {exc}")
                    continue
                if status < 200 or status >= 400:
                    errors.append(
                        f"external link {target!r} returned status {status}"
                    )
            continue

        if parsed.scheme in ("mailto",):
            if "@" not in parsed.path:
                errors.append(f"mailto link {target!r} missing '@'")
            continue

        # Otherwise treat as repo-relative. Strip fragment for file resolution.
        rel = parsed.path
        fragment = parsed.fragment

        if rel.startswith("/"):
            errors.append(
                f"absolute path link {target!r} not permitted; use repo-relative path"
            )
            continue

        # Resolve relative to the W15 doc's directory.
        candidate = (DOC_PATH.parent / rel).resolve()

        # Containment: candidate must stay inside REPO_ROOT.
        try:
            candidate.relative_to(REPO_ROOT)
        except ValueError:
            errors.append(f"link {target!r} escapes repo root: {candidate}")
            continue

        if not candidate.exists():
            errors.append(
                f"internal link {target!r} resolves to missing file {candidate}"
            )
            continue

        # If the link includes a fragment AND points to a markdown file inside
        # the repo, validate the fragment against that file's headings.
        if fragment and candidate.suffix.lower() == ".md":
            try:
                other_body_raw = candidate.read_text(encoding="utf-8")
            except OSError as exc:
                errors.append(f"link {target!r}: cannot read {candidate}: {exc}")
                continue
            m = _FRONT_MATTER_RE.match(other_body_raw)
            other_body = m.group("body") if m else other_body_raw
            other_slugs = {
                _slugify(text) for _, text in _all_headings_with_levels(other_body)
            }
            if fragment not in other_slugs:
                errors.append(
                    f"link {target!r}: fragment {fragment!r} not found in "
                    f"{candidate.name}"
                )

    assert not errors, "W15 link resolution failed:\n  - " + "\n  - ".join(errors)
