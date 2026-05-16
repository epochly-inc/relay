"""W14.1 doc-content tests for `docs/internal/eu-ai-act-readiness-draft.md`.

Plumbing-tier tests that bind each VAL-W14-NNN contract assertion to a
parser-driven check against the committed doc. Per CLAUDE.md TDD
discipline, each test carries `@pytest.mark.fulfills("VAL-W14-NNN")` so
the gate engine can trace test-to-assertion coverage.

The tests intentionally operate offline (no HTTP probes): per CLAUDE.md
"TESTING DISCIPLINE", tier-1 plumbing tests run without network access.
Repo-relative link resolution and intra-doc anchor checks run
unconditionally (VAL-W14-013). External HTTPS link probing is gated on
the opt-in environment variable ``RELAY_W14_LINKCHECK=1`` so CI
plumbing remains offline while local or nightly link-check runs can
verify 2xx status when desired.

This is the highest-stakes banned-copy assertion in the operation:
W14 is the document most likely to drift into prohibited
``compliant`` / ``certified`` / ``AI Act-approved`` / ``guaranteed AI
Act compliance`` terminology. VAL-W14-005 enforces zero matches across
the entire file (body AND front-matter), closing the C-GAP-007
front-matter evasion path.

Spec citations:
- §J.1 (current legal state + two-timeline scenarios + GPAI date)
- §J.3 (Article coverage map)
- §J.5 (forbidden product copy / permitted framing)
- PW1-6 (counsel review path; pro-bono candidates; publication gating)
"""

from __future__ import annotations

import os
import re
import urllib.parse
import urllib.request
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
DOC_REL_PATH = "docs/internal/eu-ai-act-readiness-draft.md"
DOC_PATH: Path = REPO_ROOT / DOC_REL_PATH


# Banned product copy per CLAUDE.md J.5 / banned pattern #9. Whole-file scan
# (front-matter + body), case-insensitive, closing C-GAP-007.
BANNED_TERMS: tuple[str, ...] = (
    "compliant",
    "certified",
    "AI Act-approved",
    "guaranteed AI Act compliance",
)


# Required H2 headings (canonical order; first H2 MUST be "Status: Internal
# Only" per VAL-W14-004 — internal-only status is the first thing a reader
# sees after front-matter). Intervening H2s are not permitted.
REQUIRED_H2: tuple[str, ...] = (
    "Status: Internal Only",
    "Scope",
    "Evidence Coverage by Annex IV Category",
    "Gaps",
    "Reviewer Path",
)


# Permitted counsel-reviewer enum values for VAL-W14-003.
PERMITTED_COUNSEL_REVIEWERS: frozenset[str] = frozenset(
    {"BABL AI", "Holistic AI", "Credo AI", "pending"}
)


# The three PW1-6 publication-gating conditions enumerated in front-matter.
# Each value is a substring that must appear in at least one
# `gating-conditions` entry.
PUBLICATION_GATING_TOKENS: tuple[str, ...] = (
    "paid counsel",
    "pro-bono",
    "self-publication",
)


# Annex IV article references required by VAL-W14-008. Each MUST appear in
# the Evidence Coverage section paired with a Relay surface citation.
REQUIRED_ARTICLES: tuple[str, ...] = (
    "Art. 9",
    "Art. 10",
    "Art. 11",
    "Art. 12",
    "Art. 13",
    "Art. 14",
    "Art. 15",
    "Art. 26",
    "Art. 27",
    "Art. 50",
    "Art. 51",  # Art. 51-55 GPAI cluster; "Art. 51" anchors the cluster
    "Art. 73",
)


# Load-bearing dates per VAL-W14-011 / spec §J.1.
REQUIRED_DATES: tuple[str, ...] = (
    "2 Aug 2026",
    "2 Dec 2026",
    "2 Aug 2027",
    "2 Dec 2027",
    "2 Aug 2028",
)


# Permitted framing terms per VAL-W14-006 / spec §J.5. The first term has
# two acceptable spellings per C-GAP-008.
PERMITTED_FRAMING_OR_ALTERNATIVES: tuple[tuple[str, ...], ...] = (
    ("AI Act readiness evidence", "EU AI Act readiness evidence"),
    ("evidence coverage",),
    ("gaps",),
    ("ready for auditor review",),
)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _read_raw() -> str:
    """Read the whole doc file (front-matter + body) as text."""
    assert DOC_PATH.exists(), f"W14 doc missing at {DOC_PATH}"
    return DOC_PATH.read_text(encoding="utf-8")


_FRONT_MATTER_RE = re.compile(
    r"\A---\s*\n(?P<yaml>.*?)\n---\s*\n(?P<body>.*)\Z", re.DOTALL
)


def _split_front_matter(raw: str) -> tuple[dict[str, Any], str]:
    """Return (front_matter_dict, body_markdown). Raises if not well-formed."""
    m = _FRONT_MATTER_RE.match(raw)
    if not m:
        raise AssertionError(
            "W14 doc must begin with a YAML front-matter block delimited by '---'."
        )
    fm_raw = m.group("yaml")
    body = m.group("body")
    parsed = yaml.safe_load(fm_raw)
    if not isinstance(parsed, dict):
        raise AssertionError("W14 front-matter must parse as a YAML mapping.")
    return parsed, body


def _h2_headings(body: str) -> list[str]:
    """Extract H2 headings (text only) in document order.

    Uses markdown-it-py so fenced code blocks are correctly skipped (a
    literal '## ...' inside a fenced block must not be counted as an H2).
    """
    md = MarkdownIt("commonmark")
    tokens = md.parse(body)
    out: list[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.type == "heading_open" and t.tag == "h2":
            inline = tokens[i + 1]
            out.append(inline.content.strip())
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
    """Extract (label, target) for every markdown link in body order.

    Uses markdown-it-py so links inside fenced code blocks are ignored.
    """
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
    """GitHub-style heading slug."""
    s = text.lower()
    s = re.sub(r"[^\w\s-]", "", s, flags=re.UNICODE)
    s = re.sub(r"\s+", "-", s).strip("-")
    return s


def _section_bodies(body: str) -> dict[str, str]:
    """Return {h2_text: section_text_through_next_h2} in doc order.

    Raw-text scan; fenced code blocks tracked so a literal '## ' inside a
    fence does not register as a heading.
    """
    sections: dict[str, str] = {}
    current_name: str | None = None
    current_lines: list[str] = []
    in_fence = False
    for line in body.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            if current_name is not None:
                current_lines.append(line)
            continue
        if not in_fence and stripped.startswith("## ") and not stripped.startswith(
            "### "
        ):
            if current_name is not None:
                sections[current_name] = "\n".join(current_lines)
            current_name = stripped[3:].strip()
            current_lines = []
            continue
        if current_name is not None:
            current_lines.append(line)
    if current_name is not None:
        sections[current_name] = "\n".join(current_lines)
    return sections


# ---------------------------------------------------------------------------
# Module-level cached parses.
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
# VAL-W14-001  Doc exists at internal-only canonical path; body >= 1000 words.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-001")
def test_w14_001_doc_exists_at_internal_only_path_with_minimum_body(
    body: str,
) -> None:
    """File present at internal-only canonical path; body >= 1000 words."""
    # Path is internal-only per PW1-6; wrong path (e.g.,
    # docs/compliance/eu-ai-act-readiness.md) fails per the contract.
    assert DOC_PATH.exists(), f"W14 doc missing at canonical path {DOC_PATH}"
    expected_parts = ("docs", "internal", "eu-ai-act-readiness-draft.md")
    actual_parts = DOC_PATH.relative_to(REPO_ROOT).parts
    assert actual_parts == expected_parts, (
        f"W14 doc must live at docs/internal/eu-ai-act-readiness-draft.md "
        f"(internal-only canonical path per PW1-6); got {actual_parts}."
    )
    word_count = len(body.split())
    assert word_count >= 1000, (
        f"W14 doc body must be >= 1000 words; got {word_count}. "
        f"VAL-W14-001 binds doc length to the minimum substantive content "
        f"threshold."
    )


# ===========================================================================
# VAL-W14-002  Front-matter declares internal-only prominently.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-002")
def test_w14_002_front_matter_internal_only_block(
    front_matter: dict[str, Any],
) -> None:
    """status: internal-only + audience: internal + publication-gated + gating-conditions."""
    required_keys = {"status", "audience", "publication-gated", "gating-conditions"}
    missing = required_keys - set(front_matter.keys())
    assert not missing, f"W14 front-matter missing keys: {sorted(missing)}"

    assert front_matter["status"] == "internal-only", (
        f"W14 front-matter status must be 'internal-only'; "
        f"got {front_matter['status']!r}. Per PW1-6 internal-only is the "
        f"load-bearing publication state."
    )
    assert front_matter["audience"] == "internal", (
        f"W14 front-matter audience must be 'internal'; "
        f"got {front_matter['audience']!r}."
    )
    assert front_matter["publication-gated"] is True, (
        f"W14 front-matter publication-gated must be True; "
        f"got {front_matter['publication-gated']!r}."
    )
    gating = front_matter["gating-conditions"]
    assert isinstance(gating, list) and gating, (
        f"W14 front-matter gating-conditions must be a non-empty list; "
        f"got {type(gating).__name__}."
    )
    haystack = " | ".join(str(g) for g in gating).lower()
    missing_tokens = [tok for tok in PUBLICATION_GATING_TOKENS if tok not in haystack]
    assert not missing_tokens, (
        f"W14 gating-conditions must enumerate all three PW1-6 publication "
        f"conditions; missing tokens: {missing_tokens}. Actual: {gating!r}."
    )


# ===========================================================================
# VAL-W14-003  Counsel-reviewer field in front-matter.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-003")
def test_w14_003_counsel_reviewer_field_present(
    front_matter: dict[str, Any],
) -> None:
    """counsel-reviewer is a named pro-bono entity OR the literal 'pending'."""
    assert "counsel-reviewer" in front_matter, (
        "W14 front-matter must contain a counsel-reviewer field per PW1-6."
    )
    reviewer = front_matter["counsel-reviewer"]
    assert isinstance(reviewer, str) and reviewer.strip(), (
        f"W14 counsel-reviewer must be a non-empty string; got {reviewer!r}."
    )
    assert reviewer in PERMITTED_COUNSEL_REVIEWERS, (
        f"W14 counsel-reviewer must be one of "
        f"{sorted(PERMITTED_COUNSEL_REVIEWERS)}; got {reviewer!r}."
    )


# ===========================================================================
# VAL-W14-004  Required H2 headings in canonical order; first H2 = Status: Internal Only.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-004")
def test_w14_004_required_h2_headings_in_canonical_order(body: str) -> None:
    found = _h2_headings(body)
    assert found == list(REQUIRED_H2), (
        f"W14 H2 headings must equal canonical sequence in order with no "
        f"extras or omissions.\n"
        f"  expected: {list(REQUIRED_H2)}\n"
        f"  actual:   {found}"
    )
    # First H2 must be the internal-only banner (load-bearing per the
    # contract — internal-only status is the first thing a reader sees
    # after front-matter).
    assert found[0] == "Status: Internal Only", (
        f"W14 first H2 must be 'Status: Internal Only'; got {found[0]!r}."
    )


# ===========================================================================
# VAL-W14-005  Banned product copy returns zero matches (whole file).
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-005")
def test_w14_005_banned_product_copy_absent_whole_file(raw_doc: str) -> None:
    """Whole-file case-insensitive scan; zero matches required.

    This is the highest-stakes banned-copy assertion in the operation;
    W14 is the document most likely to drift. Scan covers body AND
    front-matter (every field, including ``description``, ``summary``,
    ``title``, ``tags``, ``audience``, ``gating-conditions``) per
    C-GAP-007.
    """
    haystack = raw_doc.lower()
    offenders = [term for term in BANNED_TERMS if term.lower() in haystack]
    assert not offenders, (
        f"W14 file contains banned product copy: {offenders}. "
        f"Banned per CLAUDE.md J.5 / banned pattern #9; PW1-6. Scan is "
        f"whole-file (front-matter + body) per C-GAP-007."
    )


# ===========================================================================
# VAL-W14-006  Permitted framing terms each appear >= 1 time in body.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-006")
def test_w14_006_permitted_framing_terms_present(body: str) -> None:
    haystack = body.lower()
    missing: list[str] = []
    for alternatives in PERMITTED_FRAMING_OR_ALTERNATIVES:
        if not any(alt.lower() in haystack for alt in alternatives):
            missing.append(" OR ".join(alternatives))
    assert not missing, (
        f"W14 body must contain >= 1 occurrence of each permitted framing "
        f"term per §J.5; missing: {missing}. C-GAP-008: the first term is "
        f"satisfied by EITHER 'AI Act readiness evidence' OR 'EU AI Act "
        f"readiness evidence'."
    )


# ===========================================================================
# VAL-W14-007  Spec § AI Act readiness mapping citation (§J.1, §J.3, §J.5).
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-007")
def test_w14_007_spec_section_j_citations_present(body: str) -> None:
    """At least 3 citations across body covering §J.1, §J.3, AND §J.5."""
    j_subsections = ("§J.1", "§J.3", "§J.5")
    counts = {sub: body.count(sub) for sub in j_subsections}
    missing = [sub for sub, c in counts.items() if c == 0]
    assert not missing, (
        f"W14 body must cite each of §J.1 (timelines), §J.3 (Article "
        f"coverage), §J.5 (forbidden product copy). Missing: {missing}. "
        f"Counts: {counts}."
    )
    total = sum(counts.values())
    assert total >= 3, (
        f"W14 body must contain >= 3 §J.x citations total; got {total}. "
        f"Counts: {counts}."
    )


# ===========================================================================
# VAL-W14-008  Annex IV evidence categories enumerated in Evidence Coverage.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-008")
def test_w14_008_annex_iv_categories_enumerated(body: str) -> None:
    sections = _section_bodies(body)
    section_text = sections.get("Evidence Coverage by Annex IV Category", "")
    assert section_text, (
        "W14 must contain a non-empty 'Evidence Coverage by Annex IV "
        "Category' section."
    )
    missing = [art for art in REQUIRED_ARTICLES if art not in section_text]
    assert not missing, (
        f"W14 Evidence Coverage section must enumerate each required Annex "
        f"IV Article from spec §J.3; missing: {missing}."
    )
    # Each Article must be paired with a Relay surface citation. We
    # approximate this by requiring backtick code-spans (e.g.,
    # `eu-ai-act:annex-iv`) on at least 8 distinct lines within the
    # section, matching the §J.3 Article coverage map density.
    code_span_lines = [
        ln for ln in section_text.splitlines() if "`" in ln and "Art." in ln
    ]
    assert len(code_span_lines) >= 8, (
        f"W14 Evidence Coverage section must pair each Article with a "
        f"Relay surface citation (backtick-quoted claim type or bundle "
        f"profile name); got only {len(code_span_lines)} Article rows with "
        f"code-spans. Spec §J.3 sets the density baseline."
    )


# ===========================================================================
# VAL-W14-009  PW1-6 pro-bono reviewer candidates documented in Reviewer Path.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-009")
def test_w14_009_pw1_6_pro_bono_reviewer_candidates(body: str) -> None:
    sections = _section_bodies(body)
    section_text = sections.get("Reviewer Path", "")
    assert section_text, "W14 must contain a non-empty 'Reviewer Path' section."
    # All three named reviewer candidates.
    for name in ("BABL AI", "Holistic AI", "Credo AI"):
        assert name in section_text, (
            f"W14 Reviewer Path must name pro-bono reviewer candidate "
            f"{name!r}."
        )
    lower = section_text.lower()
    # Cold-email reach-out approach.
    assert "cold-email" in lower or "cold email" in lower, (
        "W14 Reviewer Path must document the cold-email reach-out approach."
    )
    # Review-only-no-publication SLA.
    sla_present = (
        "review-only-no-publication" in lower
        or ("review only" in lower and "no publication" in lower)
        or ("review-only" in lower and "no-publication" in lower)
    )
    assert sla_present, (
        "W14 Reviewer Path must document the review-only-no-publication SLA."
    )
    # ~6-week typical turnaround.
    turnaround_present = (
        "six-week" in lower
        or "six week" in lower
        or "6-week" in lower
        or "6 week" in lower
    )
    assert turnaround_present, (
        "W14 Reviewer Path must document the ~6-week typical turnaround."
    )


# ===========================================================================
# VAL-W14-010  No-paid-counsel position documented in Reviewer Path.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-010")
def test_w14_010_no_paid_counsel_position(body: str) -> None:
    sections = _section_bodies(body)
    section_text = sections.get("Reviewer Path", "")
    assert section_text, "W14 must contain a non-empty 'Reviewer Path' section."
    lower = section_text.lower()
    # No paid counsel for v0.1 per PW1-6.
    assert "no paid counsel" in lower, (
        "W14 Reviewer Path must state 'no paid counsel' is part of v0.1 "
        "per PW1-6."
    )
    # Draft / not published / internal review only literals.
    for literal in ("DRAFT", "NOT PUBLISHED", "INTERNAL REVIEW ONLY"):
        assert literal in section_text, (
            f"W14 Reviewer Path must contain the literal {literal!r} "
            f"(uppercase) to mark the document state per PW1-6."
        )
    # Three publication gates referenced.
    for token in PUBLICATION_GATING_TOKENS:
        assert token in lower, (
            f"W14 Reviewer Path must reference the publication gate {token!r} "
            f"per PW1-6."
        )


# ===========================================================================
# VAL-W14-011  Two-timeline scenario note + GPAI 2027 obligation date.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-011")
def test_w14_011_two_timelines_and_gpai_date(body: str) -> None:
    """All five load-bearing dates per §J.1 must appear as literal substrings."""
    missing = [date for date in REQUIRED_DATES if date not in body]
    assert not missing, (
        f"W14 body must contain each of the five §J.1 load-bearing dates; "
        f"missing: {missing}. C-MIN-003: '2 Aug 2027' (GPAI obligation "
        f"date) is explicitly required."
    )


# ===========================================================================
# VAL-W14-012  No-legal-advice disclaimer present in body.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-012")
def test_w14_012_no_legal_advice_disclaimer_in_body(body: str) -> None:
    """Disclaimer must appear in the body, not only in front-matter."""
    lower = body.lower()
    # The phrase must explicitly disclaim legal advice.
    legal_advice_present = (
        "not legal advice" in lower
        or "does not constitute legal advice" in lower
        or "is not a substitute for legal advice" in lower
    )
    assert legal_advice_present, (
        "W14 body must contain an explicit 'not legal advice' disclaimer "
        "(PW1-6 self-publication path #3)."
    )
    # Must also instruct readers to obtain their own counsel review.
    own_counsel_present = (
        "their own counsel" in lower
        or "obtain their own counsel" in lower
        or "obtain independent counsel" in lower
        or "obtain qualified counsel" in lower
        or "consult their own counsel" in lower
    )
    assert own_counsel_present, (
        "W14 disclaimer must instruct readers/customers to obtain their "
        "own counsel review before relying on the document."
    )


# ===========================================================================
# VAL-W14-013  Internal + external links resolve.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W14-013")
def test_w14_013_links_resolve(body: str) -> None:
    links = _markdown_links(body)
    assert links, "W14 doc must contain at least one markdown link."

    # Collect headings for anchor resolution.
    headings = _all_headings_with_levels(body)
    heading_slugs = {_slugify(text) for _, text in headings}

    errors: list[str] = []

    for label, target in links:
        if not target:
            errors.append(f"empty link target for label {label!r}")
            continue

        # Pure anchor link e.g. '#scope'.
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
            if os.environ.get("RELAY_W14_LINKCHECK") == "1":
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

        # If the link includes a fragment AND points to a markdown file
        # inside the repo, validate the fragment against that file's
        # headings.
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

    assert not errors, "W14 link resolution failed:\n  - " + "\n  - ".join(errors)
