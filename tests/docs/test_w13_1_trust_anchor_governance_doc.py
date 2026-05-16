"""W13.1 doc-content tests for `docs/legal/trust-anchor-governance.md`.

Plumbing-tier tests that bind each VAL-W13-NNN contract assertion to a
parser-driven check against the committed doc. Per CLAUDE.md TDD discipline,
each test carries `@pytest.mark.fulfills("VAL-W13-NNN")` so the gate engine
can trace test-to-assertion coverage.

The tests intentionally operate offline (no HTTP probes): per CLAUDE.md
"TESTING DISCIPLINE", tier-1 plumbing tests run without network access.
Repo-relative link resolution and intra-doc anchor checks run unconditionally
(VAL-W13-012). External HTTPS link probing is gated on the opt-in environment
variable ``RELAY_W13_LINKCHECK=1`` so CI plumbing remains offline while local
or nightly link-check runs can verify 2xx status when desired.

Spec citations:
- §AO.1 (architecture), §AO.2 (defense), §AO.3 (governance steps), §AO.4 (anti-cloning)
- §AB (transparency log + RFC 3161 TSA)
- §L.1 (key registry)
- PW1-3 (TSA partner decision), PW1-4 (JWKS hosting), PW1-6 (pro-bono counsel path)
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
DOC_REL_PATH = "docs/legal/trust-anchor-governance.md"
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


# Required H2 headings (canonical order; no intervening H2s permitted).
REQUIRED_H2: tuple[str, ...] = (
    "Overview",
    "Trust Anchor Architecture",
    "Key Custody",
    "Transparency Log",
    "Governance Process",
    "Fork Path (BYO Trust Anchor)",
    "Disclosure & Rotation Policy",
)


# Permitted counsel-reviewer enum values for VAL-W13-002.
PERMITTED_COUNSEL_REVIEWERS: frozenset[str] = frozenset(
    {"BABL AI", "Holistic AI", "Credo AI", "pending"}
)


# Permitted status enum values per VAL-W13-002.
PERMITTED_STATUS_VALUES: frozenset[str] = frozenset(
    {"draft", "review", "counsel-review-pending", "approved"}
)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _read_raw() -> str:
    """Read the whole doc file (front-matter + body) as text."""
    assert DOC_PATH.exists(), f"W13 doc missing at {DOC_PATH}"
    return DOC_PATH.read_text(encoding="utf-8")


_FRONT_MATTER_RE = re.compile(r"\A---\s*\n(?P<yaml>.*?)\n---\s*\n(?P<body>.*)\Z", re.DOTALL)


def _split_front_matter(raw: str) -> tuple[dict[str, Any], str]:
    """Return (front_matter_dict, body_markdown). Raises if not well-formed."""
    m = _FRONT_MATTER_RE.match(raw)
    if not m:
        raise AssertionError(
            "W13 doc must begin with a YAML front-matter block delimited by '---'."
        )
    fm_raw = m.group("yaml")
    body = m.group("body")
    parsed = yaml.safe_load(fm_raw)
    if not isinstance(parsed, dict):
        raise AssertionError("W13 front-matter must parse as a YAML mapping.")
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
            # next token is inline content for the heading
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
    """Extract (label, target) for every markdown link in body order.

    Uses markdown-it-py so links inside fenced code blocks are ignored (a
    'link' inside a ``` block is just text, not a real markdown link).
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
    """GitHub-style heading slug: lowercase, non-alphanum -> hyphen, collapse, strip."""
    s = text.lower()
    # Drop characters that GitHub strips entirely (most punctuation).
    # We keep alphanum + hyphen + underscore + spaces, replace spaces -> hyphen.
    s = re.sub(r"[^\w\s-]", "", s, flags=re.UNICODE)
    s = re.sub(r"\s+", "-", s).strip("-")
    return s


def _is_rfc3339_date(value: object) -> bool:
    """Accept YYYY-MM-DD (RFC 3339 full-date) or full RFC 3339 datetime string.

    Also accepts a Python date/datetime object (PyYAML may parse plain
    YYYY-MM-DD as date) so the spec-required string form is not required.
    """
    if isinstance(value, date):  # also matches datetime since datetime <: date
        return True
    if not isinstance(value, str):
        return False
    # Full date YYYY-MM-DD
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", value)
    if m:
        try:
            date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            return True
        except ValueError:
            return False
    # Full RFC 3339 date-time (subset: YYYY-MM-DDTHH:MM:SS[.fff](Z|+HH:MM))
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


def _coerce_date(value: object) -> date:
    """Coerce an RFC 3339 date/datetime or PyYAML date to a python date."""
    if isinstance(value, date):
        return value
    assert isinstance(value, str), f"date-like value expected, got {type(value)!r}"
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", value)
    assert m, f"value {value!r} is not RFC 3339 date"
    return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))


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
# VAL-W13-001  Doc exists at canonical path, non-empty body >= 800 words.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-001")
def test_w13_001_doc_exists_with_minimum_body_word_count(body: str) -> None:
    """File present, parses, and body >= 800 words after stripping front-matter."""
    word_count = len(body.split())
    assert word_count >= 800, (
        f"W13 doc body must be >= 800 words; got {word_count}. "
        f"VAL-W13-001 binds doc length to the minimum substantive content threshold."
    )


# ===========================================================================
# VAL-W13-002  Front-matter present + well-formed (exact key set + valid values).
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-002")
def test_w13_002_front_matter_has_required_keys_and_valid_values(
    front_matter: dict[str, Any],
) -> None:
    required_keys = {
        "status",
        "last-reviewed-by",
        "last-reviewed-on",
        "next-review-due",
        "counsel-reviewer",
    }
    missing = required_keys - set(front_matter.keys())
    assert not missing, f"W13 front-matter missing keys: {sorted(missing)}"

    status = front_matter["status"]
    assert status in PERMITTED_STATUS_VALUES, (
        f"W13 front-matter status={status!r} not in {sorted(PERMITTED_STATUS_VALUES)}"
    )

    last_reviewed_by = front_matter["last-reviewed-by"]
    assert isinstance(last_reviewed_by, str) and last_reviewed_by.strip(), (
        "W13 front-matter last-reviewed-by must be a non-empty string"
    )

    assert _is_rfc3339_date(front_matter["last-reviewed-on"]), (
        f"W13 front-matter last-reviewed-on must be RFC 3339; "
        f"got {front_matter['last-reviewed-on']!r}"
    )
    assert _is_rfc3339_date(front_matter["next-review-due"]), (
        f"W13 front-matter next-review-due must be RFC 3339; "
        f"got {front_matter['next-review-due']!r}"
    )

    # next-review-due must be <= 180 days after last-reviewed-on per AO.3 step 1
    # ("Updated semi-annually").
    last = _coerce_date(front_matter["last-reviewed-on"])
    nxt = _coerce_date(front_matter["next-review-due"])
    delta_days = (nxt - last).days
    assert 0 < delta_days <= 180, (
        f"W13 next-review-due must be within 180 days of last-reviewed-on; "
        f"got {delta_days} days. Per AO.3 step 1 'Updated semi-annually'."
    )

    reviewer = front_matter["counsel-reviewer"]
    assert reviewer in PERMITTED_COUNSEL_REVIEWERS, (
        f"W13 counsel-reviewer must be one of {sorted(PERMITTED_COUNSEL_REVIEWERS)}; "
        f"got {reviewer!r}."
    )


# ===========================================================================
# VAL-W13-003  Required H2 headings present in canonical order; no intervening H2s.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-003")
def test_w13_003_required_h2_headings_in_canonical_order(body: str) -> None:
    found = _h2_headings(body)
    assert found == list(REQUIRED_H2), (
        f"W13 H2 headings must equal canonical sequence in order with no extras.\n"
        f"  expected: {list(REQUIRED_H2)}\n"
        f"  actual:   {found}"
    )


# ===========================================================================
# VAL-W13-004  AO architecture citations present (AO.1, AO.2, AO.4).
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-004")
def test_w13_004_section_ao_citations_present(body: str) -> None:
    for cite in ("§AO.1", "§AO.2", "§AO.4"):
        assert cite in body, f"W13 body must cite spec section {cite!r}"


# ===========================================================================
# VAL-W13-005  PW1-3 TSA partner: Sigstore primary, Sectigo fallback, FreeTSA rejected.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-005")
def test_w13_005_pw1_3_tsa_partner_decision(body: str) -> None:
    assert "Sigstore" in body, "W13 must name Sigstore (TSA) as the primary partner."
    assert "Sectigo" in body, "W13 must name Sectigo as the commercial fallback."
    assert "FreeTSA" in body, "W13 must reference FreeTSA explicitly."
    # FreeTSA must be rejected for production use.
    lower = body.lower()
    rejection_present = (
        "freetsa is rejected for production" in lower
        or "freetsa: rejected for production" in lower
        or "freetsa rejected for production" in lower
        or "rejected for production use" in lower
        and "freetsa" in lower
    )
    assert rejection_present, (
        "W13 must explicitly state that FreeTSA is rejected for production use."
    )


# ===========================================================================
# VAL-W13-006  PW1-4 JWKS hosting URL + Cloudflare attribution.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-006")
def test_w13_006_pw1_4_jwks_url_and_cloudflare(body: str) -> None:
    assert "https://relay.epochly.com/.well-known/jwks.json" in body, (
        "W13 must contain the literal JWKS hosting URL."
    )
    assert "Cloudflare" in body, "W13 must name Cloudflare as JWKS hosting provider."
    # Either Pages or Workers KV must be named per PW1-4.
    assert ("Cloudflare Pages" in body) or ("Workers KV" in body), (
        "W13 must specify Cloudflare Pages or Workers KV as the JWKS hosting mechanism."
    )


# ===========================================================================
# VAL-W13-007  OSS verifier default trust anchor + BYO mechanism documented.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-007")
def test_w13_007_oss_verifier_default_and_byo(body: str) -> None:
    # OSS verifier defaults to Relay-Inc JWKS.
    lower = body.lower()
    default_phrase_present = (
        "defaults to" in lower and "relay.epochly.com/.well-known/jwks.json" in lower
    )
    assert default_phrase_present, (
        "W13 must state the OSS relay-verifier defaults to the Relay-Inc JWKS at "
        "relay.epochly.com/.well-known/jwks.json (CLAUDE.md banned pattern #13)."
    )
    # BYO mechanism documented (flag or config).
    byo_phrase_present = "byo" in lower and (
        "--trust-anchor" in lower or "trust_anchor" in lower or "config" in lower or "flag" in lower
    )
    assert byo_phrase_present, (
        "W13 must document a BYO trust-anchor mechanism (flag or config path)."
    )


# ===========================================================================
# VAL-W13-008  PW1-6 pro-bono counsel review path + all three named reviewers.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-008")
def test_w13_008_pw1_6_pro_bono_path_and_three_reviewers(body: str) -> None:
    lower = body.lower()
    assert "pro-bono" in lower or "pro bono" in lower, (
        "W13 Governance Process must name the pro-bono counsel review path."
    )
    for name in ("BABL AI", "Holistic AI", "Credo AI"):
        assert name in body, f"W13 must name pro-bono reviewer candidate {name!r}."


# ===========================================================================
# VAL-W13-009  Transparency log section references AB + Merkle/public/witness design.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-009")
def test_w13_009_transparency_log_section_references_section_ab(body: str) -> None:
    assert "§AB" in body, "W13 Transparency Log section must cite spec section §AB."
    lower = body.lower()
    assert "append-only" in lower, "W13 must describe an append-only Merkle tree."
    assert "merkle" in lower, "W13 must describe Merkle tree design."
    public_phrase = (
        "publicly readable" in lower or "public readability" in lower or "public read" in lower
    )
    assert public_phrase, "W13 must describe public readability of the transparency log."
    assert "witness" in lower, "W13 must describe witness signatures."


# ===========================================================================
# VAL-W13-010  Key custody section: KMS/HSM, rotation, compromise response,
#              revocation publication.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-010")
def test_w13_010_key_custody_kms_rotation_compromise_revocation(body: str) -> None:
    lower = body.lower()
    assert "kms" in lower, "W13 Key Custody must name KMS custody."
    assert "hsm" in lower, "W13 Key Custody must name HSM custody."
    assert "rotation" in lower, "W13 must describe key rotation procedure."
    # Compromise response.
    assert "compromise" in lower, "W13 must describe key compromise response."
    # Revocation publication.
    assert "revocation" in lower, "W13 must describe revocation publication."


# ===========================================================================
# VAL-W13-011  Banned product copy returns zero matches (entire file, case-insensitive).
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-011")
def test_w13_011_banned_product_copy_absent_whole_file(raw_doc: str) -> None:
    haystack = raw_doc.lower()
    offenders = [term for term in BANNED_TERMS if term.lower() in haystack]
    assert not offenders, (
        f"W13 file contains banned product copy: {offenders}. "
        "Banned per CLAUDE.md J.5 / banned pattern #9. Scan is whole-file "
        "(front-matter + body) per C-GAP-007."
    )


# ===========================================================================
# VAL-W13-012  Internal + external links resolve.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-012")
def test_w13_012_links_resolve(body: str) -> None:
    links = _markdown_links(body)
    assert links, "W13 doc must contain at least one markdown link."

    # Collect headings for anchor resolution.
    headings = _all_headings_with_levels(body)
    heading_slugs = {_slugify(text) for _, text in headings}

    errors: list[str] = []

    for label, target in links:
        if not target:
            errors.append(f"empty link target for label {label!r}")
            continue

        # Pure anchor link e.g. '#trust-anchor-architecture'
        if target.startswith("#"):
            slug = target[1:]
            if slug not in heading_slugs:
                errors.append(f"anchor target {target!r} not found among {sorted(heading_slugs)}")
            continue

        parsed = urllib.parse.urlparse(target)

        # External http(s) link.
        if parsed.scheme in ("http", "https"):
            if not parsed.netloc:
                errors.append(f"external link {target!r} missing netloc")
                continue
            # Plumbing tier: skip network. Opt-in network check.
            if os.environ.get("RELAY_W13_LINKCHECK") == "1":
                req = urllib.request.Request(target, method="HEAD")
                try:
                    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                        status = resp.status
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"external link {target!r} HEAD failed: {exc}")
                    continue
                if status < 200 or status >= 400:
                    errors.append(f"external link {target!r} returned status {status}")
            continue

        if parsed.scheme in ("mailto",):
            # Well-formedness check only.
            if "@" not in parsed.path:
                errors.append(f"mailto link {target!r} missing '@'")
            continue

        # Otherwise treat as repo-relative. Strip fragment for file resolution.
        rel = parsed.path
        fragment = parsed.fragment

        if rel.startswith("/"):
            errors.append(f"absolute path link {target!r} not permitted; use repo-relative path")
            continue

        # Resolve relative to the W13 doc's directory.
        candidate = (DOC_PATH.parent / rel).resolve()

        # Containment: candidate must stay inside REPO_ROOT.
        try:
            candidate.relative_to(REPO_ROOT)
        except ValueError:
            errors.append(f"link {target!r} escapes repo root: {candidate}")
            continue

        if not candidate.exists():
            errors.append(f"internal link {target!r} resolves to missing file {candidate}")
            continue

        # If the link includes a fragment AND points to a markdown file inside
        # the repo, validate the fragment against that file's headings.
        if fragment and candidate.suffix.lower() == ".md":
            try:
                other_body_raw = candidate.read_text(encoding="utf-8")
            except OSError as exc:
                errors.append(f"link {target!r}: cannot read {candidate}: {exc}")
                continue
            # Strip front-matter if present.
            m = _FRONT_MATTER_RE.match(other_body_raw)
            other_body = m.group("body") if m else other_body_raw
            other_slugs = {_slugify(text) for _, text in _all_headings_with_levels(other_body)}
            if fragment not in other_slugs:
                errors.append(
                    f"link {target!r}: fragment {fragment!r} not found in {candidate.name}"
                )

    assert not errors, "W13 link resolution failed:\n  - " + "\n  - ".join(errors)


# ===========================================================================
# VAL-W13-013  Cross-references: each H2 section contains >= 1 spec citation.
# ===========================================================================


# Citation tokens recognized as spec references. The contract permits §AO.x,
# §AB, §L.1, §K, plus file-relative paths. We accept any of these forms.
_CITATION_RE = re.compile(
    r"(?:§[A-Z]+(?:\.[0-9]+)?(?:\.[0-9]+)?)"  # spec section like AO, AO.3, AO.3.1
    r"|(?:PW1-\d+)"  # pre-week-1 decisions
    r"|(?:\bCLAUDE\.md\b)"  # workspace CLAUDE.md
    r"|(?:planning/epochly-replay-spec\.md)"  # file-relative spec path
    r"|(?:\bCEO plan\b)"  # ceo plan reference
    r"|(?:\beng plan\b)"  # eng plan reference
)


def _section_bodies(body: str) -> dict[str, str]:
    """Return {h2_text: section_text_through_next_h2} mapping in doc order.

    Uses raw text scanning rather than markdown_it so we can preserve original
    line content for citation matching (markdown_it tokens drop separators
    between paragraphs in a way that loses some context).
    """
    sections: dict[str, str] = {}
    current_name: str | None = None
    current_lines: list[str] = []
    in_fence = False
    for line in body.splitlines():
        # Track fenced code blocks so '## ' inside code is not a heading.
        stripped = line.lstrip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            if current_name is not None:
                current_lines.append(line)
            continue
        if not in_fence and stripped.startswith("## ") and not stripped.startswith("### "):
            # flush previous
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


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W13-013")
def test_w13_013_each_h2_section_has_spec_citation(body: str) -> None:
    sections = _section_bodies(body)
    missing: list[str] = []
    for name in REQUIRED_H2:
        section_text = sections.get(name, "")
        if not _CITATION_RE.search(section_text):
            missing.append(name)
    assert not missing, (
        f"W13 H2 sections missing a spec/PW1/CLAUDE.md citation (>= 1 per section): {missing}"
    )
