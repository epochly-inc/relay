#!/usr/bin/env python3
"""Generate ACEF Executive Overview PDF — publication-ready."""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch, mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
    KeepTogether, HRFlowable, Image, Flowable
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Group, Circle
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
from reportlab.pdfgen import canvas
from io import BytesIO
import textwrap

# ── Color Palette ───────────────────────────────────────────────────────
NAVY      = HexColor("#1B2A4A")
DARK_BLUE = HexColor("#2C3E6B")
MID_BLUE  = HexColor("#3B5998")
ACCENT    = HexColor("#0077B6")
TEAL      = HexColor("#00B4D8")
LIGHT_BG  = HexColor("#F0F4F8")
LIGHT_LINE= HexColor("#CBD5E1")
DARK_TEXT  = HexColor("#1E293B")
MID_TEXT   = HexColor("#475569")
LIGHT_TEXT = HexColor("#64748B")
SUCCESS    = HexColor("#059669")
WARNING    = HexColor("#D97706")
DANGER     = HexColor("#DC2626")
WHITE      = white

# ── Custom Flowables ────────────────────────────────────────────────────

class ColorBlock(Flowable):
    """A colored background block with text content."""
    def __init__(self, width, height, bg_color, content_lines, text_color=WHITE,
                 font_size=11, padding=12):
        Flowable.__init__(self)
        self.width = width
        self.height = height
        self.bg_color = bg_color
        self.content_lines = content_lines
        self.text_color = text_color
        self.font_size = font_size
        self.padding = padding

    def draw(self):
        self.canv.setFillColor(self.bg_color)
        self.canv.roundRect(0, 0, self.width, self.height, 6, fill=1, stroke=0)
        self.canv.setFillColor(self.text_color)
        self.canv.setFont("Helvetica", self.font_size)
        y = self.height - self.padding - self.font_size
        for line in self.content_lines:
            if line.startswith("**"):
                self.canv.setFont("Helvetica-Bold", self.font_size + 1)
                self.canv.drawString(self.padding, y, line.replace("**", ""))
                self.canv.setFont("Helvetica", self.font_size)
            else:
                self.canv.drawString(self.padding, y, line)
            y -= self.font_size + 6


class SectionDivider(Flowable):
    """A thin accent line with optional label."""
    def __init__(self, width, label="", color=ACCENT):
        Flowable.__init__(self)
        self.width = width
        self.label = label
        self.color = color

    def wrap(self, availWidth, availHeight):
        return (self.width, 2)

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(1.5)
        self.canv.line(0, 1, self.width, 1)


class ArchitectureDiagram(Flowable):
    """Render the 9-layer architecture diagram."""
    def __init__(self, width, height):
        Flowable.__init__(self)
        self.width = width
        self.height = height

    def wrap(self, availWidth, availHeight):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        layers = [
            ("Layer 9", "CLI & Rendering", "cli/, render.py", HexColor("#1B2A4A")),
            ("Layer 8", "Advanced Ops", "redaction.py, merge.py", HexColor("#2C3E6B")),
            ("Layer 7", "Assessment", "assessment_builder.py", HexColor("#2E4A7A")),
            ("Layer 6", "Validation Pipeline", "validation/ (engine, operators, rollup)", HexColor("#3B5998")),
            ("Layer 5", "Knowledge Base", "templates/ (11 regulation mappings)", HexColor("#4A6FB5")),
            ("Layer 4", "Cryptography", "signing.py (JWS RS256/ES256)", HexColor("#0077B6")),
            ("Layer 3", "Serialization", "export.py, loader.py", HexColor("#0088CC")),
            ("Layer 2", "Core Builder", "package.py", HexColor("#00A0DC")),
            ("Layer 1", "Primitives", "integrity.py (RFC 8785, SHA-256, Merkle)", HexColor("#00B4D8")),
            ("Layer 0", "Foundation", "errors.py, models/ (Pydantic v2)", HexColor("#48CAE4")),
        ]

        box_h = (self.height - 20) / len(layers)
        y = self.height - 10

        for i, (layer_label, name, detail, color) in enumerate(layers):
            box_y = y - box_h
            # Draw box
            c.setFillColor(color)
            c.roundRect(30, box_y, self.width - 60, box_h - 3, 4, fill=1, stroke=0)
            # Layer label
            c.setFillColor(HexColor("#FFFFFF"))
            c.setFont("Helvetica-Bold", 8)
            c.drawString(40, box_y + box_h/2 - 3, layer_label)
            # Name
            c.setFont("Helvetica-Bold", 10)
            c.drawString(110, box_y + box_h/2 - 3, name)
            # Detail
            c.setFont("Helvetica", 8)
            c.setFillColor(HexColor("#E0E8F0"))
            c.drawString(300, box_y + box_h/2 - 3, detail)
            c.setFillColor(WHITE)
            y -= box_h


class ValidationPipelineDiagram(Flowable):
    """Render the 4-phase validation pipeline."""
    def __init__(self, width, height):
        Flowable.__init__(self)
        self.width = width
        self.height = height

    def wrap(self, availWidth, availHeight):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        phases = [
            ("Phase 1", "Schema\nValidation", "JSON Schema\nfor manifest,\nenvelope, payload", ACCENT),
            ("Phase 2", "Integrity\nVerification", "SHA-256 hashes,\nMerkle tree,\nJWS signatures", HexColor("#0088CC")),
            ("Phase 3", "Reference\nChecking", "Entity URNs,\nfile paths,\nduplicates", HexColor("#3B5998")),
            ("Phase 4", "Rule\nEvaluation", "DSL operators,\nprovision rollup,\nper-subject", NAVY),
        ]

        box_w = (self.width - 80) / 4
        arrow_w = 16
        x = 10

        for i, (label, name, detail, color) in enumerate(phases):
            # Box
            c.setFillColor(color)
            c.roundRect(x, 10, box_w, self.height - 20, 6, fill=1, stroke=0)

            # Phase label
            c.setFillColor(HexColor("#B0C4DE"))
            c.setFont("Helvetica", 8)
            c.drawCentredString(x + box_w/2, self.height - 25, label)

            # Name
            c.setFillColor(WHITE)
            c.setFont("Helvetica-Bold", 10)
            lines = name.split("\n")
            ty = self.height - 42
            for line in lines:
                c.drawCentredString(x + box_w/2, ty, line)
                ty -= 13

            # Detail
            c.setFont("Helvetica", 7.5)
            c.setFillColor(HexColor("#D0DCE8"))
            dlines = detail.split("\n")
            ty = 50
            for line in dlines:
                c.drawCentredString(x + box_w/2, ty, line)
                ty -= 10

            x += box_w

            # Arrow
            if i < 3:
                c.setStrokeColor(LIGHT_LINE)
                c.setFillColor(LIGHT_LINE)
                c.setLineWidth(2)
                ax = x + 2
                ay = self.height / 2
                c.line(ax, ay, ax + arrow_w - 6, ay)
                # Arrowhead
                p = c.beginPath()
                p.moveTo(ax + arrow_w - 6, ay + 4)
                p.lineTo(ax + arrow_w, ay)
                p.lineTo(ax + arrow_w - 6, ay - 4)
                p.close()
                c.drawPath(p, fill=1, stroke=0)
                x += arrow_w


class BundleLayoutDiagram(Flowable):
    """Render the bundle directory layout as a visual."""
    def __init__(self, width, height):
        Flowable.__init__(self)
        self.width = width
        self.height = height

    def wrap(self, availWidth, availHeight):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        # Background
        c.setFillColor(HexColor("#F8FAFC"))
        c.roundRect(0, 0, self.width, self.height, 8, fill=1, stroke=0)
        c.setStrokeColor(LIGHT_LINE)
        c.roundRect(0, 0, self.width, self.height, 8, fill=0, stroke=1)

        entries = [
            (0, "my-system.acef/", True, NAVY),
            (1, "acef-manifest.json", False, ACCENT),
            (1, "records/", True, MID_BLUE),
            (2, "risk_register.jsonl", False, MID_TEXT),
            (2, "dataset_card.jsonl", False, MID_TEXT),
            (2, "event_log/", True, MID_BLUE),
            (3, "event_log.0001.jsonl", False, LIGHT_TEXT),
            (1, "artifacts/", True, MID_BLUE),
            (2, "eval-report.pdf", False, MID_TEXT),
            (1, "hashes/", True, SUCCESS),
            (2, "content-hashes.json", False, MID_TEXT),
            (2, "merkle-tree.json", False, MID_TEXT),
            (1, "signatures/", True, WARNING),
            (2, "provider-signature.jws", False, MID_TEXT),
        ]

        y = self.height - 20
        for indent, name, is_dir, color in entries:
            x = 20 + indent * 24
            c.setFillColor(color)
            if is_dir:
                c.setFont("Helvetica-Bold", 9)
                # Folder icon (simple)
                c.setFillColor(color)
                c.drawString(x, y, name)
            else:
                c.setFont("Helvetica", 9)
                c.setFillColor(color)
                c.drawString(x, y, name)
            y -= 16

        # Labels on right side
        annotations = [
            (self.height - 36, "Envelope: metadata, subjects, entities, profiles", ACCENT),
            (self.height - 68, "Evidence in deterministic JSONL", MID_BLUE),
            (self.height - 132, "Binary attachments", MID_BLUE),
            (self.height - 164, "SHA-256 + Merkle tree (outside hash domain)", SUCCESS),
            (self.height - 212, "Detached JWS (outside hash domain)", WARNING),
        ]
        for ay, text, color in annotations:
            c.setFont("Helvetica", 7.5)
            c.setFillColor(color)
            c.drawString(260, ay, text)


# ── Page Templates ──────────────────────────────────────────────────────

def cover_page(canvas_obj, doc):
    """Draw the cover page."""
    c = canvas_obj
    w, h = letter

    # Full-page navy background
    c.setFillColor(NAVY)
    c.rect(0, 0, w, h, fill=1, stroke=0)

    # Accent bar at top
    c.setFillColor(TEAL)
    c.rect(0, h - 8, w, 8, fill=1, stroke=0)

    # Main title block
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 42)
    c.drawString(60, h - 200, "ACEF")

    c.setFont("Helvetica", 18)
    c.setFillColor(TEAL)
    c.drawString(60, h - 235, "AI Compliance Evidence Format")

    # Subtitle
    c.setFillColor(HexColor("#94A3B8"))
    c.setFont("Helvetica", 14)
    c.drawString(60, h - 280, "Executive Technical Overview")

    # Divider line
    c.setStrokeColor(TEAL)
    c.setLineWidth(2)
    c.line(60, h - 300, 300, h - 300)

    # Description block
    c.setFillColor(HexColor("#CBD5E1"))
    c.setFont("Helvetica", 11)
    lines = [
        "An open, vendor-neutral specification and reference SDK",
        "for packaging machine-readable proof that AI systems",
        "comply with applicable regulations, standards, and",
        "governance commitments.",
    ]
    y = h - 340
    for line in lines:
        c.drawString(60, y, line)
        y -= 18

    # Version / metadata block
    c.setFillColor(HexColor("#64748B"))
    c.setFont("Helvetica", 10)
    c.drawString(60, 120, "Specification Version: 0.3 (Working Draft)")
    c.drawString(60, 104, "SDK Version: 0.1.0 (Alpha)")
    c.drawString(60, 88, "License: Apache 2.0 (code) / CC-BY 4.0 (schemas & templates)")
    c.drawString(60, 72, "Maintained by: AI Commons (non-profit, open standard)")
    c.drawString(60, 52, "Date: March 2026")

    # Accent bar at bottom
    c.setFillColor(TEAL)
    c.rect(0, 0, w, 4, fill=1, stroke=0)


def header_footer(canvas_obj, doc):
    """Standard page header/footer."""
    c = canvas_obj
    w, h = letter

    # Header line
    c.setStrokeColor(LIGHT_LINE)
    c.setLineWidth(0.5)
    c.line(54, h - 40, w - 54, h - 40)

    # Header text
    c.setFillColor(LIGHT_TEXT)
    c.setFont("Helvetica", 8)
    c.drawString(54, h - 36, "ACEF Executive Technical Overview")
    c.drawRightString(w - 54, h - 36, "Confidential")

    # Footer
    c.setStrokeColor(LIGHT_LINE)
    c.line(54, 40, w - 54, 40)
    c.setFillColor(LIGHT_TEXT)
    c.setFont("Helvetica", 8)
    c.drawString(54, 28, "AI Compliance Evidence Format — v0.1.0")
    c.drawRightString(w - 54, 28, f"Page {doc.page}")


# ── Styles ──────────────────────────────────────────────────────────────

styles = getSampleStyleSheet()

s_h1 = ParagraphStyle("H1Custom", parent=styles["Heading1"],
    fontName="Helvetica-Bold", fontSize=22, textColor=NAVY,
    spaceBefore=24, spaceAfter=8, leading=26)

s_h2 = ParagraphStyle("H2Custom", parent=styles["Heading2"],
    fontName="Helvetica-Bold", fontSize=15, textColor=DARK_BLUE,
    spaceBefore=18, spaceAfter=6, leading=19)

s_h3 = ParagraphStyle("H3Custom", parent=styles["Heading3"],
    fontName="Helvetica-Bold", fontSize=12, textColor=MID_BLUE,
    spaceBefore=12, spaceAfter=4, leading=15)

s_body = ParagraphStyle("BodyCustom", parent=styles["Normal"],
    fontName="Helvetica", fontSize=10, textColor=DARK_TEXT,
    spaceBefore=4, spaceAfter=6, leading=14.5, alignment=TA_JUSTIFY)

s_body_tight = ParagraphStyle("BodyTight", parent=s_body,
    spaceBefore=2, spaceAfter=3)

s_callout = ParagraphStyle("Callout", parent=s_body,
    fontName="Helvetica-Oblique", fontSize=10.5, textColor=MID_BLUE,
    leftIndent=20, rightIndent=20, spaceBefore=8, spaceAfter=8,
    leading=15, alignment=TA_LEFT)

s_code = ParagraphStyle("Code", parent=styles["Normal"],
    fontName="Courier", fontSize=8.5, textColor=DARK_TEXT,
    spaceBefore=2, spaceAfter=2, leading=11,
    leftIndent=16, backColor=HexColor("#F1F5F9"))

s_bullet = ParagraphStyle("Bullet", parent=s_body,
    leftIndent=28, bulletIndent=16, spaceBefore=2, spaceAfter=2)

s_caption = ParagraphStyle("Caption", parent=styles["Normal"],
    fontName="Helvetica-Oblique", fontSize=8.5, textColor=LIGHT_TEXT,
    spaceBefore=4, spaceAfter=10, alignment=TA_CENTER)

s_toc = ParagraphStyle("TOC", parent=styles["Normal"],
    fontName="Helvetica", fontSize=11, textColor=DARK_BLUE,
    spaceBefore=6, spaceAfter=3, leading=16, leftIndent=10)

s_toc_sub = ParagraphStyle("TOCSub", parent=s_toc,
    fontSize=10, textColor=MID_TEXT, leftIndent=30)


# ── Helpers ─────────────────────────────────────────────────────────────

def bullet(text):
    return Paragraph(f"<bullet>&bull;</bullet> {text}", s_bullet)

def code_block(text):
    lines = text.strip().split("\n")
    return [Paragraph(l.replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;"), s_code) for l in lines]

def make_table(headers, rows, col_widths=None):
    """Create a styled table."""
    data = [headers] + rows
    if col_widths is None:
        col_widths = [None] * len(headers)
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), NAVY),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8.5),
        ('TEXTCOLOR', (0, 1), (-1, -1), DARK_TEXT),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_BG]),
        ('LINEBELOW', (0, 0), (-1, 0), 1, ACCENT),
        ('LINEBELOW', (0, -1), (-1, -1), 0.5, LIGHT_LINE),
        ('GRID', (0, 0), (-1, -1), 0.25, LIGHT_LINE),
    ]))
    return t

def section_line():
    return HRFlowable(width="100%", thickness=1, color=LIGHT_LINE,
                      spaceBefore=6, spaceAfter=6)


# ── Document Construction ───────────────────────────────────────────────

def build_document():
    output_path = "/sessions/kind-loving-feynman/mnt/ACEF/ACEF_Executive_Overview.pdf"
    page_w, page_h = letter

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54, rightMargin=54,
        topMargin=54, bottomMargin=54,
        title="ACEF Executive Technical Overview",
        author="AI Commons",
        subject="AI Compliance Evidence Format — Specification & SDK Overview",
    )

    content_width = page_w - 108  # 54 + 54 margins
    story = []

    # ════════════════════════════════════════════════════════════════════
    # COVER PAGE (handled via onFirstPage)
    # ════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, page_h - 120))  # Push past cover
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════════
    # TABLE OF CONTENTS
    # ════════════════════════════════════════════════════════════════════
    story.append(Paragraph("Contents", s_h1))
    story.append(SectionDivider(content_width))
    story.append(Spacer(1, 8))

    toc_items = [
        ("1", "Executive Summary"),
        ("2", "Architecture & Design Philosophy"),
        ("3", "Core Capabilities & Feature Set"),
        ("4", "SDK Surface Area"),
        ("5", "Regulatory Coverage"),
        ("6", "Integration Model & Developer Experience"),
        ("7", "Security Model"),
        ("8", "Current Status & Open Items"),
    ]
    for num, title in toc_items:
        story.append(Paragraph(f"<b>{num}.</b>&nbsp;&nbsp;&nbsp;{title}", s_toc))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════════
    # 1. EXECUTIVE SUMMARY
    # ════════════════════════════════════════════════════════════════════
    story.append(Paragraph("1. Executive Summary", s_h1))
    story.append(SectionDivider(content_width))

    story.append(Paragraph(
        "ACEF (AI Compliance Evidence Format) is an open, vendor-neutral specification and reference Python SDK "
        "that solves a critical and rapidly emerging problem: <b>how do organizations prove, in a machine-verifiable way, "
        "that their AI systems comply with the growing patchwork of global regulations?</b>",
        s_body))

    story.append(Paragraph(
        "As the EU AI Act enters enforcement, as NIST AI RMF adoption accelerates, and as China, the UK, and "
        "the US Copyright Office impose new obligations, AI providers and deployers face an urgent need for a "
        "standard evidence container. Today, compliance evidence is scattered across PDFs, spreadsheets, emails, "
        "and internal wikis — unstructured, unsigned, and unverifiable. ACEF replaces this with a deterministic, "
        "cryptographically signed, content-addressable bundle format that packages evidence against specific "
        "regulatory provisions and evaluates it with machine-executable rules.",
        s_body))

    story.append(Paragraph("<b>The Problem</b>", s_h3))
    story.append(Paragraph(
        "AI compliance today requires assembling proof across dozens of regulatory provisions — risk assessments, "
        "dataset documentation, evaluation results, incident reports, transparency disclosures — and mapping that "
        "proof to specific legal obligations. This process is manual, error-prone, and produces artifacts that "
        "cannot be independently verified. Auditors receive static documents with no integrity guarantees. "
        "Regulators cannot programmatically assess compliance across hundreds of high-risk systems. Organizations "
        "maintain separate evidence packages for each jurisdiction, with no interoperability.",
        s_body))

    story.append(Paragraph("<b>What ACEF Provides</b>", s_h3))

    story.append(bullet(
        "<b>A specification</b> (v0.3, working draft) defining an immutable, signable evidence bundle format with "
        "16 core record types, a W3C PROV-compatible entity model, and a regulation-agnostic envelope."))
    story.append(bullet(
        "<b>A Python reference SDK</b> (v0.1.0) implementing the complete specification: package construction, "
        "4-phase validation, 10-operator DSL rule engine, cryptographic signing, privacy-preserving redaction, "
        "multi-source merging, and human-readable report generation."))
    story.append(bullet(
        "<b>11 regulation mapping templates</b> covering the EU AI Act, GPAI Code of Practice, EU Labelling CoP, "
        "NIST AI RMF, NIST GAI Profile, US Copyright Office, OMB M-24-10, China CAC, ISO 42001, ISO 23894, "
        "and UK AI & Copyright guidance."))
    story.append(bullet(
        "<b>A conformance test suite</b> with 19 golden test vectors across 5 regulatory frameworks, enabling "
        "cross-implementation interoperability."))

    story.append(Paragraph("<b>Why It Matters</b>", s_h3))
    story.append(Paragraph(
        "ACEF transforms AI compliance from a document-management problem into a software-engineering problem. "
        "Evidence bundles are deterministic (byte-identical across implementations), cryptographically secured "
        "(SHA-256 content hashes, Merkle trees, JWS detached signatures), and machine-evaluable (every compliance "
        "claim is backed by verifiable evidence linked to specific provisions). This enables automated compliance "
        "checking, auditor tooling, regulatory intake pipelines, and continuous compliance monitoring — none of "
        "which are possible with today's unstructured approaches.",
        s_body))

    story.append(Paragraph(
        "For engineering and product leaders evaluating ACEF: this is infrastructure for the compliance layer "
        "of AI systems. It is to regulatory evidence what SBOM is to software supply chains — a structured, "
        "verifiable, interoperable container that makes compliance auditable at scale.",
        s_callout))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════════
    # 2. ARCHITECTURE & DESIGN PHILOSOPHY
    # ════════════════════════════════════════════════════════════════════
    story.append(Paragraph("2. Architecture & Design Philosophy", s_h1))
    story.append(SectionDivider(content_width))

    story.append(Paragraph("<b>Design Principles</b>", s_h2))

    principles = [
        ("Regulation-agnostic envelope, regulation-specific payloads",
         "The core envelope schema is jurisdiction-neutral. Regulation-specific requirements are expressed "
         "as pluggable templates with machine-executable evaluation rules, not hard-coded logic."),
        ("Evidence, not assertions",
         "Every compliance claim links to verifiable artifacts — evaluation reports, dataset cards, risk "
         "registers, signed attestations. ACEF captures proof, not promises."),
        ("Machine-readable first, human-readable second",
         "All data is structured JSON/JSONL with JSON Schemas. Human-readable reports are derived outputs, "
         "not the source of truth."),
        ("Immutable, signable, chainable bundles",
         "Once exported, a bundle's content is fixed. JWS detached signatures attest to integrity. "
         "Bundles can reference prior bundles for version chaining."),
        ("Deterministic by design",
         "Two implementations producing a bundle from the same logical data MUST produce byte-identical output. "
         "This is enforced through RFC 8785 canonicalization, deterministic record ordering, and canonical archive parameters."),
        ("Privacy-aware",
         "Confidential evidence can be redacted while preserving integrity verification through SHA-256 hash "
         "commitments. Five confidentiality levels support graduated disclosure."),
    ]

    for title, desc in principles:
        story.append(Paragraph(f"<b>{title}.</b> {desc}", s_body))

    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>Three Independently Versioned Modules</b>", s_h2))
    story.append(Paragraph(
        "The specification is organized into three modules, each versioned independently to allow "
        "backward-compatible evolution:",
        s_body))

    mod_data = [
        ["Module", "Scope", "Current Version"],
        ["ACEF Core", "Envelope schema, entity model, bundle layout,\nintegrity model, serialization, errors", "1.0.0"],
        ["ACEF Profiles", "Record type schemas, regulation templates,\nrule DSL, variant registry", "1.0.0"],
        ["ACEF Assessment", "Assessment results, provision rollup,\nsigned conclusions", "1.0.0"],
    ]
    story.append(make_table(mod_data[0], mod_data[1:], [100, 280, 100]))

    story.append(Spacer(1, 12))
    story.append(Paragraph("<b>Layered Architecture</b>", s_h2))
    story.append(Paragraph(
        "The SDK implements a strict 10-layer dependency hierarchy. Each layer depends only on layers below it, "
        "preventing circular imports and enabling independent testing. The diagram below shows the complete stack "
        "from foundational error taxonomy and data models up through the CLI and report rendering.",
        s_body))

    story.append(Spacer(1, 6))
    story.append(ArchitectureDiagram(content_width, 290))
    story.append(Paragraph("Figure 1: SDK Architecture — 10-Layer Dependency Hierarchy", s_caption))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════════
    # 2b. BUNDLE LAYOUT & VALIDATION PIPELINE
    # ════════════════════════════════════════════════════════════════════
    story.append(Paragraph("<b>Bundle Layout</b>", s_h2))
    story.append(Paragraph(
        "An ACEF Evidence Bundle is a content-addressable directory (or .acef.tar.gz archive) with a strict layout. "
        "The manifest contains the envelope (metadata, subjects, entities, profiles, audit trail). Records are stored "
        "as deterministic JSONL files, one per record type, with automatic sharding at 100K records or 256 MB. "
        "Binary artifacts live in a dedicated directory. The hash and signature directories sit outside the hash domain, "
        "eliminating circular dependencies.",
        s_body))

    story.append(Spacer(1, 6))
    story.append(BundleLayoutDiagram(content_width, 240))
    story.append(Paragraph("Figure 2: Content-Addressable Bundle Directory Layout", s_caption))

    story.append(Spacer(1, 6))
    story.append(Paragraph("<b>Four-Phase Validation Pipeline</b>", s_h2))
    story.append(Paragraph(
        "Validation proceeds through four sequential phases. Each phase collects all errors before stopping, "
        "providing comprehensive diagnostics rather than failing on the first issue. The pipeline progresses from "
        "structural validation through cryptographic integrity, referential consistency, and finally regulatory "
        "rule evaluation.",
        s_body))

    story.append(Spacer(1, 6))
    story.append(ValidationPipelineDiagram(content_width, 115))
    story.append(Paragraph("Figure 3: Four-Phase Validation Pipeline", s_caption))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════════
    # 3. CORE CAPABILITIES
    # ════════════════════════════════════════════════════════════════════
    story.append(Paragraph("3. Core Capabilities & Feature Set", s_h1))
    story.append(SectionDivider(content_width))

    story.append(Paragraph("<b>Entity Model (W3C PROV-Compatible)</b>", s_h2))
    story.append(Paragraph(
        "ACEF models the AI system landscape through four entity types — Subjects (AI systems or models), "
        "Components (model, retriever, guardrail, orchestrator, tool, database, API), Datasets (training, "
        "evaluation, or operational data), and Actors (provider, deployer, auditor, regulator, data subject). "
        "Seven relationship types (wraps, calls, fine_tunes, deploys, trains_on, evaluates_with, oversees) "
        "link entities into a directed graph compatible with W3C PROV provenance semantics. Every evidence "
        "record carries entity references that bind it to specific subjects, components, datasets, and actors.",
        s_body))

    story.append(Paragraph("<b>16 Core Record Types</b>", s_h2))
    story.append(Paragraph(
        "The v1 specification defines 16 frozen record types that cover the full spectrum of AI compliance evidence. "
        "Each type has a dedicated JSON Schema for its payload. The variant registry extends base types with "
        "12 discriminated variants for specialized use cases (e.g., management_review, gpai_annex_xi_model_doc).",
        s_body))

    rt_data = [
        ["Record Type", "Purpose", "Category"],
        ["risk_register", "Risk identification and assessment", "Governance"],
        ["risk_treatment", "Risk mitigation measures and testing logs", "Governance"],
        ["dataset_card", "Dataset documentation (source, bias, quality)", "Data"],
        ["data_provenance", "Acquisition method, licensing, copyright", "Data"],
        ["evaluation_report", "Model/system evaluation results and metrics", "Testing"],
        ["event_log", "Runtime events, inference logs, logging specs", "Operations"],
        ["human_oversight_action", "Human override actions and justifications", "Oversight"],
        ["transparency_disclosure", "Public-facing AI disclosures", "Transparency"],
        ["transparency_marking", "Synthetic content metadata and watermarks", "Transparency"],
        ["disclosure_labeling", "User-facing AI interaction labels", "Transparency"],
        ["copyright_rights_reservation", "Rights reservation declarations", "IP"],
        ["license_record", "License terms and attribution requirements", "IP"],
        ["incident_report", "Post-deployment incident documentation", "Operations"],
        ["governance_policy", "AI governance policies, use-case inventory", "Governance"],
        ["conformity_declaration", "Formal conformity assessments", "Governance"],
        ["evidence_gap", "Documented gaps with remediation plans", "Meta"],
    ]
    story.append(make_table(rt_data[0], rt_data[1:], [155, 240, 80]))

    story.append(Spacer(1, 10))

    story.append(Paragraph("<b>Rule DSL & Evaluation Engine</b>", s_h2))
    story.append(Paragraph(
        "Regulation mapping templates express compliance requirements as machine-executable rules using a "
        "purpose-built DSL with 10 operators. Rules are bound to specific provisions and carry severity levels "
        "(fail, warning, info) that feed into the 7-step provision rollup algorithm. The DSL supports scope "
        "filtering by entity reference, obligation role, lifecycle phase, and modality — enabling precise, "
        "context-aware evaluation.",
        s_body))

    op_data = [
        ["Operator", "Semantics", "Empty-Set"],
        ["has_record_type", "At least N records of a given type exist", "Fail"],
        ["field_present", "A field exists in all matching records", "Vacuous pass"],
        ["field_value", "Field satisfies comparison (eq, gt, regex, ...)", "Vacuous pass"],
        ["evidence_freshness", "Records within max_age_days of evaluation", "Fail"],
        ["exists_where", "At least one record matches nested conditions", "Fail"],
        ["attachment_kind_exists", "Attachment of specific type is present", "Fail"],
        ["all_records_match", "All matching records satisfy a condition", "Vacuous pass"],
        ["count_satisfies", "Record count meets threshold", "Depends on op"],
        ["redaction_compliant", "Redaction uses only allowed methods", "Vacuous pass"],
        ["scope_filter", "Filter records by entity refs before evaluation", "N/A"],
    ]
    story.append(make_table(op_data[0], op_data[1:], [130, 260, 80]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>7-Step Provision Rollup Algorithm</b>", s_h2))
    story.append(Paragraph(
        "After all rules for a provision are evaluated, the SDK computes a deterministic provision outcome "
        "using a strict 7-step precedence algorithm. This ensures consistent assessment results across "
        "implementations. The steps, in order of precedence, are:",
        s_body))

    rollup_data = [
        ["Step", "Condition", "Outcome"],
        ["1", "Fatal evaluation error (ACEF-040 to ACEF-045)", "NOT_ASSESSED"],
        ["2", "Provision effective_date is in the future", "SKIPPED"],
        ["3", "evidence_gap record exists for this provision", "GAP_ACKNOWLEDGED"],
        ["4", "Any fail-severity rule returned FAILED", "NOT_SATISFIED"],
        ["5", "Any warning-severity rule returned FAILED", "PARTIALLY_SATISFIED"],
        ["6", "Only info-severity violations present", "SATISFIED"],
        ["7", "All rules passed across all severities", "SATISFIED"],
    ]
    story.append(make_table(rollup_data[0], rollup_data[1:], [40, 280, 145]))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════════
    # 3b. INTEGRITY, SIGNING, ADVANCED OPS
    # ════════════════════════════════════════════════════════════════════
    story.append(Paragraph("<b>Cryptographic Integrity Model</b>", s_h2))
    story.append(Paragraph(
        "Every file in the hash domain (manifest, records, artifacts) is hashed using SHA-256 over its "
        "RFC 8785-canonicalized form (for JSON/JSONL) or raw bytes (for binary files). These hashes are "
        "collected in content-hashes.json, then organized into a Merkle tree with a computed root hash. "
        "The Merkle tree uses odd-leaf promotion (not duplication) and raw 32-byte digests for inner nodes. "
        "Detached JWS signatures (RS256 or ES256 only, per RFC 7515) are computed over content-hashes.json, "
        "enabling multiple independent signers (provider, auditor, notified body) without modifying the bundle.",
        s_body))

    story.append(Paragraph("<b>Privacy-Preserving Redaction</b>", s_h2))
    story.append(Paragraph(
        "ACEF supports five confidentiality levels: public, redacted, hash-committed, regulator-only, "
        "and under-NDA. The redaction module replaces sensitive payloads with SHA-256 hash commitments, "
        "allowing recipients to verify that evidence exists and is consistent without accessing the "
        "underlying data. This enables graduated disclosure — a regulator receives the full bundle while "
        "a public auditor receives a redacted version with cryptographic proof of completeness.",
        s_body))

    story.append(Paragraph("<b>Multi-Source Merging</b>", s_h2))
    story.append(Paragraph(
        "The merge module combines evidence from multiple packages (e.g., different teams, vendors, or "
        "time periods) into a unified bundle. Three strategies are available: keep_latest (newest timestamp "
        "wins for duplicate records), keep_all (deduplicate by record_id, combine conflicts), and fail "
        "(raise on any conflicts). Merge diagnostics report duplicate record IDs, overlapping entity IDs, "
        "and incompatible metadata.",
        s_body))

    story.append(Paragraph("<b>Report Generation</b>", s_h2))
    story.append(Paragraph(
        "The render module produces human-readable compliance reports from Assessment Bundles in two formats: "
        "full Markdown (suitable for documentation systems) and console-formatted output (with rich formatting "
        "for terminal display). Reports include assessment metadata, structural error summaries, per-profile "
        "provision summaries, per-subject results, and rule-level evidence links.",
        s_body))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════════
    # 4. SDK SURFACE AREA
    # ════════════════════════════════════════════════════════════════════
    story.append(Paragraph("4. SDK Surface Area", s_h1))
    story.append(SectionDivider(content_width))

    story.append(Paragraph(
        "The Python SDK exposes a carefully designed public API through the top-level <font face='Courier'>acef</font> "
        "package. The API is organized around five functional domains:",
        s_body))

    story.append(Paragraph("<b>Package Construction</b>", s_h3))
    story.append(Paragraph(
        "The <font face='Courier'>Package</font> class is the primary builder API. It provides methods for adding "
        "subjects, components, datasets, actors, relationships, profiles, and evidence records. All entity creation "
        "returns typed objects with auto-generated URN identifiers. The <font face='Courier'>record()</font> method "
        "accepts 15 parameters covering record type, provisions addressed, payload, obligation role, entity "
        "references, confidentiality level, trust level, collector information, attachments, attestation, and "
        "retention requirements. The <font face='Courier'>export()</font> method serializes to either a directory "
        "bundle or a .acef.tar.gz archive.",
        s_body))

    story.append(Paragraph("<b>Validation & Assessment</b>", s_h3))
    story.append(Paragraph(
        "The <font face='Courier'>validate()</font> function accepts a Package or filesystem path and optional "
        "profile list. It executes the 4-phase validation pipeline and returns a fully populated "
        "<font face='Courier'>AssessmentBundle</font> with per-rule results, per-provision summaries (including "
        "per-subject breakdowns), structural errors, and template digests. "
        "<font face='Courier'>export_assessment()</font> writes the assessment to disk with optional signing.",
        s_body))

    story.append(Paragraph("<b>Signing & Verification</b>", s_h3))
    story.append(Paragraph(
        "<font face='Courier'>sign_bundle()</font> computes a detached JWS over content-hashes.json and writes it "
        "to the signatures directory. <font face='Courier'>verify_detached_jws()</font> validates a signature "
        "against a public key. Both RS256 and ES256 are supported; all other algorithms are rejected with ACEF-013. "
        "Certificate chains (x5c) are supported for enterprise PKI integration.",
        s_body))

    story.append(Paragraph("<b>Privacy & Merging</b>", s_h3))
    story.append(Paragraph(
        "<font face='Courier'>redact_package()</font> produces a redacted copy with hash commitments. "
        "<font face='Courier'>merge_packages()</font> combines multiple packages with configurable conflict "
        "resolution. Both operations produce new packages — the originals are never modified.",
        s_body))

    story.append(Paragraph("<b>CLI Interface</b>", s_h3))
    story.append(Paragraph(
        "The <font face='Courier'>acef</font> command-line tool provides seven commands: "
        "<font face='Courier'>init</font> (create a new bundle), "
        "<font face='Courier'>validate</font> (run validation pipeline), "
        "<font face='Courier'>inspect</font> (examine bundle contents), "
        "<font face='Courier'>doctor</font> (diagnose issues), "
        "<font face='Courier'>record</font> (add evidence records), "
        "<font face='Courier'>export</font> (convert between formats), and "
        "<font face='Courier'>scaffold</font> (generate evidence templates for a regulation). "
        "Output formats include text and JSON. The CLI is built on Click with Rich formatting.",
        s_body))

    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>Module Map</b>", s_h2))

    mod_map = [
        ["Module", "Key Exports", "Lines"],
        ["package.py", "Package (builder API)", "~550"],
        ["export.py", "export_directory, export_archive", "~250"],
        ["loader.py", "load (directory & archive)", "~400"],
        ["integrity.py", "canonicalize, sha256_hex, build_merkle_tree", "~300"],
        ["signing.py", "create_detached_jws, sign_bundle, verify_detached_jws", "~450"],
        ["assessment_builder.py", "build_assessment, export_assessment", "~300"],
        ["redaction.py", "redact_package, redact_record", "~200"],
        ["merge.py", "merge_packages", "~200"],
        ["render.py", "render_markdown, render_console", "~250"],
        ["errors.py", "ACEFError hierarchy, 60 error codes", "~200"],
        ["models/", "Pydantic v2 models, enums, URNs", "~1500"],
        ["validation/", "Engine, operators, rollup, schema, integrity, refs", "~1500"],
        ["templates/", "Registry, models, 11 JSON templates", "~500+"],
        ["cli/", "7 Click commands, formatters", "~600"],
    ]
    story.append(make_table(mod_map[0], mod_map[1:], [130, 270, 55]))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════════
    # 5. REGULATORY COVERAGE
    # ════════════════════════════════════════════════════════════════════
    story.append(Paragraph("5. Regulatory Coverage", s_h1))
    story.append(SectionDivider(content_width))

    story.append(Paragraph(
        "ACEF ships with 11 regulation mapping templates covering 8 jurisdictions. Each template encodes "
        "the specific provisions, required evidence types, evaluation rules, and effective dates for a "
        "regulatory framework. Templates are JSON files conforming to a dedicated schema, and new templates "
        "can be authored without modifying the SDK.",
        s_body))

    reg_data = [
        ["Template", "Jurisdiction", "Force", "Provisions"],
        ["EU AI Act 2024", "EU", "Binding", "Art. 9-17, 50, 53 (30+)"],
        ["GPAI Code of Practice 2025", "EU", "Binding", "Transparency, copyright"],
        ["EU Labelling CoP 2026", "EU", "Binding", "Art. 50 marking/labelling"],
        ["NIST AI RMF 1.0", "US", "Voluntary", "GOVERN, MAP, MEASURE, MANAGE"],
        ["NIST GAI Profile (600-1)", "US", "Voluntary", "GAI-specific controls"],
        ["US Copyright Office Part 3", "US", "Advisory", "Lawful acquisition, fair use"],
        ["OMB M-24-10", "US", "Binding (fed.)", "Federal AI use-case inventory"],
        ["China CAC Labeling 2025", "China", "Binding", "Explicit/implicit labels"],
        ["ISO/IEC 42001:2023", "Intl.", "Voluntary", "AI management system"],
        ["ISO/IEC 23894:2023", "Intl.", "Voluntary", "AI risk management"],
        ["UK AI & Copyright 2026", "UK", "Advisory", "Training data disclosure"],
    ]
    story.append(make_table(reg_data[0], reg_data[1:], [155, 65, 70, 185]))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Templates are independently versionable and hot-loadable via the template registry. Custom templates "
        "for internal governance frameworks, industry standards, or emerging regulations can be authored "
        "following the Template Authoring Guide and validated against the template JSON Schema.",
        s_body))

    story.append(Spacer(1, 6))
    story.append(Paragraph("<b>Conformance Test Vectors</b>", s_h2))
    story.append(Paragraph(
        "Each template is accompanied by test vectors — complete evidence bundles with expected assessment "
        "outcomes (pass and fail scenarios). These vectors serve as the normative conformance suite for "
        "alternative implementations. The current suite includes 19 test bundles across 5 frameworks:",
        s_body))

    tv_data = [
        ["Framework", "Test Bundles", "Examples"],
        ["EU AI Act", "10", "Art. 9 pass/fail, Art. 50 marking, Art. 53 Annex XI, multi-subject"],
        ["China CAC", "3", "Explicit/implicit pass, missing metadata fail, retention pass"],
        ["NIST AI RMF", "2", "GOVERN/MAP/MEASURE/MANAGE pass, missing policy fail"],
        ["OMB M-24-10", "2", "Inventory/governance pass, missing CAIO fail"],
        ["EU GPAI CoP", "2", "Transparency/copyright pass, missing training summary fail"],
    ]
    story.append(make_table(tv_data[0], tv_data[1:], [90, 70, 315]))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════════
    # 6. INTEGRATION MODEL
    # ════════════════════════════════════════════════════════════════════
    story.append(Paragraph("6. Integration Model & Developer Experience", s_h1))
    story.append(SectionDivider(content_width))

    story.append(Paragraph("<b>Programmatic SDK Usage</b>", s_h2))
    story.append(Paragraph(
        "The SDK is designed for integration into CI/CD pipelines, MLOps platforms, and compliance management "
        "systems. A typical integration flow follows this pattern:",
        s_body))

    flow_data = [
        ["Step", "API Call", "Purpose"],
        ["1", "Package(producer=...)", "Initialize evidence bundle with producer metadata"],
        ["2", "pkg.add_subject(...)", "Declare the AI system or model being documented"],
        ["3", "pkg.add_component/dataset/actor(...)", "Build the entity graph"],
        ["4", "pkg.add_relationship(...)", "Link entities with provenance relationships"],
        ["5", "pkg.add_profile(...)", "Declare applicable regulation profiles"],
        ["6", "pkg.record(type, payload, ...)", "Record evidence against provisions"],
        ["7", "pkg.sign(key_path)", "Cryptographically sign the bundle"],
        ["8", "pkg.export(path)", "Export as directory or .acef.tar.gz archive"],
        ["9", "acef.validate(path, profiles)", "Validate and produce Assessment Bundle"],
        ["10", "acef.render(assessment)", "Generate human-readable compliance report"],
    ]
    story.append(make_table(flow_data[0], flow_data[1:], [35, 195, 240]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>Determinism & Interoperability</b>", s_h2))
    story.append(Paragraph(
        "ACEF's determinism guarantees are foundational to its interoperability model. Any conformant "
        "implementation producing a bundle from the same logical record set will produce byte-identical "
        "output. This is enforced through RFC 8785 JSON canonicalization, deterministic record ordering "
        "(timestamp ascending, record_id tiebreaker), fixed sharding thresholds, and canonical archive "
        "parameters (gzip level 6, mtime=0, OS=0xFF, owner 0/0, permissions 0644/0755). The conformance "
        "test suite validates this property across implementations.",
        s_body))

    story.append(Paragraph("<b>Extension Model</b>", s_h2))
    story.append(Paragraph(
        "ACEF supports vendor extensions through the <font face='Courier'>x-</font> prefix convention "
        "(inspired by OTLP semantic conventions). Custom record types prefixed with "
        "<font face='Courier'>x-vendor/</font> are accepted by the SDK and pass through validation "
        "without payload schema enforcement. Extension fields in payloads follow the same prefix rule. "
        "This allows organizations to augment evidence packages with proprietary data without breaking "
        "conformance.",
        s_body))

    story.append(Paragraph("<b>Bundle Chaining</b>", s_h2))
    story.append(Paragraph(
        "Packages can reference prior bundles via <font face='Courier'>prior_package_ref</font>, creating "
        "an immutable chain of evidence snapshots over time. This supports continuous compliance: each "
        "bundle captures the state of evidence at a point in time, and the chain provides a complete "
        "audit history. The <font face='Courier'>acef.chain()</font> convenience function initializes "
        "a new package pre-linked to its predecessor.",
        s_body))

    story.append(Paragraph("<b>Error Taxonomy</b>", s_h2))
    story.append(Paragraph(
        "The SDK implements a structured error taxonomy with 60 codes (ACEF-001 through ACEF-060) "
        "organized into six categories: schema errors, integrity errors, reference errors, profile "
        "errors, evaluation errors, and format errors. Each error carries a severity (fatal, error, "
        "warning, info), a human-readable message, and a JSON path to the offending element. This "
        "enables precise diagnostics and actionable remediation guidance.",
        s_body))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════════
    # 7. SECURITY MODEL
    # ════════════════════════════════════════════════════════════════════
    story.append(Paragraph("7. Security Model", s_h1))
    story.append(SectionDivider(content_width))

    story.append(Paragraph(
        "ACEF implements defense-in-depth across multiple attack surfaces:",
        s_body))

    sec_data = [
        ["Threat", "Mitigation", "Implementation"],
        ["Bundle tampering", "SHA-256 content hashes + Merkle tree\n+ JWS detached signatures", "integrity.py, signing.py"],
        ["Path traversal", "Multi-layer validation at add, export,\nand load time", "package.py, export.py, loader.py"],
        ["Tar bomb / zip bomb", "Size limits (10 GB total, 1 GB/file),\nfile count limit (100K), no symlinks", "loader.py"],
        ["ReDoS (regex)", "Pattern length cap (1024), input cap\n(1M chars), SIGALRM timeout (5s)", "operators.py"],
        ["Algorithm confusion", "RS256 and ES256 ONLY; all others\nrejected with ACEF-013", "signing.py"],
        ["Credential leakage", "Hash commitments for confidential\nevidence; 5 confidentiality levels", "redaction.py"],
        ["Signature replay", "Signatures bound to content-hashes.json;\ntimestamped manifests", "signing.py"],
    ]
    story.append(make_table(sec_data[0], sec_data[1:], [110, 200, 165]))

    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════════════
    # 8. STATUS & OPEN ITEMS
    # ════════════════════════════════════════════════════════════════════
    story.append(Paragraph("8. Current Status & Open Items", s_h1))
    story.append(SectionDivider(content_width))

    story.append(Paragraph("<b>Maturity</b>", s_h2))

    status_data = [
        ["Dimension", "Status", "Detail"],
        ["Specification", "v0.3 Working Draft", "Feature-complete for v1 scope; community review ongoing"],
        ["SDK", "v0.1.0 Alpha", "API stable but may change before 1.0; production use at own risk"],
        ["Python support", ">= 3.11", "No plans for lower version support"],
        ["Test coverage", "34 test files", "Unit, integration, conformance; 19 golden test vectors"],
        ["Documentation", "5 documents", "Architecture, User Guide, API Reference, Template Authoring, Conformance"],
        ["License", "Apache 2.0 / CC-BY 4.0", "Code: Apache 2.0; Schemas & templates: CC-BY 4.0"],
    ]
    story.append(make_table(status_data[0], status_data[1:], [110, 130, 235]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>Noted Open Items from the Specification</b>", s_h2))

    story.append(bullet(
        "<b>CRL/OCSP revocation checking:</b> Certificate revocation checking is RECOMMENDED but not REQUIRED "
        "for v1. Full revocation support is deferred to a future version."))
    story.append(bullet(
        "<b>Zero-knowledge proof redaction:</b> The redaction_method field supports ZKP references, but no "
        "ZKP implementation is included in the SDK. Hash commitments are the current mechanism."))
    story.append(bullet(
        "<b>Cross-language implementations:</b> The conformance test suite and deterministic output specification "
        "are designed to enable implementations in other languages (Go, TypeScript, Rust), but only the Python "
        "reference implementation exists today."))
    story.append(bullet(
        "<b>Template coverage gaps:</b> Some regulatory frameworks have partial template coverage. The EU AI Act "
        "template is the most comprehensive (30+ provisions); others cover core requirements but may not "
        "encode every sub-provision."))
    story.append(bullet(
        "<b>Retention enforcement:</b> Retention policies are declared in metadata and per-record retention "
        "fields, but enforcement (automatic deletion, archival) is out of scope for the SDK — it is left "
        "to the hosting system."))
    story.append(bullet(
        "<b>Real-time streaming:</b> ACEF bundles are point-in-time snapshots. Continuous monitoring and "
        "streaming evidence ingestion are not addressed by the current specification."))

    story.append(Spacer(1, 14))
    story.append(Paragraph("<b>Recommendation</b>", s_h2))
    story.append(Paragraph(
        "ACEF addresses a genuine infrastructure gap in the AI compliance landscape. The specification is "
        "well-designed, the reference SDK is feature-complete for its stated scope, and the deterministic "
        "output model creates a credible path to cross-implementation interoperability. For organizations "
        "facing imminent EU AI Act compliance deadlines or building compliance tooling, ACEF merits serious "
        "evaluation as the evidence packaging layer. The primary risks are typical of pre-1.0 open standards: "
        "API instability, limited ecosystem, and evolving regulatory requirements that may outpace template updates.",
        s_callout))

    # ── Build PDF ───────────────────────────────────────────────────────
    doc.build(
        story,
        onFirstPage=cover_page,
        onLaterPages=header_footer,
    )

    print(f"PDF generated: {output_path}")
    return output_path


if __name__ == "__main__":
    build_document()
