"""
pdf_generator.py
----------------
MSME Shield — Professional A4 PDF Report Generator v2.0

Generates a complete, multi-section PDF report from a FullScanResponse dict.

Public API:
    generate_report(scan_data: dict, filename: str) -> str | None
        Returns filename on success, None on any failure.

STRICT CONSTRAINTS:
    - Zero HTTP calls. Zero DB calls. Zero Pydantic imports.
    - All ReportLab imports at the top of this file only.
    - Every section function appends flowables to 'story'. Returns nothing.
    - admin_password / credentials are never referenced here.
    - Never raises — doc.build() is wrapped in try/except.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# COLOR PALETTE — matches dashboard.py exactly
# ---------------------------------------------------------------------------

DARK      = colors.HexColor("#1D1D1F")
SECONDARY = colors.HexColor("#6E6E73")
ACCENT    = colors.HexColor("#0071E3")
SUCCESS   = colors.HexColor("#34C759")
WARNING   = colors.HexColor("#FF9F0A")
CRITICAL  = colors.HexColor("#FF3B30")
BG_LIGHT  = colors.HexColor("#F5F5F7")
BORDER    = colors.HexColor("#E5E5EA")
WHITE     = colors.white

# Risk band colours
_BAND_COLOR: dict[str, Any] = {
    "LOW":      SUCCESS,
    "MEDIUM":   WARNING,
    "CRITICAL": CRITICAL,
}
_BAND_BG_HEX: dict[str, str] = {
    "LOW":      "#34C75912",
    "MEDIUM":   "#FF9F0A12",
    "CRITICAL": "#FF3B3012",
}
_BAND_EMOJI: dict[str, str] = {
    "LOW":      "✓  LOW RISK",
    "MEDIUM":   "⚠  MEDIUM RISK",
    "CRITICAL": "🚨  CRITICAL RISK",
}

# Password score → label
_PWD_LABEL: dict[int, tuple[str, Any]] = {
    0: ("Very Weak",   CRITICAL),
    1: ("Weak",        CRITICAL),
    2: ("Fair",        WARNING),
    3: ("Strong",      SUCCESS),
    4: ("Very Strong", SUCCESS),
}

# Governance control metadata — mirrors dashboard.py CONTROL_META
_CONTROL_META: dict[str, dict] = {
    "log_retention":          {"label": "180-Day Log Retention",              "citation": "CERT-In §6(ii)",             "statutory": True,  "tier": 1, "remediation": "Configure centralised log aggregation. Retain all logs ≥180 days. Non-compliance attracts penalties under IT Act 2000 §70B."},
    "incident_reporting":     {"label": "6-Hour Incident Reporting (CERT-In)","citation": "CERT-In §4",                 "statutory": True,  "tier": 1, "remediation": "Designate a CERT-In nodal officer. Document 6-hour reporting procedure. Register at cert-in.org.in."},
    "incident_plan":          {"label": "Incident Response Plan",             "citation": "CERT-In/GEN-2/2022 + NIST RS.RP-1","statutory":True,"tier": 1, "remediation": "Document IRP covering detection, escalation contacts, containment steps, and CERT-In reporting."},
    "mfa_enabled":            {"label": "MFA on Critical Systems",            "citation": "CERT-In §6(v) + NIST PR.AC-7","statutory": True, "tier": 1, "remediation": "Enable MFA on all admin and remote-access accounts."},
    "ntp_sync":               {"label": "NTP Time Synchronisation",           "citation": "CERT-In §6(i)",              "statutory": True,  "tier": 1, "remediation": "Sync all systems to time.google.com or pool.ntp.org."},
    "offline_backup":         {"label": "Offline / Air-Gapped Backup",        "citation": "NIST CSF 2.0 PR.IP-4",      "statutory": False, "tier": 1, "remediation": "Implement 3-2-1 backup policy: 3 copies, 2 different media, 1 offsite or offline."},
    "least_privilege":        {"label": "Least Privilege Access Control",     "citation": "NIST CSF 2.0 PR.AC-4",      "statutory": False, "tier": 1, "remediation": "Audit all user accounts. Remove admin rights from standard users."},
    "patch_management":       {"label": "Patch Management Cadence",           "citation": "NIST CSF 2.0 PR.IP-12",     "statutory": False, "tier": 1, "remediation": "Monthly patching cycle. Critical patches (CVSS ≥9.0) within 72 hours."},
    "phishing_training":      {"label": "Phishing Awareness Training",        "citation": "NIST CSF 2.0 PR.AT-1",      "statutory": False, "tier": 1, "remediation": "Annual phishing awareness training for all staff."},
    "firewall_segmentation":  {"label": "Firewall / Network Segmentation",    "citation": "NIST CSF 2.0 PR.PT-3",      "statutory": False, "tier": 1, "remediation": "Enable OS firewall on all machines. Segment guest WiFi from business network."},
    "asset_inventory":        {"label": "Asset Inventory",                    "citation": "NIST CSF 2.0 ID.AM-1",      "statutory": False, "tier": 2, "remediation": "Maintain documented inventory of all hardware and software assets."},
    "vulnerability_disclosure":{"label":"Vulnerability Disclosure Policy",    "citation": "NIST CSF 2.0 DE.AE-1",      "statutory": False, "tier": 2, "remediation": "Publish a responsible disclosure policy. Designate a security contact email."},
    "privileged_access_ws":   {"label": "Privileged Access Workstations",     "citation": "NIST CSF 2.0 PR.AC-5",      "statutory": False, "tier": 2, "remediation": "Designate separate workstations for administrative tasks only."},
    "security_logging":       {"label": "Security Logging / SIEM",            "citation": "NIST CSF 2.0 DE.CM-1",      "statutory": False, "tier": 2, "remediation": "Configure centralised security event logging. Alert on failed logins."},
    "vendor_risk":            {"label": "Third-Party Vendor Risk Assessment",  "citation": "NIST CSF 2.0 ID.SC-2",      "statutory": False, "tier": 2, "remediation": "Assess security posture of key vendors with data access annually."},
    "penetration_testing":    {"label": "Annual Penetration Testing",          "citation": "NIST CSF 2.0 PR.IP-10",     "statutory": False, "tier": 3, "remediation": "Annual penetration testing by a CERT-In empanelled auditor."},
    "data_classification":    {"label": "Data Classification Policy",          "citation": "NIST CSF 2.0 PR.DS-1",      "statutory": False, "tier": 3, "remediation": "Classify all business data as Public, Internal, Confidential, or Restricted."},
    "bcp_drp_tested":         {"label": "BCP / DRP Documented and Tested",    "citation": "NIST CSF 2.0 RC.RP-1",      "statutory": False, "tier": 3, "remediation": "Document BCP and DRP. Conduct tabletop exercises at least annually."},
    "vapt_remediation":       {"label": "VAPT Results Tracked and Remediated","citation": "NIST CSF 2.0 RS.AN-1",      "statutory": False, "tier": 3, "remediation": "Track VAPT findings. Critical findings remediated within 30 days."},
    "dedicated_ir_team":      {"label": "Dedicated Incident Response Team",   "citation": "NIST CSF 2.0 RS.CO-1",      "statutory": False, "tier": 3, "remediation": "Form a dedicated IR team: Incident Commander, Technical Lead, Comms Lead."},
}

_TIER1_KEYS = [
    "log_retention", "incident_reporting", "incident_plan", "mfa_enabled",
    "ntp_sync", "offline_backup", "least_privilege", "patch_management",
    "phishing_training", "firewall_segmentation",
]
_TIER2_KEYS = [
    "asset_inventory", "vulnerability_disclosure", "privileged_access_ws",
    "security_logging", "vendor_risk",
]
_TIER3_KEYS = [
    "penetration_testing", "data_classification", "bcp_drp_tested",
    "vapt_remediation", "dedicated_ir_team",
]

# ---------------------------------------------------------------------------
# Internal: page geometry (set once, reused everywhere)
# ---------------------------------------------------------------------------

_PAGE_W, _PAGE_H = A4
_MARGIN          = 2.0 * cm
_BODY_W          = _PAGE_W - 2 * _MARGIN  # usable width ≈ 451 pts
_FOOTER_Y        = _MARGIN * 0.6           # y position of footer from bottom


# ===========================================================================
# STYLE FACTORY
# ===========================================================================

def _make_styles() -> dict[str, ParagraphStyle]:
    """Return all paragraph styles used throughout the report."""
    base = {
        "title": ParagraphStyle(
            "MSMETitle",
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=DARK,
            spaceAfter=4,
            alignment=TA_LEFT,
        ),
        "tagline": ParagraphStyle(
            "MSMETagline",
            fontName="Helvetica-Oblique",
            fontSize=12,
            textColor=SECONDARY,
            spaceAfter=2,
            alignment=TA_LEFT,
        ),
        "section_heading": ParagraphStyle(
            "MSMESectionHeading",
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=DARK,
            spaceBefore=14,
            spaceAfter=4,
        ),
        "subsection_heading": ParagraphStyle(
            "MSMESubsection",
            fontName="Helvetica-Bold",
            fontSize=11,
            textColor=DARK,
            spaceBefore=10,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "MSMEBody",
            fontName="Helvetica",
            fontSize=9,
            textColor=DARK,
            leading=14,
            spaceAfter=4,
        ),
        "bold_body": ParagraphStyle(
            "MSMEBoldBody",
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=DARK,
            leading=14,
        ),
        "caption": ParagraphStyle(
            "MSMECaption",
            fontName="Helvetica-Oblique",
            fontSize=8,
            textColor=SECONDARY,
            spaceAfter=2,
        ),
        "small": ParagraphStyle(
            "MSMESmall",
            fontName="Helvetica",
            fontSize=8,
            textColor=SECONDARY,
            leading=12,
        ),
        "small_italic": ParagraphStyle(
            "MSMESmallItalic",
            fontName="Helvetica-Oblique",
            fontSize=8,
            textColor=SECONDARY,
            leading=12,
        ),
        "tbl_header": ParagraphStyle(
            "MSMETblHeader",
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=SECONDARY,
            alignment=TA_LEFT,
        ),
        "tbl_cell": ParagraphStyle(
            "MSMETblCell",
            fontName="Helvetica",
            fontSize=8,
            textColor=DARK,
            leading=12,
        ),
        "tbl_cell_mono": ParagraphStyle(
            "MSMETblCellMono",
            fontName="Helvetica",
            fontSize=8,
            textColor=ACCENT,
            leading=12,
        ),
        "meta_key": ParagraphStyle(
            "MSMEMetaKey",
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=SECONDARY,
        ),
        "meta_val": ParagraphStyle(
            "MSMEMetaVal",
            fontName="Helvetica",
            fontSize=9,
            textColor=DARK,
        ),
        "score_giant": ParagraphStyle(
            "MSMEScoreGiant",
            fontName="Helvetica-Bold",
            fontSize=28,
            textColor=DARK,
            alignment=TA_CENTER,
            leading=34,
        ),
        "score_band": ParagraphStyle(
            "MSMEScoreBand",
            fontName="Helvetica-Bold",
            fontSize=18,
            textColor=DARK,
            alignment=TA_CENTER,
            leading=22,
        ),
        "score_formula": ParagraphStyle(
            "MSMEScoreFormula",
            fontName="Helvetica-Oblique",
            fontSize=9,
            textColor=SECONDARY,
            alignment=TA_CENTER,
        ),
        "pillar_title": ParagraphStyle(
            "MSMEPillarTitle",
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=SECONDARY,
            alignment=TA_CENTER,
        ),
        "pillar_score": ParagraphStyle(
            "MSMEPillarScore",
            fontName="Helvetica-Bold",
            fontSize=18,
            textColor=DARK,
            alignment=TA_CENTER,
            leading=22,
        ),
        "pillar_weight": ParagraphStyle(
            "MSMEPillarWeight",
            fontName="Helvetica",
            fontSize=8,
            textColor=SECONDARY,
            alignment=TA_CENTER,
        ),
        "status_yes": ParagraphStyle(
            "MSMEStatusYes",
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=SUCCESS,
            alignment=TA_CENTER,
        ),
        "status_no": ParagraphStyle(
            "MSMEStatusNo",
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=CRITICAL,
            alignment=TA_CENTER,
        ),
        "statutory_note": ParagraphStyle(
            "MSMEStatutory",
            fontName="Helvetica-Oblique",
            fontSize=8,
            textColor=ACCENT,
        ),
        "remediation_label": ParagraphStyle(
            "MSMERemLabel",
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=DARK,
        ),
        "remediation_body": ParagraphStyle(
            "MSMERemBody",
            fontName="Helvetica",
            fontSize=8,
            textColor=SECONDARY,
            leading=12,
        ),
        "footer": ParagraphStyle(
            "MSMEFooter",
            fontName="Helvetica",
            fontSize=7.5,
            textColor=SECONDARY,
        ),
        "footer_disclaimer": ParagraphStyle(
            "MSMEFooterDisclaimer",
            fontName="Helvetica-Oblique",
            fontSize=8,
            textColor=SECONDARY,
            leading=12,
            alignment=TA_CENTER,
        ),
    }
    return base


# ===========================================================================
# FOOTER CALLBACK
# ===========================================================================

def _draw_footer(canvas: Any, doc: Any) -> None:
    """Draw footer on every page via SimpleDocTemplate callback."""
    canvas.saveState()

    page_num   = canvas.getPageNumber()
    today_str  = datetime.now().strftime("%d %b %Y")
    footer_y   = _FOOTER_Y + 6
    line_y     = footer_y + 14

    # Horizontal rule above footer
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(_MARGIN, line_y, _PAGE_W - _MARGIN, line_y)

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(SECONDARY)

    # Left
    canvas.drawString(_MARGIN, footer_y, "MSME Shield — Confidential")
    # Centre
    canvas.drawCentredString(
        _PAGE_W / 2, footer_y,
        f"Page {page_num}",
    )
    # Right
    canvas.drawRightString(
        _PAGE_W - _MARGIN, footer_y,
        f"Generated {today_str}",
    )

    # Bottom disclaimer
    canvas.setFont("Helvetica-Oblique", 7)
    canvas.drawCentredString(
        _PAGE_W / 2, footer_y - 11,
        "This report is generated for informational purposes. "
        "Consult a CERT-In empanelled auditor for statutory compliance certification.",
    )

    canvas.restoreState()


# ===========================================================================
# HELPER UTILITIES
# ===========================================================================

def _hr(color: Any = BORDER, thickness: float = 0.5) -> HRFlowable:
    return HRFlowable(
        width="100%", thickness=thickness,
        color=color, spaceAfter=4, spaceBefore=4,
    )


def _spacer(h: float = 0.3) -> Spacer:
    return Spacer(1, h * cm)


def _section_rule(story: list, styles: dict, title: str) -> None:
    """Append a section heading + thin rule."""
    story.append(Paragraph(title, styles["section_heading"]))
    story.append(_hr(BORDER, 0.5))
    story.append(_spacer(0.15))


def _info_box(
    story: list,
    styles: dict,
    text: str,
    bg: Any = BG_LIGHT,
    border_color: Any = BORDER,
    text_style: str = "body",
) -> None:
    """Generic rounded info/warning box (single-cell table)."""
    tbl = Table([[Paragraph(text, styles[text_style])]], colWidths=[_BODY_W])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), bg),
        ("BOX",           (0, 0), (-1, -1), 1, border_color),
        ("ROUNDEDCORNERS",[6]),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
    ]))
    story.append(tbl)
    story.append(_spacer(0.2))


def _score_color(score: float) -> Any:
    if score >= 70:
        return CRITICAL
    if score >= 40:
        return WARNING
    return SUCCESS


def _applicable_keys(maturity: str) -> list[str]:
    m = (maturity or "basic").lower().strip()
    if m == "advanced":
        return _TIER1_KEYS + _TIER2_KEYS + _TIER3_KEYS
    if m == "intermediate":
        return _TIER1_KEYS + _TIER2_KEYS
    return _TIER1_KEYS


def _mini_bar_table(score: float, color: Any, width: float) -> Table:
    """Return a thin progress-bar as a 2-column Table."""
    filled = max(0.0, min(100.0, score))
    empty  = 100.0 - filled
    bar_h  = 4
    row = [[""]]
    tbl = Table(row, colWidths=[width])
    # We draw two nested cells: filled and empty
    filled_w = width * filled / 100.0
    empty_w  = width - filled_w
    inner = Table([[""]], colWidths=[width])
    # Use a gradient trick via two-column table
    data = [["", ""]]
    bar_tbl = Table(data, colWidths=[filled_w, empty_w], rowHeights=[bar_h])
    bar_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), color),
        ("BACKGROUND", (1, 0), (1, 0), BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))
    return bar_tbl


# ===========================================================================
# SECTION 1 — COVER / HEADER
# ===========================================================================

def _section_header(story: list, data: dict, styles: dict) -> None:
    org_name  = data.get("organization_name") or data.get("org_name") or "Unknown Organisation"
    scan_id   = data.get("scan_id", "—")
    timestamp = data.get("timestamp", "")
    generated = datetime.now().strftime("%d %B %Y, %H:%M IST")

    try:
        ts_fmt = datetime.fromisoformat(timestamp).strftime("%-d %b %Y, %H:%M")
    except Exception:
        ts_fmt = timestamp[:16] if timestamp else "—"

    # Logo row
    logo_para = Paragraph(
        "🛡️  MSME Shield",
        ParagraphStyle("Logo", fontName="Helvetica-Bold", fontSize=22, textColor=DARK),
    )
    sub_para = Paragraph(
        "Cyber Risk Quantification Report",
        ParagraphStyle("Sub", fontName="Helvetica", fontSize=12, textColor=SECONDARY),
    )
    logo_tbl = Table([[logo_para], [sub_para]], colWidths=[_BODY_W])
    logo_tbl.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))
    story.append(logo_tbl)
    story.append(_hr(BORDER, 1.0))
    story.append(_spacer(0.2))

    # Metadata table
    meta_rows = [
        ["Organisation:",  org_name],
        ["Generated:",     generated],
        ["Scan ID:",       f"#{scan_id}"],
        ["Scan Date:",     ts_fmt],
        ["Framework:",     "CERT-In April 2022 + NIST CSF 2.0"],
        ["TRL:",           "8 — System Complete and Qualified"],
    ]
    meta_data = [
        [
            Paragraph(r[0], styles["meta_key"]),
            Paragraph(str(r[1]), styles["meta_val"]),
        ]
        for r in meta_rows
    ]
    col_w = [_BODY_W * 0.28, _BODY_W * 0.72]
    meta_tbl = Table(meta_data, colWidths=col_w)
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), BG_LIGHT),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER),
        ("ROUNDEDCORNERS",[6]),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.25, BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(meta_tbl)
    story.append(_spacer(0.4))


# ===========================================================================
# SECTION 2 — MRQM SCORE CARD
# ===========================================================================

def _section_score_card(story: list, data: dict, styles: dict) -> None:
    mrqm      = float(data.get("mrqm_score") or 0.0)
    tech      = float(data.get("tech_score") or 0.0)
    gov       = float(data.get("governance_score") or 0.0)
    exp       = float(data.get("exposure_score") or 0.0)
    band      = (data.get("risk_band") or "PENDING").upper()
    status    = data.get("status", "")
    is_pending = status == "pending_governance"

    band_color = _BAND_COLOR.get(band, SECONDARY)
    band_bg    = colors.HexColor(_BAND_BG_HEX.get(band, "#6E6E7312"))
    band_label = _BAND_EMOJI.get(band, band)

    score_display = mrqm if not is_pending else tech
    score_label   = f"{score_display:.1f} / 100"
    if is_pending:
        score_label += "  (Governance Pending)"

    # Score card box — 3 rows
    band_p = Paragraph(band_label, ParagraphStyle(
        "BandLbl", fontName="Helvetica-Bold", fontSize=16,
        textColor=band_color, alignment=TA_CENTER,
    ))
    score_p = Paragraph(score_label, ParagraphStyle(
        "ScoreLbl", fontName="Helvetica-Bold", fontSize=28,
        textColor=band_color, alignment=TA_CENTER, leading=34,
    ))
    formula_p = Paragraph(
        "(0.45 × Technical)  +  (0.35 × Governance)  +  (0.20 × Exposure)",
        styles["score_formula"],
    )
    score_tbl = Table(
        [[band_p], [score_p], [formula_p]],
        colWidths=[_BODY_W],
    )
    score_tbl.setStyle(TableStyle([
        ("BOX",           (0, 0), (-1, -1), 1.5, band_color),
        ("BACKGROUND",    (0, 0), (-1, -1), band_bg),
        ("ROUNDEDCORNERS",[8]),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 16),
    ]))
    story.append(score_tbl)
    story.append(_spacer(0.3))

    # Three pillar cards
    pillar_w = _BODY_W / 3.0

    def _pillar_cell(icon: str, label: str, score: float, weight: str, pending: bool = False) -> Table:
        p_color = _score_color(score) if not pending else ACCENT
        score_str = f"{score:.1f}" if not pending else "—"
        bar = _mini_bar_table(score if not pending else 0.0, p_color, pillar_w - 20)
        inner_data = [
            [Paragraph(f"{icon}  {label}", styles["pillar_title"])],
            [Paragraph(score_str, ParagraphStyle(
                "PS", fontName="Helvetica-Bold", fontSize=22,
                textColor=p_color, alignment=TA_CENTER, leading=28,
            ))],
            [bar],
            [Paragraph(weight, styles["pillar_weight"])],
        ]
        inner = Table(inner_data, colWidths=[pillar_w - 16])
        inner.setStyle(TableStyle([
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ]))
        outer = Table([[inner]], colWidths=[pillar_w])
        outer.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), BG_LIGHT),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER),
            ("ROUNDEDCORNERS",[6]),
            ("TOPPADDING",    (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ]))
        return outer

    pillars_row = [[
        _pillar_cell("🔬", "Technical",  tech, "45% of MRQM"),
        _pillar_cell("📋", "Governance", gov,  "35% of MRQM", pending=is_pending),
        _pillar_cell("🌐", "Exposure",   exp,  "20% of MRQM"),
    ]]
    pillars_tbl = Table(pillars_row, colWidths=[pillar_w, pillar_w, pillar_w])
    pillars_tbl.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(pillars_tbl)
    story.append(_spacer(0.4))


# ===========================================================================
# SECTION 3 — ACTIVE PROBING RESULTS
# ===========================================================================

def _section_active_probing(story: list, data: dict, styles: dict) -> None:
    _section_rule(story, styles, "Active Probing Results")

    ssl_days   = int(data.get("ssl_days") or 45)
    pwd_score  = int(data.get("password_score") or 0)

    # SSL label
    if ssl_days <= 0:
        ssl_label = "⚠  Certificate Expired"
        ssl_color = CRITICAL
    elif ssl_days == 45:
        ssl_label = "Domain not provided to agent"
        ssl_color = SECONDARY
    elif ssl_days <= 30:
        ssl_label = f"⚠  {ssl_days} days remaining"
        ssl_color = WARNING
    else:
        ssl_label = f"✓  {ssl_days} days remaining"
        ssl_color = SUCCESS

    # Password label
    pwd_lbl, pwd_col = _PWD_LABEL.get(pwd_score, ("Unknown", SECONDARY))

    half = _BODY_W / 2.0

    def _probe_card(title: str, value: str, vcol: Any, caption: str) -> Table:
        t_p = Paragraph(title, ParagraphStyle(
            "PTop", fontName="Helvetica-Bold", fontSize=8,
            textColor=SECONDARY,
        ))
        v_p = Paragraph(value, ParagraphStyle(
            "PVal", fontName="Helvetica-Bold", fontSize=13,
            textColor=vcol, leading=18,
        ))
        c_p = Paragraph(caption, styles["small_italic"])
        inner = Table([[t_p], [v_p], [c_p]], colWidths=[half - 24])
        inner.setStyle(TableStyle([
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ]))
        outer = Table([[inner]], colWidths=[half - 8])
        outer.setStyle(TableStyle([
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER),
            ("BACKGROUND",    (0, 0), (-1, -1), BG_LIGHT),
            ("ROUNDEDCORNERS",[6]),
            ("TOPPADDING",    (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
        ]))
        return outer

    ssl_card = _probe_card(
        "SSL CERTIFICATE",
        ssl_label,
        ssl_color,
        "Checked via ssl/socket live probe",
    )
    pwd_card = _probe_card(
        "ADMIN PASSWORD STRENGTH",
        pwd_lbl,
        pwd_col,
        "Assessed via zxcvbn — credential never stored",
    )
    row_tbl = Table([[ssl_card, pwd_card]], colWidths=[half, half])
    row_tbl.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 2),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 2),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(row_tbl)
    story.append(_spacer(0.2))
    story.append(Paragraph(
        "Password is evaluated in-process and immediately discarded. "
        "It is never transmitted or persisted.",
        styles["small_italic"],
    ))
    story.append(_spacer(0.3))


# ===========================================================================
# SECTION 4 — SOFTWARE VULNERABILITIES
# ===========================================================================

def _section_vulnerabilities(story: list, data: dict, styles: dict) -> None:
    _section_rule(story, styles, "Software Vulnerability Findings")
    story.append(Paragraph(
        "Source: NVD API v2.0  +  EPSS (FIRST.org)  +  endoflife.date",
        styles["caption"],
    ))
    story.append(_spacer(0.15))

    cve_findings = data.get("cve_findings") or []
    # Handle both list and dict with 'findings' key
    if isinstance(cve_findings, dict):
        cve_findings = cve_findings.get("findings", [])
    cve_findings = cve_findings or []

    any_eol = bool(data.get("any_eol", False))

    # Flatten CVE rows
    cve_rows: list[dict] = []
    sw_count = len(cve_findings)
    for finding in cve_findings:
        sw_name  = finding.get("software_name", "")
        sw_ver   = finding.get("version", "")
        is_eol_f = finding.get("is_eol", False)
        for cve in (finding.get("cves") or []):
            cve_rows.append({
                "software": sw_name,
                "version":  sw_ver,
                "cve_id":   cve.get("cve_id", ""),
                "cvss":     float(cve.get("cvss_score") or 0.0),
                "epss":     float(cve.get("epss_probability") or 0.0),
                "risk":     float(cve.get("per_cve_risk") or 0.0),
                "eol":      is_eol_f,
            })
    cve_rows.sort(key=lambda r: r["risk"], reverse=True)
    cve_count = len(cve_rows)

    if not cve_rows:
        _info_box(
            story, styles,
            "✓  No known vulnerabilities detected in the scanned software inventory.",
            bg=colors.HexColor("#F0FFF4"),
            border_color=SUCCESS,
        )
    else:
        story.append(Paragraph(
            f"{sw_count} software items scanned  ·  "
            f"{cve_count} CVE{'s' if cve_count != 1 else ''} found  ·  "
            f"EOL software: {'Detected ⚠' if any_eol else 'None'}",
            styles["bold_body"],
        ))
        story.append(_spacer(0.15))

        # Column widths: Software 25%, Version 12%, CVE 20%, CVSS 10%, EPSS 10%, Risk 13%
        cw = [
            _BODY_W * 0.25,
            _BODY_W * 0.12,
            _BODY_W * 0.20,
            _BODY_W * 0.10,
            _BODY_W * 0.10,
            _BODY_W * 0.13,
            _BODY_W * 0.10,  # EOL flag column
        ]
        cw[-1] = _BODY_W - sum(cw[:-1])  # fill remainder

        header_row = [
            Paragraph("SOFTWARE",   styles["tbl_header"]),
            Paragraph("VERSION",    styles["tbl_header"]),
            Paragraph("CVE ID",     styles["tbl_header"]),
            Paragraph("CVSS",       styles["tbl_header"]),
            Paragraph("EPSS",       styles["tbl_header"]),
            Paragraph("RISK",       styles["tbl_header"]),
            Paragraph("EOL",        styles["tbl_header"]),
        ]
        tbl_data = [header_row]

        max_rows = 15
        display_rows = cve_rows[:max_rows]

        for row in display_rows:
            cvss = row["cvss"]
            epss = row["epss"]
            if cvss >= 9.0:
                cvss_col = CRITICAL
            elif cvss >= 7.0:
                cvss_col = WARNING
            else:
                cvss_col = SECONDARY
            epss_col = CRITICAL if epss > 0.7 else SECONDARY
            eol_txt  = "⚠ EOL" if row["eol"] else "—"
            eol_col  = WARNING if row["eol"] else SECONDARY

            tbl_data.append([
                Paragraph(row["software"], styles["tbl_cell"]),
                Paragraph(row["version"],  styles["tbl_cell"]),
                Paragraph(row["cve_id"],   styles["tbl_cell_mono"]),
                Paragraph(f"{cvss:.1f}", ParagraphStyle(
                    "CVSScell", fontName="Helvetica-Bold",
                    fontSize=8, textColor=cvss_col,
                )),
                Paragraph(f"{epss:.3f}", ParagraphStyle(
                    "EPSScell", fontName="Helvetica",
                    fontSize=8, textColor=epss_col,
                )),
                Paragraph(f"{row['risk']:.4f}", styles["tbl_cell"]),
                Paragraph(eol_txt, ParagraphStyle(
                    "EOLcell", fontName="Helvetica-Bold",
                    fontSize=8, textColor=eol_col,
                )),
            ])

        style_cmds = [
            ("BACKGROUND",    (0, 0), (-1, 0), BG_LIGHT),
            ("LINEBELOW",     (0, 0), (-1, 0), 0.5, BORDER),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER),
            ("GRID",          (0, 0), (-1, -1), 0.25, BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]
        for i in range(1, len(tbl_data)):
            if i % 2 == 0:
                style_cmds.append(("BACKGROUND", (0, i), (-1, i), BG_LIGHT))

        cve_tbl = Table(tbl_data, colWidths=cw, repeatRows=1)
        cve_tbl.setStyle(TableStyle(style_cmds))
        story.append(cve_tbl)

        if cve_count > max_rows:
            story.append(_spacer(0.1))
            story.append(Paragraph(
                f"Showing top {max_rows} vulnerabilities by risk score. "
                "Full data available in the MSME Shield dashboard.",
                styles["caption"],
            ))

    story.append(_spacer(0.2))

    if any_eol:
        eol_bg = colors.HexColor("#FFFBEB")
        _info_box(
            story, styles,
            "⚠  End-of-Life Software Detected\n\n"
            "One or more installed software items has passed its official end-of-life date "
            "and no longer receives security patches. All vulnerabilities in EOL software "
            "are permanently unpatched.  A flat penalty of +20.0 points was applied to the "
            "Technical Score.  (Source: endoflife.date)",
            bg=eol_bg,
            border_color=WARNING,
        )

    story.append(_spacer(0.3))


# ===========================================================================
# SECTION 5 — GOVERNANCE COMPLIANCE
# ===========================================================================

def _section_governance(story: list, data: dict, styles: dict) -> None:
    _section_rule(story, styles, "Governance Compliance Assessment")

    # Determine maturity from scan_data
    gov_answers = data.get("governance_answers") or {}
    it_maturity = (data.get("it_maturity") or "basic").lower().strip()
    # Fallback: infer from remediation list tier max if not in data
    rem_list = data.get("remediation_priorities") or []
    gov_score = float(data.get("governance_score") or 0.0)

    story.append(Paragraph(
        f"Framework: CERT-In Directions April 2022 + NIST CSF 2.0  |  "
        f"Maturity: {it_maturity.title()}",
        styles["caption"],
    ))
    story.append(_spacer(0.15))

    if not gov_answers:
        _info_box(
            story, styles,
            "Governance assessment not yet submitted for this scan.",
            bg=colors.HexColor("#E8F0FE"),
            border_color=ACCENT,
        )
        story.append(_spacer(0.3))
        return

    applicable = _applicable_keys(it_maturity)
    compliant_ct = sum(1 for k in applicable if bool(gov_answers.get(k, False)))
    total_ct     = len(applicable)

    story.append(Paragraph(
        f"{compliant_ct} of {total_ct} controls compliant  ·  "
        f"Governance Score: {gov_score:.1f} / 100",
        styles["bold_body"],
    ))
    story.append(_spacer(0.2))

    # Compliance table
    cw = [_BODY_W * 0.40, _BODY_W * 0.12, _BODY_W * 0.35, _BODY_W * 0.13]
    header_row = [
        Paragraph("CONTROL",   styles["tbl_header"]),
        Paragraph("STATUS",    styles["tbl_header"]),
        Paragraph("FRAMEWORK REFERENCE", styles["tbl_header"]),
        Paragraph("TIER",      styles["tbl_header"]),
    ]
    tbl_data = [header_row]

    for key in applicable:
        meta    = _CONTROL_META.get(key, {})
        label   = meta.get("label", key)
        cit     = meta.get("citation", "")
        stat    = bool(meta.get("statutory", False))
        tier    = meta.get("tier", 1)
        comp    = bool(gov_answers.get(key, False))

        control_cell_parts = [Paragraph(label, styles["tbl_cell"])]
        if stat:
            control_cell_parts.append(
                Paragraph("(Statutory)", styles["statutory_note"])
            )
        # Wrap in a Table so we can stack label + statutory note
        ctrl_inner = Table(
            [[p] for p in control_cell_parts],
            colWidths=[cw[0] - 12],
        )
        ctrl_inner.setStyle(TableStyle([
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ]))

        status_p = Paragraph(
            "✓ YES" if comp else "✗ NO",
            styles["status_yes"] if comp else styles["status_no"],
        )
        tbl_data.append([
            ctrl_inner,
            status_p,
            Paragraph(cit, styles["tbl_cell"]),
            Paragraph(f"Tier {tier}", styles["tbl_cell"]),
        ])

    style_cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0), BG_LIGHT),
        ("LINEBELOW",     (0, 0), (-1, 0), 0.5, BORDER),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER),
        ("GRID",          (0, 0), (-1, -1), 0.25, BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (1, 0), (1, -1), "CENTER"),
        ("ALIGN",         (3, 0), (3, -1), "CENTER"),
    ]
    for i in range(1, len(tbl_data)):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), BG_LIGHT))

    gov_tbl = Table(tbl_data, colWidths=cw, repeatRows=1)
    gov_tbl.setStyle(TableStyle(style_cmds))
    story.append(gov_tbl)
    story.append(_spacer(0.4))

    # --- Remediation Priorities ---
    story.append(Paragraph(
        "Action Items — Prioritised by Risk Impact",
        styles["subsection_heading"],
    ))
    story.append(Paragraph(
        "Statutory obligations listed first, then by governance weight descending.",
        styles["caption"],
    ))
    story.append(_spacer(0.15))

    if not rem_list:
        _info_box(
            story, styles,
            "✓  All assessed governance controls are compliant. "
            "Maintain current security posture and reassess quarterly.",
            bg=colors.HexColor("#F0FFF4"),
            border_color=SUCCESS,
        )
    else:
        for item in rem_list:
            label_r  = item.get("label", "")
            cit_r    = item.get("citation", "")
            stat_r   = bool(item.get("statutory", False))
            wt_r     = float(item.get("weight") or 0.0)
            rem_r    = item.get("remediation", "")
            tier_r   = item.get("tier", 1)
            lborder  = ACCENT if stat_r else BORDER

            stat_note = "  [Statutory]" if stat_r else ""
            header_p = Paragraph(
                f"{label_r}{stat_note}",
                styles["remediation_label"],
            )
            cit_p = Paragraph(
                f"{cit_r}  |  Tier {tier_r}  |  Weight: {wt_r:.1f}%",
                styles["statutory_note"],
            )
            body_p = Paragraph(rem_r, styles["remediation_body"])

            content = Table(
                [[header_p], [cit_p], [body_p]],
                colWidths=[_BODY_W - 24],
            )
            content.setStyle(TableStyle([
                ("TOPPADDING",    (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ]))

            # Card with left-border trick: two-column table
            spacer_col = Table([[""]], colWidths=[4])
            spacer_col.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), lborder),
                ("TOPPADDING",    (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ]))
            card_inner = Table(
                [[spacer_col, content]],
                colWidths=[4, _BODY_W - 4],
            )
            card_inner.setStyle(TableStyle([
                ("TOPPADDING",    (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))

            card = Table([[card_inner]], colWidths=[_BODY_W])
            card.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), BG_LIGHT),
                ("BOX",           (0, 0), (-1, -1), 0.5, BORDER),
                ("ROUNDEDCORNERS",[4]),
                ("TOPPADDING",    (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
            ]))
            story.append(card)
            story.append(_spacer(0.15))

    story.append(_spacer(0.3))


# ===========================================================================
# SECTION 6 — OPEN PORTS / EXPOSURE
# ===========================================================================

def _section_exposure(story: list, data: dict, styles: dict) -> None:
    _section_rule(story, styles, "Network Exposure Analysis")

    open_ports      = data.get("open_ports") or []
    allowlisted     = data.get("allowlisted_ports") or []
    allowlist_set   = {int(a.get("port", 0)) for a in allowlisted if isinstance(a, dict)}

    open_only = [p for p in open_ports if str(p.get("state", "")).lower() == "open"]
    total_ct  = len(open_only)

    if not open_only:
        _info_box(
            story, styles,
            "No open ports detected during the agent scan.",
            bg=colors.HexColor("#F0FFF4"),
            border_color=SUCCESS,
        )
        story.append(_spacer(0.3))
        return

    flagged     = [p for p in open_only if int(p.get("port", 0)) not in allowlist_set]
    allowed_pts = [p for p in open_only if int(p.get("port", 0)) in allowlist_set]

    story.append(Paragraph(
        f"{total_ct} port{'s' if total_ct != 1 else ''} detected  ·  "
        f"{len(flagged)} scored  ·  "
        f"{len(allowed_pts)} allowlisted (intentionally open)",
        styles["bold_body"],
    ))
    story.append(_spacer(0.2))

    # PORT_RISK_WEIGHTS (mirrors dashboard.py)
    _PORT_W: dict[int, float] = {
        3389: 85.0, 23: 90.0, 21: 70.0, 22: 40.0, 445: 80.0,
        1433: 75.0, 3306: 75.0, 5432: 70.0, 8080: 30.0, 8443: 15.0,
        80: 10.0, 443: 5.0, 25: 60.0, 110: 55.0, 143: 55.0,
        53: 35.0, 161: 65.0, 5900: 80.0, 6379: 75.0, 27017: 75.0,
    }

    def _port_weight(p: dict) -> float:
        w = float(p.get("risk_weight") or 0.0)
        return w if w > 0.0 else _PORT_W.get(int(p.get("port", 0)), 5.0)

    def _risk_level(w: float) -> tuple[str, Any]:
        if w >= 70:
            return "Critical", CRITICAL
        if w >= 40:
            return "Medium",   WARNING
        return "Low",      SUCCESS

    half = _BODY_W / 2.0

    # Flagged ports table
    flagged_data = [[
        Paragraph("PORT",    styles["tbl_header"]),
        Paragraph("SERVICE", styles["tbl_header"]),
        Paragraph("RISK",    styles["tbl_header"]),
    ]]
    for p in flagged:
        w = _port_weight(p)
        rlabel, rcol = _risk_level(w)
        flagged_data.append([
            Paragraph(str(p.get("port", "")), ParagraphStyle(
                "PortNum", fontName="Helvetica-Bold",
                fontSize=9, textColor=DARK,
            )),
            Paragraph(str(p.get("service", "unknown")), styles["tbl_cell"]),
            Paragraph(rlabel, ParagraphStyle(
                "RiskLvl", fontName="Helvetica-Bold",
                fontSize=9, textColor=rcol,
            )),
        ])

    if len(flagged_data) == 1:
        flagged_data.append([
            Paragraph("—", styles["tbl_cell"]),
            Paragraph("No flagged ports", styles["tbl_cell"]),
            Paragraph("—", styles["tbl_cell"]),
        ])

    flagged_cw = [half * 0.22, half * 0.42, half * 0.36]
    flagged_style = [
        ("BACKGROUND",    (0, 0), (-1, 0), BG_LIGHT),
        ("LINEBELOW",     (0, 0), (-1, 0), 0.5, BORDER),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER),
        ("GRID",          (0, 0), (-1, -1), 0.25, BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i in range(1, len(flagged_data)):
        if i % 2 == 0:
            flagged_style.append(("BACKGROUND", (0, i), (-1, i), BG_LIGHT))
    f_tbl = Table(flagged_data, colWidths=flagged_cw, repeatRows=1)
    f_tbl.setStyle(TableStyle(flagged_style))

    # Allowlisted ports table (right side)
    allow_title = Paragraph(
        "✓  Intentionally open — excluded from scoring",
        ParagraphStyle("AllowTitle", fontName="Helvetica-Oblique",
                       fontSize=8, textColor=SUCCESS),
    )
    allow_data = [[
        Paragraph("PORT",        styles["tbl_header"]),
        Paragraph("DESCRIPTION", styles["tbl_header"]),
    ]]
    if allowed_pts:
        for p in allowed_pts:
            pnum = int(p.get("port", 0))
            desc = next(
                (a.get("description", "—")
                 for a in allowlisted
                 if isinstance(a, dict) and int(a.get("port", -1)) == pnum),
                "—",
            )
            allow_data.append([
                Paragraph(str(pnum), styles["tbl_cell"]),
                Paragraph(desc, styles["tbl_cell"]),
            ])
    else:
        allow_data.append([Paragraph("—", styles["tbl_cell"]),
                           Paragraph("None", styles["tbl_cell"])])

    allow_cw = [half * 0.25, half * 0.75]
    allow_style = [
        ("BACKGROUND",    (0, 0), (-1, 0), BG_LIGHT),
        ("LINEBELOW",     (0, 0), (-1, 0), 0.5, BORDER),
        ("BOX",           (0, 0), (-1, -1), 0.5, BORDER),
        ("GRID",          (0, 0), (-1, -1), 0.25, BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]
    a_tbl = Table(allow_data, colWidths=allow_cw, repeatRows=1)
    a_tbl.setStyle(TableStyle(allow_style))

    # Left = flagged header + table; right = allowlisted title + table
    left_col = Table(
        [[Paragraph("Flagged Ports", styles["subsection_heading"])], [f_tbl]],
        colWidths=[half - 8],
    )
    left_col.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))
    right_col = Table(
        [[Paragraph("Allowlisted Ports", styles["subsection_heading"])],
         [allow_title], [a_tbl]],
        colWidths=[half - 8],
    )
    right_col.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))

    two_col = Table([[left_col, right_col]], colWidths=[half, half])
    two_col.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(two_col)
    story.append(_spacer(0.2))
    story.append(Paragraph(
        "Port risk weights sourced from CISA/FBI StopRansomware Advisory 2022 and "
        "NSA/CISA Network Infrastructure Security Guide 2022.",
        styles["small_italic"],
    ))
    story.append(_spacer(0.3))


# ===========================================================================
# PUBLIC API
# ===========================================================================

def generate_report(scan_data: dict, filename: str) -> "str | None":
    """
    Generate a complete MSME Shield A4 PDF report.

    Args:
        scan_data: FullScanResponse serialised to a dict. Keys include:
            scan_id, organization_name, timestamp, status,
            tech_score, governance_score, exposure_score,
            mrqm_score, risk_band, ssl_days, password_score,
            any_eol, software_inventory, cve_findings,
            governance_answers, remediation_priorities,
            open_ports, allowlisted_ports
        filename: Full path to write the PDF.

    Returns:
        filename on success, None on any failure.
    """
    try:
        styles = _make_styles()
        story: list[Any] = []

        _section_header(story, scan_data, styles)
        _section_score_card(story, scan_data, styles)
        _section_active_probing(story, scan_data, styles)
        _section_vulnerabilities(story, scan_data, styles)
        _section_governance(story, scan_data, styles)
        _section_exposure(story, scan_data, styles)

        doc = SimpleDocTemplate(
            filename,
            pagesize=A4,
            rightMargin=_MARGIN,
            leftMargin=_MARGIN,
            topMargin=_MARGIN,
            bottomMargin=_MARGIN + 1.4 * cm,  # extra room for footer
            title="MSME Shield — Cyber Risk Quantification Report",
            author="MSME Shield v2.0",
            subject="CERT-In + NIST CSF 2.0 Compliance Assessment",
        )

        doc.build(
            story,
            onFirstPage=_draw_footer,
            onLaterPages=_draw_footer,
        )
        return filename

    except Exception:
        logger.exception("pdf_generator.generate_report() failed for %s", filename)
        return None
