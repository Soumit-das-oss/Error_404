"""
VAJRA Forensic Platform - Certified PDF Report Generator (ReportLab Platypus)
Produces an executive-grade digital forensic dossier with cryptographic integrity proof.
Zero disk writes (100% in-memory buffer).
"""

import io
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Table,
    TableStyle,
    Spacer,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import A4


def _pdf_sanitize(val: Any) -> str:
    """Safely escape literal &, <, > characters for ReportLab Paragraph rendering."""
    if val is None:
        return ""
    s = str(val).strip()
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def generate_case_pdf(case_data: Dict[str, Any]) -> bytes:
    """Generate a structured, executive-grade forensic PDF dossier using ReportLab Platypus.

    Complies with:
      - Standard A4 geometry with 0.5-inch margins (36pt)
      - Zero disk writes (pure in-memory BytesIO buffer)
      - Navy (#0F172A), Charcoal (#1E293B), and threat tier color palette
      - Auto-wrapping Paragraph cells in tables for SHA-256 and long headers
      - Multi-column MTA hop and deduction tables
      - Running footer: 'Certified Digital Forensic Dossier | VAJRA Forensic Platform (Air-Gapped Ingestion)'
    """
    if hasattr(case_data, "model_dump"):
        case_intel = case_data.model_dump(mode="json")
    else:
        case_intel = dict(case_data or {})

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    # Design System & Palette
    NAVY = colors.HexColor("#0F172A")
    CHARCOAL = colors.HexColor("#1E293B")
    SLATE_BORDER = colors.HexColor("#CBD5E1")
    SLATE_HEADER = colors.HexColor("#E2E8F0")
    ROW_ALT = colors.HexColor("#F8FAFC")
    WHITE = colors.HexColor("#FFFFFF")

    CRIMSON = colors.HexColor("#DC2626")
    AMBER = colors.HexColor("#D97706")
    EMERALD = colors.HexColor("#16A34A")

    CRIMSON_BG = colors.HexColor("#FEF2F2")
    AMBER_BG = colors.HexColor("#FFFBEB")
    EMERALD_BG = colors.HexColor("#F0FDF4")

    # Extract forensic fields
    case_id = str(case_intel.get("case_id", "N/A"))
    sha256 = str(case_intel.get("sha256", "N/A"))
    subject = str(case_intel.get("subject") or "No Subject Line")
    sender = str(case_intel.get("sender") or "Unknown")
    sender_display_name = str(case_intel.get("sender_display_name") or "None")
    message_id = str(case_intel.get("message_id") or "N/A")
    earliest_public_ip = str(case_intel.get("earliest_public_ip") or "None detected")
    llm_summary = str(case_intel.get("llm_summary") or case_intel.get("ai_summary") or "Forensic examination completed.")

    risk = case_intel.get("risk", {})
    score = int(risk.get("score", case_intel.get("score", 0)))
    verdict = str(risk.get("verdict", case_intel.get("verdict", "SAFE"))).upper()
    penalties = risk.get("penalties", case_intel.get("penalties", []))

    auth = case_intel.get("auth", {})
    spf = auth.get("spf", {})
    dkim = auth.get("dkim", {})
    dmarc = auth.get("dmarc", {})

    hops: List[Dict[str, Any]] = case_intel.get("hops", [])

    # Determine threat theme
    if verdict in ("MALICIOUS", "CRITICAL") or score >= 60:
        threat_color = CRIMSON
        threat_bg = CRIMSON_BG
        verdict_label = "MALICIOUS THREAT"
    elif verdict == "SUSPICIOUS" or (20 <= score <= 59):
        threat_color = AMBER
        threat_bg = AMBER_BG
        verdict_label = "SUSPICIOUS ANOMALY"
    else:
        threat_color = EMERALD
        threat_bg = EMERALD_BG
        verdict_label = "SAFE / AUTHENTIC"

    # Styles
    styles = getSampleStyleSheet()

    doc_title_style = ParagraphStyle(
        "VajraDocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=NAVY,
    )

    meta_hdr_right = ParagraphStyle(
        "VajraMetaRight",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor("#64748B"),
        alignment=2,
    )

    section_heading_style = ParagraphStyle(
        "VajraSectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=NAVY,
        spaceBefore=5,
        spaceAfter=3,
    )

    banner_score_style = ParagraphStyle(
        "VajraBannerScore",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        alignment=1,
    )

    banner_brief_style = ParagraphStyle(
        "VajraBannerBrief",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=14,  # Exact 14pt leading
        textColor=CHARCOAL,
        alignment=0,
    )

    custody_label_style = ParagraphStyle(
        "VajraCustodyLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=10,
        textColor=NAVY,
    )

    custody_val_style = ParagraphStyle(
        "VajraCustodyVal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        textColor=CHARCOAL,
    )

    custody_mono_style = ParagraphStyle(
        "VajraCustodyMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7,
        leading=9.5,
        textColor=CHARCOAL,
    )

    th_style = ParagraphStyle(
        "VajraTH",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9.5,
        textColor=NAVY,
        alignment=1,
    )

    td_center_style = ParagraphStyle(
        "VajraTDCenter",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7,
        leading=9,
        alignment=1,
        textColor=CHARCOAL,
    )

    td_left_style = ParagraphStyle(
        "VajraTDLeft",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7,
        leading=9,
        textColor=CHARCOAL,
    )

    td_mono_style = ParagraphStyle(
        "VajraTDMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=6.5,
        leading=8.5,
        textColor=CHARCOAL,
    )

    penalty_rule_style = ParagraphStyle(
        "VajraPenaltyRule",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9.5,
        textColor=CRIMSON,
    )

    penalty_pts_style = ParagraphStyle(
        "VajraPenaltyPts",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=CRIMSON,
        alignment=1,
    )

    penalty_reason_style = ParagraphStyle(
        "VajraPenaltyReason",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7,
        leading=9,
        textColor=CHARCOAL,
    )

    story = []

    # 1. Header Line
    utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    hdr_left = Paragraph(
        f"<b>VAJRA FORENSIC DOSSIER</b><br/><font size=7 color='#64748B'>CASE ID: {_pdf_sanitize(case_id)}</font>",
        doc_title_style,
    )
    hdr_right = Paragraph(
        f"Generated: {utc_now} UTC<br/>Problem Statement: SIH2026 - SHS0106",
        meta_hdr_right,
    )
    hdr_table = Table([[hdr_left, hdr_right]], colWidths=[3.5 * inch, 3.5 * inch])
    hdr_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(hdr_table)
    story.append(Spacer(1, 4))

    # Prominent DLP Bypass Security Alert Banner if operator disabled privacy shield
    dlp_sec = case_intel.get("dlp_security", {})
    dlp_bypassed = (
        (isinstance(dlp_sec, dict) and dlp_sec.get("status") == "BYPASSED")
        or (isinstance(dlp_sec, dict) and dlp_sec.get("masking_active") is False)
        or (case_intel.get("dlp_masking") is False)
    )
    if dlp_bypassed:
        dlp_alert_hdr = ParagraphStyle(
            "VajraDlpAlertHdr",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=CRIMSON,
            alignment=1,
        )
        dlp_alert_sub = ParagraphStyle(
            "VajraDlpAlertSub",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=6.5,
            leading=8.5,
            textColor=colors.HexColor("#7F1D1D"),
            alignment=1,
        )
        dlp_p1 = Paragraph("⚠️ FORENSIC INTEGRITY NOTICE: DLP PRIVACY SHIELD WAS BYPASSED FOR THIS INVESTIGATION.", dlp_alert_hdr)
        dlp_p2 = Paragraph("Raw evidence processed without PII scrubbing. Platform disclaims legal liability for data exposure or regulatory non-compliance.", dlp_alert_sub)
        dlp_alert_table = Table([[dlp_p1], [dlp_p2]], colWidths=[7.0 * inch])
        dlp_alert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), CRIMSON_BG),
            ("BOX", (0, 0), (-1, -1), 1.2, CRIMSON),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(dlp_alert_table)
        story.append(Spacer(1, 4))

    # 2. Verdict Banner
    banner_score = Paragraph(
        f"<font color='{threat_color.hexval()}'><b>[ SCORE: {score} / 100 ] — {verdict_label}</b></font>",
        banner_score_style,
    )
    banner_brief = Paragraph(_pdf_sanitize(llm_summary), banner_brief_style)
    banner_table = Table([[banner_score], [banner_brief]], colWidths=[7.0 * inch])
    banner_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), threat_bg),
        ("BOX", (0, 0), (-1, -1), 1.2, threat_color),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, threat_color),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 6))

    # 3. Cryptographic Chain of Custody Table
    story.append(Paragraph("CRYPTOGRAPHIC CHAIN OF CUSTODY", section_heading_style))
    custody_data = [
        [Paragraph("Subject:", custody_label_style), Paragraph(_pdf_sanitize(subject), custody_val_style)],
        [Paragraph("Envelope From:", custody_label_style), Paragraph(_pdf_sanitize(sender), custody_val_style)],
        [Paragraph("Display Name:", custody_label_style), Paragraph(_pdf_sanitize(sender_display_name), custody_val_style)],
        [Paragraph("Candidate Origin IP:", custody_label_style), Paragraph(_pdf_sanitize(earliest_public_ip), custody_mono_style)],
        [Paragraph("Message-ID:", custody_label_style), Paragraph(_pdf_sanitize(message_id), custody_mono_style)],
        [Paragraph("Evidence SHA-256 Hash:", custody_label_style), Paragraph(_pdf_sanitize(sha256), custody_mono_style)],
    ]
    custody_table = Table(custody_data, colWidths=[1.8 * inch, 5.2 * inch])
    custody_table_style = [
        ("GRID", (0, 0), (-1, -1), 0.5, SLATE_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    for r in range(len(custody_data)):
        bg = ROW_ALT if r % 2 == 1 else WHITE
        custody_table_style.append(("BACKGROUND", (0, r), (-1, r), bg))
    custody_table.setStyle(TableStyle(custody_table_style))
    story.append(custody_table)
    story.append(Spacer(1, 6))

    # 4. Authentication Matrix Table
    story.append(Paragraph("CRYPTOGRAPHIC &amp; DNS AUTHENTICATION MATRIX", section_heading_style))
    def _auth_card(title: str, rfc: str, st: str, det: str) -> Paragraph:
        st_u = st.upper()
        if st_u == "PASS":
            c_hex = "#16A34A"
        elif st_u in ("FAIL", "SOFTFAIL"):
            c_hex = "#DC2626"
        elif st_u in ("NONE", "MISSING", "UNKNOWN", "UNVERIFIABLE"):
            c_hex = "#D97706"
        else:
            c_hex = "#64748B"
        return Paragraph(
            f"<b>{title}</b> <font size=6.5 color='#64748B'>({rfc})</font><br/>"
            f"<font color='{c_hex}'><b>[{st_u}]</b></font><br/>"
            f"<font size=6.5 color='#475569'>{_pdf_sanitize(det)}</font>",
            td_left_style,
        )

    spf_st = str(spf.get("status", "NONE"))
    spf_dt = str(spf.get("details") or spf.get("record") or "No SPF details recorded")
    dkim_st = str(dkim.get("status", "NONE"))
    dkim_dt = str(dkim.get("details") or "No DKIM signature verified")
    dmarc_st = str(dmarc.get("status", "NONE"))
    dmarc_pol = str(dmarc.get("policy", "none"))
    dmarc_dt = str(dmarc.get("details") or f"Policy enforcement: {dmarc_pol}")

    auth_data = [
        [
            _auth_card("SPF Verification", "RFC 7208", spf_st, spf_dt),
            _auth_card("DKIM Signature", "RFC 6376", dkim_st, dkim_dt),
            _auth_card("DMARC Enforcement", "RFC 7489", dmarc_st, dmarc_dt),
        ]
    ]
    auth_table = Table(auth_data, colWidths=[2.3 * inch, 2.3 * inch, 2.4 * inch])
    auth_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, SLATE_BORDER),
        ("BACKGROUND", (0, 0), (-1, -1), WHITE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 6))

    # 5. Reverse MTA Hop Traversal Table
    story.append(Paragraph("REVERSE MTA HOP TRAVERSAL (ORIGIN PINPOINTING)", section_heading_style))
    hop_col_widths = [0.5 * inch, 1.3 * inch, 1.8 * inch, 1.8 * inch, 0.8 * inch, 0.8 * inch]
    hop_headers = [
        Paragraph("Hop #", th_style),
        Paragraph("Relay IP", th_style),
        Paragraph("Geolocation", th_style),
        Paragraph("ASN / ISP", th_style),
        Paragraph("Tor Node", th_style),
        Paragraph("Delay", th_style),
    ]
    hop_table_data = [hop_headers]
    if hops:
        for h in hops:
            h_num = Paragraph(f"#{h.get('hop_number', '-')}", td_center_style)
            h_ip = Paragraph(_pdf_sanitize(h.get("ip", "-")), td_mono_style)
            loc = f"{h.get('city') or 'Unknown'}, {h.get('country') or 'Unknown'}"
            h_loc = Paragraph(_pdf_sanitize(loc), td_left_style)
            asn_val = h.get("asn_org") or (f"AS{h.get('asn')}" if h.get("asn") else "-")
            h_asn = Paragraph(_pdf_sanitize(asn_val), td_left_style)
            if h.get("is_tor_exit"):
                h_tor = Paragraph("<font color='#DC2626'><b>TOR EXIT</b></font>", td_center_style)
            else:
                h_tor = Paragraph("<font color='#16A34A'>CLEAN</font>", td_center_style)
            d_val = f"{h.get('delay_seconds'):.1f}s" if h.get("delay_seconds") is not None else "-"
            h_del = Paragraph(d_val, td_center_style)
            hop_table_data.append([h_num, h_ip, h_loc, h_asn, h_tor, h_del])
    else:
        empty_hop = Paragraph("No public MTA relays identified in header traversal.", td_center_style)
        hop_table_data.append([empty_hop, "", "", "", "", ""])

    hop_table = Table(hop_table_data, colWidths=hop_col_widths)
    hop_style = [
        ("BACKGROUND", (0, 0), (-1, 0), SLATE_HEADER),
        ("GRID", (0, 0), (-1, -1), 0.5, SLATE_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]
    if not hops:
        hop_style.append(("SPAN", (0, 1), (5, 1)))
        hop_style.append(("BACKGROUND", (0, 1), (-1, 1), WHITE))
    else:
        for r in range(1, len(hop_table_data)):
            bg = ROW_ALT if r % 2 == 1 else WHITE
            hop_style.append(("BACKGROUND", (0, r), (-1, r), bg))
    hop_table.setStyle(TableStyle(hop_style))
    story.append(hop_table)
    story.append(Spacer(1, 6))

    # 6. Itemized Risk Deductions Table
    story.append(Paragraph("ITEMIZED THREAT DEDUCTIONS &amp; HEURISTICS", section_heading_style))
    deduction_col_widths = [1.8 * inch, 0.8 * inch, 4.4 * inch]
    deduction_headers = [
        Paragraph("Rule Code", th_style),
        Paragraph("Penalty", th_style),
        Paragraph("Forensic Justification", th_style),
    ]
    deduction_table_data = [deduction_headers]
    if penalties:
        for p in penalties:
            r_rule = Paragraph(_pdf_sanitize(p.get("rule", "-")), penalty_rule_style)
            r_pts = Paragraph(f"+{p.get('penalty', 0)}", penalty_pts_style)
            r_reason = Paragraph(_pdf_sanitize(p.get("reason", "-")), penalty_reason_style)
            deduction_table_data.append([r_rule, r_pts, r_reason])
    else:
        empty_p = Paragraph("<font color='#16A34A'><b>Clean Audit: Zero threat penalties triggered.</b></font>", td_center_style)
        deduction_table_data.append([empty_p, "", ""])

    deduction_table = Table(deduction_table_data, colWidths=deduction_col_widths)
    ded_style = [
        ("BACKGROUND", (0, 0), (-1, 0), SLATE_HEADER),
        ("GRID", (0, 0), (-1, -1), 0.5, SLATE_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if not penalties:
        ded_style.append(("SPAN", (0, 1), (2, 1)))
        ded_style.append(("BACKGROUND", (0, 1), (-1, 1), WHITE))
    else:
        for r in range(1, len(deduction_table_data)):
            bg = ROW_ALT if r % 2 == 1 else WHITE
            ded_style.append(("BACKGROUND", (0, r), (-1, r), bg))
    deduction_table.setStyle(TableStyle(ded_style))
    story.append(deduction_table)

    # 7. In-Memory Attachments Forensic Metadata Audit
    attachments = case_intel.get("attachments", [])
    if attachments:
        story.append(Spacer(1, 6))
        story.append(Paragraph("ATTACHMENT FORENSIC HASH &amp; METADATA AUDIT", section_heading_style))
        att_col_widths = [1.8 * inch, 1.2 * inch, 0.8 * inch, 3.2 * inch]
        att_headers = [
            Paragraph("Filename", th_style),
            Paragraph("Content-Type", th_style),
            Paragraph("Size", th_style),
            Paragraph("Cryptographic Hash (SHA-256)", th_style),
        ]
        att_table_data = [att_headers]
        for a in attachments:
            fname = Paragraph(_pdf_sanitize(a.get("filename", "unnamed")), td_left_style)
            ctype = Paragraph(_pdf_sanitize(a.get("content_type", "application/octet-stream")), td_left_style)
            size_b = a.get("size_bytes", 0)
            size_str = f"{size_b / 1024:.1f} KB" if size_b >= 1024 else f"{size_b} B"
            sz = Paragraph(size_str, td_center_style)
            sha = Paragraph(_pdf_sanitize(a.get("sha256", "-")), td_mono_style)
            att_table_data.append([fname, ctype, sz, sha])

        att_table = Table(att_table_data, colWidths=att_col_widths)
        att_style = [
            ("BACKGROUND", (0, 0), (-1, 0), SLATE_HEADER),
            ("GRID", (0, 0), (-1, -1), 0.5, SLATE_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]
        for r in range(1, len(att_table_data)):
            bg = ROW_ALT if r % 2 == 1 else WHITE
            att_style.append(("BACKGROUND", (0, r), (-1, r), bg))
        att_table.setStyle(TableStyle(att_style))
        story.append(att_table)

    # 8. Running Footer Callback
    def _add_running_footer(canvas, doc_obj):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(36, 18, "Certified Digital Forensic Dossier | VAJRA Forensic Platform (Air-Gapped Ingestion)")
        canvas.drawRightString(A4[0] - 36, 18, f"Page {doc_obj.page}")
        canvas.setStrokeColor(SLATE_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(36, 26, A4[0] - 36, 26)
        canvas.restoreState()

    # Build document into in-memory buffer
    doc.build(story, onFirstPage=_add_running_footer, onLaterPages=_add_running_footer)
    return buffer.getvalue()


# Alias for backward and forward compatibility
generate_pdf_report = generate_case_pdf
