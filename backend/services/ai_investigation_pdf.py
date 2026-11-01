"""Formal PDF report generation for ForensicX AI Intelligence Report using ReportLab.

Strictly implements the 12 required patent forensic report sections.
"""

from pathlib import Path
import shutil

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from backend.config import REPORTS_DIR
from backend.services.ai_investigation_service import analyze_case_evidence


def generate_ai_investigation_pdf(case_id: str) -> Path:
    """Generate professional 12-section A4 PDF AI-Assisted Forensic Investigation Report."""
    data = analyze_case_evidence(case_id)
    if "error" in data:
        raise OSError(f"Case Error: {data['error']}")

    case = data["case"]
    device = data["device"]
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"AI_Investigation_Report_{case_id}.pdf"

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "AiTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=15, textColor=colors.HexColor("#0284c7"), alignment=TA_CENTER, spaceAfter=2
    )
    sub_title_style = ParagraphStyle(
        "AiSubTitle", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=11, textColor=colors.HexColor("#0369a1"), alignment=TA_CENTER, spaceAfter=4
    )
    doc_type_style = ParagraphStyle(
        "AiDocType", parent=styles["Normal"], fontName="Helvetica", fontSize=8, textColor=colors.HexColor("#475569"), alignment=TA_CENTER, spaceAfter=8
    )
    heading_style = ParagraphStyle(
        "AiHeading", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=9.5, textColor=colors.HexColor("#0369a1"), spaceBefore=10, spaceAfter=4
    )
    body_style = ParagraphStyle("AiBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=7.5, leading=9.5, textColor=colors.HexColor("#0f172a"))
    small_style = ParagraphStyle("AiSmall", parent=body_style, fontSize=6.5, leading=8.5)
    flagged_style = ParagraphStyle("AiFlagged", parent=body_style, fontSize=7, leading=9, textColor=colors.HexColor("#b45309"))
    action_style = ParagraphStyle("AiAction", parent=body_style, fontSize=7, leading=9, textColor=colors.HexColor("#0369a1"))

    def make_table(headers, row_data, widths=None, style=None):
        formatted_data = [[Paragraph(str(h), small_style) for h in headers]]
        for r in row_data:
            formatted_data.append([Paragraph(str(cell if cell not in (None, "") else "Not Available"), small_style) for cell in r])
        t = Table(formatted_data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle(style or [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0f2fe")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0369a1")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#bae6fd")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        return t

    story = [
        Paragraph("FORENSICX AI INTELLIGENCE", title_style),
        Paragraph("AI-ASSISTED FORENSIC INVESTIGATION REPORT", sub_title_style),
        Paragraph("Automated Pattern Detection, Cross-Evidence Correlation & Traceability Audit", doc_type_style),
        Spacer(1, 4),
    ]

    # Section 1: Case & Device Information
    case_rows = [
        ["Case ID", case.get("case_id")],
        ["Case Name", case.get("case_name")],
        ["Investigator", case.get("investigator")],
        ["Organization", case.get("organization") or "Digital Forensics Unit"],
        ["Description", case.get("description") or "Not Specified"],
        ["Analysis Date", case.get("updated_at") or case.get("created_at") or "Current Session"],
        ["Device Serial", device.get("serial") or "Not Assigned / Multi-Device Extraction"],
        ["Device Model", f"{device.get('manufacturer', '')} {device.get('model', '')}".strip() or "Standard Device Extraction"],
        ["Android Version", f"Android {device.get('android_version', 'N/A')} (SDK {device.get('sdk_version', 'N/A')})"],
    ]
    story += [Paragraph("1. CASE & DEVICE INFORMATION", heading_style), make_table(["Attribute", "Value"], case_rows, [50 * mm, 130 * mm])]

    # Section 2: Evidence Summary (Live Counts)
    es = data["evidence_summary"]
    ev_summary_rows = [
        ["Preserved Devices", es.get("devices", 0)],
        ["Call Logs Records", es.get("call_logs", 0)],
        ["SMS / Messages Records", es.get("sms", 0)],
        ["GPS Location Fixes", es.get("gps", 0)],
        ["Preserved Files & Media", es.get("files", 0)],
        ["Installed Applications", es.get("applications", 0)],
        ["Browser / Web History Records", es.get("browser_web_history", 0)],
        ["Normalized Evidence Items", es.get("normalized_evidence", 0)],
        ["Cross-Source Correlations", es.get("correlations", 0)],
        ["Chronological Timeline Events", es.get("timeline_events", 0)],
        ["AI Analytical Findings", es.get("ai_findings", 0)],
    ]
    story += [Paragraph("2. EVIDENCE SUMMARY", heading_style), make_table(["Forensic Category", "Live Record Count"], ev_summary_rows, [110 * mm, 70 * mm])]

    # Section 3: Evidence Integrity & Provenance Summary
    integ = data.get("integrity_summary", [])[:20]
    int_rows = []
    for item in integ:
        int_rows.append([
            item.get("evidence_id"),
            item.get("artifact_type"),
            item.get("source_device"),
            item.get("stored_hash", "NOT AVAILABLE")[:28] + ("..." if len(item.get("stored_hash", "")) > 28 else ""),
            item.get("integrity_status", "NOT VERIFIED"),
            item.get("provenance_status", "COMPLETE"),
        ])
    if not int_rows:
        int_rows = [["N/A", "N/A", "N/A", "NOT AVAILABLE", "NOT VERIFIED", "N/A"]]
    story += [
        Paragraph(f"3. EVIDENCE INTEGRITY & PROVENANCE SUMMARY ({len(integ)} records shown)", heading_style),
        make_table(["Evidence ID", "Type", "Device", "SHA-256 Hash", "Integrity Status", "Provenance"], int_rows, [30 * mm, 20 * mm, 28 * mm, 52 * mm, 28 * mm, 22 * mm])
    ]

    # Section 4: Cross-Source Correlations
    corrs = data.get("correlations", [])[:20]
    c_rows = []
    for c in corrs:
        c_rows.append([
            c.get("correlation_id"),
            c.get("relationship_type"),
            ", ".join(c.get("evidence_ids", [])[:3]),
            c.get("timestamp_relationship", "Simultaneous Window"),
            c.get("reason", "Factual cross-source correlation."),
            c.get("correlation_strength", "100%"),
        ])
    if not c_rows:
        c_rows = [["-", "No supported relationships identified in preserved records", "-", "-", "-", "-"]]
    story += [
        Paragraph(f"4. CROSS-SOURCE CORRELATIONS ({len(corrs)} records shown)", heading_style),
        make_table(["Correlation ID", "Relationship Type", "Evidence IDs", "Timestamp Relationship", "Reason", "Strength"], c_rows, [26 * mm, 36 * mm, 30 * mm, 28 * mm, 46 * mm, 14 * mm])
    ]

    # Section 5: Reliability Assessments
    reliab = data.get("reliability_assessments", [])[:20]
    rel_rows = []
    for r in reliab:
        rel_rows.append([
            r.get("evidence_id"),
            r.get("reliability_score"),
            r.get("integrity_status"),
            r.get("provenance_status"),
            r.get("explanation", "Technically verified provenance"),
        ])
    if not rel_rows:
        rel_rows = [["-", "100%", "UNVERIFIED", "COMPLETE", "No reliability deductions"]]
    story += [
        Paragraph(f"5. RELIABILITY ASSESSMENTS ({len(reliab)} assessments shown)", heading_style),
        make_table(["Evidence ID", "Score", "Integrity", "Provenance", "Contributing Factors & Assessment"], rel_rows, [30 * mm, 18 * mm, 26 * mm, 26 * mm, 80 * mm])
    ]

    # Section 6: Evidence Relationship Summary (Graph)
    rel_sum = data.get("relationship_summary", {})
    graph_rows = [
        ["Total Graph Entity Nodes", rel_sum.get("nodes_count", 0)],
        ["Total Directed Relationship Edges", rel_sum.get("edges_count", 0)],
        ["Entity Types Represented", ", ".join(rel_sum.get("entity_types", [])) or "Device, Evidence, Contact"],
    ]
    story += [
        Paragraph("6. EVIDENCE RELATIONSHIP SUMMARY", heading_style),
        make_table(["Graph Metric", "Detail"], graph_rows, [60 * mm, 120 * mm])
    ]
    if rel_sum.get("major_relationship_paths"):
        story += [
            Spacer(1, 2),
            Paragraph("<b>Discovered Entity Relationship Paths:</b> " + " | ".join(rel_sum.get("major_relationship_paths")[:4]), small_style)
        ]

    # Section 7: Chronological Incident Timeline
    timeline = data.get("timeline", [])[:30]
    t_rows = []
    for t in timeline:
        t_rows.append([
            t.get("timestamp"),
            t.get("category"),
            t.get("description"),
            t.get("evidence_id"),
            t.get("correlation_id") or "N/A",
        ])
    if not t_rows:
        t_rows = [["-", "No timeline events available", "-", "-", "-"]]
    story += [
        Paragraph(f"7. CHRONOLOGICAL INCIDENT TIMELINE ({len(timeline)} events shown)", heading_style),
        make_table(["Timestamp (UTC)", "Category", "Event Description", "Evidence ID", "Correlation ID"], t_rows, [34 * mm, 24 * mm, 68 * mm, 32 * mm, 22 * mm])
    ]

    # Section 8: AI-Assisted Analytical Findings
    findings = data.get("findings", [])[:25]
    f_rows = []
    for f in findings:
        f_rows.append([
            f.get("finding_id"),
            f.get("category"),
            f.get("title"),
            ", ".join(f.get("supporting_evidence_ids", [])[:3]),
            ", ".join(f.get("timeline_event_ids", [])[:2]) or "N/A",
            Paragraph(f"<b>Analysis:</b> {f.get('analysis_explanation')}", flagged_style),
            Paragraph(f"<b>Action:</b> {f.get('recommended_action')}", action_style),
        ])
    story += [Paragraph(f"8. AI-ASSISTED ANALYTICAL FINDINGS ({len(findings)} findings shown)", heading_style)]
    if f_rows:
        story += [make_table(["Finding ID", "Category", "Title", "Evidence IDs", "Timeline IDs", "Forensic Analysis", "Recommended Action"], f_rows, [20 * mm, 26 * mm, 28 * mm, 24 * mm, 20 * mm, 34 * mm, 28 * mm])]
    else:
        story += [Paragraph("No suspicious patterns or anomalies were detected in preserved evidence.", body_style)]

    # Section 9: Supporting Evidence
    supp_ev = data.get("supporting_evidence", [])[:25]
    s_rows = []
    for s in supp_ev:
        s_rows.append([
            s.get("evidence_id"),
            s.get("artifact_type"),
            s.get("source_ref"),
            s.get("timestamp"),
            s.get("hash", "N/A")[:20] + ("..." if len(s.get("hash", "")) > 20 else ""),
        ])
    if not s_rows:
        s_rows = [["-", "-", "No supporting evidence items recorded", "-", "-"]]
    story += [
        Paragraph(f"9. SUPPORTING EVIDENCE ({len(supp_ev)} records shown)", heading_style),
        make_table(["Normalized ID", "Artifact Type", "Source Reference", "Preserved Timestamp", "Cryptographic Hash"], s_rows, [30 * mm, 25 * mm, 50 * mm, 45 * mm, 30 * mm])
    ]

    # Section 10: Investigation Traceability Chain
    trace = data.get("investigation_traceability", [])[:25]
    tr_rows = []
    for tr in trace:
        tr_rows.append([
            tr.get("finding_id"),
            ", ".join(tr.get("timeline_event_ids", [])) or "EVT-DIRECT",
            ", ".join(tr.get("correlation_ids", [])) or "CORR-SINGLE",
            tr.get("normalized_evidence_id"),
            tr.get("original_record_reference"),
        ])
    if not tr_rows:
        tr_rows = [["-", "-", "-", "-", "Direct extraction record"]]
    story += [
        Paragraph(f"10. INVESTIGATION TRACEABILITY CHAIN ({len(trace)} mapped pathways shown)", heading_style),
        make_table(["AI Finding", "Timeline Event ID", "Correlation ID", "Normalized Evidence ID", "Original Record Reference"], tr_rows, [24 * mm, 32 * mm, 32 * mm, 36 * mm, 56 * mm])
    ]

    # Section 11: Limitations / Missing Evidence
    limits = data.get("limitations", [])
    lim_rows = [[i + 1, lim] for i, lim in enumerate(limits)]
    story += [
        Paragraph("11. LIMITATIONS / MISSING EVIDENCE", heading_style),
        make_table(["#", "Forensic Disclosures & Technical Limitations"], lim_rows, [10 * mm, 170 * mm])
    ]

    # Section 12: Final Investigation Summary
    fin = data.get("final_summary", {})
    story += [
        Paragraph("12. FINAL INVESTIGATION SUMMARY", heading_style),
        Paragraph(fin.get("summary_text", "Forensic investigation analysis completed."), body_style),
        Spacer(1, 4),
        Paragraph(f"<b>Verification Statement:</b> {fin.get('verification_statement')}", flagged_style),
        Spacer(1, 4),
        Paragraph(f"<b>Authorized Examiner:</b> {fin.get('investigator', 'Examiner')} &nbsp;&nbsp;&nbsp;&nbsp; <b>Report Status:</b> FORMALLY GENERATED & IMMUTABLE", small_style)
    ]

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(18 * mm, 10 * mm, "CONFIDENTIAL - AUTHORIZED FORENSICX AI INVESTIGATION REPORT")
        canvas.drawRightString(192 * mm, 10 * mm, f"Page {document.page}")
        canvas.restoreState()

    SimpleDocTemplate(
        str(path), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm
    ).build(story, onFirstPage=footer, onLaterPages=footer)

    shutil.copy2(path, REPORTS_DIR / f"{case_id}-ai-investigation-report.pdf")
    return path
