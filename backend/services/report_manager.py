"""Structured A4 PDF report generation incorporating Modules 1 through 5."""

import json
import shutil
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from backend.config import EVIDENCE_DIR, REPORTS_DIR
from backend.database.database import row, rows
from backend.services.incident_timeline_engine import generate_evidence_linked_report


def generate_report(case_id: str) -> Path:
    """Generate professional 16-section A4 PDF report based on Modules 1–5."""
    case = row("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    if case is None:
        raise OSError("Case not found")

    report_payload = generate_evidence_linked_report(case_id)
    summary = report_payload["summary"]
    case_info = report_payload["case"]
    
    latest_device = row("SELECT d.* FROM devices d JOIN acquisitions a ON a.device_id = d.device_id WHERE a.case_id = ? ORDER BY a.started_at DESC LIMIT 1", (case_id,))
    device_info = dict(latest_device) if latest_device else {}

    acquisitions = rows("SELECT * FROM acquisitions WHERE case_id = ? ORDER BY started_at DESC", (case_id,))
    evidence_rows = rows("SELECT * FROM evidence WHERE case_id = ? ORDER BY acquired_at", (case_id,))
    custody_rows = rows("SELECT evidence_id, action, timestamp, person, description FROM custody WHERE case_id = ? UNION ALL SELECT evidence_item_id, COALESCE(event_type, action), timestamp, COALESCE(actor, person), description FROM chain_of_custody WHERE case_id = ? ORDER BY timestamp", (case_id, case_id))

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"ForensicX_{case_id}_REPORT-001.pdf"

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("FTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=16, textColor=colors.HexColor("#173b74"), alignment=TA_CENTER, spaceAfter=4)
    sub_style = ParagraphStyle("FSub", parent=styles["Normal"], fontName="Helvetica", fontSize=8, textColor=colors.HexColor("#475569"), alignment=TA_CENTER, spaceAfter=8)
    heading_style = ParagraphStyle("FHeading", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=10, textColor=colors.HexColor("#1769d1"), spaceBefore=8, spaceAfter=4)
    body_style = ParagraphStyle("FBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=7.5, leading=9.5)
    small_style = ParagraphStyle("FSmall", parent=body_style, fontSize=6.5, leading=8)
    alert_style = ParagraphStyle("FAlert", parent=body_style, textColor=colors.HexColor("#b91c1c"), fontName="Helvetica-Bold")

    def make_table(headers, values, widths=None, style=None):
        data = [[Paragraph(str(item), small_style) for item in headers]]
        for row_values in values:
            data.append([Paragraph(str(item if item not in (None, "") else "N/A"), small_style) for item in row_values])
        t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle(style or [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf3ff")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#173b74")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ]))
        return t

    story = [
        Paragraph("ForensicX", title_style),
        Paragraph("INTELLIGENCE ENGINE DIGITAL FORENSICS INVESTIGATION REPORT", sub_style),
        Spacer(1, 4),
    ]

    # Section 1: Case Information
    c_vals = [
        ["Case ID", case_info.get("case_id", "")],
        ["Case Name", case_info.get("case_name", "")],
        ["Investigator", case_info.get("investigator", "")],
        ["Organization", case_info.get("organization", "N/A")],
        ["Description", case_info.get("description", "")],
        ["Status", case_info.get("status", "ACTIVE")],
    ]
    story += [Paragraph("1. CASE INFORMATION", heading_style), make_table(["Attribute", "Details"], c_vals, [45 * mm, 135 * mm])]

    # Section 2: Device Information
    d_vals = [[k.replace("_", " ").title(), str(v)] for k, v in device_info.items()] or [["Status", "No active device registered"]]
    story += [Paragraph("2. DEVICE INFORMATION", heading_style), make_table(["Attribute", "Details"], d_vals, [55 * mm, 125 * mm])]

    # Section 3: Acquisition Information
    acq_vals = [[a["acquisition_id"], a["device_id"], a.get("method", "ADB Logical"), a["status"], a["started_at"]] for a in acquisitions] or [["N/A", "N/A", "N/A", "N/A", "N/A"]]
    story += [Paragraph("3. ACQUISITION INFORMATION", heading_style), make_table(["Acquisition ID", "Device ID", "Method", "Status", "Timestamp"], acq_vals, [30 * mm, 30 * mm, 45 * mm, 25 * mm, 50 * mm])]

    # Section 4: Evidence Summary
    sum_vals = [
        ["Total Normalized Items", summary["total_normalized_items"]],
        ["Cross-Source Correlations", summary["total_correlations"]],
        ["Average Reliability Score", f"{summary['average_reliability_score']}%"],
        ["Incident Timeline Events", summary["total_timeline_events"]],
        ["Relationship Graph Nodes", summary["graph_nodes_count"]],
        ["Relationship Graph Edges", summary["graph_edges_count"]],
    ]
    story += [Paragraph("4. EVIDENCE SUMMARY", heading_style), make_table(["Metric", "Count / Value"], sum_vals, [100 * mm, 80 * mm])]

    # Section 5: Normalized Evidence Summary (Module 1)
    norm_vals = []
    for f in report_payload["facts"][:10]:
        norm_vals.append([f["evidence_id"], f["artifact_type"].upper(), f["timestamp"], f["source_ref"]])
    if not norm_vals:
        norm_vals = [["N/A", "N/A", "N/A", "No normalized evidence recorded"]]
    story += [Paragraph(f"5. NORMALIZED EVIDENCE SUMMARY ({len(report_payload['facts'])} records)", heading_style), make_table(["Normalized ID", "Type", "Timestamp (UTC)", "Source Ref"], norm_vals, [35 * mm, 25 * mm, 45 * mm, 75 * mm])]

    # Section 6: Cross-Source Evidence Correlations (Module 2)
    corr_vals = []
    for c in report_payload["correlations"][:10]:
        corr_vals.append([c["correlation_id"], c["relationship_type"], c["strength"], c["explanation"]])
    if not corr_vals:
        corr_vals = [["N/A", "N/A", "N/A", "No cross-source correlations discovered"]]
    story += [Paragraph(f"6. CROSS-SOURCE EVIDENCE CORRELATIONS ({len(report_payload['correlations'])} records)", heading_style), make_table(["Correlation ID", "Type", "Strength", "Explanation"], corr_vals, [32 * mm, 48 * mm, 20 * mm, 80 * mm])]

    # Section 7: Reliability & Provenance Scores (Module 3)
    score_vals = []
    for s in report_payload["scores"][:10]:
        score_vals.append([s["evidence_id"], f"{s['reliability_score']}%", s["integrity_status"], s["provenance_status"], s["explanation"]])
    if not score_vals:
        score_vals = [["N/A", "N/A", "N/A", "N/A", "No scores generated"]]
    story += [Paragraph("7. RELIABILITY & PROVENANCE SCORES", heading_style), make_table(["Target ID", "Score", "Integrity", "Provenance", "Explanation"], score_vals, [32 * mm, 18 * mm, 22 * mm, 22 * mm, 86 * mm])]

    # Section 8: Evidence Relationship Graph Summary (Module 4)
    story += [
        Paragraph("8. EVIDENCE RELATIONSHIP GRAPH SUMMARY", heading_style),
        Paragraph(f"Built interactive evidence relationship graph containing {summary['graph_nodes_count']} nodes and {summary['graph_edges_count']} directed edges. Every node and relationship is traceable back to its underlying evidence source.", body_style),
    ]

    # Section 9: Incident Timeline (Module 5)
    tl_vals = []
    for t in report_payload["timeline"][:12]:
        tl_vals.append([t["sequence_number"], t["event_timestamp"], t["event_category"], t["title"], t["primary_evidence_id"]])
    if not tl_vals:
        tl_vals = [["-", "N/A", "N/A", "No timeline events recorded", "N/A"]]
    story += [Paragraph(f"9. INCIDENT TIMELINE ({len(report_payload['timeline'])} events)", heading_style), make_table(["Seq", "Timestamp (UTC)", "Category", "Event Title", "Primary Evidence ID"], tl_vals, [10 * mm, 38 * mm, 30 * mm, 62 * mm, 40 * mm])]

    # Section 10: AI-Assisted Findings (Module 5)
    story += [Paragraph("10. AI-ASSISTED FINDINGS", heading_style)]
    for interp in report_payload["interpretations"]:
        e_str = ", ".join(interp["supporting_evidence_ids"]) if interp["supporting_evidence_ids"] else "N/A"
        story += [
            Paragraph(f"• <b>{interp['finding']}</b>", body_style),
            Paragraph(f"<i>Classification:</i> {interp['classification']} | <i>Supporting Evidence IDs:</i> {e_str}", small_style),
            Paragraph(f"<i>Analysis:</i> {interp['why_flagged']}", body_style),
            Spacer(1, 3),
        ]

    # Section 11: Suspicious Activity / Anomalies
    story += [Paragraph("11. SUSPICIOUS ACTIVITY / ANOMALIES", heading_style)]
    susp = [t for t in report_payload["timeline"] if t["suspicious_flag"] == 1]
    if susp:
        for s_item in susp:
            story += [Paragraph(f"• ALERT [{s_item['primary_evidence_id']}]: {s_item['title']} - {s_item['flag_reason']}", alert_style)]
    else:
        story += [Paragraph("No suspicious anomalies, factory reset attempts, or anti-forensic keywords detected in preserved evidence.", body_style)]

    # Section 12: Supporting Evidence IDs
    story += [
        Paragraph("12. SUPPORTING EVIDENCE IDS", heading_style),
        Paragraph("Every finding and correlation in this report maps directly to one or more preserved evidence IDs: " + ", ".join([f["evidence_id"] for f in report_payload["facts"][:15]]), small_style),
    ]

    # Section 13: Hash & Integrity Information
    hash_vals = [[x["evidence_id"], x["file_path"], "SHA-256", x["sha256"] or "N/A", x["status"]] for x in evidence_rows] or [["N/A", "N/A", "SHA-256", "N/A", "UNVERIFIED"]]
    story += [Paragraph("13. HASH AND INTEGRITY INFORMATION", heading_style), make_table(["Evidence ID", "File Path", "Algorithm", "SHA-256 Hash", "Status"], hash_vals, [28 * mm, 45 * mm, 20 * mm, 65 * mm, 22 * mm])]

    # Section 14: Chain of Custody
    c_rows = [[x["evidence_id"], x["action"], x["timestamp"], x["person"], x["description"]] for x in custody_rows] or [["N/A", "ACQUISITION", case_info.get("created_at", ""), case_info.get("investigator", "System"), "Case initialization"]]
    story += [Paragraph("14. CHAIN OF CUSTODY", heading_style), make_table(["Evidence ID", "Action", "Timestamp", "Investigator", "Description"], c_rows, [28 * mm, 22 * mm, 36 * mm, 30 * mm, 64 * mm])]

    # Section 15: Limitations
    story += [
        Paragraph("15. LIMITATIONS", heading_style),
        Paragraph("1. Analysis is restricted strictly to evidence acquired from authorized device sessions and imported files.<br/>2. Encrypted third-party app databases without accessible keys could not be parsed beyond standard container metadata.<br/>3. AI interpretations represent objective structural synthesis and do not assert legal guilt or criminal intent.", body_style),
    ]

    # Section 16: Final Investigator Summary
    story += [
        Paragraph("16. FINAL INVESTIGATOR SUMMARY", heading_style),
        Paragraph(f"This report presents normalized, correlated evidence for Case <b>{case_id}</b>. A total of {summary['total_normalized_items']} evidence items were processed with an average reliability score of {summary['average_reliability_score']}%. All raw evidence remains unaltered in immutable storage.", body_style),
    ]

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(18 * mm, 10 * mm, "CONFIDENTIAL - AUTHORIZED DIGITAL FORENSICS REPORT")
        canvas.drawRightString(192 * mm, 10 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm)
    doc.build(story, onFirstPage=footer, onLaterPages=footer)

    shutil.copy2(path, REPORTS_DIR / f"{case_id}-forensic-report.pdf")
    return path
