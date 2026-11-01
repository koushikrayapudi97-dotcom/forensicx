"""Forensic report API."""

import logging
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

from backend.config import REPORTS_DIR
from backend.database.database import connect, row, utc_now
from backend.services.auth_service import check_case_access, get_session_user
from backend.services.report_manager import generate_report
from backend.api.auth_routes import SESSION_COOKIE

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{case_id}")
def create_report(case_id: str, request: Request):
    session_id = request.cookies.get(SESSION_COOKIE, "")
    user = getattr(request.state, "user", None) or get_session_user(session_id)
    check_case_access(case_id, user)

    try:
        report_path = generate_report(case_id)
    except Exception as exc:
        logger.exception("Error generating PDF report for case %s: %s", case_id, exc)
        raise HTTPException(status_code=500, detail="Report could not be generated.") from None

    # Validate that generated report resides within current REPORTS_DIR
    resolved_path = report_path.resolve()
    from backend.services import report_manager as rm
    try:
        resolved_path.relative_to(rm.REPORTS_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=500, detail="Invalid report path generated.")

    now = utc_now()
    acquisition = row("SELECT * FROM acquisitions WHERE case_id = ? ORDER BY started_at DESC LIMIT 1", (case_id,))
    if acquisition:
        with connect() as connection:
            connection.execute(
                "INSERT INTO acquisition_logs (case_id, device_id, acquisition_id, event, status, message, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, acquisition["device_id"], acquisition["acquisition_id"], "REPORT_GENERATED", "INFO", "PDF report generated.", now, "PDF report generated.")
            )
            connection.execute(
                "INSERT INTO chain_of_custody (case_id, device_id, acquisition_id, event_type, action, actor, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, acquisition["device_id"], acquisition["acquisition_id"], "REPORT_GENERATED", "REPORT_GENERATED", "System", "System", now, "PDF report generated.")
            )
    return FileResponse(resolved_path, media_type="application/pdf", filename=f"ForensicX_{case_id}_REPORT-001.pdf")
