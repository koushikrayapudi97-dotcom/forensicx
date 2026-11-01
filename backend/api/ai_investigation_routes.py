"""API endpoints for AI Investigation & Evidence Correlation Report."""

import logging
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

from backend.config import REPORTS_DIR
from backend.database.database import record_chain_event, row
from backend.services.auth_service import check_case_access, get_session_user
from backend.services.ai_investigation_service import analyze_case_evidence
from backend.services.ai_investigation_pdf import generate_ai_investigation_pdf
from backend.api.auth_routes import SESSION_COOKIE

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/ai-investigation", tags=["ai-investigation"])


def _caller_user(request: Request) -> dict | None:
    session_id = request.cookies.get(SESSION_COOKIE, "")
    return get_session_user(session_id)


@router.get("/{case_id}")
def get_ai_investigation(case_id: str, request: Request) -> dict:
    """Analyze real evidence for a case and return AI findings & correlations."""
    user = _caller_user(request)
    check_case_access(case_id, user)

    analysis = analyze_case_evidence(case_id)
    record_chain_event(
        case_id=case_id,
        action="AI_INVESTIGATION_PERFORMED",
        description=f"AI evidence correlation scan executed. Detected {analysis.get('summary', {}).get('total_findings', 0)} suspicious findings and {analysis.get('summary', {}).get('correlations_count', 0)} cross-evidence correlations.",
        person="Investigator",
    )
    return analysis


@router.get("/{case_id}/pdf")
def download_ai_investigation_pdf(case_id: str, request: Request):
    """Generate and download the 11-section AI Forensic Report PDF."""
    user = _caller_user(request)
    check_case_access(case_id, user)

    try:
        pdf_path = generate_ai_investigation_pdf(case_id)
        resolved_path = pdf_path.resolve()
        try:
            resolved_path.relative_to(REPORTS_DIR.resolve())
        except ValueError:
            raise HTTPException(status_code=500, detail="Invalid report file location.")

        record_chain_event(
            case_id=case_id,
            action="AI_INVESTIGATION_REPORT_GENERATED",
            description=f"11-Section AI Investigation Forensic PDF report generated for case {case_id}.",
            person="Investigator",
        )
        filename = f"ForensicX_{case_id}_AI_Investigation_Report.pdf"
        return FileResponse(
            path=str(resolved_path),
            filename=filename,
            media_type="application/pdf"
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error generating AI investigation report for case %s: %s", case_id, exc)
        raise HTTPException(status_code=500, detail="AI investigation PDF report could not be generated.") from None



