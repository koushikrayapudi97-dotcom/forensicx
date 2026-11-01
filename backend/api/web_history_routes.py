"""API endpoints for Web & Browser History Evidence."""

from fastapi import APIRouter, HTTPException, Request

from backend.config import EVIDENCE_DIR
from backend.database.database import row, rows
from backend.services.auth_service import check_case_access, get_session_user
from backend.services.evidence_normalizer import normalize_case
from backend.api.auth_routes import SESSION_COOKIE

router = APIRouter(prefix="/api/web-history", tags=["web-history"])


@router.get("/{case_id}")
def get_web_history(case_id: str, request: Request) -> dict:
    """Return real web history records for a case."""
    session_id = request.cookies.get(SESSION_COOKIE, "")
    user = get_session_user(session_id)
    case = check_case_access(case_id, user)

    # Try DB first
    db_records = rows("SELECT * FROM browser_history WHERE case_id = ? ORDER BY id", (case_id,))
    if db_records:
        return {
            "case_id": case_id,
            "count": len(db_records),
            "history": db_records,
            "status": "available",
        }

    # Fall back to evidence normalizer
    data = normalize_case(case, EVIDENCE_DIR)
    history = data.get("browser_history", [])
    return {
        "case_id": case_id,
        "count": len(history),
        "history": history,
        "status": "available" if history else "unavailable",
    }
