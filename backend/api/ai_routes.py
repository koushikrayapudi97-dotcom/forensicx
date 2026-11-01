"""Optional evidence-grounded AI analysis API."""

from fastapi import APIRouter, HTTPException

from backend.database.database import row, rows
from forensic.ai import get_provider

router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.get("/{case_id}")
def analyze_case(case_id: str) -> dict:
	if row("SELECT case_id FROM cases WHERE case_id = ?", (case_id,)) is None:
		raise HTTPException(status_code=404, detail="Case not found.")
	evidence = rows("SELECT evidence_id, file_path, sha256, status FROM evidence WHERE case_id = ?", (case_id,))
	return get_provider().analyze(evidence)