"""Evidence-backed filesystem, metadata, timeline, and search APIs."""

from fastapi import APIRouter, HTTPException, Request

from backend.config import EVIDENCE_DIR, IDENTIFIER_PATTERN
from backend.database.database import record_chain_event, row, rows
from backend.services.auth_service import check_case_access, get_session_user
from backend.api.auth_routes import SESSION_COOKIE
from forensic.filesystem import analyze
from forensic.metadata import extract
from forensic.search import search
from forensic.timeline import build

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


def _caller_user(request: Request) -> dict | None:
	session_id = request.cookies.get(SESSION_COOKIE, "")
	return get_session_user(session_id)


def _evidence_path(evidence_id: str, user: dict | None = None):
	if not IDENTIFIER_PATTERN.match(evidence_id):
		raise HTTPException(status_code=400, detail="Invalid evidence identifier format.")
	evidence = row("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
	if evidence is None:
		raise HTTPException(status_code=404, detail="Evidence not found.")
	check_case_access(evidence["case_id"], user)

	resolved_root = EVIDENCE_DIR.resolve()
	path = (resolved_root / evidence["file_path"].lstrip("/\\")).resolve()
	try:
		path.relative_to(resolved_root)
	except ValueError:
		raise HTTPException(status_code=400, detail="Invalid evidence path resolution.")

	if not path.exists():
		raise HTTPException(status_code=404, detail="Preserved evidence file is missing.")
	return path, evidence


@router.get("/files/{evidence_id}")
def filesystem_files(evidence_id: str, request: Request) -> dict:
	user = _caller_user(request)
	path, _ = _evidence_path(evidence_id, user)
	return analyze(path)


@router.get("/metadata/{evidence_id}")
def evidence_metadata(evidence_id: str, request: Request) -> dict:
	user = _caller_user(request)
	path, evidence = _evidence_path(evidence_id, user)
	meta = extract(path)
	item = row("SELECT evidence_item_id FROM evidence_items WHERE evidence_item_id = ? OR legacy_evidence_id = ?", (evidence_id, evidence_id))
	item_id = item["evidence_item_id"] if item else None
	record_chain_event(
		case_id=evidence["case_id"],
		action="FILE_ANALYSIS_PERFORMED",
		description=f"File metadata and SHA-256 analysis performed for evidence {evidence_id} ({path.name}).",
		person="Investigator",
		device_id=evidence.get("device_id"),
		acquisition_id=evidence.get("acquisition_id"),
		evidence_item_id=item_id,
	)
	return meta


@router.get("/timeline/{evidence_id}")
def evidence_timeline(evidence_id: str, request: Request) -> list[dict]:
	user = _caller_user(request)
	path, _ = _evidence_path(evidence_id, user)
	return build(path)


@router.get("/search/{case_id}")
def keyword_search(case_id: str, q: str, request: Request) -> list[dict]:
	user = _caller_user(request)
	check_case_access(case_id, user)
	sanitized_q = q.strip()[:100]
	paths = [EVIDENCE_DIR / item["file_path"] for item in rows("SELECT file_path FROM evidence WHERE case_id = ?", (case_id,))]
	results = []
	for path in paths:
		if path.exists():
			results.extend(search(str(path.parent), sanitized_q))
	return [item for item in results if item["file"].startswith(str(EVIDENCE_DIR.resolve()))]