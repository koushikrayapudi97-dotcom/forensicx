"""Forensic image import API."""

from fastapi import APIRouter, Request

from backend.database.models import AuthorizedImportCreate, ImageImportCreate
from backend.services.auth_service import check_case_access, get_session_user
from backend.services.authorized_importer import import_authorized_file
from backend.api.auth_routes import SESSION_COOKIE

router = APIRouter(prefix="/api/evidence", tags=["image-import"])


def _caller_user(request: Request) -> dict | None:
	session_id = request.cookies.get(SESSION_COOKIE, "")
	return get_session_user(session_id)


@router.post("/import", status_code=201)
def import_forensic_image(payload: ImageImportCreate, request: Request) -> dict:
	user = _caller_user(request)
	check_case_access(payload.case_id, user)
	return import_authorized_file(payload.case_id, payload.source_path, payload.investigator, "forensic_image", "Images", payload.device_id, payload.acquisition_id)


@router.post("/import-authorized", status_code=201)
def import_authorized(payload: AuthorizedImportCreate, request: Request) -> dict:
	user = _caller_user(request)
	check_case_access(payload.case_id, user)
	return import_authorized_file(payload.case_id, payload.source_path, payload.investigator, payload.source, payload.evidence_type, payload.device_id, payload.acquisition_id)