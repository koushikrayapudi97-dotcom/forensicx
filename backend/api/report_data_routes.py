"""Structured report data API; raw evidence remains on disk."""

from fastapi import APIRouter, HTTPException, Request

from backend.config import EVIDENCE_DIR
from backend.database.database import row
from backend.services.auth_service import check_case_access, get_session_user
from backend.services.evidence_normalizer import normalize_case
from backend.services.device_manager import DeviceManager
from backend.services.adb_manager import AdbError
from backend.api.auth_routes import SESSION_COOKIE

router = APIRouter(prefix="/api/report-data", tags=["report-data"])


@router.get("/{case_id}")
def report_data(case_id: str, request: Request) -> dict:
	session_id = request.cookies.get(SESSION_COOKIE, "")
	user = get_session_user(session_id)
	case = check_case_access(case_id, user)
	result = normalize_case(case, EVIDENCE_DIR)
	latest = row("SELECT a.device_id FROM acquisitions a WHERE a.case_id = ? ORDER BY a.started_at DESC LIMIT 1", (case_id,))
	if latest:
		device = row("SELECT * FROM devices WHERE device_id = ?", (latest["device_id"],))
		if device:
			result["device"] = device
	try:
		devices = DeviceManager().detect().get("devices", [])
		connected = next((item["serial"] for item in devices if item["state"] == "device"), None)
		if connected:
			result["device"] = DeviceManager().get_info(connected)
	except AdbError:
		pass
	return result