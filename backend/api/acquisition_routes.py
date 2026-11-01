"""Controlled acquisition API."""

from fastapi import APIRouter, HTTPException, Request

from backend.config import IDENTIFIER_PATTERN
from backend.database.database import connect, row, rows, utc_now
from backend.database.models import AcquisitionCreate
from backend.services.acquisition_manager import acquire
from backend.services.adb_manager import AdbError
from backend.services.auth_service import check_case_access, get_session_user
from backend.services.device_manager import DeviceManager
from backend.api.auth_routes import SESSION_COOKIE

router = APIRouter(prefix="/api/acquisition", tags=["acquisition"])


def _caller_user(request: Request) -> dict | None:
    session_id = request.cookies.get(SESSION_COOKIE, "")
    return get_session_user(session_id)


@router.post("")
def start_acquisition(payload: AcquisitionCreate, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(payload.case_id, user)
    result = acquire(payload.case_id, payload.serial, DeviceManager())
    if result["status"] == "failed" and result["errors"]:
        raise HTTPException(status_code=409, detail=result["errors"][0])
    result["source"] = payload.source
    result["method"] = payload.method
    return result


@router.get("")
def list_acquisitions(request: Request, case_id: str | None = None) -> list[dict]:
    query = "SELECT a.*, d.model, d.serial, (SELECT COUNT(*) FROM evidence e WHERE e.acquisition_id = a.acquisition_id) AS evidence_count FROM acquisitions a JOIN devices d ON d.device_id = a.device_id"
    parameters = ()
    if case_id:
        user = _caller_user(request)
        check_case_access(case_id, user)
        query += " WHERE case_id = ?"
        parameters = (case_id,)
    return rows(query + " ORDER BY started_at DESC", parameters)


@router.post("/{acquisition_id}/finalize")
def finalize_acquisition(acquisition_id: str, request: Request) -> dict:
    if not IDENTIFIER_PATTERN.match(acquisition_id):
        raise HTTPException(status_code=400, detail="Invalid acquisition identifier format.")
    acquisition = row("SELECT * FROM acquisitions WHERE acquisition_id = ?", (acquisition_id,))
    if acquisition is None:
        raise HTTPException(status_code=404, detail="Acquisition not found.")
    user = _caller_user(request)
    check_case_access(acquisition["case_id"], user)
    now = utc_now()
    with connect() as connection:
        connection.execute("UPDATE acquisitions SET status = 'FINALIZED', ended_at = ?, last_activity = ? WHERE acquisition_id = ?", (now, now, acquisition_id))
        connection.execute("UPDATE devices SET connection_state = 'disconnected', last_seen_at = ? WHERE device_id = ?", (now, acquisition["device_id"]))
        connection.execute("INSERT INTO acquisition_logs (case_id, device_id, acquisition_id, event, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)", (acquisition["case_id"], acquisition["device_id"], acquisition_id, "ACQUISITION_FINALIZED", now, "Acquisition finalized by investigator."))
        connection.execute("INSERT INTO chain_of_custody (case_id, device_id, acquisition_id, action, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?, ?)", (acquisition["case_id"], acquisition["device_id"], acquisition_id, "ACQUISITION_FINALIZED", "Investigator", now, "Acquisition finalized by investigator."))
    return row("SELECT * FROM acquisitions WHERE acquisition_id = ?", (acquisition_id,))