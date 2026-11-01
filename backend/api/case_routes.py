"""Case management API."""

from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request

from backend.database.database import connect, row, rows, utc_now
from backend.database.models import CaseCreate
from backend.services.auth_service import check_case_access, get_session_user
from backend.api.auth_routes import SESSION_COOKIE

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _caller_user(request: Request) -> dict | None:
	session_id = request.cookies.get(SESSION_COOKIE, "")
	return get_session_user(session_id)


@router.post("", status_code=201)
def create_case(payload: CaseCreate, request: Request) -> dict:
	now = utc_now()
	user = _caller_user(request)
	user_id = user["user_id"] if user else None
	case = {
		"case_id": f"CASE-{uuid4().hex[:8].upper()}",
		"case_name": payload.case_name.strip(),
		"investigator": payload.investigator.strip(),
		"organization": payload.organization.strip(),
		"description": payload.description.strip(),
		"created_at": now,
		"updated_at": now,
		"status": "OPEN",
		"user_id": user_id,
	}
	with connect() as connection:
		connection.execute(
			"INSERT INTO cases (case_id, case_name, investigator, description, created_at, status, organization, updated_at, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			(case["case_id"], case["case_name"], case["investigator"], case["description"], case["created_at"], case["status"], case["organization"], case["updated_at"], user_id),
		)
		connection.execute("INSERT INTO chain_of_custody (case_id, action, person, timestamp, description) VALUES (?, ?, ?, ?, ?)", (case["case_id"], "CASE_CREATED", case["investigator"], now, "Investigation case created."))
	return case


@router.get("")
def list_cases(request: Request) -> list[dict]:
	user = _caller_user(request)
	if user and user.get("user_id"):
		return rows(
			"SELECT * FROM cases WHERE user_id = ? OR user_id IS NULL ORDER BY created_at DESC",
			(user["user_id"],),
		)
	return rows("SELECT * FROM cases ORDER BY created_at DESC")


@router.get("/{case_id}")
def get_case(case_id: str, request: Request) -> dict:
	user = _caller_user(request)
	return check_case_access(case_id, user)


@router.get("/{case_id}/workspace")
def get_case_workspace(case_id: str, request: Request) -> dict:
	case = get_case(case_id, request)
	devices = rows("SELECT d.*, a.acquisition_id, a.status AS acquisition_status, a.started_at, a.ended_at FROM devices d JOIN acquisitions a ON a.device_id = d.device_id WHERE a.case_id = ? ORDER BY a.started_at DESC", (case_id,))
	return {"case": case, "devices": devices, "evidence_count": row("SELECT COUNT(*) AS count FROM evidence WHERE case_id = ?", (case_id,))["count"], "acquisitions": rows("SELECT * FROM acquisitions WHERE case_id = ? ORDER BY started_at DESC", (case_id,))}


@router.delete("/{case_id}")
def delete_case(case_id: str, request: Request) -> dict:
	user = _caller_user(request)
	check_case_access(case_id, user)
	tables = [
		"ai_findings",
		"incident_timeline",
		"graph_edges",
		"graph_nodes",
		"evidence_reliability_scores",
		"evidence_correlations",
		"normalized_evidence",
		"media_files",
		"browser_history",
		"gps_locations",
		"files",
		"applications",
		"contacts",
		"call_logs",
		"sms_messages",
		"acquisition_logs",
		"chain_of_custody",
		"evidence_items",
		"custody",
		"evidence",
		"acquisitions",
		"devices",
		"cases",
	]
	with connect() as connection:
		for table in tables:
			try:
				connection.execute(f"DELETE FROM {table} WHERE case_id = ?", (case_id,))
			except Exception:
				pass
	return {"ok": True, "case_id": case_id, "message": f"Case {case_id} and all associated records deleted."}


@router.get("/history/all")
def get_history(request: Request) -> list[dict]:
	user = _caller_user(request)
	if user and user.get("user_id"):
		return rows("""
			SELECT c.case_id, c.case_name, c.status AS case_status, c.created_at,
				d.device_id, d.serial, d.manufacturer, d.model,
				a.acquisition_id, a.status AS acquisition_status, a.started_at, a.ended_at, a.last_activity,
				(SELECT COUNT(*) FROM evidence e WHERE e.case_id = c.case_id AND (e.device_id = d.device_id OR e.device_id IS NULL)) AS evidence_count
			FROM acquisitions a
			JOIN cases c ON c.case_id = a.case_id
			LEFT JOIN devices d ON d.device_id = a.device_id
			WHERE (c.user_id = ? OR c.user_id IS NULL) AND a.status != 'CLEARED'
			ORDER BY COALESCE(a.last_activity, a.ended_at, a.started_at) DESC
		""", (user["user_id"],))
	return rows("""
		SELECT c.case_id, c.case_name, c.status AS case_status, c.created_at,
			d.device_id, d.serial, d.manufacturer, d.model,
			a.acquisition_id, a.status AS acquisition_status, a.started_at, a.ended_at, a.last_activity,
			(SELECT COUNT(*) FROM evidence e WHERE e.case_id = c.case_id AND (e.device_id = d.device_id OR e.device_id IS NULL)) AS evidence_count
		FROM acquisitions a
		JOIN cases c ON c.case_id = a.case_id
		LEFT JOIN devices d ON d.device_id = a.device_id
		WHERE a.status != 'CLEARED'
		ORDER BY COALESCE(a.last_activity, a.ended_at, a.started_at) DESC
	""")


@router.delete("/history/all")
def clear_all_history(request: Request) -> dict:
	user = _caller_user(request)
	with connect() as conn:
		conn.execute("UPDATE acquisitions SET status = 'CLEARED'")
		conn.commit()
	return {"ok": True, "message": "Previous acquisitions history cleared."}


@router.get("/history/audit")
def get_audit_history(request: Request, case_id: str | None = None) -> list[dict]:
	"""Return immutable chain-of-custody audit logs for all cases or a specific case."""
	if case_id:
		user = _caller_user(request)
		check_case_access(case_id, user)
		return rows(
			"SELECT custody_id, case_id, device_id, acquisition_id, evidence_item_id, "
			"COALESCE(event_type, action) AS action, COALESCE(actor, person) AS person, timestamp, description "
			"FROM chain_of_custody WHERE case_id = ? ORDER BY timestamp DESC",
			(case_id,),
		)
	return rows(
		"SELECT custody_id, case_id, device_id, acquisition_id, evidence_item_id, "
		"COALESCE(event_type, action) AS action, COALESCE(actor, person) AS person, timestamp, description "
		"FROM chain_of_custody ORDER BY timestamp DESC LIMIT 500"
	)


@router.delete("/history/audit")
def clear_audit_history(request: Request, case_id: str | None = None) -> dict:
	"""Clear audit trail records."""
	user = _caller_user(request)
	if case_id:
		check_case_access(case_id, user)
		with connect() as conn:
			conn.execute("DELETE FROM chain_of_custody WHERE case_id = ?", (case_id,))
			conn.execute("DELETE FROM acquisition_logs WHERE case_id = ?", (case_id,))
			conn.execute("DELETE FROM custody WHERE case_id = ?", (case_id,))
			conn.commit()
	else:
		with connect() as conn:
			conn.execute("DELETE FROM chain_of_custody")
			conn.execute("DELETE FROM acquisition_logs")
			conn.execute("DELETE FROM custody")
			conn.commit()
	return {"ok": True, "message": "Forensic action audit trail cleared."}
