"""Evidence and chain-of-custody API."""

from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request

from backend.config import EVIDENCE_DIR, IDENTIFIER_PATTERN
from backend.database.database import connect, row, rows, utc_now
from backend.database.models import CustodyCreate, EvidenceCreate
from backend.services.auth_service import check_case_access, get_session_user
from backend.services.hashing import calculate_sha256, verify_sha256
from backend.api.auth_routes import SESSION_COOKIE

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


def _caller_user(request: Request) -> dict | None:
	session_id = request.cookies.get(SESSION_COOKIE, "")
	return get_session_user(session_id)


def _safe_path(value: str) -> Path:
	if not value or "\x00" in value:
		raise HTTPException(status_code=400, detail="Invalid evidence file path.")
	resolved_root = EVIDENCE_DIR.resolve()
	candidate = (resolved_root / value.lstrip("/\\")).resolve() if not Path(value).is_absolute() else Path(value).resolve()
	try:
		candidate.relative_to(resolved_root)
	except ValueError:
		raise HTTPException(status_code=400, detail="Path traversal detected: Evidence file must be inside the evidence directory.")
	return candidate


def _sync_case_evidence_files(case_id: str) -> None:
	"""Auto-discover and index all physical evidence files in EVIDENCE_DIR/case_id."""
	case_dir = EVIDENCE_DIR / case_id
	if not case_dir.is_dir():
		return
	for p in case_dir.rglob("*"):
		if not p.is_file() or p.name.endswith(".pdf"):
			continue
		rel_path = str(p.relative_to(EVIDENCE_DIR))
		existing = row("SELECT evidence_id FROM evidence WHERE case_id = ? AND file_path = ?", (case_id, rel_path))
		if existing is None:
			try:
				hash_value = calculate_sha256(p)["hash"]
				ev_id = f"EVD-{uuid4().hex[:8].upper()}"
				item_id = f"ITEM-{uuid4().hex[:8].upper()}"
				now = utc_now()
				with connect() as connection:
					latest_acq = row("SELECT acquisition_id, device_id FROM acquisitions WHERE case_id = ? ORDER BY started_at DESC LIMIT 1", (case_id,))
					if latest_acq:
						dev_id = latest_acq["device_id"]
						acq_id = latest_acq["acquisition_id"]
					else:
						dev_row = row("SELECT device_id FROM devices WHERE case_id = ?", (case_id,))
						if dev_row:
							dev_id = dev_row["device_id"]
						else:
							dev_id = f"DEV-{uuid4().hex[:8].upper()}"
							connection.execute(
								"INSERT OR IGNORE INTO devices (device_id, serial, manufacturer, model, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
								(dev_id, f"SERIAL-{case_id}", "Android", "Generic Device", now, now)
							)
						acq_id = f"ACQ-{uuid4().hex[:8].upper()}"
						connection.execute(
							"INSERT OR IGNORE INTO acquisitions (acquisition_id, case_id, device_id, status, started_at, last_activity) VALUES (?, ?, ?, ?, ?, ?)",
							(acq_id, case_id, dev_id, "COMPLETED", now, now)
						)

					connection.execute(
						"INSERT INTO evidence (evidence_id, case_id, device_serial, evidence_type, source, file_path, acquired_at, sha256, size, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
						(ev_id, case_id, "DEVICE", "Preserved File", "ADB Storage", rel_path, now, hash_value, p.stat().st_size, "ACQUIRED"),
					)
					connection.execute(
						"INSERT INTO evidence_items (evidence_item_id, case_id, device_id, acquisition_id, evidence_type, source, original_path, timestamp, hash, created_at, legacy_evidence_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
						(item_id, case_id, dev_id, acq_id, "Preserved File", "ADB Storage", rel_path, now, hash_value, now, ev_id),
					)
					connection.execute("INSERT INTO hashes (evidence_item_id, algorithm, value, calculated_at) VALUES (?, ?, ?, ?)", (item_id, "SHA-256", hash_value, now))
					connection.execute(
						"INSERT INTO chain_of_custody (case_id, evidence_item_id, event_type, action, actor, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
						(case_id, item_id, "HASH_CALCULATED", "HASH_CALCULATED", "System", "System", now, f"SHA-256 calculated for discovered artifact ({p.name})."),
					)
			except Exception:
				continue


@router.get("")
def list_evidence(request: Request, case_id: str | None = None) -> list[dict]:
	if not case_id:
		raise HTTPException(status_code=400, detail="case_id is required; evidence cannot be listed across cases.")
	user = _caller_user(request)
	check_case_access(case_id, user)
	return rows("SELECT * FROM evidence WHERE case_id = ? ORDER BY acquired_at DESC", (case_id,))


@router.delete("/all")
def clear_all_evidence(request: Request, case_id: str | None = None) -> dict:
	user = _caller_user(request)
	if case_id:
		check_case_access(case_id, user)
		with connect() as conn:
			conn.execute("DELETE FROM custody WHERE case_id = ?", (case_id,))
			conn.execute("DELETE FROM files WHERE case_id = ?", (case_id,))
			conn.execute("DELETE FROM evidence WHERE case_id = ?", (case_id,))
			conn.execute("DELETE FROM hashes WHERE evidence_item_id IN (SELECT evidence_item_id FROM evidence_items WHERE case_id = ? AND evidence_item_id NOT GLOB '*-MI')", (case_id,))
			conn.execute("DELETE FROM evidence_items WHERE case_id = ? AND evidence_item_id NOT GLOB '*-MI'", (case_id,))
			conn.commit()
	else:
		with connect() as conn:
			conn.execute("DELETE FROM custody")
			conn.execute("DELETE FROM files")
			conn.execute("DELETE FROM evidence")
			conn.execute("DELETE FROM hashes WHERE evidence_item_id NOT GLOB '*-MI'")
			conn.execute("DELETE FROM evidence_items WHERE evidence_item_id NOT GLOB '*-MI'")
			conn.commit()
	return {"ok": True, "message": "Evidence artifacts and extracted files cleared."}


@router.get("/{evidence_id}")
def get_evidence(evidence_id: str, request: Request) -> dict:
	if not IDENTIFIER_PATTERN.match(evidence_id):
		raise HTTPException(status_code=400, detail="Invalid evidence identifier format.")
	evidence = row("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
	if evidence is None:
		raise HTTPException(status_code=404, detail="Evidence not found.")
	user = _caller_user(request)
	check_case_access(evidence["case_id"], user)
	return evidence


@router.post("", status_code=201)
def create_evidence(payload: EvidenceCreate, request: Request) -> dict:
	user = _caller_user(request)
	check_case_access(payload.case_id, user)
	path = _safe_path(payload.file_path)
	if not path.is_file():
		raise HTTPException(status_code=400, detail="Evidence file does not exist.")
	evidence_id = f"EVD-{uuid4().hex[:8].upper()}"
	hash_value = calculate_sha256(path)["hash"]
	evidence = {"evidence_id": evidence_id, "case_id": payload.case_id, "device_serial": payload.device_serial, "evidence_type": payload.evidence_type, "source": payload.source, "file_path": str(path.relative_to(EVIDENCE_DIR)), "acquired_at": utc_now(), "sha256": hash_value, "size": path.stat().st_size, "status": "ACQUIRED"}
	with connect() as connection:
		connection.execute("INSERT INTO evidence (evidence_id, case_id, device_serial, evidence_type, source, file_path, acquired_at, sha256, size, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", tuple(evidence.values()))
		connection.execute("INSERT INTO custody (evidence_id, case_id, action, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?)", (evidence_id, payload.case_id, "CREATED", payload.device_serial, utc_now(), "Evidence registered and SHA-256 calculated."))
	return evidence


@router.get("/{evidence_id}/custody")
def list_custody(evidence_id: str, request: Request) -> list[dict]:
	if not IDENTIFIER_PATTERN.match(evidence_id):
		raise HTTPException(status_code=400, detail="Invalid evidence identifier format.")
	evidence = row("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
	if evidence is None:
		raise HTTPException(status_code=404, detail="Evidence not found.")
	user = _caller_user(request)
	check_case_access(evidence["case_id"], user)
	return rows("SELECT * FROM custody WHERE evidence_id = ? ORDER BY timestamp", (evidence_id,))


@router.post("/{evidence_id}/verify")
def verify_evidence(evidence_id: str, request: Request) -> dict:
	if not IDENTIFIER_PATTERN.match(evidence_id):
		raise HTTPException(status_code=400, detail="Invalid evidence identifier format.")
	evidence = row("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
	if evidence is None:
		raise HTTPException(status_code=404, detail="Evidence not found.")
	user = _caller_user(request)
	check_case_access(evidence["case_id"], user)
	valid = verify_sha256(_safe_path(evidence["file_path"]), evidence["sha256"] or "")
	status_str = "VERIFIED" if valid else "INTEGRITY_FAILED"
	action_str = "HASH_VERIFIED" if valid else "HASH_MISMATCH"
	desc_str = f"SHA-256 integrity verification: {'VERIFIED' if valid else 'INTEGRITY MISMATCH'}"
	item = row("SELECT evidence_item_id FROM evidence_items WHERE evidence_item_id = ? OR legacy_evidence_id = ?", (evidence_id, evidence_id))
	item_id = item["evidence_item_id"] if item else None
	with connect() as connection:
		connection.execute("UPDATE evidence SET status = ? WHERE evidence_id = ?", (status_str, evidence_id))
		connection.execute("INSERT INTO custody (evidence_id, case_id, action, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?)", (evidence_id, evidence["case_id"], status_str, "System", utc_now(), desc_str))
		connection.execute(
			"INSERT INTO chain_of_custody (case_id, device_id, acquisition_id, evidence_item_id, event_type, action, actor, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			(evidence["case_id"], evidence.get("device_id"), evidence.get("acquisition_id"), item_id, action_str, action_str, "Investigator", "Investigator", utc_now(), desc_str),
		)
	return {"evidence_id": evidence_id, "algorithm": "SHA-256", "verified": valid}


@router.post("/verify-all/{case_id}")
def verify_all_case_evidence(case_id: str, request: Request) -> dict:
	user = _caller_user(request)
	check_case_access(case_id, user)
	_sync_case_evidence_files(case_id)
	evidence_list = rows("SELECT * FROM evidence WHERE case_id = ?", (case_id,))
	verified_count = 0
	failed_count = 0
	results = []
	for item in evidence_list:
		ev_id = item["evidence_id"]
		valid = verify_sha256(_safe_path(item["file_path"]), item["sha256"] or "")
		status_str = "VERIFIED" if valid else "INTEGRITY_FAILED"
		if valid:
			verified_count += 1
		else:
			failed_count += 1
		results.append({"evidence_id": ev_id, "file_path": item["file_path"], "verified": valid})
		with connect() as connection:
			connection.execute("UPDATE evidence SET status = ? WHERE evidence_id = ?", (status_str, ev_id))
	return {
		"case_id": case_id,
		"total": len(evidence_list),
		"verified": verified_count,
		"failed": failed_count,
		"results": results,
	}


@router.post("/{evidence_id}/custody", status_code=201)
def add_custody(evidence_id: str, payload: CustodyCreate, request: Request) -> dict:
	if not IDENTIFIER_PATTERN.match(evidence_id):
		raise HTTPException(status_code=400, detail="Invalid evidence identifier format.")
	evidence = row("SELECT case_id FROM evidence WHERE evidence_id = ?", (evidence_id,))
	if evidence is None:
		raise HTTPException(status_code=404, detail="Evidence not found.")
	user = _caller_user(request)
	check_case_access(evidence["case_id"], user)
	with connect() as connection:
		cursor = connection.execute("INSERT INTO custody (evidence_id, case_id, action, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?)", (evidence_id, evidence["case_id"], payload.action.upper(), payload.person.strip(), utc_now(), payload.description.strip()))
		custody_id = cursor.lastrowid
	return row("SELECT * FROM custody WHERE id = ?", (custody_id,))