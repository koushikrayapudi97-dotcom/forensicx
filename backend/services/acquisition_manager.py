"""Controlled acquisition of read-only, legitimately exposed ADB data."""

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from backend.config import EVIDENCE_DIR
from backend.database.database import connect, row, utc_now
from backend.services.adb_manager import AdbError
from backend.services.device_manager import DeviceManager
from backend.services.hashing import calculate_sha256
from backend.services.mobile_intelligence import collect_intelligence


def _session(case_id: str, serial: str, info: dict) -> tuple[str, str]:
	now = utc_now()
	with connect() as connection:
		device = row("SELECT * FROM devices WHERE serial = ?", (serial,))
		if device is None:
			device_id = f"DEV-{uuid4().hex[:8].upper()}"
			connection.execute("INSERT INTO devices (device_id, serial, manufacturer, model, android_version, sdk_version, connection_state, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (device_id, serial, info.get("manufacturer", ""), info.get("model", ""), info.get("android_version", ""), info.get("sdk_version", ""), "device", now, now))
		else:
			device_id = device["device_id"]
			connection.execute("UPDATE devices SET case_id = ?, manufacturer = ?, model = ?, android_version = ?, sdk_version = ?, connection_state = 'device', connection_status = 'connected', adb_status = 'authorized', last_seen_at = ?, updated_at = ? WHERE device_id = ?", (case_id, info.get("manufacturer", ""), info.get("model", ""), info.get("android_version", ""), info.get("sdk_version", ""), now, now, device_id))
		acquisition = connection.execute("SELECT acquisition_id FROM acquisitions WHERE case_id = ? AND device_id = ? AND status IN ('STARTED', 'RUNNING', 'DISCONNECTED') ORDER BY started_at DESC LIMIT 1", (case_id, device_id)).fetchone()
		if acquisition:
			acquisition_id = acquisition[0]
			connection.execute("UPDATE acquisitions SET status = 'RUNNING', last_activity = ?, ended_at = NULL WHERE acquisition_id = ?", (now, acquisition_id))
		else:
			acquisition_id = f"ACQ-{uuid4().hex[:8].upper()}"
			connection.execute("INSERT INTO acquisitions (acquisition_id, case_id, device_id, source, method, status, started_at, last_activity) VALUES (?, ?, ?, 'adb', 'ADB / Logical Acquisition', 'RUNNING', ?, ?)", (acquisition_id, case_id, device_id, now, now))
		connection.execute("INSERT INTO acquisition_logs (case_id, device_id, acquisition_id, event, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)", (case_id, device_id, acquisition_id, "ACQUISITION_STARTED", now, "Acquisition started or resumed."))
		connection.execute("INSERT INTO chain_of_custody (case_id, device_id, acquisition_id, action, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?, ?)", (case_id, device_id, acquisition_id, "ACQUISITION_STARTED", "System", now, "Acquisition started or resumed."))
	return device_id, acquisition_id


def _ensure_case_layout(case_dir: Path) -> None:
	for name in ("device", "sms", "calls", "contacts", "applications", "files", "images", "videos", "audio", "documents", "browser", "location", "social", "raw", "hashes", "reports", "acquired", "logs"):
		(case_dir / name).mkdir(parents=True, exist_ok=True)


def _persist_structured_records(case_id: str, device_id: str, acquisition_id: str, evidence_item_id: str, intelligence: dict) -> None:
	with connect() as connection:
		connection.execute("DELETE FROM sms_messages WHERE acquisition_id = ?", (acquisition_id,))
		connection.execute("DELETE FROM call_logs WHERE acquisition_id = ?", (acquisition_id,))
		connection.execute("DELETE FROM gps_locations WHERE acquisition_id = ?", (acquisition_id,))
		for item in intelligence.get("sms", {}).get("records", []):
			connection.execute("INSERT INTO sms_messages (evidence_item_id, case_id, device_id, acquisition_id, address, body, message_type, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (evidence_item_id, case_id, device_id, acquisition_id, item.get("address"), item.get("body"), item.get("type"), item.get("date")))
		for item in intelligence.get("call_logs", {}).get("records", []):
			connection.execute("INSERT INTO call_logs (evidence_item_id, case_id, device_id, acquisition_id, number, name, call_type, duration, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (evidence_item_id, case_id, device_id, acquisition_id, item.get("number"), item.get("name"), item.get("type"), item.get("duration"), item.get("date")))
		# Persist GPS records — already structured from mobile_intelligence.py
		for fix in intelligence.get("gps", {}).get("records", []):
			lat = fix.get("latitude")
			lon = fix.get("longitude")
			if not lat or not lon:
				continue
			connection.execute(
				"INSERT INTO gps_locations (evidence_item_id, case_id, device_id, acquisition_id, latitude, longitude, accuracy, provider, timestamp, raw_line) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				(evidence_item_id, case_id, device_id, acquisition_id, lat, lon, fix.get("accuracy") or "Unknown", fix.get("provider") or "unknown", fix.get("timestamp"), fix.get("raw") or ""),
			)
		connection.execute("DELETE FROM files WHERE acquisition_id = ?", (acquisition_id,))
		for item in intelligence.get("files", {}).get("records", []):
			orig_path = item.get("original_path") or item.get("_data") or ""
			if not orig_path:
				continue
			fname = item.get("file_name") or orig_path.split("/")[-1]
			fsize = item.get("size") or item.get("_size") or 0
			fmime = item.get("mime_type") or "application/octet-stream"
			ftstamp = item.get("date_modified") or item.get("timestamp") or utc_now()
			connection.execute(
				"INSERT INTO files (evidence_item_id, case_id, device_id, acquisition_id, original_path, file_name, size, mime_type, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
				(evidence_item_id, case_id, device_id, acquisition_id, orig_path, fname, fsize, fmime, ftstamp),
			)
		connection.execute("DELETE FROM browser_history WHERE acquisition_id = ?", (acquisition_id,))
		for item in intelligence.get("browser_history", {}).get("records", []):
			url_val = item.get("url") or ""
			if not url_val:
				continue
			connection.execute(
				"INSERT INTO browser_history (evidence_item_id, case_id, device_id, acquisition_id, browser, url, title, visit_timestamp, visit_count, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				(
					evidence_item_id,
					case_id,
					device_id,
					acquisition_id,
					item.get("browser") or "Unknown Browser",
					url_val,
					item.get("title") or url_val,
					item.get("visit_timestamp") or item.get("date") or utc_now(),
					int(item.get("visit_count") or item.get("visits") or 1),
					item.get("source") or "content://browser",
				),
			)
		connection.execute("DELETE FROM media_files WHERE acquisition_id = ?", (acquisition_id,))
		for item in intelligence.get("media_files", {}).get("records", []):
			path = item.get("original_path") or ""
			if not path:
				continue
			connection.execute(
				"INSERT INTO media_files (evidence_item_id, case_id, device_id, acquisition_id, media_type, file_name, original_path, file_size, mime_type, date_taken, duration, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				(
					evidence_item_id,
					case_id,
					device_id,
					acquisition_id,
					item.get("media_type") or "Image",
					item.get("file_name") or path.split("/")[-1],
					path,
					int(item.get("size") or 0),
					item.get("mime_type") or "application/octet-stream",
					item.get("date_taken") or utc_now(),
					item.get("duration") or "",
					item.get("source") or "content://media",
				),
			)




def acquire(case_id: str, serial: str, device_manager: DeviceManager) -> dict:
	start = datetime.now(timezone.utc).isoformat()
	case_dir = EVIDENCE_DIR / case_id
	_ensure_case_layout(case_dir)
	acquired_dir = case_dir / "acquired"
	logs_dir = case_dir / "logs"
	acquired_dir.mkdir(parents=True, exist_ok=True)
	logs_dir.mkdir(parents=True, exist_ok=True)
	commands = [["getprop"], ["dumpsys", "battery"], ["logcat", "-d", "-t", "200"]]
	errors: list[str] = []
	artifact_paths: list[Path] = []
	intelligence: dict = {}
	try:
		info = device_manager.get_info(serial)
		serial = info.get("serial", serial)
		device_id, acquisition_id = _session(case_id, serial, info)
		device_info_path = acquired_dir / "device_info.json"
		device_info_path.write_text(json.dumps(info, indent=2), encoding="utf-8")
		artifact_paths.append(device_info_path)
		intelligence_path = acquired_dir / "mobile_intelligence.json"
		intelligence = collect_intelligence(serial, device_manager)
		intelligence_path.write_text(json.dumps(intelligence, indent=2), encoding="utf-8")
		artifact_paths.append(intelligence_path)
		for command in commands:
			try:
				output = device_manager.adb_manager.shell(serial, command)
				filename = {"getprop": "getprop.txt", "dumpsys": "battery.txt", "logcat": "logcat.txt"}[command[0]]
				artifact_path = acquired_dir / filename
				artifact_path.write_text(output, encoding="utf-8")
				artifact_paths.append(artifact_path)
				(logs_dir / filename).write_text(output, encoding="utf-8")
			except AdbError as exc:
				errors.append(str(exc))
		status = "completed" if not errors else "completed_with_errors"
	except (AdbError, OSError) as exc:
		errors.append(str(exc))
		status = "failed"
	end = datetime.now(timezone.utc).isoformat()
	artifacts = []
	device_id = locals().get("device_id")
	acquisition_id = locals().get("acquisition_id")
	for artifact_path in artifact_paths:
		try:
			hash_value = calculate_sha256(artifact_path)["hash"]
			relative_path = str(artifact_path.relative_to(EVIDENCE_DIR))
			existing = row("SELECT evidence_id FROM evidence WHERE case_id = ? AND file_path = ?", (case_id, relative_path))
			if existing is None:
				evidence_id = f"EVD-{uuid4().hex[:8].upper()}"
				with connect() as connection:
					connection.execute("INSERT INTO evidence (evidence_id, case_id, device_serial, device_id, acquisition_id, evidence_type, source, file_path, acquired_at, sha256, size, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (evidence_id, case_id, serial, device_id, acquisition_id, "ADB acquisition artifact", "Authorized ADB", relative_path, utc_now(), hash_value, artifact_path.stat().st_size, "ACQUIRED"))
					connection.execute("INSERT INTO custody (evidence_id, case_id, action, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?)", (evidence_id, case_id, "ACQUIRED", "System", utc_now(), "Created by controlled authorized ADB acquisition."))
					item_id = f"ITEM-{uuid4().hex[:8].upper()}"
					connection.execute("INSERT INTO evidence_items (evidence_item_id, case_id, device_id, acquisition_id, evidence_type, source, original_path, timestamp, hash, created_at, legacy_evidence_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (item_id, case_id, device_id, acquisition_id, "ADB acquisition artifact", "Authorized ADB", relative_path, utc_now(), hash_value, utc_now(), evidence_id))
					connection.execute("INSERT INTO hashes (evidence_item_id, algorithm, value, calculated_at) VALUES (?, ?, ?, ?)", (item_id, "SHA-256", hash_value, utc_now()))
					connection.execute("INSERT INTO chain_of_custody (case_id, device_id, acquisition_id, evidence_item_id, action, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (case_id, device_id, acquisition_id, item_id, "HASH_CALCULATED", "System", utc_now(), "SHA-256 calculated for acquired evidence."))
			else:
				evidence_id = existing["evidence_id"]
				with connect() as connection:
					connection.execute("UPDATE evidence SET device_id = COALESCE(device_id, ?), acquisition_id = COALESCE(acquisition_id, ?) WHERE evidence_id = ?", (device_id, acquisition_id, evidence_id))
			artifacts.append({"evidence_id": evidence_id, "file_path": relative_path, "sha256": hash_value, "size": artifact_path.stat().st_size})
		except OSError as exc:
			errors.append(str(exc))
	if device_id and acquisition_id and intelligence:
		mobile_evidence = row("SELECT evidence_id FROM evidence WHERE case_id = ? AND file_path LIKE ?", (case_id, "%mobile_intelligence.json"))
		if mobile_evidence:
			item_id = mobile_evidence["evidence_id"]
			mobile_item = row("SELECT evidence_item_id FROM evidence_items WHERE legacy_evidence_id = ?", (item_id,))
			if mobile_item:
				item_id = mobile_item["evidence_item_id"]
			_persist_structured_records(case_id, device_id, acquisition_id, item_id, intelligence)
			try:
				from backend.services.incident_timeline_engine import build_incident_timeline
				build_incident_timeline(case_id)
			except Exception:
				pass
	record = {"case_id": case_id, "serial": serial, "started_at": start, "ended_at": end, "commands": commands, "artifacts": artifacts, "status": status, "errors": errors}
	(case_dir / "acquisition.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
	if acquisition_id:
		with connect() as connection:
			final_status = "COMPLETED" if status == "completed" else "COMPLETED_WITH_ERRORS"
			connection.execute("UPDATE acquisitions SET status = ?, ended_at = ?, last_activity = ? WHERE acquisition_id = ?", (final_status, end, end, acquisition_id))
			connection.execute("INSERT INTO acquisition_logs (case_id, device_id, acquisition_id, event, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)", (case_id, device_id, acquisition_id, "ACQUISITION_FINALIZED", end, final_status))
	return record