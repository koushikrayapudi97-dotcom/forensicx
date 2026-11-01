"""Preserve authorized acquisition exports and associate them with a session."""

import shutil
from pathlib import Path
from uuid import uuid4

from fastapi import HTTPException

from backend.config import EVIDENCE_DIR
from backend.database.database import connect, row, utc_now
from backend.services.hashing import calculate_sha256

SOURCE_METHODS = {
    "android_backup": "Android Backup",
    "ios_backup": "iOS Backup",
    "forensic_tool": "Authorized Forensic Tool Output",
    "forensic_image": "Forensic Disk/Image File",
    "autopsy": "Autopsy Evidence Export",
    "cellebrite": "Cellebrite Authorized Export",
    "sd_card": "SD Card / External Storage",
    "manual": "Manual Authorized Import",
    "other": "Other Authorized Source",
}


def _case_layout(case_dir: Path) -> None:
    for name in ("device", "sms", "calls", "contacts", "applications", "files", "images", "videos", "audio", "documents", "browser", "location", "social", "raw", "hashes", "reports"):
        (case_dir / name).mkdir(parents=True, exist_ok=True)


def _session(case_id: str, investigator: str, device_id: str | None, acquisition_id: str | None, source: str) -> tuple[str, str]:
    now = utc_now()
    with connect() as connection:
        if device_id:
            device = connection.execute("SELECT device_id FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if device is None:
                raise HTTPException(status_code=404, detail="Device not found.")
        else:
            device_id = f"DEV-SOURCE-{uuid4().hex[:8].upper()}"
            serial = f"AUTHORIZED-SOURCE-{uuid4().hex[:8].upper()}"
            connection.execute("INSERT INTO devices (device_id, serial, serial_number, platform, connection_state, connection_status, adb_status, lock_status, created_at, last_seen_at, updated_at) VALUES (?, ?, ?, 'Unknown', 'source', 'not_applicable', 'not_applicable', 'unknown', ?, ?, ?)", (device_id, serial, serial, now, now, now))
        if acquisition_id:
            acquisition = connection.execute("SELECT acquisition_id FROM acquisitions WHERE acquisition_id = ? AND case_id = ? AND device_id = ?", (acquisition_id, case_id, device_id)).fetchone()
            if acquisition is None:
                raise HTTPException(status_code=404, detail="Acquisition does not belong to this case and device.")
        else:
            acquisition_id = f"ACQ-{uuid4().hex[:8].upper()}"
            connection.execute("INSERT INTO acquisitions (acquisition_id, case_id, device_id, source, method, status, started_at, last_activity, notes) VALUES (?, ?, ?, ?, ?, 'IN PROGRESS', ?, ?, ?)", (acquisition_id, case_id, device_id, source, SOURCE_METHODS.get(source, SOURCE_METHODS["other"]), now, now, f"Authorized import by {investigator}."))
            connection.execute("INSERT INTO chain_of_custody (case_id, device_id, acquisition_id, event_type, action, actor, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (case_id, device_id, acquisition_id, "ACQUISITION_STARTED", "ACQUISITION_STARTED", investigator, investigator, now, f"Authorized {SOURCE_METHODS.get(source, source)} import started."))
            connection.execute("INSERT INTO acquisition_logs (case_id, device_id, acquisition_id, event, status, message, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (case_id, device_id, acquisition_id, "ACQUISITION_STARTED", "INFO", f"Authorized {SOURCE_METHODS.get(source, source)} import started.", now, f"Authorized {SOURCE_METHODS.get(source, source)} import started."))
    return device_id, acquisition_id


def import_authorized_file(case_id: str, source_path: str, investigator: str, source: str, evidence_type: str, device_id: str | None = None, acquisition_id: str | None = None) -> dict:
    if row("SELECT case_id FROM cases WHERE case_id = ?", (case_id,)) is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    path = Path(source_path).expanduser().resolve()
    if not path.is_file():
        raise HTTPException(status_code=400, detail="The authorized source must be an existing file.")
    device_id, acquisition_id = _session(case_id, investigator, device_id, acquisition_id, source)
    now = utc_now()
    evidence_id = f"EVD-{uuid4().hex[:8].upper()}"
    case_dir = (EVIDENCE_DIR / case_id).resolve()
    try:
        case_dir.relative_to(EVIDENCE_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case directory path.")
    _case_layout(case_dir)
    destination_dir = (case_dir / ("images" if source == "forensic_image" else "raw")).resolve()
    import re
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', path.name)
    destination = destination_dir / f"{evidence_id}_{safe_name}"
    try:
        destination.resolve().relative_to(destination_dir)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid destination path.")
    shutil.copy2(path, destination)
    digest = calculate_sha256(destination)["hash"]
    relative = str(destination.relative_to(EVIDENCE_DIR))
    item_id = f"ITEM-{uuid4().hex[:8].upper()}"
    with connect() as connection:
        connection.execute("INSERT INTO evidence (evidence_id, case_id, device_serial, device_id, acquisition_id, evidence_type, source, file_path, acquired_at, sha256, size, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (evidence_id, case_id, device_id, device_id, acquisition_id, evidence_type, SOURCE_METHODS.get(source, source), relative, now, digest, destination.stat().st_size, "IMPORTED"))
        connection.execute("INSERT INTO evidence_items (evidence_item_id, case_id, device_id, acquisition_id, evidence_type, source, original_path, stored_path, timestamp, hash, hash_sha256, created_at, legacy_evidence_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (item_id, case_id, device_id, acquisition_id, evidence_type, SOURCE_METHODS.get(source, source), str(path), relative, now, digest, digest, now, evidence_id))
        connection.execute("INSERT INTO hashes (evidence_item_id, algorithm, value, calculated_at) VALUES (?, 'SHA-256', ?, ?)", (item_id, digest, now))
        description = f"Imported and preserved {path.name}; original source was not modified."
        connection.execute("INSERT INTO custody (evidence_id, case_id, action, person, timestamp, description) VALUES (?, ?, 'IMPORTED', ?, ?, ?)", (evidence_id, case_id, investigator, now, description))
        connection.execute("INSERT INTO chain_of_custody (case_id, device_id, acquisition_id, evidence_item_id, event_type, action, actor, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (case_id, device_id, acquisition_id, item_id, "EVIDENCE_IMPORTED", "EVIDENCE_IMPORTED", investigator, investigator, now, description))
        connection.execute("INSERT INTO chain_of_custody (case_id, device_id, acquisition_id, evidence_item_id, event_type, action, actor, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (case_id, device_id, acquisition_id, item_id, "HASH_CALCULATED", "HASH_CALCULATED", "System", "System", now, "SHA-256 calculated for imported evidence."))
        connection.execute("INSERT INTO acquisition_logs (case_id, device_id, acquisition_id, event, status, message, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (case_id, device_id, acquisition_id, "EVIDENCE_IMPORTED", "COMPLETED", description, now, description))
        connection.execute("UPDATE acquisitions SET status = 'COMPLETED', completed_at = ?, ended_at = ?, last_activity = ? WHERE acquisition_id = ?", (now, now, now, acquisition_id))
    return {"evidence_id": evidence_id, "evidence_item_id": item_id, "case_id": case_id, "device_id": device_id, "acquisition_id": acquisition_id, "source": SOURCE_METHODS.get(source, source), "evidence_type": evidence_type, "original_filename": path.name, "original_path": str(path), "stored_path": relative, "sha256": digest, "status": "COMPLETED", "imported_at": now}
