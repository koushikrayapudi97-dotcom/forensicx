"""Preserve investigator-supplied forensic images without altering them."""

import shutil
from pathlib import Path
from uuid import uuid4

from fastapi import HTTPException

from backend.config import EVIDENCE_DIR
from backend.database.database import connect, row, utc_now
from backend.services.hashing import calculate_sha256

SUPPORTED_EXTENSIONS = {".dd", ".raw", ".img", ".e01"}


def import_image(case_id: str, source_path: str, investigator: str) -> dict:
	if row("SELECT case_id FROM cases WHERE case_id = ?", (case_id,)) is None:
		raise HTTPException(status_code=404, detail="Case not found.")
	source = Path(source_path).expanduser().resolve()
	if source.suffix.lower() not in SUPPORTED_EXTENSIONS:
		raise HTTPException(status_code=400, detail="Unsupported forensic image format. Supported formats: .dd, .raw, .img, .E01.")
	if not source.is_file():
		raise HTTPException(status_code=400, detail="The supplied forensic image does not exist.")

	evidence_id = f"EVD-{uuid4().hex[:8].upper()}"
	case_dir = EVIDENCE_DIR / case_id
	image_dir = case_dir / "images"
	workspace = case_dir / "analysis" / evidence_id
	image_dir.mkdir(parents=True, exist_ok=True)
	workspace.mkdir(parents=True, exist_ok=True)
	destination = image_dir / f"{evidence_id}_{source.name}"
	shutil.copy2(source, destination)
	hash_value = calculate_sha256(destination)["hash"]
	relative_path = str(destination.relative_to(EVIDENCE_DIR))
	with connect() as connection:
		connection.execute("INSERT INTO evidence (evidence_id, case_id, device_serial, evidence_type, source, file_path, acquired_at, sha256, size, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (evidence_id, case_id, "N/A", "Forensic image", f"Imported: {source.name}", relative_path, utc_now(), hash_value, destination.stat().st_size, "IMPORTED"))
		connection.execute("INSERT INTO custody (evidence_id, case_id, action, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?)", (evidence_id, case_id, "IMPORTED", investigator, utc_now(), f"Preserved investigator-supplied image {source.name}; original was not modified."))
	return {"evidence_id": evidence_id, "case_id": case_id, "original_filename": source.name, "original_path": str(source), "preserved_path": relative_path, "size": destination.stat().st_size, "sha256": hash_value, "imported_at": utc_now(), "analysis_workspace": str(workspace.relative_to(EVIDENCE_DIR)), "filesystem_analysis": "Unsupported filesystem until a compatible image parser is configured."}