"""Metadata extraction without inventing unavailable fields."""

import hashlib
import mimetypes
from datetime import datetime, timezone
from pathlib import Path


def extract(path: str | Path) -> dict:
	item = Path(path)
	if not item.is_file():
		return {"status": "metadata unavailable", "error": "File does not exist", "filename": item.name}
	stat = item.stat()
	sha256 = hashlib.sha256(item.read_bytes()).hexdigest()
	created_iso = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()
	modified_iso = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
	accessed_iso = datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat()
	return {
		"status": "metadata present",
		"filename": item.name,
		"path": str(item),
		"mime_type": mimetypes.guess_type(item.name)[0] or "application/octet-stream",
		"size": stat.st_size,
		"sha256": sha256,
		"created": created_iso,
		"modified": modified_iso,
		"accessed": accessed_iso,
		"exif": "metadata unavailable",
	}
