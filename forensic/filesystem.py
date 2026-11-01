"""Filesystem inventory for accessible directory evidence."""

from datetime import datetime, timezone
from pathlib import Path

from forensic.classification import classify_file


def _timestamp(value: float) -> str:
	return datetime.fromtimestamp(value, timezone.utc).isoformat()


def analyze(path: str | Path) -> dict:
	root = Path(path)
	if root.suffix.lower() in {".dd", ".raw", ".img", ".e01"}:
		return {"status": "unsupported", "message": "Unsupported filesystem", "files": []}
	if not root.exists():
		return {"status": "missing", "message": "Evidence path does not exist", "files": []}
	files = []
	for item in root.rglob("*") if root.is_dir() else [root]:
		if not item.is_file():
			continue
		stat = item.stat()
		files.append({"path": str(item), "relative_path": str(item.relative_to(root)) if root.is_dir() else item.name, "size": stat.st_size, "extension": item.suffix.lower(), "created": _timestamp(stat.st_ctime), "modified": _timestamp(stat.st_mtime), "accessed": _timestamp(stat.st_atime), **classify_file(item)})
	return {"status": "supported", "message": None, "files": files}