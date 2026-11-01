"""Evidence file classification using signatures where practical."""

import mimetypes
from pathlib import Path


def classify_file(path: str | Path) -> dict[str, str]:
	path = Path(path)
	with path.open("rb") as file:
		header = file.read(16)
	if header.startswith(b"\x89PNG") or header.startswith(b"\xff\xd8\xff") or header.startswith(b"GIF8"):
		category, mime = "Image", mimetypes.guess_type(path.name)[0] or "application/octet-stream"
	elif header.startswith(b"PK\x03\x04"):
		category, mime = "Archive", "application/zip"
	elif header.startswith(b"%PDF"):
		category, mime = "Document", "application/pdf"
	elif header.startswith(b"MZ"):
		category, mime = "Executable", "application/vnd.microsoft.portable-executable"
	else:
		mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
		category = {"video": "Video", "audio": "Audio", "text": "Document", "image": "Image", "application/x-sqlite3": "Database"}.get(mime.split("/")[0], "Unknown")
	return {"filename": path.name, "category": category, "mime_type": mime}