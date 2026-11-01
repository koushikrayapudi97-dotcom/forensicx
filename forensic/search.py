"""Read-only keyword search over authorized text evidence."""

from pathlib import Path


def search(root: str, query: str) -> list[dict]:
	if not query.strip():
		return []
	results = []
	for path in Path(root).rglob("*"):
		if not path.is_file() or path.suffix.lower() not in {".txt", ".log", ".json", ".csv", ".xml"}:
			continue
		try:
			for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
				if query.casefold() in line.casefold():
					results.append({"file": str(path), "matched_text": line[:1000], "location": number, "timestamp": None})
		except OSError:
			continue
	return results