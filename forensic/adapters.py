"""Import-status adapters for authorized external forensic tool exports."""

from pathlib import Path


def inspect_external_source(source_path: str, source_type: str) -> dict:
	path = Path(source_path).expanduser().resolve()
	if not path.exists():
		return {"status": "missing", "message": "The supplied export does not exist.", "source_type": source_type}
	return {"status": "ready_for_import", "message": "Authorized export detected; parser-specific import is not configured.", "source_type": source_type, "path": str(path)}


def tool_status() -> list[dict[str, str]]:
	return [{"name": name, "status": "Commercial forensic source not configured."} for name in ("Cellebrite Export Adapter", "Autopsy Export Adapter", "Generic Forensic Evidence Adapter")]