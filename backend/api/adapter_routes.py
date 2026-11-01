"""External forensic export adapter status API."""

from fastapi import APIRouter

from forensic.adapters import inspect_external_source, tool_status

router = APIRouter(prefix="/api/adapters", tags=["adapters"])


@router.get("")
def adapters() -> list[dict[str, str]]:
	return tool_status()


@router.get("/inspect")
def inspect(path: str, source_type: str = "generic") -> dict:
	return inspect_external_source(path, source_type)