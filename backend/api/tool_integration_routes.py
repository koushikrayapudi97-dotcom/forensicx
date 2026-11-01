"""API routes for Multi-Source Forensic Tool Integrations."""

from typing import Any
from pathlib import Path
from pydantic import BaseModel, Field

from fastapi import APIRouter, HTTPException, Request

from backend.api.auth_routes import SESSION_COOKIE
from backend.services.auth_service import check_case_access, get_session_user
from backend.services.tool_integrations.integration_registry import registry

router = APIRouter(prefix="/api/integrations", tags=["tool-integrations"])


def _caller_user(request: Request) -> dict:
    session_id = request.cookies.get(SESSION_COOKIE, "")
    user = get_session_user(session_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


class AutopsyImportPayload(BaseModel):
    case_id: str = Field(..., description="Target ForensicX Case ID")
    report_path: str = Field(..., description="Path to Autopsy HTML, TSV, or JSON report")


class CellebriteImportPayload(BaseModel):
    case_id: str = Field(..., description="Target ForensicX Case ID")
    file_path: str = Field(..., description="Path to Cellebrite UFDR archive, XML, or JSON report")


class IosImportPayload(BaseModel):
    case_id: str = Field(..., description="Target ForensicX Case ID")
    backup_path: str = Field(..., description="Path to iOS backup directory or standalone SQLite DB")


@router.get("/status")
def get_integrations_status(request: Request) -> dict[str, Any]:
    """Retrieve operational status, installation, and licensing for all 4 external forensic tools."""
    _caller_user(request)
    return registry.get_status_matrix()


@router.get("/history/recent")
def get_recent_history(request: Request, case_id: str | None = None) -> list[dict[str, Any]]:
    """Retrieve audit history of recent tool integration actions and imports."""
    user = _caller_user(request)
    if case_id:
        check_case_access(case_id, user)
    from backend.database.database import get_tool_events
    return get_tool_events(case_id=case_id, limit=50)


@router.get("/{tool_id}")
def get_tool_details(tool_id: str, request: Request) -> dict[str, Any]:
    """Get detailed capabilities, supported formats, and configuration for a specific tool."""
    _caller_user(request)
    adapter = registry.get_adapter(tool_id)
    if not adapter:
        raise HTTPException(status_code=404, detail=f"Tool adapter '{tool_id}' not found.")
    return {
        **adapter.get_status(),
        "capabilities": adapter.get_capabilities(),
    }


# ── Autopsy Endpoints ─────────────────────────────────────────────────────────

@router.post("/autopsy/prepare/{case_id}")
def prepare_autopsy_workspace(case_id: str, request: Request) -> dict[str, Any]:
    """Prepare an examination directory and manifest for Autopsy ingest."""
    user = _caller_user(request)
    check_case_access(case_id, user)
    adapter = registry.get_adapter("autopsy")
    if not adapter:
        raise HTTPException(status_code=500, detail="Autopsy adapter unavailable.")
    return adapter.prepare_case_workspace(case_id, investigator=user.get("full_name", "Investigator"))


@router.post("/autopsy/launch")
def launch_autopsy_gui(request: Request) -> dict[str, Any]:
    """Safely launch the Autopsy GUI application on the host workstation."""
    _caller_user(request)
    adapter = registry.get_adapter("autopsy")
    if not adapter:
        raise HTTPException(status_code=500, detail="Autopsy adapter unavailable.")
    return adapter.launch_autopsy()


@router.post("/autopsy/import")
def import_autopsy_report(payload: AutopsyImportPayload, request: Request) -> dict[str, Any]:
    """Ingest Autopsy examination report (HTML, TSV, JSON) into a ForensicX case."""
    user = _caller_user(request)
    check_case_access(payload.case_id, user)
    adapter = registry.get_adapter("autopsy")
    if not adapter:
        raise HTTPException(status_code=500, detail="Autopsy adapter unavailable.")
    return adapter.import_results(
        case_id=payload.case_id,
        report_file_path=payload.report_path,
        investigator=user.get("full_name", "Investigator"),
    )


# ── Cellebrite Endpoints ──────────────────────────────────────────────────────

@router.post("/cellebrite/import")
def import_cellebrite_export(payload: CellebriteImportPayload, request: Request) -> dict[str, Any]:
    """Ingest authorized Cellebrite UFDR archive, XML report, or JSON export into a case."""
    user = _caller_user(request)
    check_case_access(payload.case_id, user)
    adapter = registry.get_adapter("cellebrite")
    if not adapter:
        raise HTTPException(status_code=500, detail="Cellebrite adapter unavailable.")
    return adapter.import_export(
        case_id=payload.case_id,
        file_path=payload.file_path,
        investigator=user.get("full_name", "Investigator"),
    )


# ── iOS / iTunes Endpoints ────────────────────────────────────────────────────

@router.post("/ios/detect")
def detect_ios_backups(request: Request) -> dict[str, Any]:
    """Scan local host system for available Apple iTunes / Finder backup folders."""
    _caller_user(request)
    adapter = registry.get_adapter("ios_backup")
    if not adapter:
        raise HTTPException(status_code=500, detail="iOS adapter unavailable.")
    return adapter.detect_environment()


@router.post("/ios/import")
def import_ios_backup(payload: IosImportPayload, request: Request) -> dict[str, Any]:
    """Ingest local iOS backup directory or standalone SQLite database (sms.db, call_history.db)."""
    user = _caller_user(request)
    check_case_access(payload.case_id, user)
    adapter = registry.get_adapter("ios_backup")
    if not adapter:
        raise HTTPException(status_code=500, detail="iOS adapter unavailable.")
    return adapter.import_backup(
        case_id=payload.case_id,
        backup_path_or_file=payload.backup_path,
        investigator=user.get("full_name", "Investigator"),
    )
