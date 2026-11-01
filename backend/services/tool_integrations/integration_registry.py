"""Central registry and dispatch manager for all ForensicX external tool integrations."""

from typing import Any

from backend.database.database import get_tool_events, record_tool_event
from backend.services.tool_integrations.adb_adapter import AdbAdapter
from backend.services.tool_integrations.autopsy_adapter import AutopsyAdapter
from backend.services.tool_integrations.base_adapter import BaseToolAdapter
from backend.services.tool_integrations.cellebrite_adapter import CellebriteAdapter
from backend.services.tool_integrations.ios_backup_adapter import IosBackupAdapter


class ToolIntegrationRegistry:
    """Singleton registry coordinating digital forensic tool adapters."""

    def __init__(self) -> None:
        self._adapters: dict[str, BaseToolAdapter] = {
            "adb": AdbAdapter(),
            "ios_backup": IosBackupAdapter(),
            "autopsy": AutopsyAdapter(),
            "cellebrite": CellebriteAdapter(),
        }

    def get_adapter(self, tool_id: str) -> BaseToolAdapter | None:
        """Lookup an adapter by its tool_id."""
        return self._adapters.get(tool_id.lower().strip())

    def list_adapters(self) -> list[BaseToolAdapter]:
        """Return all registered adapters in standard poster order."""
        return list(self._adapters.values())

    def get_status_matrix(self) -> dict[str, Any]:
        """Compile a complete status summary across all 4 integrated tools."""
        statuses = []
        installed_count = 0
        ready_count = 0

        for adapter in self.list_adapters():
            st = adapter.get_status()
            statuses.append(st)
            if st.get("installed"):
                installed_count += 1
            if st.get("available"):
                ready_count += 1

        recent_events = get_tool_events(limit=20)

        return {
            "project_title": "AI-Based Multi-Source Mobile Forensic Evidence Correlation and Intelligence System",
            "total_tools_supported": len(self._adapters),
            "tools_installed": installed_count,
            "tools_ready": ready_count,
            "tools": statuses,
            "recent_events": recent_events,
        }


# Global shared instance
registry = ToolIntegrationRegistry()
