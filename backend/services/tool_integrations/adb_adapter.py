"""Tool 1: Android Debug Bridge (ADB) Integration Adapter."""

import shutil
from pathlib import Path
from typing import Any

from backend.config import ADB_EXECUTABLE, adb_candidates
from backend.services.adb_manager import AdbManager
from backend.services.device_manager import DeviceManager
from backend.services.tool_integrations.base_adapter import BaseToolAdapter


class AdbAdapter(BaseToolAdapter):
    """Adapter for Tool 1: Android Debug Bridge (ADB)."""

    def __init__(self) -> None:
        self._adb_mgr = AdbManager()
        self._dev_mgr = DeviceManager()

    @property
    def tool_id(self) -> str:
        return "adb"

    @property
    def name(self) -> str:
        return "Android Debug Bridge (ADB)"

    @property
    def category(self) -> str:
        return "Live Mobile Acquisition & Triage"

    @property
    def poster_reference(self) -> str:
        return "Tool 1: Android Debug Bridge (ADB)"

    @property
    def description(self) -> str:
        return (
            "Direct USB/network interface for Android physical and logical extraction, "
            "triage commands, SMS/call dumps, file system pulling, and APK acquisition."
        )

    def _resolve_executable(self) -> str | None:
        for candidate in [ADB_EXECUTABLE, *adb_candidates()]:
            if shutil.which(candidate):
                return shutil.which(candidate)
            if candidate != ADB_EXECUTABLE and Path(candidate).is_file():
                return str(Path(candidate).resolve())
        return None

    def get_status(self) -> dict[str, Any]:
        exe_path = self._resolve_executable()
        installed = exe_path is not None
        connected_devices = []

        if installed:
            try:
                detection = self._dev_mgr.detect()
                connected_devices = detection.get("devices", [])
            except Exception:
                pass

        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "category": self.category,
            "poster_reference": self.poster_reference,
            "installed": installed,
            "available": installed,
            "status_label": "Installed & Active" if installed else "Not Installed / Missing from PATH",
            "executable_path": exe_path,
            "license_type": "Open Source (Apache 2.0 / Android Open Source Project)",
            "license_status": "Active / Unrestricted",
            "connected_devices_count": len(connected_devices),
            "connected_devices": connected_devices,
            "modes_supported": [
                "Live Logical Extraction",
                "Non-Invasive Triage",
                "SMS & Call Database Pull",
                "File System Extraction",
                "APK Artifact Analysis",
            ],
            "supported_formats": [
                "Android Debug Bridge Protocol",
                "Raw Tarball Archive (.tar)",
                "SQLite Databases (sms.db, contacts2.db)",
                "Android Package (.apk)",
            ],
            "documentation": (
                "Official Android SDK platform-tools utility. Supports automated live device acquisition, "
                "hash calculation, and chain-of-custody logging into ForensicX."
            ),
        }

    def get_capabilities(self) -> list[str]:
        return [
            "Device auto-detection over USB with ADB debugging",
            "Non-invasive logical acquisition of SMS, Call Logs, Contacts, and Files",
            "Real-time device state monitoring (unauthorized, offline, device)",
            "Direct cryptographic hash generation and chain-of-custody logging",
        ]
