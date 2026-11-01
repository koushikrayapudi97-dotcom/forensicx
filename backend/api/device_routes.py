"""Device information API."""

from fastapi import APIRouter

from backend.services.adb_manager import AdbError
from backend.services.device_manager import DeviceManager
from backend.services.mobile_intelligence import collect_intelligence

router = APIRouter(prefix="/api/device", tags=["device"])


@router.get("/info")
def get_device_info(serial: str | None = None) -> dict:
    manager = DeviceManager()
    status = manager.detect()
    selected = serial or next((device["serial"] for device in status["devices"] if device["state"] == "device"), None)
    if not selected:
        return {
            "device_id": "DEV-UNKNOWN",
            "manufacturer": "Not Available",
            "model": "No ADB Device Connected",
            "android_version": "N/A",
            "sdk_version": "N/A",
            "build_id": "N/A",
            "serial": "N/A",
            "battery": "N/A",
            "status": "disconnected",
            "platform": "Android",
            "connection_status": "disconnected",
            "lock_status": "unknown",
            "adb_status": "offline",
            "usb_debugging": "disabled",
            "acquisition_readiness": "UNAVAILABLE",
        }
    try:
        return manager.get_info(selected)
    except AdbError:
        return {
            "device_id": "DEV-UNKNOWN",
            "manufacturer": "Not Available",
            "model": selected,
            "android_version": "N/A",
            "sdk_version": "N/A",
            "build_id": "N/A",
            "serial": selected,
            "battery": "N/A",
            "status": "disconnected",
            "platform": "Android",
            "connection_status": "disconnected",
            "lock_status": "unknown",
            "adb_status": "offline",
            "usb_debugging": "disabled",
            "acquisition_readiness": "RESTRICTED",
        }


@router.get("/intelligence")
def get_mobile_intelligence(serial: str | None = None) -> dict:
    manager = DeviceManager()
    status = manager.detect()
    selected = serial or next((device["serial"] for device in status["devices"] if device["state"] == "device"), None)
    if not selected:
        return {"status": "unavailable", "message": "No authorized device connected."}
    try:
        return collect_intelligence(selected, manager)
    except AdbError as exc:
        return {"status": "unavailable", "message": str(exc)}


@router.get("/assessment")
def get_device_assessment() -> dict:
    manager = DeviceManager()
    status = manager.detect()
    assessed = []
    for device in status["devices"]:
        item = {
            **device,
            "platform": "Android",
            "connection_status": "connected" if device["state"] == "device" else device["state"],
            "adb_status": "authorized" if device["state"] == "device" else device["state"],
            "usb_debugging": "enabled" if device["state"] == "device" else "unknown",
            "lock_status": "unknown",
            "acquisition_readiness": "READY" if device["state"] == "device" else "RESTRICTED",
            "limitation": None if device["state"] == "device" else "Direct acquisition unavailable: device is restricted or ADB access is unavailable.",
        }
        assessed.append(item)
    return {
        "readiness": status["readiness"],
        "limitation": status["limitation"],
        "devices": assessed,
        "options": [
            "Import Authorized Acquisition",
            "Import Forensic Image",
            "Import Backup",
            "Import Autopsy Evidence",
            "Import Cellebrite Export",
            "Record Acquisition Limitation",
            "View Acquisition Details",
        ],
    }