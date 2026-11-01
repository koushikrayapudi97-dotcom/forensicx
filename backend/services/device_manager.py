"""Device detection orchestration for the API layer."""

from uuid import uuid4

from backend.database.database import connect, row, utc_now
from backend.services.adb_manager import AdbError, AdbManager


class DeviceManager:
    def __init__(self, adb_manager: AdbManager | None = None):
        self.adb_manager = adb_manager or AdbManager()

    def detect(self) -> dict:
        try:
            devices = self.adb_manager.list_devices()
        except AdbError as exc:
            return {"connected": False, "devices": [], "error": str(exc), "readiness": "UNAVAILABLE", "limitation": "Direct acquisition unavailable: ADB access is unavailable."}
        now = utc_now()
        try:
            with connect() as connection:
                present_serials = {device.serial for device in devices}
                previously_connected = connection.execute("SELECT device_id, serial FROM devices WHERE connection_state = 'device'").fetchall()
                for previous in previously_connected:
                    if previous["serial"] not in present_serials:
                        connection.execute("UPDATE devices SET connection_state = 'disconnected', connection_status = 'disconnected', adb_status = 'offline', updated_at = ?, last_seen_at = ? WHERE device_id = ?", (now, now, previous["device_id"]))
                        active = connection.execute("SELECT case_id, acquisition_id FROM acquisitions WHERE device_id = ? AND status IN ('RUNNING', 'STARTED') ORDER BY started_at DESC LIMIT 1", (previous["device_id"],)).fetchone()
                        if active:
                            connection.execute("UPDATE acquisitions SET status = 'DISCONNECTED', last_activity = ? WHERE acquisition_id = ?", (now, active["acquisition_id"]))
                            connection.execute("INSERT INTO acquisition_logs (case_id, device_id, acquisition_id, event, status, message, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (active["case_id"], previous["device_id"], active["acquisition_id"], "DEVICE_DISCONNECTED", "INFO", "ADB device disconnected; evidence preserved and acquisition can resume.", now, "ADB device disconnected; evidence preserved and acquisition can resume."))
                            connection.execute("INSERT INTO chain_of_custody (case_id, device_id, acquisition_id, event_type, action, actor, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (active["case_id"], previous["device_id"], active["acquisition_id"], "DEVICE_DISCONNECTED", "DEVICE_DISCONNECTED", "System", "System", now, "ADB device disconnected; evidence preserved."))
                for device in devices:
                    known = row("SELECT device_id FROM devices WHERE serial = ?", (device.serial,))
                    device_id = known["device_id"] if known else f"DEV-{uuid4().hex[:8].upper()}"
                    if known:
                        connection.execute("UPDATE devices SET connection_state = ?, connection_status = ?, adb_status = ?, last_seen_at = ?, updated_at = ? WHERE device_id = ?", (device.state, "connected" if device.state == "device" else device.state, "authorized" if device.state == "device" else device.state, now, now, device_id))
                    else:
                        connection.execute("INSERT INTO devices (device_id, serial, serial_number, platform, connection_state, connection_status, adb_status, created_at, last_seen_at, updated_at) VALUES (?, ?, ?, 'Android', ?, ?, ?, ?, ?, ?)", (device_id, device.serial, device.serial, device.state, "connected" if device.state == "device" else device.state, "authorized" if device.state == "device" else device.state, now, now, now))
                        if device.state == "device":
                            active = connection.execute("SELECT case_id, acquisition_id FROM acquisitions WHERE device_id = ? AND status IN ('RUNNING', 'STARTED', 'DISCONNECTED') ORDER BY started_at DESC LIMIT 1", (device_id,)).fetchone()
                            if active:
                                connection.execute("INSERT INTO acquisition_logs (case_id, device_id, acquisition_id, event, status, message, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (active["case_id"], device_id, active["acquisition_id"], "DEVICE_CONNECTED", "INFO", "ADB device connected.", now, "ADB device connected."))
                                connection.execute("INSERT INTO chain_of_custody (case_id, device_id, acquisition_id, event_type, action, actor, person, timestamp, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (active["case_id"], device_id, active["acquisition_id"], "DEVICE_CONNECTED", "DEVICE_CONNECTED", "System", "System", now, "ADB device connected."))
        except Exception:
            pass

        result_devices = []
        for device in devices:
            device_id = row("SELECT device_id FROM devices WHERE serial = ?", (device.serial,))["device_id"]
            active = row("SELECT case_id, acquisition_id FROM acquisitions WHERE device_id = ? AND status IN ('RUNNING', 'STARTED', 'DISCONNECTED') ORDER BY started_at DESC", (device_id,))
            result_devices.append({**device.as_dict(), "device_id": device_id, "case_id": active["case_id"] if active else None, "acquisition_id": active["acquisition_id"] if active else None})
        return {
            "connected": any(device.state == "device" for device in devices),
            "devices": result_devices,
            "readiness": "READY" if any(device.state == "device" for device in devices) else ("RESTRICTED" if devices else "UNAVAILABLE"),
            "limitation": None if any(device.state == "device" for device in devices) else ("Direct acquisition unavailable: device is restricted or ADB access is unavailable." if devices else "Direct acquisition unavailable: no ADB device is connected."),
        }

    def get_info(self, serial: str) -> dict:
        status = self.detect()
        devices = status.get("devices", [])

        # If serial is empty or placeholder, try to pick the first authorized device
        if not serial or serial == "auto":
            authorized = next((d for d in devices if d.get("state") == "device"), None)
            if authorized:
                serial = authorized["serial"]

        target = next((d for d in devices if d.get("serial") == serial), None)
        if not target:
            # Fall back to any active authorized device if present
            authorized = next((d for d in devices if d.get("state") == "device"), None)
            if authorized:
                serial = authorized["serial"]
                target = authorized
            elif not devices:
                raise AdbError(
                    "No ADB device connected. Please verify the phone is connected via USB, unlocked, and USB debugging is enabled in Developer Options."
                )
            else:
                unauthorized = next((d for d in devices if d.get("state") == "unauthorized"), None)
                if unauthorized:
                    raise AdbError(
                        f"Device '{unauthorized.get('serial')}' is connected but UNAUTHORIZED. Please unlock your phone screen and tap 'Allow USB debugging' (select 'Always allow from this computer') on the popup prompt."
                    )
                offline = next((d for d in devices if d.get("state") == "offline"), None)
                if offline:
                    raise AdbError(
                        f"Device '{offline.get('serial')}' is OFFLINE. Please reconnect the USB cable or toggle USB debugging off and on in Developer Options."
                    )
                raise AdbError(
                    f"The selected device '{serial}' is not connected and authorized. Available devices: {', '.join(f'{d.get('serial')} ({d.get('state')})' for d in devices)}."
                )

        if target.get("state") == "unauthorized":
            raise AdbError(
                f"Device '{serial}' is connected but UNAUTHORIZED. Please unlock your phone screen and tap 'Allow USB debugging' (select 'Always allow from this computer') on the popup prompt."
            )
        elif target.get("state") == "offline":
            raise AdbError(
                f"Device '{serial}' is OFFLINE. Please reconnect the USB cable or toggle USB debugging off and on in Developer Options."
            )
        elif target.get("state") != "device":
            raise AdbError(
                f"Device '{serial}' is not in ready state (current state: '{target.get('state')}'). Please ensure the phone is unlocked and authorized."
            )

        def read_property(name: str) -> str:
            return self.adb_manager.shell(serial, ["getprop", name]) or "Not available with current authorization/configuration"

        battery_output = self.adb_manager.shell(serial, ["dumpsys", "battery"])
        battery = "Not available with current authorization/configuration"
        for line in battery_output.splitlines():
            if line.strip().startswith("level:"):
                battery = line.split(":", 1)[1].strip() + "%"
                break

        device_record = row("SELECT device_id FROM devices WHERE serial = ?", (serial,))
        device_id = device_record["device_id"] if device_record else f"DEV-{uuid4().hex[:8].upper()}"

        return {
            "device_id": device_id,
            "manufacturer": read_property("ro.product.manufacturer"),
            "model": read_property("ro.product.model"),
            "android_version": read_property("ro.build.version.release"),
            "sdk_version": read_property("ro.build.version.sdk"),
            "build_id": read_property("ro.build.id"),
            "serial": serial,
            "battery": battery,
            "status": "connected",
            "platform": "Android",
            "connection_status": "connected",
            "lock_status": "unknown",
            "adb_status": "authorized",
            "usb_debugging": "enabled",
            "acquisition_readiness": "READY",
        }