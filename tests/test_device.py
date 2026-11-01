from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app
from backend.services.adb_manager import AdbManager
from backend.services import auth_service


FAKE_USER = {"user_id": "USR-TEST", "full_name": "Tester", "email": "t@t.com", "status": "active"}


def test_parse_devices_output():
    output = "List of devices attached\nABC123\tdevice\nPHONE2\toffline\n"
    with patch("backend.services.adb_manager.shutil.which", return_value="adb"), patch("backend.services.adb_manager.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = output
        run.return_value.stderr = ""
        devices = AdbManager().list_devices()
    assert [(device.serial, device.state) for device in devices] == [("ABC123", "device"), ("PHONE2", "offline")]


def test_device_endpoint_reports_connected_device():
    with patch("backend.main.device_manager.detect", return_value={"connected": True, "devices": [{"serial": "ABC123", "state": "device"}]}), \
         patch("backend.main.get_session_user", return_value=FAKE_USER):
        response = TestClient(app).get("/api/device")
    assert response.status_code == 200
    assert response.json()["connected"] is True


def test_device_endpoint_handles_missing_adb():
    with patch("backend.main.device_manager.detect", return_value={"connected": False, "devices": [], "error": "ADB is not installed."}), \
         patch("backend.main.get_session_user", return_value=FAKE_USER):
        response = TestClient(app).get("/api/device")
    assert response.json() == {"connected": False, "devices": [], "error": "ADB is not installed."}