from pathlib import Path

from backend.database import database
from backend.services import acquisition_manager


class MultiDeviceManager:
    class Adb:
        def shell(self, serial, arguments):
            if arguments[:2] == ["content", "query"] and "content://sms" in arguments:
                return f"Row: _id=1, address={serial}-sms, date=1700000000000, type=1, body=sms-{serial}"
            if arguments[:2] == ["content", "query"] and "content://call_log/calls" in arguments:
                return f"Row: _id=2, number={serial}-call, date=1700000000000, duration=30, type=2, name=Contact-{serial}"
            if arguments == ["dumpsys", "location"]:
                return "location output"
            if arguments == ["getprop"]:
                return "properties for " + serial
            if arguments == ["dumpsys", "battery"]:
                return "level: 80"
            if arguments[:3] == ["logcat", "-d", "-t"]:
                return "logcat for " + serial
            return ""

    def __init__(self):
        self.adb_manager = self.Adb()

    def get_info(self, serial):
        return {
            "serial": serial,
            "manufacturer": "Test Manufacturer",
            "model": "Test Model " + serial,
            "android_version": "15",
            "sdk_version": "35",
            "build_id": "TEST",
            "battery": "80%",
            "status": "connected",
        }


def create_case(case_id):
    now = database.utc_now()
    conn = database.connect()
    try:
        conn.execute(
            "INSERT INTO cases (case_id, case_name, title, investigator, description, created_at, updated_at, status, organization) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (case_id, case_id, case_id, "Tester", "Isolation test", now, now, "OPEN", "Test"),
        )
        conn.commit()
    finally:
        conn.close()


def test_two_devices_are_isolated_and_same_device_resumes(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "isolation.db")
    evidence_root = tmp_path / "evidence"
    monkeypatch.setattr(acquisition_manager, "EVIDENCE_DIR", evidence_root)
    database.initialize_database()
    create_case("CASE-ONE")
    create_case("CASE-TWO")
    manager = MultiDeviceManager()

    first = acquisition_manager.acquire("CASE-ONE", "DEVICE-ONE", manager)
    second = acquisition_manager.acquire("CASE-TWO", "DEVICE-TWO", manager)

    assert first["status"] == "completed"
    assert second["status"] == "completed"
    assert (evidence_root / "CASE-ONE" / "sms").is_dir()
    assert (evidence_root / "CASE-TWO" / "calls").is_dir()

    first_evidence = database.rows("SELECT case_id, device_id, acquisition_id, file_path FROM evidence WHERE case_id = ?", ("CASE-ONE",))
    second_evidence = database.rows("SELECT case_id, device_id, acquisition_id, file_path FROM evidence WHERE case_id = ?", ("CASE-TWO",))
    assert first_evidence and second_evidence
    assert {item["case_id"] for item in first_evidence} == {"CASE-ONE"}
    assert {item["case_id"] for item in second_evidence} == {"CASE-TWO"}
    assert {item["device_id"] for item in first_evidence}.isdisjoint({item["device_id"] for item in second_evidence})
    assert database.rows("SELECT case_id FROM call_logs WHERE case_id = ?", ("CASE-ONE",))
    assert database.rows("SELECT case_id FROM call_logs WHERE case_id = ?", ("CASE-TWO",))

    device_id = first_evidence[0]["device_id"]
    acquisition_id = first_evidence[0]["acquisition_id"]
    with database.connect() as connection:
        connection.execute("UPDATE acquisitions SET status = 'DISCONNECTED' WHERE acquisition_id = ?", (acquisition_id,))
    resumed = acquisition_manager.acquire("CASE-ONE", "DEVICE-ONE", manager)
    matching = database.rows("SELECT acquisition_id FROM acquisitions WHERE case_id = ? AND device_id = ?", ("CASE-ONE", device_id))
    assert resumed["status"] == "completed"
    assert [item["acquisition_id"] for item in matching].count(acquisition_id) == 1
    assert len(matching) == 1
