from fastapi.testclient import TestClient

from backend.database import database
from backend.api import evidence_routes
from backend.services import acquisition_manager, report_manager
from backend.services import image_importer
from backend.services.hashing import calculate_sha256, verify_sha256
from backend.services.mobile_intelligence import _provider_rows
from backend.services import auth_service
from backend.main import app

FAKE_USER = {"user_id": "USR-TEST", "full_name": "Tester", "email": "t@t.com", "status": "active"}


class FakeAdb:
    def __init__(self):
        self.commands = []

    def shell(self, serial, arguments):
        self.commands.append((serial, arguments))
        return "key=value"


class FakeDeviceManager:
    def __init__(self):
        self.adb_manager = FakeAdb()

    def get_info(self, serial):
        return {"serial": serial, "status": "connected"}


def test_hash_calculation_and_verification(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"forensic sample")
    result = calculate_sha256(path)
    assert result["algorithm"] == "SHA-256"
    assert verify_sha256(path, result["hash"])
    assert not verify_sha256(path, "0" * 64)


def test_provider_output_is_structured_without_inventing_records():
    output = "Row: _id=7, address=5551234, date=1700000000, type=1, body=hello, investigator\nnot a row\n"
    assert _provider_rows(output) == [{"_id": "7", "address": "5551234", "date": "1700000000", "type": "1", "body": "hello, investigator"}]


def test_case_evidence_verification_and_report(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "test.db")
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    monkeypatch.setattr(evidence_routes, "EVIDENCE_DIR", evidence_root)
    report_root = tmp_path / "reports"
    monkeypatch.setattr(report_manager, "REPORTS_DIR", report_root)
    monkeypatch.setattr("backend.main.get_session_user", lambda _: FAKE_USER)
    database.initialize_database()
    client = TestClient(app)

    case_response = client.post("/api/cases", json={"case_name": "Unit Case", "investigator": "Tester", "description": "Evidence test"})
    assert case_response.status_code == 201
    case_id = case_response.json()["case_id"]
    evidence_file = evidence_root / case_id / "sample.txt"
    evidence_file.parent.mkdir()
    evidence_file.write_text("authorized evidence", encoding="utf-8")

    evidence_response = client.post("/api/evidence", json={"case_id": case_id, "device_serial": "TEST", "evidence_type": "Text", "source": "Test fixture", "file_path": f"{case_id}/sample.txt"})
    assert evidence_response.status_code == 201
    evidence_id = evidence_response.json()["evidence_id"]
    verification = client.post(f"/api/evidence/{evidence_id}/verify")
    assert verification.json()["verified"] is True
    custody = client.get(f"/api/evidence/{evidence_id}/custody")
    assert custody.status_code == 200
    assert custody.json()[0]["action"] == "CREATED"
    report = client.get(f"/api/reports/{case_id}")
    assert report.status_code == 200
    assert report.headers["content-type"] == "application/pdf"
    assert (report_root / f"{case_id}-forensic-report.pdf").is_file()


def test_forensic_image_import_preserves_and_hashes_test_fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "image-test.db")
    evidence_root = tmp_path / "evidence"
    monkeypatch.setattr(image_importer, "EVIDENCE_DIR", evidence_root)
    database.initialize_database()
    with database.connect() as connection:
        connection.execute("INSERT INTO cases (case_id, case_name, investigator, description, created_at, status, organization, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", ("CASE-IMAGE", "Synthetic test fixture", "Tester", "TEST DATA only", "2026-09-04T00:00:00+00:00", "OPEN", "Test organization", "2026-09-04T00:00:00+00:00"))
    source = tmp_path / "authorized-test-image.img"
    source.write_bytes(b"TEST DATA - synthetic forensic image fixture")
    result = image_importer.import_image("CASE-IMAGE", str(source), "Tester")
    preserved = evidence_root / result["preserved_path"]
    assert preserved.read_bytes() == source.read_bytes()
    assert result["original_filename"] == source.name
    assert len(result["sha256"]) == 64
    assert result["filesystem_analysis"].startswith("Unsupported filesystem")


def test_acquisition_saves_only_controlled_outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(acquisition_manager, "EVIDENCE_DIR", tmp_path / "evidence")
    fake_manager = FakeDeviceManager()
    with database.connect() as connection:
        connection.execute("INSERT OR REPLACE INTO cases (case_id, case_name, investigator, description, created_at, status, organization, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", ("CASE-TEST", "Test", "Tester", "", "2026-09-04T00:00:00+00:00", "OPEN", "Test organization", "2026-09-04T00:00:00+00:00"))
    result = acquisition_manager.acquire("CASE-TEST", "SERIAL", fake_manager)
    case_root = tmp_path / "evidence" / "CASE-TEST"
    assert result["status"] == "completed"
    assert (case_root / "acquired" / "device_info.json").is_file()
    assert (case_root / "logs" / "logcat.txt").is_file()
    issued = [command for _, command in fake_manager.adb_manager.commands]
    # Core commands must be present in order; GPS strategies may add extra commands
    assert ["content", "query", "--uri", "content://sms", "--projection", "_id:address:date:type:body", "--sort", "date"] in issued
    assert ["content", "query", "--uri", "content://call_log/calls", "--projection", "_id:number:date:duration:type:name", "--sort", "date"] in issued
    assert ["dumpsys", "location"] in issued
    assert ["getprop"] in issued
    assert ["dumpsys", "battery"] in issued
    assert ["logcat", "-d", "-t", "200"] in issued
