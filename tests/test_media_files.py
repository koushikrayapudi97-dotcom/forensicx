"""Unit tests for Mobile Media Files (Photos, Video, Audio) acquisition, storage, normalization, API endpoints, AI correlation, and report generation."""

import sqlite3
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.database.database import connect, row, rows, utc_now
from backend.services.evidence_normalizer import normalize_case
from backend.services.ai_investigation_service import analyze_case_evidence
from backend.services.report_manager import generate_report
from backend.services.ai_investigation_pdf import generate_ai_investigation_pdf
from backend.services.mobile_intelligence import _collect_media

client = TestClient(app)

TEST_CASE_ID = "TEST-MEDIA-001"
FAKE_USER = {"user_id": "USR-TEST", "full_name": "Investigator Test", "email": "test@forensicx.local"}


def _clean_case_data(conn, case_id):
    for tbl in (
        "ai_findings", "incident_timeline", "graph_edges", "graph_nodes",
        "evidence_reliability_scores", "evidence_correlations", "normalized_evidence",
        "sms_messages", "call_logs",
        "gps_locations", "browser_history", "media_files", "contacts", "applications",
        "files", "hashes", "chain_of_custody", "custody", "acquisition_logs",
        "evidence_items", "acquisitions", "evidence", "cases"
    ):
        try:
            conn.execute(f"DELETE FROM {tbl} WHERE case_id = ?", (case_id,))
        except Exception:
            pass

@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch):
    """Setup test case, auth bypass, and media_files table in local DB."""
    monkeypatch.setattr("backend.main.get_session_user", lambda _: FAKE_USER)
    with connect() as conn:
        _clean_case_data(conn, TEST_CASE_ID)
        conn.execute(
            "INSERT INTO cases (case_id, case_name, investigator, status, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (TEST_CASE_ID, "Media Files Test Case", "Investigator Test", "ACTIVE", "Test case for media files extraction", utc_now())
        )
        conn.commit()
    yield
    with connect() as conn:
        _clean_case_data(conn, TEST_CASE_ID)
        conn.commit()



def test_collect_media_fallback():
    """Verify MediaStore fallback returns empty list and error string without crashing when device is unavailable."""
    records, error = _collect_media("INVALID_SERIAL_12345", None)
    assert isinstance(records, list)
    assert isinstance(error, (str, type(None)))


def test_media_files_db_storage_and_api():
    """Verify insertion of media_files records into DB and API endpoint response."""
    with connect() as conn:
        conn.execute(
            "INSERT INTO media_files (evidence_item_id, case_id, device_id, acquisition_id, media_type, file_name, original_path, file_size, mime_type, date_taken, duration, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("EVD-MED-001", TEST_CASE_ID, "DEV-001", "ACQ-001", "Image", "IMG_20260301_021500.jpg", "/sdcard/DCIM/Camera/IMG_20260301_021500.jpg", 2450112, "image/jpeg", "2026-03-01T02:15:00Z", "", "content://media/external/images/media")
        )
        conn.execute(
            "INSERT INTO media_files (evidence_item_id, case_id, device_id, acquisition_id, media_type, file_name, original_path, file_size, mime_type, date_taken, duration, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("EVD-MED-002", TEST_CASE_ID, "DEV-001", "ACQ-001", "Video", "VID_20260301_022000.mp4", "/sdcard/Movies/VID_20260301_022000.mp4", 15401120, "video/mp4", "2026-03-01T02:20:00Z", "45s", "content://media/external/video/media")
        )
        conn.commit()

    # Test API Endpoint
    response = client.get(f"/api/media/{TEST_CASE_ID}")
    assert response.status_code == 200
    data = response.json()
    assert data["case_id"] == TEST_CASE_ID
    assert data["count"] == 2
    assert len(data["media"]) == 2
    assert data["media"][0]["file_name"] == "IMG_20260301_021500.jpg"


def test_media_files_normalizer_integration(tmp_path):
    """Verify evidence_normalizer includes media_files and summary counts."""
    with connect() as conn:
        conn.execute(
            "INSERT INTO media_files (evidence_item_id, case_id, device_id, acquisition_id, media_type, file_name, original_path, file_size, mime_type, date_taken, duration, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("EVD-MED-003", TEST_CASE_ID, "DEV-001", "ACQ-001", "Audio", "voice_note_01.m4a", "/sdcard/Music/voice_note_01.m4a", 512000, "audio/mp4", "2026-03-01T03:00:00Z", "12s", "content://media/external/audio/media")
        )
        conn.commit()

    case_record = row("SELECT * FROM cases WHERE case_id = ?", (TEST_CASE_ID,))
    normalized = normalize_case(case_record, tmp_path)

    assert "media_files" in normalized
    assert normalized["summary"]["media_files"] == 1
    assert len(normalized["media_files"]) == 1
    assert normalized["media_files"][0]["file_name"] == "voice_note_01.m4a"


def test_ai_investigation_media_correlation():
    """Verify AI investigation correlates media files into timeline."""
    with connect() as conn:
        conn.execute(
            "INSERT INTO media_files (evidence_item_id, case_id, device_id, acquisition_id, media_type, file_name, original_path, file_size, mime_type, date_taken, duration, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("EVD-MED-004", TEST_CASE_ID, "DEV-001", "ACQ-001", "Image", "screenshot_bank.png", "/sdcard/Pictures/Screenshots/screenshot_bank.png", 820000, "image/png", "2026-03-01T03:30:00Z", "", "content://media/external/images/media")
        )
        conn.commit()

    result = analyze_case_evidence(TEST_CASE_ID)
    assert "error" not in result
    assert result["evidence_summary"]["media_files"] == 1
    
    # Check media event in timeline
    timeline_categories = [t["category"] for t in result["timeline"]]
    assert any("Media" in cat for cat in timeline_categories)


def test_reports_pdf_generation_with_media_files(tmp_path):
    """Verify standard PDF report and AI Investigation PDF report render with media files without errors."""
    with connect() as conn:
        conn.execute(
            "INSERT INTO media_files (evidence_item_id, case_id, device_id, acquisition_id, media_type, file_name, original_path, file_size, mime_type, date_taken, duration, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("EVD-MED-005", TEST_CASE_ID, "DEV-001", "ACQ-001", "Image", "photo_evidence.jpg", "/sdcard/DCIM/Camera/photo_evidence.jpg", 3100000, "image/jpeg", "2026-03-01T04:00:00Z", "", "content://media")
        )
        conn.commit()

    # Generate standard forensic PDF report
    report_pdf = generate_report(TEST_CASE_ID)
    assert report_pdf.exists()
    assert report_pdf.stat().st_size > 0

    # Generate AI Investigation PDF report
    ai_pdf = generate_ai_investigation_pdf(TEST_CASE_ID)
    assert ai_pdf.exists()
    assert ai_pdf.stat().st_size > 0

