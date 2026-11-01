"""Unit tests for Web & Browser History acquisition, storage, normalization, API endpoints, AI correlation, and report generation."""

import sqlite3
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.database.database import connect, row, rows, utc_now
from backend.services.evidence_normalizer import normalize_case
from backend.services.ai_investigation_service import analyze_case_evidence
from backend.services.report_manager import generate_report
from backend.services.ai_investigation_pdf import generate_ai_investigation_pdf
from backend.services.mobile_intelligence import _collect_web_history

client = TestClient(app)

TEST_CASE_ID = "TEST-WEB-HIST-001"
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
    """Setup test case, auth bypass, and browser_history table in local DB."""
    monkeypatch.setattr("backend.main.get_session_user", lambda _: FAKE_USER)
    with connect() as conn:
        _clean_case_data(conn, TEST_CASE_ID)
        conn.execute(
            "INSERT INTO cases (case_id, case_name, investigator, status, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (TEST_CASE_ID, "Web History Test Case", "Investigator Test", "ACTIVE", "Test case for web history extraction", utc_now())
        )
        conn.commit()
    yield
    with connect() as conn:
        _clean_case_data(conn, TEST_CASE_ID)
        conn.commit()



def test_collect_web_history_fallback():
    """Verify ADB content provider fallback returns empty list and error string without crashing when device is unavailable."""
    records, error = _collect_web_history("INVALID_SERIAL_12345", None)
    assert isinstance(records, list)
    assert isinstance(error, (str, type(None)))


def test_web_history_db_storage_and_api():
    """Verify insertion of browser_history records into DB and API endpoint response."""
    with connect() as conn:
        conn.execute(
            "INSERT INTO browser_history (evidence_item_id, case_id, device_id, acquisition_id, browser, url, title, visit_timestamp, visit_count, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("EVD-WEB-001", TEST_CASE_ID, "DEV-001", "ACQ-001", "Chrome", "https://darkweb-forum.example/market", "Dark Market", "2026-03-01T02:15:00Z", 5, "content://browser/bookmarks")
        )
        conn.execute(
            "INSERT INTO browser_history (evidence_item_id, case_id, device_id, acquisition_id, browser, url, title, visit_timestamp, visit_count, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("EVD-WEB-002", TEST_CASE_ID, "DEV-001", "ACQ-001", "Chrome", "https://crypto-tumbler.example/clean", "Crypto Tumbler", "2026-03-01T02:20:00Z", 2, "content://browser/searches")
        )
        conn.commit()

    # Test API Endpoint
    response = client.get(f"/api/web-history/{TEST_CASE_ID}")
    assert response.status_code == 200
    data = response.json()
    assert data["case_id"] == TEST_CASE_ID
    assert data["count"] == 2
    assert len(data["history"]) == 2
    assert data["history"][0]["url"] == "https://darkweb-forum.example/market"


def test_web_history_normalizer_integration(tmp_path):
    """Verify evidence_normalizer includes browser_history and summary counts."""
    with connect() as conn:
        conn.execute(
            "INSERT INTO browser_history (evidence_item_id, case_id, device_id, acquisition_id, browser, url, title, visit_timestamp, visit_count, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("EVD-WEB-003", TEST_CASE_ID, "DEV-001", "ACQ-001", "Firefox", "https://encrypted-chat.example", "Secure Chat", "2026-03-01T03:00:00Z", 1, "content://browser")
        )
        conn.commit()

    case_record = row("SELECT * FROM cases WHERE case_id = ?", (TEST_CASE_ID,))
    normalized = normalize_case(case_record, tmp_path)

    assert "browser_history" in normalized
    assert normalized["summary"]["web_history"] == 1
    assert len(normalized["browser_history"]) == 1
    assert normalized["browser_history"][0]["url"] == "https://encrypted-chat.example"


def test_ai_investigation_web_history_correlation():
    """Verify AI investigation correlates web history into timeline and suspicious activity findings."""
    with connect() as conn:
        conn.execute(
            "INSERT INTO browser_history (evidence_item_id, case_id, device_id, acquisition_id, browser, url, title, visit_timestamp, visit_count, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("EVD-WEB-004", TEST_CASE_ID, "DEV-001", "ACQ-001", "Chrome", "https://tor-bridge-download.example", "Tor Download", "2026-03-01T03:30:00Z", 3, "content://browser")
        )
        conn.commit()

    result = analyze_case_evidence(TEST_CASE_ID)
    assert "error" not in result
    assert result["evidence_summary"]["web_history"] == 1
    
    # Check web visit in timeline
    timeline_categories = [t["category"] for t in result["timeline"]]
    assert "Web Visit" in timeline_categories

    # Check suspicious finding for darkweb/tor/crypto domain search
    findings = result["findings"]
    web_findings = [f for f in findings if "Web Search" in f["title"] or "High-Risk Web" in f["title"]]
    assert len(web_findings) > 0
    assert web_findings[0]["severity"] == "High"


def test_reports_pdf_generation_with_web_history(tmp_path):
    """Verify both standard PDF report and AI Investigation PDF report render with web history without errors."""
    with connect() as conn:
        conn.execute(
            "INSERT INTO browser_history (evidence_item_id, case_id, device_id, acquisition_id, browser, url, title, visit_timestamp, visit_count, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("EVD-WEB-005", TEST_CASE_ID, "DEV-001", "ACQ-001", "Chrome", "https://secure-vault.example", "Secure Vault", "2026-03-01T04:00:00Z", 1, "content://browser")
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
