"""End-to-End Workflow Integration Test Suite for ForensicX.

Tests the full forensic lifecycle:
Acquisition/Evidence Storage -> File Analysis -> Hash Verification -> Malware Analysis -> AI Investigation -> Final PDF Reports -> Audit History.
"""

from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from backend.config import EVIDENCE_DIR
from backend.database.database import connect, record_chain_event, utc_now
from backend.main import app
from backend.services.hashing import calculate_sha256

client = TestClient(app)

FAKE_USER = {"user_id": "USR-WORKFLOW-TEST", "full_name": "Test Investigator", "email": "investigator@test.com", "status": "active"}


@pytest.fixture
def setup_test_case(monkeypatch):
    """Create a temporary test case and real evidence file on disk."""
    monkeypatch.setattr("backend.main.get_session_user", lambda _: FAKE_USER)
    case_id = "CASE-WORKFLOW-TEST"
    device_serial = "SERIAL-WF-001"

    device_id = "DEV-WF-001"
    acq_id = "ACQ-WF-001"
    ev_id = "EVD-WF-001"

    case_dir = EVIDENCE_DIR / case_id / "acquired"
    case_dir.mkdir(parents=True, exist_ok=True)

    # Create real sample evidence file
    sample_file = case_dir / "sample_artifact.txt"
    sample_file.write_text("ForensicX Evidence Integrity Verification Test Data", encoding="utf-8")
    rel_path = str(sample_file.relative_to(EVIDENCE_DIR))
    sha256_val = calculate_sha256(sample_file)["hash"]
    now = utc_now()

    cleanup_tables = [
        "ai_findings", "incident_timeline", "graph_edges", "graph_nodes",
        "evidence_reliability_scores", "evidence_correlations", "normalized_evidence",
        "call_logs", "sms_messages", "gps_locations", "browser_history", "media_files",
        "files", "contacts", "applications", "hashes", "custody", "chain_of_custody",
        "acquisition_logs", "evidence_items", "evidence", "acquisitions", "cases"
    ]

    with connect() as conn:
        for tbl in cleanup_tables:
            try:
                conn.execute(f"DELETE FROM {tbl} WHERE case_id = ?", (case_id,))
            except Exception:
                pass
        conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
        conn.commit()

    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO cases (case_id, case_name, investigator, description, created_at, status) "
            "VALUES (?, 'Workflow Test Case', 'Investigator Test', 'Automated Test Case', ?, 'ACTIVE')",
            (case_id, now)
        )
        conn.execute(
            "INSERT OR REPLACE INTO devices (device_id, serial, connection_state, created_at, last_seen_at) "
            "VALUES (?, ?, 'connected', ?, ?)",
            (device_id, device_serial, now, now)
        )
        conn.execute(
            "INSERT OR REPLACE INTO acquisitions (acquisition_id, case_id, device_id, status, started_at, ended_at, last_activity) "
            "VALUES (?, ?, ?, 'COMPLETED', ?, ?, ?)",
            (acq_id, case_id, device_id, now, now, now)
        )
        conn.execute(
            "INSERT OR REPLACE INTO evidence (evidence_id, case_id, device_serial, evidence_type, source, file_path, acquired_at, sha256, size, status, device_id, acquisition_id) "
            "VALUES (?, ?, ?, 'file', 'ADB', ?, ?, ?, ?, 'ACQUIRED', ?, ?)",
            (ev_id, case_id, device_serial, rel_path, now, sha256_val, sample_file.stat().st_size, device_id, acq_id)
        )
        conn.execute(
            "INSERT OR REPLACE INTO evidence_items (evidence_item_id, case_id, device_id, acquisition_id, evidence_type, source, original_path, timestamp, hash, created_at, legacy_evidence_id) "
            "VALUES (?, ?, ?, ?, 'file', 'ADB', ?, ?, ?, ?, ?)",
            (ev_id, case_id, device_id, acq_id, rel_path, now, sha256_val, now, ev_id)
        )
        conn.execute(
            "INSERT OR REPLACE INTO chain_of_custody (case_id, device_id, acquisition_id, evidence_item_id, event_type, action, actor, person, timestamp, description) "
            "VALUES (?, ?, ?, ?, 'EVIDENCE_ACQUIRED', 'EVIDENCE_ACQUIRED', 'Investigator', 'Investigator', ?, 'Acquired test evidence file')",
            (case_id, device_id, acq_id, ev_id, now)
        )


    yield {
        "case_id": case_id,
        "device_id": device_id,
        "acquisition_id": acq_id,
        "evidence_id": ev_id,
        "file_path": sample_file,
        "sha256": sha256_val,
    }

    try:
        sample_file.unlink(missing_ok=True)
    except Exception:
        pass

    with connect() as conn:
        for tbl in cleanup_tables:
            try:
                conn.execute(f"DELETE FROM {tbl} WHERE case_id = ?", (case_id,))
            except Exception:
                pass
        conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
        conn.commit()


def test_full_workflow_end_to_end(setup_test_case):
    info = setup_test_case
    case_id = info["case_id"]
    ev_id = info["evidence_id"]

    # 1. File Analysis
    resp_meta = client.get(f"/api/analysis/metadata/{ev_id}")
    assert resp_meta.status_code == 200, resp_meta.text
    meta = resp_meta.json()
    assert meta["status"] == "metadata present"
    assert meta["filename"] == "sample_artifact.txt"
    assert meta["sha256"] == info["sha256"]
    assert meta["size"] == info["file_path"].stat().st_size

    # 2. Hash Verification
    resp_verify = client.post(f"/api/evidence/{ev_id}/verify")
    assert resp_verify.status_code == 200, resp_verify.text
    verify_data = resp_verify.json()
    assert verify_data["verified"] is True
    assert verify_data["evidence_id"] == ev_id

    # 3. Malware Analysis
    resp_malware = client.get(f"/api/malware-analysis/{case_id}")
    assert resp_malware.status_code == 200, resp_malware.text
    malware_data = resp_malware.json()
    assert "summary" in malware_data
    assert "results" in malware_data
    # Verify PDF generation
    resp_malware_pdf = client.get(f"/api/malware-analysis/{case_id}/pdf")
    assert resp_malware_pdf.status_code == 200
    assert resp_malware_pdf.headers["content-type"] == "application/pdf"

    # 4. AI Investigation
    resp_ai = client.get(f"/api/ai-investigation/{case_id}")
    assert resp_ai.status_code == 200, resp_ai.text
    ai_data = resp_ai.json()
    assert "summary" in ai_data
    assert "findings" in ai_data
    assert "correlations" in ai_data
    # Verify PDF generation
    resp_ai_pdf = client.get(f"/api/ai-investigation/{case_id}/pdf")
    assert resp_ai_pdf.status_code == 200
    assert resp_ai_pdf.headers["content-type"] == "application/pdf"

    # 5. Audit History Verification
    resp_audit = client.get("/api/cases/history/audit")
    assert resp_audit.status_code == 200, resp_audit.text
    audit_logs = resp_audit.json()
    case_actions = [a["action"] for a in audit_logs if a["case_id"] == case_id]

    assert "FILE_ANALYSIS_PERFORMED" in case_actions
    assert "HASH_VERIFIED" in case_actions
    assert "MALWARE_ANALYSIS_PERFORMED" in case_actions
    assert "MALWARE_REPORT_GENERATED" in case_actions
    assert "AI_INVESTIGATION_PERFORMED" in case_actions
    assert "AI_INVESTIGATION_REPORT_GENERATED" in case_actions
