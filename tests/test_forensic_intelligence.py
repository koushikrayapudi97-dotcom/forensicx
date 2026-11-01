"""Automated unit and integration test suite for ForensicX Modules 1 through 5."""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.database.database import connect, row, rows, utc_now
from backend.main import app
from backend.services.evidence_correlation_engine import get_evidence_correlations, run_correlation_engine
from backend.services.evidence_graph_engine import build_evidence_graph, get_graph_data, trace_graph_path
from backend.services.evidence_normalization_engine import get_normalized_evidence, normalize_case
from backend.services.evidence_reliability_engine import get_reliability_scores, run_reliability_engine
from backend.services.incident_timeline_engine import build_incident_timeline, generate_evidence_linked_report, get_incident_timeline
from backend.services.report_manager import generate_report


from uuid import uuid4


def _clean_case_data(conn, case_id):
    for tbl in (
        "normalized_evidence", "evidence_correlations", "evidence_reliability_scores",
        "graph_edges", "graph_nodes", "incident_timeline", "sms_messages", "call_logs",
        "gps_locations", "browser_history", "media_files", "contacts", "applications",
        "files", "hashes", "chain_of_custody", "custody", "acquisition_logs",
        "evidence_items", "acquisitions", "evidence", "cases"
    ):
        try:
            conn.execute(f"DELETE FROM {tbl} WHERE case_id = ?", (case_id,))
        except Exception:
            pass


@pytest.fixture
def test_case_id():
    """Create a temporary test case with heterogeneous real evidence records."""
    c_id = f"TEST-CASE-{uuid4().hex[:12].upper()}"
    d_id = f"DEV-TEST-{uuid4().hex[:12].upper()}"
    a_id = f"ACQ-TEST-{uuid4().hex[:12].upper()}"

    with connect() as conn:
        _clean_case_data(conn, c_id)
        conn.execute(
            "INSERT INTO cases (case_id, case_name, investigator, description, created_at, status) VALUES (?, ?, ?, ?, ?, ?)",
            (c_id, "Test Forensic Intelligence Case", "Lead Investigator", "Test Description", utc_now(), "ACTIVE"),
        )
        conn.execute(
            "INSERT INTO devices (device_id, serial, manufacturer, model, android_version, sdk_version, connection_state, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (d_id, f"SERIAL-{uuid4().hex[:6]}", "Google", "Pixel 7", "14", "34", "device", utc_now(), utc_now()),
        )
        conn.execute(
            "INSERT INTO acquisitions (acquisition_id, case_id, device_id, source, method, status, started_at, last_activity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (a_id, c_id, d_id, "adb", "ADB Logical Acquisition", "RUNNING", utc_now(), utc_now()),
        )

        item_id = f"ITEM-{uuid4().hex[:6]}"
        conn.execute(
            "INSERT INTO evidence_items (evidence_item_id, case_id, device_id, acquisition_id, evidence_type, source, timestamp, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (item_id, c_id, d_id, a_id, "SMS", "ADB", utc_now(), utc_now()),
        )

        # 1. SMS record (with Unicode / Devanagari text)
        conn.execute(
            "INSERT INTO sms_messages (evidence_item_id, case_id, device_id, acquisition_id, address, body, message_type, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (item_id, c_id, d_id, a_id, "+919876543210", "Important evidence meeting at location. सावधान!", "1", "1726300000000"),
        )

        # 2. Call log
        conn.execute(
            "INSERT INTO call_logs (evidence_item_id, case_id, device_id, acquisition_id, number, name, call_type, duration, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (item_id, c_id, d_id, a_id, "+919876543210", "Suspect Alpha", "1", "125", "1726300100000"),
        )

        # 3. GPS Location fix
        conn.execute(
            "INSERT INTO gps_locations (evidence_item_id, case_id, device_id, acquisition_id, latitude, longitude, accuracy, provider, timestamp, raw_line) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (item_id, c_id, d_id, a_id, "12.9716", "77.5946", "10.0", "gps", "1726300200000", "gps 12.9716,77.5946 acc=10"),
        )

        # 4. Web History (with suspicious search term)
        conn.execute(
            "INSERT INTO browser_history (evidence_item_id, case_id, device_id, acquisition_id, browser, url, title, visit_timestamp, visit_count, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (item_id, c_id, d_id, a_id, "Chrome", "https://example.com/wipe-factory-reset", "How to factory reset device", "1726300300000", 3, "content://browser"),
        )

        # 5. Media file (with SHA-256)
        conn.execute(
            "INSERT INTO media_files (evidence_item_id, case_id, device_id, acquisition_id, media_type, file_name, original_path, file_size, mime_type, date_taken, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (item_id, c_id, d_id, a_id, "Image", "evidence_photo.jpg", "/sdcard/DCIM/evidence_photo.jpg", 2048576, "image/jpeg", "1726300400000", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
        )

    yield c_id

    with connect() as conn:
        _clean_case_data(conn, c_id)
        conn.commit()


def test_module1_normalization(test_case_id):
    """Test Module 1 Evidence Normalization Engine."""
    res = normalize_case(test_case_id)
    assert res["total"] >= 5
    assert res["success"] >= 5

    items = get_normalized_evidence(test_case_id)
    assert len(items) >= 5

    # Check SMS item normalization & Unicode text
    sms_item = next(i for i in items if i["artifact_type"] == "sms")
    assert sms_item["timestamp_utc"] is not None
    assert sms_item["entity_info"]["address"] == "+919876543210"
    assert "सावधान" in sms_item["content"]["body"]

    # Check GPS item normalization
    gps_item = next(i for i in items if i["artifact_type"] == "gps")
    assert gps_item["location_info"]["latitude"] == 12.9716
    assert gps_item["location_info"]["longitude"] == 77.5946
    assert "google.com/maps" in gps_item["location_info"]["maps_url"]



def test_module1_idempotency(test_case_id):
    """Test that running normalization multiple times does not produce duplicate records."""
    res1 = normalize_case(test_case_id)
    res2 = normalize_case(test_case_id)
    assert res1["total"] == res2["total"]

    items = get_normalized_evidence(test_case_id)
    assert len(items) == res1["total"]


def test_module2_correlation(test_case_id):
    """Test Module 2 Cross-Source Evidence Correlation Engine."""
    res = run_correlation_engine(test_case_id)
    assert res["total_correlations"] >= 1

    corrs = get_evidence_correlations(test_case_id)
    # Must find phone number match between SMS and Call log
    phone_corr = next((c for c in corrs if c["relationship_type"] in ("PHONE_COMMUNICATION_MATCH", "Communication Correlation", "Temporal + Communication Correlation")), None)
    assert phone_corr is not None
    assert phone_corr["matching_attributes"]["matched_phone_number"] == "+919876543210"


def test_module3_reliability_scoring(test_case_id):
    """Test Module 3 Evidence Reliability & Provenance Scoring Engine."""
    res = run_reliability_engine(test_case_id)
    assert res["total_scored"] >= 5
    assert res["average_reliability_score"] > 50.0

    scores = get_reliability_scores(test_case_id)
    for s in scores:
        assert 0.0 <= s["reliability_score"] <= 100.0
        assert s["integrity_status"] in ("VERIFIED", "UNVERIFIED", "NO_HASH", "MISMATCH")


def test_module4_relationship_graph(test_case_id):
    """Test Module 4 Evidence Relationship Graph Engine."""
    res = build_evidence_graph(test_case_id)
    assert res["nodes_count"] >= 5
    assert res["edges_count"] >= 4

    g_data = get_graph_data(test_case_id)
    nodes = g_data["nodes"]
    assert any(n["entity_type"] == "DEVICE" for n in nodes)
    assert any(n["entity_type"] == "PHONE_NUMBER" for n in nodes)

    # Test path tracing between two nodes
    dev_node = next(n for n in nodes if n["entity_type"] == "DEVICE")
    phone_node = next(n for n in nodes if n["entity_type"] == "PHONE_NUMBER")

    path_res = trace_graph_path(test_case_id, dev_node["node_id"], phone_node["node_id"])
    assert path_res["found"] is True
    assert len(path_res["path"]) >= 2


def test_module5_incident_timeline_and_report(test_case_id):
    """Test Module 5 Incident Timeline, AI Report Payload, and PDF Generation."""
    res = build_incident_timeline(test_case_id)
    assert res["total_events"] >= 5
    assert res["suspicious_events"] >= 1  # Web search contains factory reset keyword

    timeline = get_incident_timeline(test_case_id)
    assert len(timeline) >= 5

    payload = generate_evidence_linked_report(test_case_id)
    assert "facts" in payload
    assert "correlations" in payload
    assert "interpretations" in payload

    # Verify report PDF generation
    pdf_path = generate_report(test_case_id)
    assert pdf_path.is_file()
    assert pdf_path.stat().st_size > 1000


def test_case_and_device_isolation(test_case_id):
    """Test strict case and device data isolation."""
    normalize_case(test_case_id)
    other_case_id = f"OTHER-CASE-{uuid4().hex[:8].upper()}"

    with connect() as conn:
        _clean_case_data(conn, other_case_id)
        conn.execute(
            "INSERT INTO cases (case_id, case_name, investigator, description, created_at, status) VALUES (?, ?, ?, ?, ?, ?)",
            (other_case_id, "Other Case", "Investigator B", "Separate Case", utc_now(), "ACTIVE"),
        )
        conn.commit()

    try:
        normalize_case(other_case_id)
        items_other = get_normalized_evidence(other_case_id)
        items_main = get_normalized_evidence(test_case_id)

        assert len(items_other) == 0
        assert len(items_main) >= 5
    finally:
        with connect() as conn:
            _clean_case_data(conn, other_case_id)
            conn.commit()


