import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database.database import connect
from backend.services.evidence_normalization_engine import normalize_case
from backend.services.evidence_correlation_engine import run_correlation_engine
from backend.services.evidence_reliability_engine import run_reliability_engine
from backend.services.evidence_graph_engine import build_evidence_graph
from backend.services.incident_timeline_engine import build_incident_timeline
from backend.services.ai_investigation_service import analyze_case_evidence

client = TestClient(app)

TEST_CASE_ID = "CASE-AI-TEST-99"
TEST_DEV_ID = "DEV-AI-TEST-99"


def _clean(case_id: str):
    with connect() as conn:
        for tbl in [
            "ai_findings",
            "incident_timeline",
            "graph_edges",
            "graph_nodes",
            "evidence_reliability_scores",
            "evidence_correlations",
            "normalized_evidence",
            "sms_messages",
            "call_logs",
            "gps_locations",
            "browser_history",
            "media_files",
            "contacts",
            "applications",
            "files",
            "hashes",
            "chain_of_custody",
            "custody",
            "acquisition_logs",
            "evidence_items",
            "acquisitions",
            "evidence",
            "devices",
            "cases",
        ]:
            try:
                conn.execute(f"DELETE FROM {tbl} WHERE case_id = ?", (case_id,))
            except Exception:
                pass
        conn.commit()


@pytest.fixture(autouse=True)
def setup_and_teardown():
    _clean(TEST_CASE_ID)
    with connect() as conn:
        conn.execute(
            "INSERT INTO cases (case_id, case_name, investigator, status, created_at) VALUES (?, ?, ?, ?, ?)",
            (TEST_CASE_ID, "AI Test Case", "Inspector Holmes", "ACTIVE", "2026-10-01 09:00:00"),
        )
        conn.execute(
            "INSERT INTO devices (device_id, case_id, serial, manufacturer, model, android_version, sdk_version, connection_state, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (TEST_DEV_ID, TEST_CASE_ID, "SERAI9988", "Google", "Pixel 8", "14", "34", "device", "2026-10-01 09:05:00", "2026-10-01 09:05:00"),
        )
        a_id = "ACQ-AI-TEST-99"
        conn.execute(
            "INSERT INTO acquisitions (acquisition_id, case_id, device_id, source, method, status, started_at, last_activity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (a_id, TEST_CASE_ID, TEST_DEV_ID, "adb", "ADB Logical Acquisition", "COMPLETED", "2026-10-01 09:10:00", "2026-10-01 09:10:00"),
        )
        item_id = "ITEM-AI-TEST-99"
        conn.execute(
            "INSERT INTO evidence_items (evidence_item_id, case_id, device_id, acquisition_id, evidence_type, source, timestamp, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (item_id, TEST_CASE_ID, TEST_DEV_ID, a_id, "COMBINED", "ADB", "2026-10-01 10:00:00", "2026-10-01 10:00:00"),
        )
        # Add SMS
        conn.execute(
            """INSERT INTO sms_messages (evidence_item_id, case_id, device_id, acquisition_id, address, body, message_type, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (item_id, TEST_CASE_ID, TEST_DEV_ID, a_id, "+15550199", "Confidential package delivery update", "1", "1726300000000"),
        )
        # Add Call Log
        conn.execute(
            """INSERT INTO call_logs (evidence_item_id, case_id, device_id, acquisition_id, number, name, call_type, duration, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (item_id, TEST_CASE_ID, TEST_DEV_ID, a_id, "+15550199", "Contact Alpha", "1", "145", "1726300100000"),
        )
        # Add GPS
        conn.execute(
            """INSERT INTO gps_locations (evidence_item_id, case_id, device_id, acquisition_id, latitude, longitude, accuracy, provider, timestamp, raw_line)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (item_id, TEST_CASE_ID, TEST_DEV_ID, a_id, "37.7749", "-122.4194", "5.0", "gps", "1726300200000", "gps 37.7749,-122.4194"),
        )
        # Add Browser history
        conn.execute(
            """INSERT INTO browser_history (evidence_item_id, case_id, device_id, acquisition_id, browser, url, title, visit_timestamp, visit_count, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (item_id, TEST_CASE_ID, TEST_DEV_ID, a_id, "Chrome", "https://maps.google.com/warehouse", "Warehouse Location", "1726300300000", 2, "content://browser"),
        )
        conn.commit()

    yield
    _clean(TEST_CASE_ID)


def test_ai_investigation_end_to_end_flow():
    # 1. Normalize
    norm_res = normalize_case(TEST_CASE_ID)
    assert norm_res["total"] >= 4

    # 2. Correlate
    corr_res = run_correlation_engine(TEST_CASE_ID)
    assert corr_res["total_correlations"] >= 1

    # 3. Reliability
    rel_res = run_reliability_engine(TEST_CASE_ID)
    assert rel_res["total_scored"] >= 4

    # 4. Graph
    graph_res = build_evidence_graph(TEST_CASE_ID)
    assert graph_res["nodes_count"] >= 4

    # 5. Timeline
    tl_res = build_incident_timeline(TEST_CASE_ID)
    assert tl_res["total_events"] >= 4

    # 6. Run AI Investigation Service
    report = analyze_case_evidence(TEST_CASE_ID)
    assert "error" not in report
    assert "findings" in report
    assert len(report["findings"]) >= 1

    # Check finding fields and traceability structure
    for f in report["findings"]:
        assert f["finding_id"].startswith("FND-")
        assert "description" in f
        assert isinstance(f["supporting_evidence_ids"], list)
        assert len(f["supporting_evidence_ids"]) > 0
        for evid in f["supporting_evidence_ids"]:
            assert evid.startswith("NORM-EV-") or evid.startswith("NEV-") or evid.startswith("ITEM-")
        assert "related_correlation_ids" in f
        assert "timeline_event_ids" in f
        assert "relationship_summary" in f
        assert "reliability_info" in f
        assert "analysis_explanation" in f
        assert f["category"] in [
            "Significant Events",
            "Communication Patterns",
            "Temporal Patterns",
            "Location Relationships",
            "File Relationships",
            "Application Relationships",
            "Browser/Web Activity Patterns",
            "Potentially Suspicious Patterns",
            "Risk Indicators",
            "Cross-Source Relationships",
        ]

    # 7. Check 12-section AI Forensic Report Payload
    assert "case" in report
    assert "evidence_summary" in report
    es = report["evidence_summary"]
    for key in ["devices", "call_logs", "sms_messages", "gps_locations", "normalized_evidence", "correlations", "timeline_events", "ai_findings"]:
        assert key in es
    assert "integrity_summary" in report
    assert "correlations" in report
    assert "reliability_assessments" in report
    assert "relationship_summary" in report
    assert "timeline" in report
    assert "findings" in report
    assert "supporting_evidence" in report
    assert "investigation_traceability" in report
    assert "limitations" in report
    assert "final_summary" in report

    # Verify traceability chain items
    trace_chain = report["investigation_traceability"]
    assert len(trace_chain) >= 1
    for t_item in trace_chain:
        assert "finding_id" in t_item
        assert "normalized_evidence_id" in t_item
        assert "correlation_ids" in t_item
        assert "original_record_reference" in t_item


def test_ai_investigation_api_endpoints(monkeypatch):
    monkeypatch.setattr("backend.main.get_session_user", lambda _: {"user_id": "TEST", "email": "test@domain.com"})
    # 1. Pipeline trigger
    resp = client.post(f"/api/intelligence/process/{TEST_CASE_ID}")
    assert resp.status_code == 200

    # 2. Get AI investigation analysis
    resp = client.get(f"/api/ai-investigation/{TEST_CASE_ID}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case"]["case_id"] == TEST_CASE_ID
    assert "findings" in data
    assert len(data["findings"]) >= 1
    assert "limitations" in data

    # 3. Generate AI Investigation PDF
    resp = client.get(f"/api/ai-investigation/{TEST_CASE_ID}/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert len(resp.content) > 1000

    # 4. Standard report endpoint
    resp = client.get(f"/api/reports/{TEST_CASE_ID}")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert len(resp.content) > 1000


def test_ai_investigation_empty_case_resilience():
    EMPTY_CASE = "CASE-AI-EMPTY-00"
    with connect() as conn:
        conn.execute(
            "INSERT INTO cases (case_id, case_name, investigator, status, created_at) VALUES (?, ?, ?, ?, ?)",
            (EMPTY_CASE, "Empty Case", "Lead Investigator", "ACTIVE", "2026-10-01 09:00:00"),
        )
        conn.commit()

    try:
        report = analyze_case_evidence(EMPTY_CASE)
        assert report["case"]["case_id"] == EMPTY_CASE
        assert len(report["findings"]) == 0
        # Limitations must explicitly disclose empty artifact sources
        assert any("not present" in lim or "unavailable" in lim or "No" in lim for lim in report["limitations"])
    finally:
        _clean(EMPTY_CASE)
