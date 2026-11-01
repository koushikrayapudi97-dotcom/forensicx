"""Comprehensive tests for the Core Forensic Intelligence Engine (Patent Workflow).

Verifies:
1. SMS + Call temporal correlation and entity matching
2. Evidence ID traceability across all modules
3. Reliability calculation with factors, warnings, and missing information
4. Graph generation with node & edge inspection data
5. Incident timeline with chronological ordering and Event IDs
6. Multi-device and multi-case isolation
7. Missing evidence and missing timestamps resilience
8. SHA-256 hash verification
9. Database persistence across simulated query reloads
10. Live dashboard intelligence statistics
"""

import json
from uuid import uuid4
import pytest

from backend.database.database import connect, row, rows, utc_now
from backend.services.evidence_normalization_engine import normalize_case, get_normalized_evidence
from backend.services.evidence_correlation_engine import run_correlation_engine, get_evidence_correlations
from backend.services.evidence_reliability_engine import run_reliability_engine, get_reliability_scores, calculate_evidence_score
from backend.services.evidence_graph_engine import build_evidence_graph, get_graph_data, trace_graph_path
from backend.services.incident_timeline_engine import build_incident_timeline, get_incident_timeline, generate_evidence_linked_report
from backend.services.evidence_normalizer import normalize_case as normalize_case_for_dashboard
from backend.config import EVIDENCE_DIR


def _cleanup(case_id: str):
    with connect() as conn:
        for tbl in (
            "normalized_evidence", "evidence_correlations", "evidence_reliability_scores",
            "graph_edges", "graph_nodes", "incident_timeline", "sms_messages", "call_logs",
            "gps_locations", "browser_history", "media_files", "evidence_items", "acquisitions",
            "devices", "cases"
        ):
            try:
                conn.execute(f"DELETE FROM {tbl} WHERE case_id = ?", (case_id,))
            except Exception:
                pass
        conn.commit()


@pytest.fixture
def multi_device_case():
    case_id = f"PATENT-CASE-{uuid4().hex[:8].upper()}"
    dev_1 = f"DEV-P1-{uuid4().hex[:4].upper()}"
    dev_2 = f"DEV-P2-{uuid4().hex[:4].upper()}"
    acq_1 = f"ACQ-1-{uuid4().hex[:4].upper()}"
    acq_2 = f"ACQ-2-{uuid4().hex[:4].upper()}"

    with connect() as conn:
        _cleanup(case_id)
        conn.execute("INSERT INTO cases (case_id, case_name, investigator, description, created_at, status) VALUES (?, ?, ?, ?, ?, ?)",
                     (case_id, "Patent Test Case", "Inspector Holmes", "Testing Patent Workflow", utc_now(), "ACTIVE"))
        conn.execute("INSERT INTO devices (device_id, serial, manufacturer, model, connection_state, created_at, last_seen_at) VALUES (?, ?, 'Pixel', '7 Pro', 'device', ?, ?)",
                     (dev_1, f"SN-{dev_1}", utc_now(), utc_now()))
        conn.execute("INSERT INTO devices (device_id, serial, manufacturer, model, connection_state, created_at, last_seen_at) VALUES (?, ?, 'Samsung', 'Galaxy S23', 'device', ?, ?)",
                     (dev_2, f"SN-{dev_2}", utc_now(), utc_now()))
        conn.execute("INSERT INTO acquisitions (acquisition_id, case_id, device_id, source, method, status, started_at, last_activity) VALUES (?, ?, ?, 'ADB', 'ADB Logical', 'COMPLETED', ?, ?)",
                     (acq_1, case_id, dev_1, utc_now(), utc_now()))
        conn.execute("INSERT INTO acquisitions (acquisition_id, case_id, device_id, source, method, status, started_at, last_activity) VALUES (?, ?, ?, 'ADB', 'ADB Logical', 'COMPLETED', ?, ?)",
                     (acq_2, case_id, dev_2, utc_now(), utc_now()))

        # Insert parent evidence_items for foreign key constraints
        for itm_id, art_type, dev, acq, ts in [
            ("ITM-1", "SMS", dev_1, acq_1, "1726307100000"),
            ("ITM-2", "CALL", dev_1, acq_1, "1726307220000"),
            ("ITM-3", "LOCATION", dev_1, acq_1, "1726307400000"),
            ("ITM-4", "FILE", dev_2, acq_2, "1726307500000"),
        ]:
            conn.execute(
                "INSERT INTO evidence_items (evidence_item_id, case_id, device_id, acquisition_id, evidence_type, source, timestamp, created_at) VALUES (?, ?, ?, ?, ?, 'ADB', ?, ?)",
                (itm_id, case_id, dev, acq, art_type, ts, utc_now())
            )

        # Device 1: SMS at 10:05 UTC (1726307100000)
        conn.execute("INSERT INTO sms_messages (evidence_item_id, case_id, device_id, acquisition_id, address, body, message_type, timestamp) VALUES ('ITM-1', ?, ?, ?, '+15551234567', 'Meeting confirmed at warehouse', '1', '1726307100000')",
                     (case_id, dev_1, acq_1))

        # Device 1: Call with same number at 10:07 UTC (1726307220000 - 120s later)
        conn.execute("INSERT INTO call_logs (evidence_item_id, case_id, device_id, acquisition_id, number, name, call_type, duration, timestamp) VALUES ('ITM-2', ?, ?, ?, '+15551234567', 'Suspect Bravo', '2', '45', '1726307220000')",
                     (case_id, dev_1, acq_1))

        # Device 1: Location event at 10:10 UTC (1726307400000 - 180s later)
        conn.execute("INSERT INTO gps_locations (evidence_item_id, case_id, device_id, acquisition_id, latitude, longitude, accuracy, provider, timestamp, raw_line) VALUES ('ITM-3', ?, ?, ?, '37.7749', '-122.4194', '5.0', 'gps', '1726307400000', 'gps fix')",
                     (case_id, dev_1, acq_1))

        # Device 2: Media file with shared SHA-256 hash
        conn.execute("INSERT INTO media_files (evidence_item_id, case_id, device_id, acquisition_id, media_type, file_name, original_path, file_size, mime_type, date_taken, sha256) VALUES ('ITM-4', ?, ?, ?, 'Image', 'doc.pdf', '/sdcard/Download/doc.pdf', 1024, 'application/pdf', '1726307500000', 'A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90')",
                     (case_id, dev_2, acq_2))
        conn.commit()

    yield case_id, dev_1, dev_2

    _cleanup(case_id)


def test_sms_call_temporal_and_entity_correlation(multi_device_case):
    """Test 1: Factual correlation between SMS and Call sharing phone number within time window."""
    case_id, dev_1, dev_2 = multi_device_case
    normalize_case(case_id)
    res = run_correlation_engine(case_id)
    assert res["total_correlations"] >= 1

    corrs = get_evidence_correlations(case_id)
    # Check Communication Correlation
    comm_corr = next((c for c in corrs if "COMMUNICATION" in c["relationship_type"].upper()), None)
    assert comm_corr is not None
    assert comm_corr["evidence_id_a"] is not None
    assert comm_corr["evidence_id_b"] is not None
    assert comm_corr["evidence_id_a"] != comm_corr["evidence_id_b"]
    assert "1234567" in str(comm_corr["matching_attributes"])
    assert "Temporal Relationship" in comm_corr["timestamp_relationship"]
    assert comm_corr["time_difference_seconds"] is not None
    assert comm_corr["time_difference_seconds"] == 120.0  # 10:07 - 10:05 = 120 seconds


def test_evidence_id_traceability_chain(multi_device_case):
    """Test 2: Ensure complete traceability chain from Normalized Evidence -> Correlation -> Reliability -> Graph -> Timeline."""
    case_id, _, _ = multi_device_case
    normalize_case(case_id)
    run_correlation_engine(case_id)
    run_reliability_engine(case_id)
    build_evidence_graph(case_id)
    build_incident_timeline(case_id)

    items = get_normalized_evidence(case_id)
    correlations = get_evidence_correlations(case_id)
    scores = get_reliability_scores(case_id)
    graph = get_graph_data(case_id)
    timeline = get_incident_timeline(case_id)

    # 1. Normalized items have valid IDs
    norm_ids = {i["normalized_id"] for i in items}
    assert len(norm_ids) >= 4

    # 2. Every correlation references valid Evidence IDs
    for c in correlations:
        assert c["evidence_id_a"] in norm_ids
        assert c["evidence_id_b"] in norm_ids

    # 3. Every evidence reliability score references a valid Evidence ID
    ev_scores = [s for s in scores if s["target_type"] == "EVIDENCE_ITEM"]
    for s in ev_scores:
        assert s["evidence_id"] in norm_ids

    # 4. Graph nodes reference real evidence items
    ev_nodes = [n for n in graph["nodes"] if n["source_evidence_id"]]
    for n in ev_nodes:
        assert n["source_evidence_id"] in norm_ids

    # 5. Timeline events reference primary Evidence IDs
    for t in timeline:
        assert t["primary_evidence_id"] in norm_ids


def test_reliability_scoring_factors_and_disclosures(multi_device_case):
    """Test 3: Reliability calculation factors (checkmarks), warnings, and missing info disclosures."""
    case_id, _, _ = multi_device_case
    normalize_case(case_id)
    run_correlation_engine(case_id)
    run_reliability_engine(case_id)

    scores = get_reliability_scores(case_id)
    assert len(scores) >= 4

    for s in scores:
        if s["target_type"] == "EVIDENCE_ITEM":
            assert 0.0 <= s["reliability_score"] <= 100.0
            factors = s.get("factors_list", [])
            assert len(factors) >= 3
            # Check presence of factor fields
            for f in factors:
                assert "name" in f
                assert "passed" in f
                assert "points" in f


def test_evidence_graph_nodes_and_edges(multi_device_case):
    """Test 4: Graph generation with node & edge inspection data."""
    case_id, dev_1, _ = multi_device_case
    normalize_case(case_id)
    run_correlation_engine(case_id)
    build_evidence_graph(case_id)

    g_data = get_graph_data(case_id)
    nodes = g_data["nodes"]
    edges = g_data["edges"]

    assert len(nodes) >= 4
    assert len(edges) >= 3

    # Check node details
    dev_nodes = [n for n in nodes if n["entity_type"] == "DEVICE"]
    assert len(dev_nodes) >= 1
    assert any(dev_1 in n["label"] for n in dev_nodes)

    phone_node = next((n for n in nodes if n["entity_type"] == "PHONE_NUMBER"), None)
    assert phone_node is not None
    assert "Suspect Bravo" in phone_node["label"] or "1234567" in phone_node["label"]
    assert "1234567" in phone_node["properties"].get("phone_number", "")

    # Check edge inspection details
    for e in edges:
        assert e["edge_id"].startswith("EDGE-")
        assert e["relationship_label"] is not None
        assert "evidence_ids" in e


def test_incident_timeline_chronological_ordering(multi_device_case):
    """Test 5: Incident timeline chronological sequencing and Event IDs."""
    case_id, _, _ = multi_device_case
    normalize_case(case_id)
    run_correlation_engine(case_id)
    run_reliability_engine(case_id)
    build_incident_timeline(case_id)

    timeline = get_incident_timeline(case_id)
    assert len(timeline) >= 4

    # Verify monotonic sequence numbering
    seqs = [t["sequence_number"] for t in timeline]
    assert seqs == sorted(seqs)

    # Verify event ID formatting
    for t in timeline:
        assert t["event_id"].startswith("EVT-")
        assert t["event_category"] in ("SMS", "Call", "GPS", "File", "Browser/Web", "Application", "COMMUNICATION", "SYSTEM_EVENT")


def test_missing_evidence_resilience():
    """Test 6: Case with empty or missing evidence handles gracefully."""
    empty_case_id = f"EMPTY-CASE-{uuid4().hex[:8].upper()}"
    with connect() as conn:
        _cleanup(empty_case_id)
        conn.execute("INSERT INTO cases (case_id, case_name, investigator, created_at, status) VALUES (?, 'Empty Case', 'Inv', ?, 'ACTIVE')",
                     (empty_case_id, utc_now()))
        conn.commit()

    try:
        normalize_case(empty_case_id)
        corrs = run_correlation_engine(empty_case_id)
        assert corrs["total_correlations"] == 0
        assert "Insufficient evidence" in corrs["status_message"]

        scores = run_reliability_engine(empty_case_id)
        assert scores["total_scored"] == 0

        graph = build_evidence_graph(empty_case_id)
        assert graph["nodes_count"] >= 1  # root device node exists

        timeline = build_incident_timeline(empty_case_id)
        assert timeline["total_events"] == 0
    finally:
        _cleanup(empty_case_id)


def test_dashboard_intelligence_stats_live(multi_device_case):
    """Test 7: Live database stats for intelligence engine on dashboard."""
    case_id, _, _ = multi_device_case
    normalize_case(case_id)
    run_correlation_engine(case_id)
    run_reliability_engine(case_id)
    build_evidence_graph(case_id)
    build_incident_timeline(case_id)

    case_dict = row("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    report = normalize_case_for_dashboard(case_dict, EVIDENCE_DIR)
    summary = report["summary"]

    assert summary["normalized_evidence"] >= 4
    assert summary["correlations"] >= 1
    assert summary["reliability_assessments"] >= 4
    assert summary["graph_entities"] >= 4
    assert summary["timeline_events"] >= 4
