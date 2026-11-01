"""Automated verification suite for ForensicX Multi-Source Tool Integrations.

Tests:
1. Tool status detection and registry matrix (ADB, Autopsy, Cellebrite, iOS/iTunes).
2. Autopsy workspace preparation, manifest generation, and HTML/TSV report ingestion.
3. Cellebrite UFDR and XML report ingestion, provenance tracking, and evidence mapping.
4. iOS backup folder detection, Manifest.db parsing, standalone database decoding.
5. Encrypted iOS backup safe rejection and forensic integrity enforcement.
6. Tool integration API endpoints, authentication, and case-access authorization.
"""

import json
import plistlib
import sqlite3
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from backend.api.auth_routes import SESSION_COOKIE
from backend.config import EVIDENCE_DIR
from backend.database.database import connect, row, rows, utc_now
from backend.main import app
from backend.services.auth_service import create_default_investigator_session
from backend.services.tool_integrations.integration_registry import registry


@pytest.fixture
def auth_client():
    client = TestClient(app)
    session_id, _ = create_default_investigator_session()
    client.cookies = {SESSION_COOKIE: session_id}
    return client


@pytest.fixture
def test_case():
    case_id = f"CASE-INTEG-{uuid4().hex[:6].upper()}"
    now = utc_now()
    with connect() as conn:
        conn.execute(
            "INSERT INTO cases (case_id, case_name, investigator, description, created_at, status, organization, updated_at) "
            "VALUES (?, 'Multi-Source Integration Test Case', 'Lead Investigator', 'Automated test suite case.', ?, 'OPEN', 'Forensic Unit', ?)",
            (case_id, now, now),
        )
    yield case_id


def test_registry_and_status_matrix():
    """Verify tool detection matrix accurately reflects installed vs unconfigured tools."""
    matrix = registry.get_status_matrix()
    assert matrix["total_tools_supported"] == 4
    tool_ids = [t["tool_id"] for t in matrix["tools"]]
    assert "adb" in tool_ids
    assert "autopsy" in tool_ids
    assert "cellebrite" in tool_ids
    assert "ios_backup" in tool_ids

    # Autopsy is installed on the host
    autopsy_status = next(t for t in matrix["tools"] if t["tool_id"] == "autopsy")
    assert autopsy_status["installed"] is True
    assert "4.23.1" in str(autopsy_status["version"]) or "4." in str(autopsy_status["version"])
    assert autopsy_status["available"] is True

    # Cellebrite has no live hardware dongle, so it must accurately report import-only mode
    cellebrite_status = next(t for t in matrix["tools"] if t["tool_id"] == "cellebrite")
    assert "Import-Only" in cellebrite_status["status_label"] or "Awaiting" in cellebrite_status["status_label"]
    assert cellebrite_status["available"] is True  # Ready for authorized offline file imports

    # iOS adapter is ready for local backups
    ios_status = next(t for t in matrix["tools"] if t["tool_id"] == "ios_backup")
    assert ios_status["available"] is True


def test_autopsy_workspace_preparation(test_case):
    """Test preparing an Autopsy workspace with verified evidence manifest."""
    autopsy_adapter = registry.get_adapter("autopsy")
    assert autopsy_adapter is not None

    res = autopsy_adapter.prepare_case_workspace(test_case, investigator="Lead Investigator")
    assert res["status"] == "SUCCESS"
    assert Path(res["workspace_path"]).is_dir()

    manifest_path = Path(res["manifest_path"])
    assert manifest_path.is_file()
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest_data["forensicx_case_id"] == test_case
    assert manifest_data["target_tool"] == "Autopsy Digital Forensics"

    # Verify event was recorded in tool_integration_events and chain_of_custody
    events = rows("SELECT * FROM tool_integration_events WHERE case_id = ? AND tool_id = 'autopsy'", (test_case,))
    assert len(events) >= 1
    assert events[0]["action"] == "PREPARE_WORKSPACE"


def test_autopsy_html_report_ingestion(tmp_path, test_case):
    """Test ingesting an Autopsy HTML report into ForensicX."""
    autopsy_adapter = registry.get_adapter("autopsy")

    html_content = """
    <!DOCTYPE html>
    <html>
    <head><title>Autopsy Web History Report</title></head>
    <body>
    <h2>Web History</h2>
    <table border="1">
        <tr><th>URL</th><th>Title</th><th>Date Accessed</th><th>Program Name</th></tr>
        <tr><td>https://secure-portal.com/login</td><td>Secure Portal</td><td>2026-03-15 14:30:00</td><td>Chrome</td></tr>
        <tr><td>https://target-bank.org/transfer</td><td>Wire Transfer</td><td>2026-03-15 14:35:12</td><td>Chrome</td></tr>
    </table>
    <h2>Messages</h2>
    <table border="1">
        <tr><th>Phone Number</th><th>Message Body</th><th>Date</th></tr>
        <tr><td>+1-555-0199</td><td>Meet me at the rendezvous point</td><td>2026-03-15 14:40:00</td></tr>
    </table>
    </body>
    </html>
    """
    report_file = tmp_path / "Autopsy_Web_History.html"
    report_file.write_text(html_content, encoding="utf-8")

    result = autopsy_adapter.import_results(test_case, str(report_file), investigator="Lead Investigator")
    assert result["status"] == "SUCCESS"
    assert result["artifacts_parsed"] >= 3

    # Check database insertions
    hist_records = rows("SELECT * FROM browser_history WHERE case_id = ?", (test_case,))
    assert len(hist_records) >= 2
    assert any("secure-portal.com" in r["url"] for r in hist_records)

    msg_records = rows("SELECT * FROM sms_messages WHERE case_id = ?", (test_case,))
    assert len(msg_records) >= 1
    assert any("rendezvous" in r["body"] for r in msg_records)

    # Check evidence preservation and sha256
    ev = row("SELECT * FROM evidence WHERE evidence_id = ?", (result["evidence_id"],))
    assert ev is not None
    assert ev["sha256"] == result["sha256"]
    assert Path(EVIDENCE_DIR / ev["file_path"]).is_file()

    # Check normalized evidence was populated
    norm_count = row("SELECT COUNT(*) as cnt FROM normalized_evidence WHERE case_id = ?", (test_case,))
    assert norm_count["cnt"] >= 3


def test_cellebrite_xml_and_ufdr_import(tmp_path, test_case):
    """Test ingesting Cellebrite XML and UFDR archives."""
    cellebrite_adapter = registry.get_adapter("cellebrite")

    xml_content = """<?xml version="1.0" encoding="utf-8"?>
    <report device="Samsung Galaxy S22" extractor="Cellebrite UFED">
        <calls>
            <call>
                <number>+1-202-555-0143</number>
                <name>Suspect Alpha</name>
                <type>Incoming</type>
                <duration>145</duration>
                <timestamp>2026-03-15T10:15:00Z</timestamp>
            </call>
        </calls>
        <messages>
            <message>
                <from>+1-202-555-0143</from>
                <text>Extraction package encrypted with SHA-256</text>
                <type>Incoming</type>
                <timestamp>2026-03-15T10:18:30Z</timestamp>
            </message>
        </messages>
        <locations>
            <location>
                <latitude>37.7749</latitude>
                <longitude>-122.4194</longitude>
                <timestamp>2026-03-15T10:20:00Z</timestamp>
            </location>
        </locations>
    </report>
    """
    xml_file = tmp_path / "Cellebrite_Extraction.xml"
    xml_file.write_text(xml_content, encoding="utf-8")

    # Ingest XML
    res_xml = cellebrite_adapter.import_export(test_case, str(xml_file), investigator="Lead Investigator")
    assert res_xml["status"] == "SUCCESS"
    assert res_xml["artifacts_parsed"] >= 3

    # Check call logs
    calls = rows("SELECT * FROM call_logs WHERE case_id = ?", (test_case,))
    assert any("+1-202-555-0143" in c["number"] for c in calls)

    # Check locations
    gps = rows("SELECT * FROM gps_locations WHERE case_id = ?", (test_case,))
    assert any("37.7749" in g["latitude"] for g in gps)

    # Now package into a UFDR (.zip container)
    ufdr_file = tmp_path / "Extraction_Package.ufdr"
    with zipfile.ZipFile(ufdr_file, "w") as z:
        z.writestr("report.xml", xml_content)

    res_ufdr = cellebrite_adapter.import_export(test_case, str(ufdr_file), investigator="Lead Investigator")
    assert res_ufdr["status"] == "SUCCESS"
    assert res_ufdr["artifacts_parsed"] >= 3


def test_ios_backup_unencrypted_parsing(tmp_path, test_case):
    """Test parsing an unencrypted iOS backup directory structure with Manifest.db."""
    ios_adapter = registry.get_adapter("ios_backup")

    backup_dir = tmp_path / "00008030-001234567890ABCD"
    backup_dir.mkdir(parents=True)

    # Create Info.plist
    info_dict = {
        "Device Name": "Investigator iPhone 13",
        "Product Version": "16.5",
        "Serial Number": "F2LNTEST1234",
        "Phone Number": "+1-800-555-0199",
    }
    with open(backup_dir / "Info.plist", "wb") as f:
        plistlib.dump(info_dict, f)

    # Create Manifest.plist (IsEncrypted = False)
    with open(backup_dir / "Manifest.plist", "wb") as f:
        plistlib.dump({"IsEncrypted": False}, f)

    # Create sample sms.db
    sms_db_path = backup_dir / "ab" / "abcdef1234567890"
    sms_db_path.parent.mkdir(parents=True, exist_ok=True)
    conn_sms = sqlite3.connect(sms_db_path)
    conn_sms.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);")
    conn_sms.execute("CREATE TABLE message (ROWID INTEGER PRIMARY KEY, handle_id INTEGER, text TEXT, date INTEGER, is_from_me INTEGER);")
    conn_sms.execute("INSERT INTO handle VALUES (1, '+1-555-999-0001');")
    # Date: 650000000 Cocoa seconds
    conn_sms.execute("INSERT INTO message VALUES (1, 1, 'iOS encrypted container verification complete.', 650000000, 0);")
    conn_sms.commit()
    conn_sms.close()

    # Create Manifest.db mapping table
    manifest_db_path = backup_dir / "Manifest.db"
    conn_man = sqlite3.connect(manifest_db_path)
    conn_man.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB);")
    conn_man.execute(
        "INSERT INTO Files (fileID, domain, relativePath, flags) VALUES ('abcdef1234567890', 'HomeDomain', 'Library/SMS/sms.db', 1)"
    )
    conn_man.commit()
    conn_man.close()

    # Ingest the backup folder
    res = ios_adapter.import_backup(test_case, str(backup_dir), investigator="Lead Investigator")
    assert res["status"] == "SUCCESS"
    assert res["device_name"] == "Investigator iPhone 13"
    assert res["artifacts_parsed"] >= 1

    # Verify SMS was parsed and decoded
    sms = rows("SELECT * FROM sms_messages WHERE case_id = ? AND body LIKE '%iOS encrypted container%'", (test_case,))
    assert len(sms) == 1
    assert sms[0]["address"] == "+1-555-999-0001"


def test_ios_encrypted_backup_safe_rejection(tmp_path, test_case):
    """Test that encrypted iOS backups are safely rejected without password guessing."""
    ios_adapter = registry.get_adapter("ios_backup")

    backup_dir = tmp_path / "ENCRYPTED_BACKUP"
    backup_dir.mkdir(parents=True)

    with open(backup_dir / "Info.plist", "wb") as f:
        plistlib.dump({"Device Name": "Encrypted iPhone", "Product Version": "17.0"}, f)

    with open(backup_dir / "Manifest.plist", "wb") as f:
        plistlib.dump({"IsEncrypted": True}, f)

    with pytest.raises(Exception) as excinfo:
        ios_adapter.import_backup(test_case, str(backup_dir), investigator="Lead Investigator")

    assert "ENCRYPTED" in str(excinfo.value)
    assert "422" in str(excinfo.value) or "encrypted" in str(excinfo.value).lower()


def test_tool_integrations_api_endpoints(auth_client, test_case):
    """Test REST API routes for tool integrations."""
    # 1. GET /api/integrations/status
    resp = auth_client.get("/api/integrations/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "tools" in data
    assert len(data["tools"]) == 4

    # 2. GET /api/integrations/autopsy
    resp_autopsy = auth_client.get("/api/integrations/autopsy")
    assert resp_autopsy.status_code == 200
    assert resp_autopsy.json()["tool_id"] == "autopsy"

    # 3. POST /api/integrations/autopsy/prepare/{case_id}
    resp_prep = auth_client.post(f"/api/integrations/autopsy/prepare/{test_case}")
    assert resp_prep.status_code == 200
    assert resp_prep.json()["status"] == "SUCCESS"

    # 4. GET /api/integrations/history/recent
    resp_hist = auth_client.get("/api/integrations/history/recent")
    assert resp_hist.status_code == 200
    assert isinstance(resp_hist.json(), list)

    # 5. Unauthorized call (without session cookie)
    unauth_client = TestClient(app)
    resp_unauth = unauth_client.get("/api/integrations/status")
    assert resp_unauth.status_code == 401


def test_ios_standalone_database_import(tmp_path, test_case):
    """Test importing standalone iOS database files (call_history.db)."""
    ios_adapter = registry.get_adapter("ios_backup")

    db_path = tmp_path / "call_history.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE ZCALLRECORD (ROWID INTEGER PRIMARY KEY, ZADDRESS TEXT, ZDATE REAL, ZDURATION REAL, ZORIGINATED INTEGER, ZANSWERED INTEGER);"
    )
    # 650000000 Cocoa seconds
    conn.execute(
        "INSERT INTO ZCALLRECORD VALUES (1, '+1-800-555-9000', 650000000.0, 180.0, 1, 1);"
    )
    conn.commit()
    conn.close()

    res = ios_adapter.import_backup(test_case, str(db_path), investigator="Lead Investigator")
    assert res["status"] == "SUCCESS"
    assert res["artifacts_parsed"] >= 1

    calls = rows("SELECT * FROM call_logs WHERE case_id = ? AND number LIKE '%+1-800-555-9000%'", (test_case,))
    assert len(calls) == 1
    assert calls[0]["duration"] == "180"


def test_autopsy_tsv_report_ingestion(tmp_path, test_case):
    """Test ingesting Autopsy TSV delimited report."""
    autopsy_adapter = registry.get_adapter("autopsy")

    tsv_content = "URL\tTitle\tDate Accessed\nhttps://darkweb-market.onion\tDark Market\t2026-03-15 15:00:00\n"
    tsv_file = tmp_path / "Web_History.tsv"
    tsv_file.write_text(tsv_content, encoding="utf-8")

    res = autopsy_adapter.import_results(test_case, str(tsv_file), investigator="Lead Investigator")
    assert res["status"] == "SUCCESS"
    assert res["artifacts_parsed"] >= 1

    history = rows("SELECT * FROM browser_history WHERE case_id = ? AND url LIKE '%darkweb-market%'", (test_case,))
    assert len(history) >= 1

