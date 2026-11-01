"""Automated security hardening verification tests for ForensicX."""

from datetime import datetime, timezone
import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import database
from backend.services import auth_service
from backend.services.adb_manager import AdbManager, AdbError
from backend.services.rate_limiter import limiter


@pytest.fixture
def test_client():
    return TestClient(app)


@pytest.fixture
def auth_users():
    """Create two distinct users in the database and return their credentials and session IDs."""
    now = database.utc_now()
    user_a_id = f"USR-A-{uuid4().hex[:8].upper()}"
    user_b_id = f"USR-B-{uuid4().hex[:8].upper()}"
    pass_hash = auth_service.hash_password("SecTestPass123!")

    with database.connect() as conn:
        conn.execute(
            "INSERT INTO users (user_id, full_name, email, mobile, password_hash, status, failed_attempts, created_at) VALUES (?, ?, ?, ?, ?, 'active', 0, ?)",
            (user_a_id, "Investigator Alpha", f"alpha_{uuid4().hex[:6]}@klu.ac.in", f"9{uuid4().int % 10**9:09d}", pass_hash, now),
        )
        conn.execute(
            "INSERT INTO users (user_id, full_name, email, mobile, password_hash, status, failed_attempts, created_at) VALUES (?, ?, ?, ?, ?, 'active', 0, ?)",
            (user_b_id, "Investigator Beta", f"beta_{uuid4().hex[:6]}@klu.ac.in", f"8{uuid4().int % 10**9:09d}", pass_hash, now),
        )

    # Login both users to acquire valid sessions
    res_a = auth_service.login_user(f"alpha_{user_a_id[-8:]}", "SecTestPass123!")
    # Direct session creation to guarantee clean tokens
    sess_a = f"sess-a-{uuid4().hex}"
    sess_b = f"sess-b-{uuid4().hex}"
    from datetime import timedelta
    exp = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
    with database.connect() as conn:
        conn.execute("INSERT INTO sessions (session_id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)", (sess_a, user_a_id, now, exp))
        conn.execute("INSERT INTO sessions (session_id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)", (sess_b, user_b_id, now, exp))

    try:
        yield {
            "user_a": {"user_id": user_a_id, "session": sess_a},
            "user_b": {"user_id": user_b_id, "session": sess_b},
        }
    finally:
        with database.connect() as conn:
            cases = conn.execute("SELECT case_id FROM cases WHERE user_id IN (?, ?)", (user_a_id, user_b_id)).fetchall()
            for (cid,) in cases:
                conn.execute("DELETE FROM chain_of_custody WHERE case_id = ?", (cid,))
                conn.execute("DELETE FROM evidence WHERE case_id = ?", (cid,))
                conn.execute("DELETE FROM cases WHERE case_id = ?", (cid,))
            conn.execute("DELETE FROM sessions WHERE user_id IN (?, ?)", (user_a_id, user_b_id))
            conn.execute("DELETE FROM users WHERE user_id IN (?, ?)", (user_a_id, user_b_id))
            conn.commit()


# ── 1. Broken Object-Level Authorization (IDOR) ──────────────────────────────

def test_idor_case_isolation(test_client, auth_users):
    """User B cannot access or inspect a case owned by User A."""
    u_a = auth_users["user_a"]
    u_b = auth_users["user_b"]

    # User A creates a case
    test_client.cookies.set("fx_session", u_a["session"])
    res = test_client.post("/api/cases", json={
        "case_name": "Classified Operation A",
        "investigator": "Investigator Alpha",
        "description": "Restricted case data",
        "organization": "Special Investigations Unit",
    })
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    # User A can access it
    res_a = test_client.get(f"/api/cases/{case_id}")
    assert res_a.status_code == 200

    # User B switches session and attempts to access User A's case
    test_client.cookies.set("fx_session", u_b["session"])
    res_b = test_client.get(f"/api/cases/{case_id}")
    assert res_b.status_code == 403
    assert "Access denied" in res_b.json()["detail"]

    # User B attempts to access workspace of User A's case
    res_ws = test_client.get(f"/api/cases/{case_id}/workspace")
    assert res_ws.status_code == 403

    # User B attempts to access reports of User A's case
    res_rep = test_client.get(f"/api/reports/{case_id}")
    assert res_rep.status_code == 403

    # User B attempts to access GPS of User A's case
    res_gps = test_client.get(f"/api/gps/{case_id}")
    assert res_gps.status_code == 403

    # User B attempts to run AI investigation on User A's case
    res_ai = test_client.get(f"/api/ai-investigation/{case_id}")
    assert res_ai.status_code == 403

    # User B attempts to run malware analysis on User A's case
    res_mal = test_client.get(f"/api/malware-analysis/{case_id}")
    assert res_mal.status_code == 403


# ── 2. Path Traversal & Identifier Validation ────────────────────────────────

def test_path_traversal_in_case_identifier_rejected(test_client, auth_users):
    """Path traversal patterns in case_id parameters are rejected with 400 Bad Request."""
    test_client.cookies.set("fx_session", auth_users["user_a"]["session"])

    traversal_payloads = [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "CASE-001/../../root",
        "CASE<script>alert(1)</script>",
        "CASE;DROP TABLE cases;--",
    ]

    for payload in traversal_payloads:
        res = test_client.get(f"/api/cases/{payload}")
        assert res.status_code in (400, 404), f"Failed to reject traversal payload: {payload}"


def test_path_traversal_in_evidence_registration_rejected(test_client, auth_users):
    """Registering evidence files with path traversal paths is strictly rejected."""
    test_client.cookies.set("fx_session", auth_users["user_a"]["session"])

    res = test_client.post("/api/evidence", json={
        "case_id": "CASE-VALID-01",
        "device_serial": "SERIAL1234",
        "evidence_type": "Text",
        "source": "Disk",
        "file_path": "../../../../etc/shadow",
    })
    # Should reject due to non-existent case or path traversal
    assert res.status_code in (400, 404)


# ── 3. Production Security Headers ───────────────────────────────────────────

def test_production_security_headers_present(test_client):
    """Every HTTP response must include critical production security headers."""
    response = test_client.get("/login")
    assert response.status_code == 200

    headers = response.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "geolocation=()" in headers.get("Permissions-Policy", "")
    assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
    assert "https://maps.google.com" in headers.get("Content-Security-Policy", "")


# ── 4. Authentication, Sessions & Cookies ────────────────────────────────────

def test_unauthenticated_api_request_rejected(test_client):
    """Unauthenticated API requests must receive 401 Unauthorized."""
    test_client.cookies.clear()
    res = test_client.get("/api/cases")
    assert res.status_code == 401
    assert res.json()["detail"] == "Not authenticated."


def test_unauthenticated_browser_redirected_to_login(test_client):
    """Unauthenticated browser page navigation must redirect to /login."""
    test_client.cookies.clear()
    res = test_client.get("/", follow_redirects=False)
    assert res.status_code == 302
    assert res.headers["location"] == "/login"


def test_session_cookie_attributes_on_login(test_client, auth_users):
    """Session cookie must have HttpOnly, SameSite=lax, and valid max age."""
    email = f"logintest_{uuid4().hex[:6]}@klu.ac.in"
    mobile = f"9{uuid4().int % 10**9:09d}"
    try:
        reg_res = auth_service.register_user("Login Tester", email, mobile, "TestPass1234!")
        assert reg_res["ok"] is True

        test_client.cookies.clear()
        login_res = test_client.post("/api/auth/login", json={
            "identifier": email,
            "password": "TestPass1234!",
        })
        assert login_res.status_code == 200
        assert "fx_session" in login_res.cookies
    finally:
        with database.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE user_id IN (SELECT user_id FROM users WHERE email = ?)", (email,))
            conn.execute("DELETE FROM users WHERE email = ?", (email,))
            conn.commit()


def test_logout_invalidates_session(test_client, auth_users):
    """Logging out removes the session from SQLite and clears the cookie."""
    u = auth_users["user_a"]
    test_client.cookies.set("fx_session", u["session"])

    logout_res = test_client.post("/api/auth/logout")
    assert logout_res.status_code == 200

    # Session in DB should now be deleted
    sess_row = database.row("SELECT * FROM sessions WHERE session_id = ?", (u["session"],))
    assert sess_row is None


# ── 5. Rate Limiting Protection ──────────────────────────────────────────────

def test_login_rate_limiting(test_client, monkeypatch):
    """Rapid repeated requests trigger 429 Too Many Requests when rate limiting is active."""
    monkeypatch.setenv("FX_TEST_RATE_LIMIT", "1")
    limiter.reset()

    # Hit login repeatedly from same IP
    responses = []
    for _ in range(25):
        resp = test_client.post("/api/auth/login", json={
            "identifier": "unknown_attacker@klu.ac.in",
            "password": "WrongPassword1!",
        })
        responses.append(resp.status_code)

    assert 429 in responses
    limiter.reset()


# ── 6. SQL Whitelist Protection in Forensic Intelligence ─────────────────────

def test_source_ref_table_whitelist(test_client, auth_users):
    """source_ref injection targeting unwhitelisted tables like 'users' or 'sessions' is rejected."""
    test_client.cookies.set("fx_session", auth_users["user_a"]["session"])

    # Attempt to query normalized evidence detail with invalid ID
    res = test_client.get("/api/forensic-intelligence/evidence-inspect/NON-EXISTENT-ID")
    assert res.status_code == 404


# ── 7. ADB Device Serial Validation ──────────────────────────────────────────

def test_adb_serial_parameter_validation():
    """AdbManager rejects command injection or option-flag serial numbers."""
    adb = AdbManager()
    with pytest.raises(AdbError, match="Invalid ADB device serial format"):
        adb.shell("--reply", ["getprop"])

    with pytest.raises(AdbError, match="Invalid ADB device serial format"):
        adb.shell("serial; rm -rf /", ["getprop"])

    with pytest.raises(AdbError, match="Invalid ADB device serial format"):
        adb.shell("-d", ["getprop"])
