"""Authentication and intrusion detection tests (18 cases)."""

import time
from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient

from backend.database import database
from backend.services import auth_service
from backend.main import app


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Each test gets its own in-memory-equivalent SQLite database."""
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "auth_test.db")
    database.initialize_database()


@pytest.fixture()
def client():
    return TestClient(app, raise_server_exceptions=True)


def _register(client, *, mobile="9876543210", email="inv@example.com",
               password="SecurePass1", name="Test Investigator"):
    return client.post("/api/auth/register", json={
        "full_name": name,
        "mobile": mobile,
        "email": email,
        "password": password,
        "confirm_password": password,
    })


def _login(client, identifier="inv@example.com", password="SecurePass1"):
    return client.post("/api/auth/login", json={
        "identifier": identifier,
        "password": password,
    })


# ── 1. Successful registration ────────────────────────────────────────────────

def test_01_successful_registration(client):
    response = _register(client)
    assert response.status_code == 201
    data = response.json()
    assert "user_id" in data
    assert data["user_id"].startswith("USR-")


# ── 2. Duplicate email registration ──────────────────────────────────────────

def test_02_duplicate_email_registration(client):
    _register(client)
    response = _register(client, mobile="9123456780")  # different mobile, same email
    assert response.status_code == 400
    assert "email" in response.json()["detail"].lower()


# ── 3. Duplicate mobile registration ─────────────────────────────────────────

def test_03_duplicate_mobile_registration(client):
    _register(client)
    response = _register(client, email="other@example.com")  # different email, same mobile
    assert response.status_code == 400
    assert "mobile" in response.json()["detail"].lower()


# ── 4. Successful login with email ────────────────────────────────────────────

def test_04_login_with_email(client):
    _register(client)
    response = _login(client, identifier="inv@example.com")
    assert response.status_code == 200
    assert response.json()["full_name"] == "Test Investigator"
    assert "fx_session" in response.cookies


# ── 5. Successful login with mobile number ────────────────────────────────────

def test_05_login_with_mobile(client):
    _register(client)
    response = _login(client, identifier="9876543210")
    assert response.status_code == 200
    assert "fx_session" in response.cookies


# ── 6. Incorrect password ─────────────────────────────────────────────────────

def test_06_incorrect_password(client):
    _register(client)
    response = _login(client, password="WrongPassword!")
    assert response.status_code == 401
    assert "Invalid login credentials" in response.json()["detail"]


# ── 7. First failed attempt ───────────────────────────────────────────────────

def test_07_first_failed_attempt(client):
    _register(client)
    response = _login(client, password="bad1")
    assert response.status_code == 401
    assert "3 attempt(s) remaining" in response.json()["detail"]


# ── 8. Second failed attempt ──────────────────────────────────────────────────

def test_08_second_failed_attempt(client):
    _register(client)
    _login(client, password="bad1")
    response = _login(client, password="bad2")
    assert response.status_code == 401
    assert "2 attempt(s) remaining" in response.json()["detail"]


# ── 9. Third failed attempt ───────────────────────────────────────────────────

def test_09_third_failed_attempt(client):
    _register(client)
    for _ in range(2):
        _login(client, password="bad")
    response = _login(client, password="bad3")
    assert response.status_code == 401
    assert "1 attempt(s) remaining" in response.json()["detail"]


# ── 10. Fourth failed attempt triggers lockout ────────────────────────────────

def test_10_fourth_attempt_triggers_lockout(client):
    _register(client)
    for _ in range(3):
        _login(client, password="bad")
    response = _login(client, password="bad4")
    assert response.status_code == 423
    assert "locked" in response.json()["detail"].lower()


# ── 11. Account temporarily locked message ────────────────────────────────────

def test_11_account_locked_message(client):
    _register(client)
    for _ in range(4):
        _login(client, password="bad")
    response = _login(client, password="bad5")
    assert response.status_code == 423
    detail = response.json()["detail"]
    assert "temporarily locked" in detail.lower()
    assert "multiple failed" in detail.lower()


# ── 12. Login blocked during lockout ─────────────────────────────────────────

def test_12_login_blocked_during_lockout(client):
    _register(client)
    for _ in range(4):
        _login(client, password="bad")
    # Even correct password is blocked during lockout
    response = _login(client, password="SecurePass1")
    assert response.status_code == 423


# ── 13. Successful login after lockout expires ────────────────────────────────

def test_13_login_after_lockout_expires(client, monkeypatch):
    _register(client)
    for _ in range(4):
        _login(client, password="bad")

    # Manually expire the lockout by setting locked_until to the past
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with database.connect() as connection:
        connection.execute("UPDATE users SET locked_until = ?", (past,))

    response = _login(client, password="SecurePass1")
    assert response.status_code == 200
    assert "fx_session" in response.cookies


# ── 14. Logout ────────────────────────────────────────────────────────────────

def test_14_logout(client):
    _register(client)
    _login(client)
    response = client.post("/api/auth/logout")
    assert response.status_code == 200
    # Session cookie should be cleared
    assert response.cookies.get("fx_session", "") == ""


# ── 15. Protected route without authentication ────────────────────────────────

def test_15_protected_route_without_auth(client):
    # Fresh client with no session cookie
    fresh = TestClient(app, raise_server_exceptions=True)
    response = fresh.get("/api/cases", follow_redirects=False)
    assert response.status_code == 401
    assert "Not authenticated" in response.json()["detail"]


# ── 16. Password hash is not plaintext ───────────────────────────────────────

def test_16_password_not_stored_as_plaintext(client):
    _register(client, password="MySecret123")
    stored = database.row("SELECT password_hash FROM users WHERE email = ?", ("inv@example.com",))
    assert stored is not None
    assert stored["password_hash"] != "MySecret123"
    assert stored["password_hash"].startswith("$2b$")  # bcrypt prefix


# ── 17. Security event creation ──────────────────────────────────────────────

def test_17_security_events_recorded(client):
    _register(client)
    _login(client, password="wrong")
    _login(client, password="SecurePass1")

    events = database.rows("SELECT event_type FROM security_events ORDER BY id")
    event_types = [e["event_type"] for e in events]
    assert "REGISTRATION_SUCCESS" in event_types
    assert "LOGIN_FAILURE" in event_types
    assert "LOGIN_SUCCESS" in event_types


# ── 18. Existing forensic tests still pass (regression) ──────────────────────

def test_18_existing_forensic_functionality_preserved(tmp_path, monkeypatch):
    """Smoke-test that core forensic routes still work when authenticated."""
    from backend.api import evidence_routes
    from backend.services import report_manager

    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "regression.db")
    evidence_root = tmp_path / "evidence"
    monkeypatch.setattr(evidence_routes, "EVIDENCE_DIR", evidence_root)
    monkeypatch.setattr(report_manager, "REPORTS_DIR", tmp_path / "reports")
    database.initialize_database()

    client = TestClient(app, raise_server_exceptions=True)

    # Register and login to get a session
    client.post("/api/auth/register", json={
        "full_name": "Regression Tester",
        "mobile": "9000000001",
        "email": "regression@example.com",
        "password": "RegPass123",
        "confirm_password": "RegPass123",
    })
    client.post("/api/auth/login", json={
        "identifier": "regression@example.com",
        "password": "RegPass123",
    })

    # Core forensic routes must still work
    case_resp = client.post("/api/cases", json={
        "case_name": "Regression Case",
        "investigator": "Tester",
        "description": "Regression test",
    })
    assert case_resp.status_code == 201
    case_id = case_resp.json()["case_id"]

    evidence_file = evidence_root / case_id / "sample.txt"
    evidence_file.parent.mkdir(parents=True)
    evidence_file.write_text("regression evidence", encoding="utf-8")

    ev_resp = client.post("/api/evidence", json={
        "case_id": case_id,
        "device_serial": "TEST",
        "evidence_type": "Text",
        "source": "Regression",
        "file_path": f"{case_id}/sample.txt",
    })
    assert ev_resp.status_code == 201

    verify_resp = client.post(f"/api/evidence/{ev_resp.json()['evidence_id']}/verify")
    assert verify_resp.json()["verified"] is True

    report_resp = client.get(f"/api/reports/{case_id}")
    assert report_resp.status_code == 200
    assert report_resp.headers["content-type"] == "application/pdf"
