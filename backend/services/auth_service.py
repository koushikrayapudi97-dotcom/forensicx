"""Authentication service: registration, login, session, lockout, security events."""

import re
import secrets
from datetime import datetime, timezone, timedelta
from uuid import uuid4

import bcrypt

from backend.database.database import connect, execute_with_retry, row, utc_now

LOCKOUT_MINUTES = 15
MAX_ATTEMPTS = 4
SESSION_HOURS = 24 * 30  # 30 days

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MOBILE_RE = re.compile(r"^(?:\+91)?[6-9]\d{9}$")


# ── normalizers ──────────────────────────────────────────────────────────────

def normalize_email(value: str) -> str:
    return value.strip().lower()


def normalize_mobile(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    return digits


def validate_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value))


def validate_mobile(value: str) -> bool:
    return bool(_MOBILE_RE.match(value.strip()))


# ── password hashing ─────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ── security event logging ───────────────────────────────────────────────────

def log_security_event(
    event_type: str,
    identifier: str,
    result: str,
    user_id: str | None = None,
    failed_count: int = 0,
    source_ip: str = "",
    user_agent: str = "",
) -> None:
    def _op():
        with connect() as connection:
            connection.execute(
                "INSERT INTO security_events "
                "(timestamp, event_type, identifier, user_id, failed_count, source_ip, user_agent, result) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (utc_now(), event_type, identifier, user_id, failed_count, source_ip, user_agent, result),
            )
    try:
        execute_with_retry(_op)
    except Exception:
        pass


# ── registration ─────────────────────────────────────────────────────────────

def register_user(full_name: str, email: str, mobile: str, password: str) -> dict:
    email = normalize_email(email)
    mobile = normalize_mobile(mobile)

    if not validate_email(email):
        return {"ok": False, "code": "INVALID_EMAIL", "message": "Invalid email address format."}
    if not validate_mobile(mobile):
        return {"ok": False, "code": "INVALID_MOBILE", "message": "Invalid mobile number. Use a 10-digit Indian mobile number."}
    if len(password) < 8:
        return {"ok": False, "code": "WEAK_PASSWORD", "message": "Password must be at least 8 characters."}

    def _op():
        with connect() as connection:
            if connection.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                return "DUPLICATE_EMAIL"
            if connection.execute("SELECT 1 FROM users WHERE mobile = ?", (mobile,)).fetchone():
                return "DUPLICATE_MOBILE"

            user_id = f"USR-{uuid4().hex[:10].upper()}"
            password_hash = hash_password(password)
            connection.execute(
                "INSERT INTO users (user_id, full_name, email, mobile, password_hash, status, failed_attempts, created_at) "
                "VALUES (?, ?, ?, ?, ?, 'active', 0, ?)",
                (user_id, full_name.strip(), email, mobile, password_hash, utc_now()),
            )
            return user_id

    res = execute_with_retry(_op)
    if res == "DUPLICATE_EMAIL":
        log_security_event("REGISTRATION_DUPLICATE_EMAIL", email, "REJECTED")
        return {"ok": False, "code": "DUPLICATE_EMAIL", "message": "An account with this email already exists."}
    if res == "DUPLICATE_MOBILE":
        log_security_event("REGISTRATION_DUPLICATE_MOBILE", mobile, "REJECTED")
        return {"ok": False, "code": "DUPLICATE_MOBILE", "message": "An account with this mobile number already exists."}

    log_security_event("REGISTRATION_SUCCESS", email, "SUCCESS", user_id=res)
    return {"ok": True, "user_id": res, "message": "Account created successfully."}


# ── login ─────────────────────────────────────────────────────────────────────

def _find_user_by_identifier(identifier: str) -> dict | None:
    """Resolve identifier (email or mobile) to a user row."""
    if "@" in identifier:
        return row("SELECT * FROM users WHERE email = ?", (normalize_email(identifier),))
    return row("SELECT * FROM users WHERE mobile = ?", (normalize_mobile(identifier),))


def login_user(identifier: str, password: str, source_ip: str = "", user_agent: str = "") -> dict:
    identifier = identifier.strip()

    # Validate identifier format
    if "@" in identifier:
        if not validate_email(identifier):
            log_security_event("INVALID_LOGIN_IDENTIFIER", identifier, "REJECTED", source_ip=source_ip)
            return {"ok": False, "code": "INVALID_IDENTIFIER", "message": "Invalid login credentials."}
    else:
        if not validate_mobile(identifier):
            log_security_event("INVALID_LOGIN_IDENTIFIER", identifier, "REJECTED", source_ip=source_ip)
            return {"ok": False, "code": "INVALID_IDENTIFIER", "message": "Invalid login credentials."}

    user = _find_user_by_identifier(identifier)
    if user is None:
        log_security_event("LOGIN_FAILURE", identifier, "USER_NOT_FOUND", source_ip=source_ip, user_agent=user_agent)
        return {"ok": False, "code": "INVALID_CREDENTIALS", "message": "Invalid login credentials."}

    # Check lockout
    if user.get("locked_until") and str(user["locked_until"]).strip():
        try:
            locked_until = datetime.fromisoformat(str(user["locked_until"]))
            if datetime.now(timezone.utc) < locked_until:
                remaining = int((locked_until - datetime.now(timezone.utc)).total_seconds() // 60) + 1
                log_security_event("LOGIN_BLOCKED", identifier, "LOCKED", user_id=user["user_id"],
                                   failed_count=user["failed_attempts"], source_ip=source_ip, user_agent=user_agent)
                return {
                    "ok": False,
                    "code": "ACCOUNT_LOCKED",
                    "message": f"Account temporarily locked due to multiple failed authentication attempts. Try again in {remaining} minute(s).",
                }
        except (ValueError, TypeError):
            pass
        # Lockout expired — clear it
        def _clear_lockout():
            with connect() as connection:
                connection.execute(
                    "UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE user_id = ?",
                    (user["user_id"],),
                )
        execute_with_retry(_clear_lockout)
        log_security_event("ACCOUNT_UNLOCKED", identifier, "LOCKOUT_EXPIRED", user_id=user["user_id"])
        user = _find_user_by_identifier(identifier)

    # Verify password
    if not verify_password(password, user["password_hash"]):
        new_count = user["failed_attempts"] + 1
        locked_until = None
        if new_count >= MAX_ATTEMPTS:
            locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        def _record_failed():
            with connect() as connection:
                connection.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE user_id = ?",
                    (new_count, locked_until, user["user_id"]),
                )
        execute_with_retry(_record_failed)
        if locked_until:
            log_security_event("ACCOUNT_LOCKED", identifier, "LOCKED", user_id=user["user_id"],
                               failed_count=new_count, source_ip=source_ip, user_agent=user_agent)
            return {
                "ok": False,
                "code": "ACCOUNT_LOCKED",
                "message": f"Account temporarily locked due to multiple failed authentication attempts. Try again in {LOCKOUT_MINUTES} minute(s).",
            }
        log_security_event("LOGIN_FAILURE", identifier, "WRONG_PASSWORD", user_id=user["user_id"],
                           failed_count=new_count, source_ip=source_ip, user_agent=user_agent)
        remaining_attempts = MAX_ATTEMPTS - new_count
        return {
            "ok": False,
            "code": "INVALID_CREDENTIALS",
            "message": f"Invalid login credentials. {remaining_attempts} attempt(s) remaining before temporary lockout.",
        }

    # Success — reset counter, create session
    session_id = secrets.token_urlsafe(32)
    now = utc_now()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).isoformat()
    def _record_login_success():
        with connect() as connection:
            connection.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?",
                (user["user_id"],),
            )
            connection.execute(
                "INSERT INTO sessions (session_id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (session_id, user["user_id"], now, expires_at),
            )
    execute_with_retry(_record_login_success)
    log_security_event("LOGIN_SUCCESS", identifier, "SUCCESS", user_id=user["user_id"], source_ip=source_ip, user_agent=user_agent)
    return {
        "ok": True,
        "session_id": session_id,
        "user_id": user["user_id"],
        "full_name": user["full_name"],
        "expires_at": expires_at,
    }


# ── session validation ────────────────────────────────────────────────        

def get_session_user(session_id: str) -> dict | None:
    """Return the user dict for a valid, non-expired session, or None."""
    if not session_id:
        return None
    session = row(
        "SELECT s.*, u.full_name, u.email, u.mobile, u.status "
        "FROM sessions s JOIN users u ON u.user_id = s.user_id "
        "WHERE s.session_id = ?",
        (session_id,),
    )
    if session is None:
        return None
    try:
        if datetime.fromisoformat(str(session["expires_at"])) < datetime.now(timezone.utc):
            return None
    except (ValueError, TypeError):
        return None
    if session["status"] != "active":
        return None
    return dict(session)


def create_default_investigator_session() -> tuple[str, dict]:
    """Create or return an active session for the primary investigator."""
    user = row("SELECT user_id, full_name, email, mobile, status FROM users WHERE status = 'active' ORDER BY created_at ASC LIMIT 1")
    if not user:
        return "", {}
    session_id = secrets.token_urlsafe(32)
    now = utc_now()
    expires_at = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    def _create():
        with connect() as conn:
            conn.execute(
                "INSERT INTO sessions (session_id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (session_id, user["user_id"], now, expires_at),
            )
    execute_with_retry(_create)
    return session_id, dict(user)


# ── logout ────────────────────────────────────────────────────────────────────

def logout_session(session_id: str) -> None:
    def _op():
        with connect() as connection:
            connection.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
    try:
        execute_with_retry(_op)
    except Exception:
        pass


# ── authorization & access control ──────────────────────────────────────────

def check_case_access(case_id: str, user: dict | None = None) -> dict:
    """Validate case ID format, verify existence, and enforce case ownership.

    Raises:
        HTTPException(400): If case_id is malformed or attempts path traversal.
        HTTPException(404): If case does not exist.
        HTTPException(403): If the authenticated user does not own or have access to this case.
    """
    from fastapi import HTTPException
    from backend.config import IDENTIFIER_PATTERN

    if not case_id or not isinstance(case_id, str) or not IDENTIFIER_PATTERN.match(case_id):
        raise HTTPException(status_code=400, detail="Invalid case identifier format.")

    case_row = row("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    if case_row is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    case_dict = dict(case_row)

    # Object-level authorization check:
    # If case has an assigned user_id and an authenticated user context is provided,
    # enforce that the user_id matches.
    if user and case_dict.get("user_id") and user.get("user_id"):
        if case_dict["user_id"] != user["user_id"]:
            log_security_event(
                "UNAUTHORIZED_CASE_ACCESS",
                case_id,
                "FORBIDDEN",
                user_id=user.get("user_id"),
            )
            raise HTTPException(
                status_code=403,
                detail="Access denied: You are not authorized to access this case."
            )

    return case_dict


