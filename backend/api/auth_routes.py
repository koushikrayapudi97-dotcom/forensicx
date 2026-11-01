"""Authentication API routes."""

from fastapi import APIRouter, Request, Response, HTTPException
from pydantic import BaseModel, Field

from backend.config import (
    SECURE_COOKIES,
    RATE_LIMIT_LOGIN_PER_MINUTE,
    RATE_LIMIT_REGISTER_PER_MINUTE,
)
from backend.services.auth_service import (
    register_user, login_user, logout_session, get_session_user, log_security_event,
)
from backend.services.rate_limiter import limiter

router = APIRouter(prefix="/api/auth", tags=["auth"])

SESSION_COOKIE = "fx_session"
COOKIE_MAX_AGE = 30 * 24 * 3600  # 30 days


class RegisterPayload(BaseModel):
    full_name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    mobile: str = Field(min_length=10, max_length=15)
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)


class LoginPayload(BaseModel):
    identifier: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=128)


@router.post("/register", status_code=201)
def register(payload: RegisterPayload, request: Request) -> dict:
    source_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = limiter.check(
        f"register:{source_ip}", limit=RATE_LIMIT_REGISTER_PER_MINUTE, window_seconds=60
    )
    if not allowed:
        log_security_event("RATE_LIMIT_EXCEEDED", f"register:{source_ip}", "BLOCKED", source_ip=source_ip)
        raise HTTPException(
            status_code=429,
            detail=f"Too many registration requests. Please wait {retry_after} seconds before trying again.",
            headers={"Retry-After": str(retry_after)},
        )

    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    result = register_user(payload.full_name, payload.email, payload.mobile, payload.password)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return {"message": result["message"], "user_id": result["user_id"]}


@router.post("/login")
def login(payload: LoginPayload, request: Request, response: Response) -> dict:
    source_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    # IP-level rate limit protection against brute force
    allowed, retry_after = limiter.check(
        f"login:{source_ip}", limit=RATE_LIMIT_LOGIN_PER_MINUTE, window_seconds=60
    )
    if not allowed:
        log_security_event(
            "RATE_LIMIT_EXCEEDED", payload.identifier.strip(), "BLOCKED", source_ip=source_ip, user_agent=user_agent
        )
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Please wait {retry_after} seconds before trying again.",
            headers={"Retry-After": str(retry_after)},
        )

    # Session fixation mitigation: invalidate any prior session cookie before issuing new
    prior_session = request.cookies.get(SESSION_COOKIE, "")
    if prior_session:
        logout_session(prior_session)

    result = login_user(payload.identifier, payload.password, source_ip, user_agent)
    if not result["ok"]:
        code = result.get("code", "")
        status = 423 if code == "ACCOUNT_LOCKED" else 401
        raise HTTPException(status_code=status, detail=result["message"])

    response.set_cookie(
        key=SESSION_COOKIE,
        value=result["session_id"],
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=SECURE_COOKIES,
        path="/",
    )
    return {"full_name": result["full_name"], "user_id": result["user_id"]}


@router.post("/logout")
def logout(request: Request, response: Response) -> dict:
    session_id = request.cookies.get(SESSION_COOKIE, "")
    if session_id:
        logout_session(session_id)
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        httponly=True,
        samesite="lax",
        secure=SECURE_COOKIES,
    )
    return {"message": "Logged out."}


@router.get("/me")
def me(request: Request) -> dict:
    session_id = request.cookies.get(SESSION_COOKIE, "")
    user = get_session_user(session_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return {"user_id": user["user_id"], "full_name": user["full_name"], "email": user["email"]}
