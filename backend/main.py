"""FastAPI application entry point."""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from fastapi.middleware.cors import CORSMiddleware
from backend.config import FRONTEND_DIR, LOGS_DIR, ALLOWED_ORIGINS, SECURE_COOKIES
from backend.database.database import initialize_database
from backend.api.acquisition_routes import router as acquisition_router
from backend.api.case_routes import router as case_router
from backend.api.device_routes import router as device_router
from backend.api.evidence_routes import router as evidence_router
from backend.api.image_routes import router as image_router
from backend.api.analysis_routes import router as analysis_router
from backend.api.ai_routes import router as ai_router
from backend.api.adapter_routes import router as adapter_router
from backend.api.report_routes import router as report_router
from backend.api.report_data_routes import router as report_data_router
from backend.api.auth_routes import router as auth_router, SESSION_COOKIE
from backend.api.gps_routes import router as gps_router
from backend.api.ai_investigation_routes import router as ai_investigation_router
from backend.api.malware_routes import router as malware_router
from backend.api.web_history_routes import router as web_history_router
from backend.api.media_routes import router as media_router
from backend.api.forensic_intelligence_routes import router as forensic_intelligence_router
from backend.api.tool_integration_routes import router as tool_integration_router
from backend.services.auth_service import get_session_user, create_default_investigator_session
from backend.services.device_manager import DeviceManager

LOGS_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOGS_DIR / "application.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Digital Forensics Investigation System", version="0.1.0")
device_manager = DeviceManager()
initialize_database()

# ── CORS Middleware ───────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# ── Security Headers Middleware ───────────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "frame-src 'self' https://maps.google.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    if request.url.path in ("/", "/login") or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# Auth routes are public (login/register/logout)
app.include_router(auth_router)

# ── authentication middleware ─────────────────────────────────────────────────
# Paths that do NOT require authentication
_PUBLIC_PREFIXES = ("/api/auth/", "/static/")
_PUBLIC_EXACT = {"/login"}


@app.middleware("http")
async def require_auth(request: Request, call_next):
    path = request.url.path

    # Always allow public paths
    if path in _PUBLIC_EXACT or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
        return await call_next(request)

    session_id = request.cookies.get(SESSION_COOKIE, "")
    user = get_session_user(session_id)

    if user is None:
        # API calls get 401 JSON; browser navigation gets redirect to /login
        if path.startswith("/api/"):
            return JSONResponse({"detail": "Not authenticated."}, status_code=401)
        return RedirectResponse("/login", status_code=302)

    request.state.user = user
    return await call_next(request)


# ── Global unhandled exception handler to avoid stack trace leakage ────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled server exception on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please contact the forensic administrator."},
    )


# ── existing device endpoint ──────────────────────────────────────────────────
@app.get("/api/device")
def get_device_status() -> dict:
    status = device_manager.detect()
    if status.get("error"):
        logger.warning("ADB detection failed: %s", status["error"])
    else:
        logger.info("ADB detection completed: %d device(s)", len(status["devices"]))
    return status


app.include_router(device_router)
app.include_router(case_router)
app.include_router(evidence_router)
app.include_router(image_router)
app.include_router(analysis_router)
app.include_router(ai_router)
app.include_router(adapter_router)
app.include_router(acquisition_router)
app.include_router(report_router)
app.include_router(report_data_router)
app.include_router(gps_router)
app.include_router(ai_investigation_router)
app.include_router(malware_router)
app.include_router(web_history_router)
app.include_router(media_router)
app.include_router(forensic_intelligence_router)
app.include_router(tool_integration_router)


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/login")
def serve_login() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "login.html")


@app.get("/")
def serve_dashboard(request: Request) -> FileResponse:
    session_id = request.cookies.get(SESSION_COOKIE, "")
    user = get_session_user(session_id)
    response = FileResponse(FRONTEND_DIR / "index.html")
    if user is None:
        new_session_id, _ = create_default_investigator_session()
        if new_session_id:
            response.set_cookie(
                key=SESSION_COOKIE,
                value=new_session_id,
                httponly=True,
                samesite="lax",
                max_age=365 * 24 * 3600,
            )
    return response
