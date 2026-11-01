import os
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
REPORTS_DIR = PROJECT_ROOT / "reports"
LOGS_DIR = PROJECT_ROOT / "logs"
DATABASE_PATH = PROJECT_ROOT / "forensics.db"
ADB_EXECUTABLE = os.getenv("FX_ADB_EXECUTABLE", "adb")
ADB_TIMEOUT_SECONDS = int(os.getenv("FX_ADB_TIMEOUT_SECONDS", "10"))

# Production Security Configuration
ENVIRONMENT = os.getenv("FX_ENV", "development").lower()
IS_PRODUCTION = ENVIRONMENT == "production"
SECURE_COOKIES = os.getenv("FX_SECURE_COOKIES", "true" if IS_PRODUCTION else "false").lower() in ("true", "1", "yes")
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("FX_ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")
    if origin.strip()
]
RATE_LIMIT_LOGIN_PER_MINUTE = int(os.getenv("FX_RATE_LIMIT_LOGIN", "15"))
RATE_LIMIT_REGISTER_PER_MINUTE = int(os.getenv("FX_RATE_LIMIT_REGISTER", "10"))

# Identifier Validation Patterns (strict rejection of path traversal / injection)
IDENTIFIER_REGEX = r"^[A-Za-z0-9_\-]+$"
SERIAL_REGEX = r"^[A-Za-z0-9_.:\-]+$"
IDENTIFIER_PATTERN = re.compile(IDENTIFIER_REGEX)
SERIAL_PATTERN = re.compile(SERIAL_REGEX)


from functools import lru_cache


@lru_cache(maxsize=1)
def adb_candidates() -> list[str]:
	"""Return PATH and common Windows SDK locations for the ADB executable."""
	candidates = [ADB_EXECUTABLE]
	local_app_data = Path.home() / "AppData" / "Local"
	candidates.extend(
		str(path)
		for root in (local_app_data / "Android" / "Sdk", local_app_data / "Microsoft" / "WinGet" / "Packages")
		if root.exists()
		for path in root.rglob("adb.exe")
	)
	return candidates