"""GPS / location evidence API."""

import csv
import io
import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from backend.config import EVIDENCE_DIR
from backend.database.database import row, rows
from backend.services.auth_service import check_case_access, get_session_user
from backend.services.evidence_normalizer import parse_gps_from_dumpsys
from backend.api.auth_routes import SESSION_COOKIE

router = APIRouter(prefix="/api/gps", tags=["gps"])


@router.get("/{case_id}")
def get_gps(case_id: str, request: Request) -> dict:
    session_id = request.cookies.get(SESSION_COOKIE, "")
    user = get_session_user(session_id)
    check_case_access(case_id, user)

    # Try DB first (post-acquisition structured records)
    db_records = rows(
        "SELECT latitude, longitude, accuracy, provider, timestamp, raw_line "
        "FROM gps_locations WHERE case_id = ? ORDER BY id",
        (case_id,),
    )
    if db_records:
        locations = [
            {**r, "maps_url": f"https://www.google.com/maps?q={r['latitude']},{r['longitude']}"}
            for r in db_records
        ]
        return {"case_id": case_id, "source": "database", "count": len(locations), "locations": locations}

    # Fall back to parsing raw file
    raw_path = EVIDENCE_DIR / case_id / "acquired" / "mobile_intelligence.json"
    if not raw_path.is_file():
        return {"case_id": case_id, "source": "none", "count": 0, "locations": []}

    try:
        data = json.loads(raw_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"case_id": case_id, "source": "none", "count": 0, "locations": []}

    raw_records = data.get("gps", {}).get("records", [])
    raw_text = "\n".join(r.get("raw", "") for r in raw_records)
    locations = parse_gps_from_dumpsys(raw_text)
    return {"case_id": case_id, "source": "file", "count": len(locations), "locations": locations}


@router.get("/{case_id}/export/csv")
def export_gps_csv(case_id: str, request: Request):
    """Export GPS locations for a case as a downloadable CSV file."""
    session_id = request.cookies.get(SESSION_COOKIE, "")
    user = get_session_user(session_id)
    check_case_access(case_id, user)

    db_records = rows(
        "SELECT latitude, longitude, accuracy, provider, timestamp, raw_line "
        "FROM gps_locations WHERE case_id = ? ORDER BY id",
        (case_id,),
    )
    locations = list(db_records)

    if not locations:
        # Fall back to file
        raw_path = EVIDENCE_DIR / case_id / "acquired" / "mobile_intelligence.json"
        if raw_path.is_file():
            try:
                data = json.loads(raw_path.read_text(encoding="utf-8"))
                raw_records = data.get("gps", {}).get("records", [])
                raw_text = "\n".join(r.get("raw", "") for r in raw_records)
                locations = parse_gps_from_dumpsys(raw_text)
            except (OSError, json.JSONDecodeError):
                locations = []

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["#", "Latitude", "Longitude", "Accuracy (m)", "Provider", "Timestamp", "Maps URL", "Raw Line"])
    for i, loc in enumerate(locations, 1):
        writer.writerow([
            i,
            loc.get("latitude", ""),
            loc.get("longitude", ""),
            loc.get("accuracy", ""),
            loc.get("provider", ""),
            loc.get("timestamp", ""),
            f"https://www.google.com/maps?q={loc.get('latitude', '')},{loc.get('longitude', '')}",
            loc.get("raw_line", "") or loc.get("raw", ""),
        ])

    output.seek(0)
    filename = f"ForensicX_{case_id}_GPS_Locations.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
