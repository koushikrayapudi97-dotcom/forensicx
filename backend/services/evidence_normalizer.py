"""Normalize preserved Android intelligence into report-ready records."""

from datetime import datetime, timezone
import json
import re
from pathlib import Path

from backend.database.database import row, rows


SMS_TYPES = {1: "Incoming", 2: "Outgoing", 3: "Draft", 4: "Outgoing", 5: "Failed", 6: "Queued"}
CALL_TYPES = {1: "Incoming", 2: "Outgoing", 3: "Missed", 4: "Voicemail", 5: "Rejected", 6: "Blocked", 7: "Answered externally"}

# Matches lines like: Last Known Locations or location=Location[gps 12.345,67.890 acc=15]
_LOCATION_RE = re.compile(
    r"(?:gps|network|fused|passive)[^\d-]*"
    r"(?P<lat>-?\d+\.\d+),(?P<lon>-?\d+\.\d+)"
    r"(?:.*?acc[=:](?P<acc>[\d.]+))?",
    re.IGNORECASE,
)
_PROVIDER_RE = re.compile(r"(gps|network|fused|passive)", re.IGNORECASE)
_TIME_RE = re.compile(r"time=([\d]+)")


def parse_gps_from_dumpsys(raw_output: str) -> list[dict]:
    """Extract structured GPS fixes from dumpsys location output."""
    results = []
    seen = set()
    for line in raw_output.splitlines():
        m = _LOCATION_RE.search(line)
        if not m:
            continue
        lat = m.group("lat")
        lon = m.group("lon")
        key = (lat, lon)
        if key in seen:
            continue
        seen.add(key)
        provider_m = _PROVIDER_RE.search(line)
        provider = provider_m.group(1).lower() if provider_m else "unknown"
        time_m = _TIME_RE.search(line)
        timestamp = None
        if time_m:
            try:
                ms = int(time_m.group(1))
                if ms > 1_000_000_000_000:
                    ms /= 1000
                timestamp = datetime.fromtimestamp(ms, timezone.utc).isoformat()
            except (ValueError, OSError):
                pass
        results.append({
            "latitude": lat,
            "longitude": lon,
            "accuracy": m.group("acc") or "Unknown",
            "provider": provider,
            "timestamp": timestamp or "Not Available",
            "maps_url": f"https://www.google.com/maps?q={lat},{lon}",
            "raw_line": line.strip(),
        })
    return results


def format_timestamp(value: object) -> str:
	try:
		number = float(str(value))
		if number > 100_000_000_000:
			number /= 1000
		return datetime.fromtimestamp(number, timezone.utc).astimezone().strftime("%d-%b-%Y %H:%M:%S")
	except (TypeError, ValueError, OverflowError, OSError):
		return "Not Available"


def _read_intelligence(case_id: str, evidence_dir: Path) -> dict:
	path = evidence_dir / case_id / "acquired" / "mobile_intelligence.json"
	if not path.is_file():
		return {}
	try:
		return json.loads(path.read_text(encoding="utf-8"))
	except (OSError, json.JSONDecodeError):
		return {}


def normalize_case(case: dict, evidence_dir: Path) -> dict:
	data = _read_intelligence(case["case_id"], evidence_dir)
	sms = []
	for index, item in enumerate(data.get("sms", {}).get("records", []), 1):
		sms.append({"sno": item.get("_id", index), "date_time": format_timestamp(item.get("date")), "address": item.get("address") or "Not Available", "type": SMS_TYPES.get(int(item["type"]) if str(item.get("type", "")).isdigit() else 0, "Unknown"), "body": item.get("body") or ""})
	calls = []
	for index, item in enumerate(data.get("call_logs", {}).get("records", []), 1):
		try:
			call_type = CALL_TYPES.get(int(item.get("type", 0)), "Unknown")
		except (TypeError, ValueError):
			call_type = "Unknown"
		seconds = item.get("duration") or "0"
		try:
			duration = f"{int(seconds) // 60:02d}:{int(seconds) % 60:02d}"
		except (TypeError, ValueError):
			duration = "00:00"
		calls.append({"sno": item.get("_id", index), "date_time": format_timestamp(item.get("date")), "number": item.get("number") or "Not Available", "name": item.get("name") or "Unknown", "type": call_type, "duration": duration, "source": "Authorized ADB"})
	# GPS — records are already structured from mobile_intelligence.py
	gps = []
	raw_gps = data.get("gps", {}).get("records", [])
	for item in raw_gps:
		lat = item.get("latitude")
		lon = item.get("longitude")
		if not lat or not lon:
			# fallback: try parsing raw line if old format
			raw_line = item.get("raw", "")
			parsed = parse_gps_from_dumpsys(raw_line)
			gps.extend(parsed)
			continue
		gps.append({
			"latitude": lat,
			"longitude": lon,
			"accuracy": item.get("accuracy") or "Unknown",
			"provider": item.get("provider") or "unknown",
			"timestamp": item.get("timestamp") or "Not Available",
			"maps_url": f"https://www.google.com/maps?q={lat},{lon}",
			"raw_line": item.get("raw") or "",
		})
	# Extracted Device Files
	extracted_files = []
	raw_files = data.get("files", {}).get("records", [])
	if not raw_files:
		# DB fallback
		raw_files = rows("SELECT * FROM files WHERE case_id = ? ORDER BY id", (case["case_id"],))
	for index, item in enumerate(raw_files, 1):
		orig = item.get("original_path") or item.get("_data") or "Unknown"
		fname = item.get("file_name") or (orig.split("/")[-1] if orig != "Unknown" else f"File_{index}")
		size_num = item.get("size") or item.get("_size") or 0
		extracted_files.append({
			"sno": item.get("_id", index),
			"file_name": fname,
			"original_path": orig,
			"size": size_num,
			"mime_type": item.get("mime_type") or "application/octet-stream",
			"date_modified": item.get("date_modified") or item.get("timestamp") or "Not Available",
		})
	db_ev_count = row("SELECT COUNT(*) AS count FROM evidence WHERE case_id = ?", (case["case_id"],))
	total_files_count = len(extracted_files) or (db_ev_count["count"] if db_ev_count else 0)

	# Extracted Web / Browser History
	web_history = []
	raw_web = data.get("browser_history", {}).get("records", [])
	if not raw_web:
		raw_web = rows("SELECT * FROM browser_history WHERE case_id = ? ORDER BY id", (case["case_id"],))
	for index, item in enumerate(raw_web, 1):
		url_val = item.get("url") or ""
		if not url_val:
			continue
		web_history.append({
			"sno": item.get("_id", index),
			"browser": item.get("browser") or "Unknown Browser",
			"url": url_val,
			"title": item.get("title") or url_val,
			"visit_timestamp": format_timestamp(item.get("visit_timestamp") or item.get("date")),
			"visit_count": int(item.get("visit_count") or item.get("visits") or 1),
			"source": item.get("source") or "content://browser",
		})

	# Extracted Media Files (Photos, Videos, Audio)
	media_files = []
	raw_media = data.get("media_files", {}).get("records", [])
	if not raw_media:
		raw_media = rows("SELECT * FROM media_files WHERE case_id = ? ORDER BY id", (case["case_id"],))
	for index, item in enumerate(raw_media, 1):
		path = item.get("original_path") or item.get("_data") or ""
		if not path:
			continue
		fname = item.get("file_name") or path.split("/")[-1]
		media_files.append({
			"sno": item.get("_id", index),
			"media_type": item.get("media_type") or "Image",
			"file_name": fname,
			"original_path": path,
			"size": int(item.get("file_size") or item.get("size") or 0),
			"mime_type": item.get("mime_type") or "application/octet-stream",
			"date_taken": format_timestamp(item.get("date_taken") or item.get("datetaken") or item.get("timestamp")),
			"duration": item.get("duration") or "",
			"source": item.get("source") or "content://media",
		})

	case_id = case.get("case_id") if isinstance(case, dict) else str(case)
	norm_cnt = row("SELECT COUNT(*) as c FROM normalized_evidence WHERE case_id = ?", (case_id,))
	corr_cnt = row("SELECT COUNT(*) as c FROM evidence_correlations WHERE case_id = ?", (case_id,))
	rel_cnt = row("SELECT COUNT(*) as c FROM evidence_reliability_scores WHERE case_id = ?", (case_id,))
	node_cnt = row("SELECT COUNT(*) as c FROM graph_nodes WHERE case_id = ?", (case_id,))
	tl_cnt = row("SELECT COUNT(*) as c FROM incident_timeline WHERE case_id = ?", (case_id,))
	ai_cnt = row("SELECT COUNT(*) as c FROM ai_findings WHERE case_id = ?", (case_id,))
	if not ai_cnt or ai_cnt["c"] == 0:
		ai_cnt = row("SELECT COUNT(*) as c FROM incident_timeline WHERE case_id = ? AND suspicious_flag = 1", (case_id,))

	return {
		"case": case,
		"device": {},
		"summary": {
			"devices": 1 if data else 0,
			"call_logs": len(calls),
			"messages": len(sms),
			"gps": len(gps),
			"files": total_files_count,
			"web_history": len(web_history),
			"media_files": len(media_files),
			"normalized_evidence": norm_cnt["c"] if norm_cnt else 0,
			"correlations": corr_cnt["c"] if corr_cnt else 0,
			"reliability_assessments": rel_cnt["c"] if rel_cnt else 0,
			"graph_entities": node_cnt["c"] if node_cnt else 0,
			"timeline_events": tl_cnt["c"] if tl_cnt else 0,
			"ai_findings": ai_cnt["c"] if ai_cnt else 0,
		},
		"calls": calls,
		"messages": sms,
		"gps": gps,
		"extracted_files": extracted_files,
		"browser_history": web_history,
		"media_files": media_files,
		"social_media": data.get("social_media", {"status": "not_available", "records": [], "error": "App-private social-media databases are not generically accessible through authorized ADB."}),
		"evidence": [],
		"raw_available": bool(data),
	}

