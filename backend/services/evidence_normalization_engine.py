"""Module 1: Evidence Normalization Engine for ForensicX.

Converts heterogeneous forensic artifacts (SMS, Calls, GPS, Browser History,
Files, Media, Contacts, Applications) into ONE standard normalized representation.
"""

from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import Path
from uuid import uuid4

from backend.config import EVIDENCE_DIR
from backend.database.database import connect, row, rows, utc_now

SMS_TYPES = {1: "Incoming", 2: "Outgoing", 3: "Draft", 4: "Outgoing", 5: "Failed", 6: "Queued"}
CALL_TYPES = {1: "Incoming", 2: "Outgoing", 3: "Missed", 4: "Voicemail", 5: "Rejected", 6: "Blocked", 7: "Answered externally"}


def parse_timestamp_to_utc(val: object) -> tuple[str | None, str, str]:
    """Parse epoch sec/ms/us, ISO 8601, and string timestamps safely into ISO 8601 UTC.
    
    Returns (iso_utc_str, original_raw_str, parsing_status).
    """
    if val is None or val == "":
        return None, "", "MISSING"

    raw_str = str(val).strip()
    
    # Try numeric epoch
    try:
        num = float(raw_str)
        if num > 1_000_000_000_000_000:  # microseconds
            num /= 1_000_000
        elif num > 100_000_000_000:  # milliseconds
            num /= 1_000
        dt = datetime.fromtimestamp(num, timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), raw_str, "SUCCESS"
    except (ValueError, TypeError, OverflowError, OSError):
        pass

    # Try ISO string / common date formats
    clean = raw_str.replace("Z", "+00:00")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%d-%b-%Y %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(raw_str.split(".")[0], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), raw_str, "SUCCESS"
        except ValueError:
            pass

    # Fall back if partially unparseable
    return None, raw_str, "PARTIAL"


def _generate_normalized_id(case_id: str, source_ref: str) -> str:
    """Generate a deterministic normalized ID based on case ID and source reference."""
    digest = hashlib.sha256(f"{case_id}::{source_ref}".encode("utf-8")).hexdigest()[:12].upper()
    return f"NORM-EV-{digest}"


def normalize_case(case_id: str) -> dict:
    """Normalize all extracted and raw evidence items for a case.
    
    Operations are fully idempotent. Re-running updates existing records.
    """
    case_rec = row("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    if not case_rec:
        return {"case_id": case_id, "error": "Case not found", "total": 0}

    # Fetch active device & acquisition metadata
    latest_acq = row(
        "SELECT a.*, d.serial FROM acquisitions a JOIN devices d ON d.device_id = a.device_id WHERE a.case_id = ? ORDER BY a.started_at DESC LIMIT 1",
        (case_id,),
    )
    device_id = latest_acq["device_id"] if latest_acq else "DEV-UNKNOWN"
    acquisition_id = latest_acq["acquisition_id"] if latest_acq else "ACQ-UNKNOWN"

    normalized_records = []

    # 1. Normalize SMS Messages
    db_sms = rows("SELECT * FROM sms_messages WHERE case_id = ? ORDER BY id", (case_id,))
    for item in db_sms:
        s_ref = f"sms_messages#{item['id']}"
        ts_utc, orig_ts, ts_status = parse_timestamp_to_utc(item.get("timestamp"))
        addr = item.get("address") or "Unknown"
        body = item.get("body") or ""
        raw_type = item.get("message_type")
        type_str = SMS_TYPES.get(int(raw_type) if str(raw_type).isdigit() else 0, "SMS")

        status = "SUCCESS" if body or addr != "Unknown" else "PARTIAL"
        entity_info = {
            "address": addr,
            "sender_receiver": addr,
            "message_direction": type_str,
        }
        content = {
            "body": body,
            "message_type": type_str,
            "character_count": len(body),
        }

        normalized_records.append({
            "normalized_id": _generate_normalized_id(case_id, s_ref),
            "evidence_item_id": item.get("evidence_item_id") or f"EVD-SMS-{item['id']}",
            "case_id": case_id,
            "device_id": item.get("device_id") or device_id,
            "acquisition_id": item.get("acquisition_id") or acquisition_id,
            "artifact_type": "sms",
            "source_method": "ADB Logical Acquisition",
            "timestamp_utc": ts_utc,
            "original_timestamp": orig_ts,
            "entity_info": json.dumps(entity_info, ensure_ascii=False),
            "content": json.dumps(content, ensure_ascii=False),
            "location_info": json.dumps({}),
            "source_ref": s_ref,
            "original_hash": None,
            "normalization_status": status,
            "provenance": json.dumps({
                "source_table": "sms_messages",
                "source_id": item["id"],
                "timestamp_parse_status": ts_status,
                "parser_version": "1.0",
            }),
        })

    # 2. Normalize Call Logs
    db_calls = rows("SELECT * FROM call_logs WHERE case_id = ? ORDER BY id", (case_id,))
    for item in db_calls:
        s_ref = f"call_logs#{item['id']}"
        ts_utc, orig_ts, ts_status = parse_timestamp_to_utc(item.get("timestamp"))
        num = item.get("number") or "Unknown"
        name = item.get("name") or "Unknown"
        raw_type = item.get("call_type")
        call_type_str = CALL_TYPES.get(int(raw_type) if str(raw_type).isdigit() else 0, "Call")
        dur = item.get("duration") or "0"

        try:
            dur_sec = int(dur)
            dur_fmt = f"{dur_sec // 60:02d}:{dur_sec % 60:02d}"
        except (ValueError, TypeError):
            dur_sec = 0
            dur_fmt = str(dur)

        entity_info = {
            "phone_number": num,
            "contact_name": name,
            "call_direction": call_type_str,
        }
        content = {
            "call_type": call_type_str,
            "duration_seconds": dur_sec,
            "duration_formatted": dur_fmt,
        }

        normalized_records.append({
            "normalized_id": _generate_normalized_id(case_id, s_ref),
            "evidence_item_id": item.get("evidence_item_id") or f"EVD-CALL-{item['id']}",
            "case_id": case_id,
            "device_id": item.get("device_id") or device_id,
            "acquisition_id": item.get("acquisition_id") or acquisition_id,
            "artifact_type": "call",
            "source_method": "ADB Logical Acquisition",
            "timestamp_utc": ts_utc,
            "original_timestamp": orig_ts,
            "entity_info": json.dumps(entity_info, ensure_ascii=False),
            "content": json.dumps(content, ensure_ascii=False),
            "location_info": json.dumps({}),
            "source_ref": s_ref,
            "original_hash": None,
            "normalization_status": "SUCCESS" if num != "Unknown" else "PARTIAL",
            "provenance": json.dumps({
                "source_table": "call_logs",
                "source_id": item["id"],
                "timestamp_parse_status": ts_status,
                "parser_version": "1.0",
            }),
        })

    # 3. Normalize GPS Locations
    db_gps = rows("SELECT * FROM gps_locations WHERE case_id = ? ORDER BY id", (case_id,))
    for item in db_gps:
        s_ref = f"gps_locations#{item['id']}"
        ts_utc, orig_ts, ts_status = parse_timestamp_to_utc(item.get("timestamp"))
        lat_val = item.get("latitude")
        lon_val = item.get("longitude")
        acc = item.get("accuracy") or "Unknown"
        prov = (item.get("provider") or "gps").lower()

        status = "SUCCESS"
        try:
            lat = float(lat_val)
            lon = float(lon_val)
            maps_url = f"https://www.google.com/maps?q={lat},{lon}"
        except (ValueError, TypeError):
            status = "FAILED"
            lat, lon, maps_url = 0.0, 0.0, ""

        location_info = {
            "latitude": lat,
            "longitude": lon,
            "accuracy": acc,
            "provider": prov,
            "maps_url": maps_url,
        }
        content = {
            "raw_line": item.get("raw_line") or "",
            "coordinates": f"{lat}, {lon}",
        }

        normalized_records.append({
            "normalized_id": _generate_normalized_id(case_id, s_ref),
            "evidence_item_id": item.get("evidence_item_id") or f"EVD-GPS-{item['id']}",
            "case_id": case_id,
            "device_id": item.get("device_id") or device_id,
            "acquisition_id": item.get("acquisition_id") or acquisition_id,
            "artifact_type": "gps",
            "source_method": "ADB Dumpsys Location",
            "timestamp_utc": ts_utc,
            "original_timestamp": orig_ts,
            "entity_info": json.dumps({"provider": prov}),
            "content": json.dumps(content, ensure_ascii=False),
            "location_info": json.dumps(location_info, ensure_ascii=False),
            "source_ref": s_ref,
            "original_hash": None,
            "normalization_status": status,
            "provenance": json.dumps({
                "source_table": "gps_locations",
                "source_id": item["id"],
                "timestamp_parse_status": ts_status,
                "parser_version": "1.0",
            }),
        })

    # 4. Normalize Browser History
    db_web = rows("SELECT * FROM browser_history WHERE case_id = ? ORDER BY id", (case_id,))
    for item in db_web:
        s_ref = f"browser_history#{item['id']}"
        ts_utc, orig_ts, ts_status = parse_timestamp_to_utc(item.get("visit_timestamp"))
        url_val = item.get("url") or ""
        title_val = item.get("title") or url_val
        browser_name = item.get("browser") or "Browser"
        visits = int(item.get("visit_count") or 1)

        domain = ""
        m = re.search(r"https?://([^/]+)", url_val)
        if m:
            domain = m.group(1)

        entity_info = {
            "browser": browser_name,
            "domain": domain,
            "url": url_val,
        }
        content = {
            "title": title_val,
            "url": url_val,
            "visit_count": visits,
            "source": item.get("source") or "content://browser",
        }

        normalized_records.append({
            "normalized_id": _generate_normalized_id(case_id, s_ref),
            "evidence_item_id": item.get("evidence_item_id") or f"EVD-WEB-{item['id']}",
            "case_id": case_id,
            "device_id": item.get("device_id") or device_id,
            "acquisition_id": item.get("acquisition_id") or acquisition_id,
            "artifact_type": "web_history",
            "source_method": "Browser Artifact Importer",
            "timestamp_utc": ts_utc,
            "original_timestamp": orig_ts,
            "entity_info": json.dumps(entity_info, ensure_ascii=False),
            "content": json.dumps(content, ensure_ascii=False),
            "location_info": json.dumps({}),
            "source_ref": s_ref,
            "original_hash": None,
            "normalization_status": "SUCCESS" if url_val else "PARTIAL",
            "provenance": json.dumps({
                "source_table": "browser_history",
                "source_id": item["id"],
                "timestamp_parse_status": ts_status,
                "parser_version": "1.0",
            }),
        })

    # 5. Normalize Files & Media
    db_files = rows("SELECT * FROM files WHERE case_id = ? ORDER BY id", (case_id,))
    for item in db_files:
        s_ref = f"files#{item['id']}"
        ts_utc, orig_ts, ts_status = parse_timestamp_to_utc(item.get("timestamp"))
        orig_path = item.get("original_path") or ""
        fname = item.get("file_name") or orig_path.split("/")[-1]
        mime = item.get("mime_type") or "application/octet-stream"

        art_type = "file"
        if mime.startswith("image/"):
            art_type = "image"
        elif mime.startswith("video/"):
            art_type = "video"
        elif "pdf" in mime or "text" in mime or "doc" in mime:
            art_type = "document"

        entity_info = {
            "file_name": fname,
            "mime_type": mime,
            "original_path": orig_path,
        }
        content = {
            "file_name": fname,
            "original_path": orig_path,
            "size_bytes": item.get("size") or 0,
            "mime_type": mime,
        }

        normalized_records.append({
            "normalized_id": _generate_normalized_id(case_id, s_ref),
            "evidence_item_id": item.get("evidence_item_id") or f"EVD-FILE-{item['id']}",
            "case_id": case_id,
            "device_id": item.get("device_id") or device_id,
            "acquisition_id": item.get("acquisition_id") or acquisition_id,
            "artifact_type": art_type,
            "source_method": "File System Acquisition",
            "timestamp_utc": ts_utc,
            "original_timestamp": orig_ts,
            "entity_info": json.dumps(entity_info, ensure_ascii=False),
            "content": json.dumps(content, ensure_ascii=False),
            "location_info": json.dumps({}),
            "source_ref": s_ref,
            "original_hash": None,
            "normalization_status": "SUCCESS" if orig_path else "PARTIAL",
            "provenance": json.dumps({
                "source_table": "files",
                "source_id": item["id"],
                "timestamp_parse_status": ts_status,
                "parser_version": "1.0",
            }),
        })

    db_media = rows("SELECT * FROM media_files WHERE case_id = ? ORDER BY id", (case_id,))
    for item in db_media:
        s_ref = f"media_files#{item['id']}"
        ts_utc, orig_ts, ts_status = parse_timestamp_to_utc(item.get("date_taken"))
        orig_path = item.get("original_path") or ""
        fname = item.get("file_name") or orig_path.split("/")[-1]
        mtype = (item.get("media_type") or "image").lower()

        art_type = "image" if "image" in mtype or "photo" in mtype else ("video" if "video" in mtype else "file")

        entity_info = {
            "file_name": fname,
            "media_type": mtype,
            "original_path": orig_path,
        }
        content = {
            "file_name": fname,
            "original_path": orig_path,
            "size_bytes": item.get("file_size") or 0,
            "mime_type": item.get("mime_type") or "media/generic",
            "duration": item.get("duration") or "",
        }

        normalized_records.append({
            "normalized_id": _generate_normalized_id(case_id, s_ref),
            "evidence_item_id": item.get("evidence_item_id") or f"EVD-MEDIA-{item['id']}",
            "case_id": case_id,
            "device_id": item.get("device_id") or device_id,
            "acquisition_id": item.get("acquisition_id") or acquisition_id,
            "artifact_type": art_type,
            "source_method": "Media Importer",
            "timestamp_utc": ts_utc,
            "original_timestamp": orig_ts,
            "entity_info": json.dumps(entity_info, ensure_ascii=False),
            "content": json.dumps(content, ensure_ascii=False),
            "location_info": json.dumps({}),
            "source_ref": s_ref,
            "original_hash": item.get("sha256"),
            "normalization_status": "SUCCESS" if orig_path else "PARTIAL",
            "provenance": json.dumps({
                "source_table": "media_files",
                "source_id": item["id"],
                "timestamp_parse_status": ts_status,
                "parser_version": "1.0",
            }),
        })

    # 6. Normalize Contacts
    db_contacts = rows("SELECT * FROM contacts WHERE case_id = ? ORDER BY id", (case_id,))
    for item in db_contacts:
        s_ref = f"contacts#{item['id']}"
        ts_utc, orig_ts, ts_status = parse_timestamp_to_utc(item.get("timestamp"))
        name = item.get("name") or "Unknown"
        num = item.get("number") or "Unknown"

        entity_info = {
            "contact_name": name,
            "phone_number": num,
        }
        content = {
            "name": name,
            "number": num,
        }

        normalized_records.append({
            "normalized_id": _generate_normalized_id(case_id, s_ref),
            "evidence_item_id": item.get("evidence_item_id") or f"EVD-CONTACT-{item['id']}",
            "case_id": case_id,
            "device_id": item.get("device_id") or device_id,
            "acquisition_id": item.get("acquisition_id") or acquisition_id,
            "artifact_type": "contact",
            "source_method": "ADB Contact Importer",
            "timestamp_utc": ts_utc,
            "original_timestamp": orig_ts,
            "entity_info": json.dumps(entity_info, ensure_ascii=False),
            "content": json.dumps(content, ensure_ascii=False),
            "location_info": json.dumps({}),
            "source_ref": s_ref,
            "original_hash": None,
            "normalization_status": "SUCCESS" if name != "Unknown" or num != "Unknown" else "PARTIAL",
            "provenance": json.dumps({
                "source_table": "contacts",
                "source_id": item["id"],
                "timestamp_parse_status": ts_status,
                "parser_version": "1.0",
            }),
        })

    # 7. Normalize Applications
    db_apps = rows("SELECT * FROM applications WHERE case_id = ? ORDER BY id", (case_id,))
    for item in db_apps:
        s_ref = f"applications#{item['id']}"
        ts_utc, orig_ts, ts_status = parse_timestamp_to_utc(item.get("timestamp"))
        pkg = item.get("package_name") or "Unknown Package"
        ver = item.get("version") or "Unknown"

        entity_info = {
            "package_name": pkg,
            "version": ver,
        }
        content = {
            "package_name": pkg,
            "version": ver,
        }

        normalized_records.append({
            "normalized_id": _generate_normalized_id(case_id, s_ref),
            "evidence_item_id": item.get("evidence_item_id") or f"EVD-APP-{item['id']}",
            "case_id": case_id,
            "device_id": item.get("device_id") or device_id,
            "acquisition_id": item.get("acquisition_id") or acquisition_id,
            "artifact_type": "application",
            "source_method": "ADB Package Manager",
            "timestamp_utc": ts_utc,
            "original_timestamp": orig_ts,
            "entity_info": json.dumps(entity_info, ensure_ascii=False),
            "content": json.dumps(content, ensure_ascii=False),
            "location_info": json.dumps({}),
            "source_ref": s_ref,
            "original_hash": None,
            "normalization_status": "SUCCESS" if pkg != "Unknown Package" else "PARTIAL",
            "provenance": json.dumps({
                "source_table": "applications",
                "source_id": item["id"],
                "timestamp_parse_status": ts_status,
                "parser_version": "1.0",
            }),
        })

    # Persist all normalized records into SQLite idempotently
    now = utc_now()
    counts = {"SUCCESS": 0, "PARTIAL": 0, "FAILED": 0, "UNSUPPORTED": 0}
    by_type = {}

    with connect() as connection:
        for r in normalized_records:
            st = r["normalization_status"]
            counts[st] = counts.get(st, 0) + 1
            art = r["artifact_type"]
            by_type[art] = by_type.get(art, 0) + 1

            connection.execute(
                """
                INSERT INTO normalized_evidence (
                    normalized_id, evidence_item_id, case_id, device_id, acquisition_id,
                    artifact_type, source_method, timestamp_utc, original_timestamp,
                    entity_info, content, location_info, source_ref, original_hash,
                    normalization_status, provenance, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id, source_ref) DO UPDATE SET
                    timestamp_utc = excluded.timestamp_utc,
                    original_timestamp = excluded.original_timestamp,
                    entity_info = excluded.entity_info,
                    content = excluded.content,
                    location_info = excluded.location_info,
                    original_hash = excluded.original_hash,
                    normalization_status = excluded.normalization_status,
                    provenance = excluded.provenance,
                    updated_at = excluded.updated_at
                """,
                (
                    r["normalized_id"], r["evidence_item_id"], r["case_id"], r["device_id"], r["acquisition_id"],
                    r["artifact_type"], r["source_method"], r["timestamp_utc"], r["original_timestamp"],
                    r["entity_info"], r["content"], r["location_info"], r["source_ref"], r["original_hash"],
                    r["normalization_status"], r["provenance"], now, now,
                ),
            )

    return {
        "case_id": case_id,
        "total": len(normalized_records),
        "success": counts["SUCCESS"],
        "partial": counts["PARTIAL"],
        "failed": counts["FAILED"],
        "unsupported": counts["UNSUPPORTED"],
        "by_type": by_type,
    }


def get_normalized_evidence(case_id: str, artifact_type: str | None = None, status: str | None = None, query: str | None = None) -> list[dict]:
    """Retrieve normalized evidence items for a case with optional filtering."""
    sql = "SELECT * FROM normalized_evidence WHERE case_id = ?"
    params = [case_id]

    if artifact_type and artifact_type.lower() != "all":
        sql += " AND artifact_type = ?"
        params.append(artifact_type.lower())

    if status and status.upper() != "ALL":
        sql += " AND normalization_status = ?"
        params.append(status.upper())

    if query:
        sql += " AND (content LIKE ? OR entity_info LIKE ? OR source_ref LIKE ? OR normalized_id LIKE ?)"
        q_pattern = f"%{query}%"
        params.extend([q_pattern, q_pattern, q_pattern, q_pattern])

    sql += " ORDER BY timestamp_utc DESC, normalized_id"
    rows_rec = rows(sql, tuple(params))

    results = []
    for r in rows_rec:
        item = dict(r)
        try:
            item["entity_info"] = json.loads(item.get("entity_info") or "{}")
        except json.JSONDecodeError:
            pass
        try:
            item["content"] = json.loads(item.get("content") or "{}")
        except json.JSONDecodeError:
            pass
        try:
            item["location_info"] = json.loads(item.get("location_info") or "{}")
        except json.JSONDecodeError:
            pass
        try:
            item["provenance"] = json.loads(item.get("provenance") or "{}")
        except json.JSONDecodeError:
            pass
        results.append(item)

    return results

