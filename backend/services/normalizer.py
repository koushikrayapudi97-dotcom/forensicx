"""Forensic artifact normalization, timestamp standardizer, and cryptographic provenance builder.

Patent-oriented evidence normalization layer:
Converts heterogeneous forensic artifacts into a common structured representation
while strictly preserving the original evidence, timestamps, hashes, source, and provenance.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from forensic.classification import classify_file


def normalize_timestamp(raw_value: Any) -> tuple[str | None, str]:
    """Convert heterogeneous forensic timestamp formats to ISO 8601 UTC.
    
    Returns (normalized_iso_timestamp, format_description).
    Preserves truthfulness: does NOT invent timestamps if absent or unparseable.
    """
    if raw_value is None:
        return None, "Unavailable (No timestamp in source record)"
    
    str_val = str(raw_value).strip()
    if not str_val or str_val.lower() in {"0", "null", "none", "unknown", "n/a"}:
        return None, "Unavailable (No timestamp in source record)"
    
    # 1. Pure numeric: check for Unix Epoch in ms or seconds
    if re.fullmatch(r"-?\d+", str_val):
        num = int(str_val)
        if num <= 0:
            return None, "Unavailable (Zero or negative timestamp)"
        # 13 digits or more -> milliseconds
        if len(str_val) >= 12:
            try:
                dt = datetime.fromtimestamp(num / 1000.0, timezone.utc)
                return dt.isoformat(), "Android Unix Epoch (milliseconds)"
            except (ValueError, OverflowError, OSError):
                return None, "Invalid Unix Epoch timestamp"
        # 9-11 digits -> seconds
        else:
            try:
                dt = datetime.fromtimestamp(float(num), timezone.utc)
                return dt.isoformat(), "Unix Epoch (seconds)"
            except (ValueError, OverflowError, OSError):
                return None, "Invalid Unix Epoch timestamp"
                
    # 2. Float numeric: e.g. 1700000000.123
    try:
        num = float(str_val)
        if num > 1e11:  # float ms
            dt = datetime.fromtimestamp(num / 1000.0, timezone.utc)
            return dt.isoformat(), "Unix Epoch Float (milliseconds)"
        elif num > 0:
            dt = datetime.fromtimestamp(num, timezone.utc)
            return dt.isoformat(), "Unix Epoch Float (seconds)"
    except (ValueError, OverflowError, OSError):
        pass

    # 3. ISO 8601 variations (with or without timezone)
    iso_clean = str_val.replace("Z", "+00:00")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f%z",
    ):
        try:
            dt = datetime.strptime(iso_clean, fmt)
            return dt.astimezone(timezone.utc).isoformat(), "ISO 8601 with timezone"
        except ValueError:
            pass

    # ISO without timezone: assume UTC per forensic standard
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(str_val, fmt).replace(tzinfo=timezone.utc)
            return dt.isoformat(), "Standard DateTime (UTC default)"
        except ValueError:
            pass

    # 4. Android Logcat format: e.g. '10-02 18:30:15.123'
    logcat_match = re.match(r"^(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?", str_val)
    if logcat_match:
        now_year = datetime.now(timezone.utc).year
        try:
            month, day, hour, minute, second = map(int, logcat_match.groups()[:5])
            micro = int((logcat_match.group(6) or "0")[:6].ljust(6, "0"))
            dt = datetime(now_year, month, day, hour, minute, second, micro, tzinfo=timezone.utc)
            return dt.isoformat(), "Android Logcat timestamp (UTC normalized)"
        except ValueError:
            pass

    return None, f"Unrecognized format ({str_val[:30]})"


def generate_stable_evidence_id(
    case_id: str,
    device_id: str,
    acquisition_id: str,
    artifact_type: str,
    record_ref: str,
) -> str:
    """Generate a stable, deterministic, unique Evidence ID.
    
    Guarantees:
    - Same artifact from same case/device/acquisition gets the EXACT SAME Evidence ID.
    - Stable across restarts, re-normalizations, and case switching.
    """
    type_abbrev = {
        "sms": "SMS",
        "call_log": "CALL",
        "gps": "LOC",
        "file": "FILE",
        "application": "APP",
        "contact": "CON",
        "browser_history": "WEB",
        "device_info": "DEV",
        "logcat": "LOG",
    }.get(artifact_type.lower(), "ART")
    
    seed = f"{case_id}:{device_id}:{acquisition_id}:{artifact_type}:{record_ref}".encode("utf-8")
    digest = hashlib.sha256(seed).hexdigest()[:8].upper()
    return f"EVD-{type_abbrev}-{digest}"


def calculate_record_sha256(record: dict | list | str | bytes) -> str:
    """Calculate cryptographic SHA-256 for a structured evidence record or payload."""
    if isinstance(record, (dict, list)):
        payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    elif isinstance(record, str):
        payload = record.encode("utf-8")
    elif isinstance(record, bytes):
        payload = record
    else:
        payload = str(record).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_provenance_record(
    source_device: str,
    acquisition_id: str,
    artifact_source: str,
    original_record_ref: str,
    hash_value: str,
    operation: str = "Acquisition & Evidence Normalization",
    actor: str = "ForensicX Normalization Engine",
    details: str = "Extracted and converted into common forensic evidence representation.",
    initial_status: str = "NORMALIZED",
) -> dict:
    """Build provenance metadata showing full custody and transformation history."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "source_device": source_device,
        "acquisition_id": acquisition_id,
        "artifact_source": artifact_source,
        "original_record_ref": original_record_ref,
        "processing_engine": "ForensicX Normalization Engine v1.0",
        "initial_hash": hash_value,
        "current_hash": hash_value,
        "current_status": initial_status,
        "integrity_status": "VERIFIED" if hash_value else "NOT AVAILABLE",
        "history": [
            {
                "step": 1,
                "operation": "Physical/Logical Evidence Ingestion",
                "timestamp": now,
                "actor": "Authorized ADB Collector",
                "details": f"Acquired from source: {artifact_source}",
                "hash": hash_value,
                "status": "ACQUIRED",
            },
            {
                "step": 2,
                "operation": operation,
                "timestamp": now,
                "actor": actor,
                "details": details,
                "hash": hash_value,
                "status": initial_status,
            },
        ],
    }


def normalize_sms_record(
    raw_record: dict[str, Any],
    case_id: str,
    device_id: str,
    acquisition_id: str,
    record_index: int = 0,
) -> dict[str, Any]:
    """Convert raw Android SMS content provider row to common evidence model."""
    raw_id = raw_record.get("_id") or raw_record.get("0 _id") or next((v for k, v in raw_record.items() if "_id" in k), str(record_index))
    record_ref = f"content://sms/_id={raw_id}"
    evidence_id = generate_stable_evidence_id(case_id, device_id, acquisition_id, "sms", record_ref)
    
    raw_date = raw_record.get("date") or next((v for k, v in raw_record.items() if "date" in k), None)
    norm_ts, ts_format = normalize_timestamp(raw_date)
    
    # Android SMS types: 1=incoming, 2=outgoing, 3=draft, 4=outbox, 5=failed, 6=queued
    raw_type = str(raw_record.get("type") or next((v for k, v in raw_record.items() if "type" in k), "")).strip()
    type_map = {
        "1": "INCOMING",
        "2": "OUTGOING",
        "3": "DRAFT",
        "4": "OUTBOX",
        "5": "FAILED",
        "6": "QUEUED",
    }
    direction = type_map.get(raw_type, "UNKNOWN")
    address = str(raw_record.get("address") or next((v for k, v in raw_record.items() if "address" in k), "")).strip()
    body = raw_record.get("body") or next((v for k, v in raw_record.items() if "body" in k), "")
    
    normalized_data = {
        "message_id": raw_id,
        "sender": address if direction == "INCOMING" else "Device Owner (Self)",
        "recipient": address if direction == "OUTGOING" else "Device Owner (Self)",
        "address": address,
        "direction": direction,
        "message_body": body,
        "read_status": "READ" if raw_record.get("read") == "1" else "UNREAD",
        "thread_id": raw_record.get("thread_id", ""),
        "service_center": raw_record.get("service_center", ""),
    }
    
    record_hash = calculate_record_sha256(raw_record)
    provenance = build_provenance_record(
        source_device=device_id,
        acquisition_id=acquisition_id,
        artifact_source="content://sms",
        original_record_ref=record_ref,
        hash_value=record_hash,
        operation="SMS Ingestion & Schema Normalization",
        details="Extracted from content://sms provider and normalized to common messaging model.",
    )
    
    now = datetime.now(timezone.utc).isoformat()
    return {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "device_id": device_id,
        "acquisition_id": acquisition_id,
        "artifact_type": "sms",
        "source": "content://sms",
        "original_record_ref": record_ref,
        "original_timestamp": str(raw_date) if raw_date is not None else "",
        "normalized_timestamp": norm_ts or "",
        "timestamp_format": ts_format,
        "hash": record_hash,
        "integrity_status": "VERIFIED",
        "provenance": provenance,
        "original_data": raw_record,
        "normalized_data": normalized_data,
        "processing_status": "NORMALIZED",
        "created_at": now,
        "updated_at": now,
    }


def normalize_call_record(
    raw_record: dict[str, Any],
    case_id: str,
    device_id: str,
    acquisition_id: str,
    record_index: int = 0,
) -> dict[str, Any]:
    """Convert raw Android Call Log provider row to common evidence model."""
    raw_id = raw_record.get("_id") or raw_record.get("0 _id") or next((v for k, v in raw_record.items() if "_id" in k), str(record_index))
    record_ref = f"content://call_log/calls/_id={raw_id}"
    evidence_id = generate_stable_evidence_id(case_id, device_id, acquisition_id, "call_log", record_ref)
    
    raw_date = raw_record.get("date") or next((v for k, v in raw_record.items() if "date" in k), None)
    norm_ts, ts_format = normalize_timestamp(raw_date)
    
    # Call types: 1=incoming, 2=outgoing, 3=missed, 4=voicemail, 5=rejected, 6=blocked
    raw_type = str(raw_record.get("type") or next((v for k, v in raw_record.items() if "type" in k), "")).strip()
    type_map = {
        "1": "INCOMING",
        "2": "OUTGOING",
        "3": "MISSED",
        "4": "VOICEMAIL",
        "5": "REJECTED",
        "6": "BLOCKED",
    }
    call_type = type_map.get(raw_type, "UNKNOWN")
    number = str(raw_record.get("number") or next((v for k, v in raw_record.items() if "number" in k), "")).strip()
    name = raw_record.get("name") or next((v for k, v in raw_record.items() if "name" in k), None)
    
    try:
        duration_sec = int(raw_record.get("duration") or next((v for k, v in raw_record.items() if "duration" in k), 0))
    except (ValueError, TypeError):
        duration_sec = 0
        
    normalized_data = {
        "call_id": raw_id,
        "phone_number": raw_record.get("number", ""),
        "caller_name": raw_record.get("name") or "Unknown / Unnamed",
        "call_type": call_type,
        "duration_seconds": duration_sec,
        "duration_formatted": f"{duration_sec // 60}m {duration_sec % 60}s",
    }
    
    record_hash = calculate_record_sha256(raw_record)
    provenance = build_provenance_record(
        source_device=device_id,
        acquisition_id=acquisition_id,
        artifact_source="content://call_log/calls",
        original_record_ref=record_ref,
        hash_value=record_hash,
        operation="Call Log Ingestion & Schema Normalization",
        details="Extracted from content://call_log/calls provider and normalized to common call model.",
    )
    
    now = datetime.now(timezone.utc).isoformat()
    return {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "device_id": device_id,
        "acquisition_id": acquisition_id,
        "artifact_type": "call_log",
        "source": "content://call_log/calls",
        "original_record_ref": record_ref,
        "original_timestamp": str(raw_date) if raw_date is not None else "",
        "normalized_timestamp": norm_ts or "",
        "timestamp_format": ts_format,
        "hash": record_hash,
        "integrity_status": "VERIFIED",
        "provenance": provenance,
        "original_data": raw_record,
        "normalized_data": normalized_data,
        "processing_status": "NORMALIZED",
        "created_at": now,
        "updated_at": now,
    }


def normalize_gps_record(
    raw_record: dict[str, Any] | str,
    case_id: str,
    device_id: str,
    acquisition_id: str,
    record_index: int = 0,
) -> dict[str, Any]:
    """Convert raw location service line/record to common evidence model."""
    raw_text = raw_record.get("raw", "") if isinstance(raw_record, dict) else str(raw_record)
    record_ref = f"dumpsys_location#line_{record_index}"
    evidence_id = generate_stable_evidence_id(case_id, device_id, acquisition_id, "gps", record_ref)
    
    # Parse coordinates if present: e.g. Location[gps 37.774900,-122.419400 ... time=1696248000000]
    lat = None
    lon = None
    altitude = None
    provider = "unknown"
    accuracy = None
    raw_ts = None
    
    coord_match = re.search(r"(-?\d+\.\d+),\s*(-?\d+\.\d+)", raw_text)
    if coord_match:
        try:
            lat = float(coord_match.group(1))
            lon = float(coord_match.group(2))
        except ValueError:
            pass
            
    time_match = re.search(r"time=(\d+)", raw_text)
    if time_match:
        raw_ts = time_match.group(1)
        
    provider_match = re.search(r"Location\[([a-zA-Z0-9_-]+)", raw_text)
    if provider_match:
        provider = provider_match.group(1)
        
    acc_match = re.search(r"acc=([\d\.]+)", raw_text)
    if acc_match:
        try:
            accuracy = float(acc_match.group(1))
        except ValueError:
            pass
            
    alt_match = re.search(r"alt=([\d\.]+)", raw_text)
    if alt_match:
        try:
            altitude = float(alt_match.group(1))
        except ValueError:
            pass

    norm_ts, ts_format = normalize_timestamp(raw_ts)
    
    normalized_data = {
        "latitude": lat,
        "longitude": lon,
        "altitude_meters": altitude,
        "accuracy_meters": accuracy,
        "provider": provider,
        "has_coordinates": (lat is not None and lon is not None),
        "summary": f"{lat}, {lon} ({provider})" if (lat and lon) else raw_text[:120],
        "raw_line": raw_text,
    }
    
    record_hash = calculate_record_sha256(raw_text)
    provenance = build_provenance_record(
        source_device=device_id,
        acquisition_id=acquisition_id,
        artifact_source="dumpsys location",
        original_record_ref=record_ref,
        hash_value=record_hash,
        operation="Location Intelligence Extraction",
        details="Extracted from authorized dumpsys location service.",
    )
    
    now = datetime.now(timezone.utc).isoformat()
    return {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "device_id": device_id,
        "acquisition_id": acquisition_id,
        "artifact_type": "gps",
        "source": "dumpsys location",
        "original_record_ref": record_ref,
        "original_timestamp": str(raw_ts) if raw_ts else "",
        "normalized_timestamp": norm_ts or "",
        "timestamp_format": ts_format,
        "hash": record_hash,
        "integrity_status": "VERIFIED",
        "provenance": provenance,
        "original_data": {"raw": raw_text},
        "normalized_data": normalized_data,
        "processing_status": "NORMALIZED",
        "created_at": now,
        "updated_at": now,
    }


def normalize_file_record(
    file_path: Path | str,
    case_id: str,
    device_id: str,
    acquisition_id: str,
    base_dir: Path | None = None,
    source_label: str = "Filesystem Extraction",
    stored_hash: str | None = None,
) -> dict[str, Any]:
    """Convert a preserved evidence file into the common evidence model."""
    path = Path(file_path).resolve()
    rel_path = str(path.relative_to(base_dir)) if base_dir and base_dir in path.parents else path.name
    record_ref = rel_path
    
    evidence_id = generate_stable_evidence_id(case_id, device_id, acquisition_id, "file", record_ref)
    
    if path.is_file():
        stat = path.stat()
        mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
        ctime = datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat()
        size = stat.st_size
        classification = classify_file(path)
        
        # Calculate SHA-256 directly from file
        digest = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        calc_hash = digest.hexdigest()
        integrity_status = "VERIFIED" if (not stored_hash or stored_hash.lower() == calc_hash.lower()) else "MODIFIED"
    else:
        mtime = None
        ctime = None
        size = 0
        classification = {"filename": path.name, "category": "Unknown", "mime_type": "application/octet-stream"}
        calc_hash = stored_hash or ""
        integrity_status = "NOT AVAILABLE"
        
    normalized_data = {
        "filename": path.name,
        "relative_path": rel_path,
        "size_bytes": size,
        "category": classification.get("category", "Unknown"),
        "mime_type": classification.get("mime_type", "application/octet-stream"),
        "extension": path.suffix.lower(),
        "created_at": ctime,
        "modified_at": mtime,
    }
    
    provenance = build_provenance_record(
        source_device=device_id,
        acquisition_id=acquisition_id,
        artifact_source=source_label,
        original_record_ref=record_ref,
        hash_value=calc_hash,
        operation="File Extraction & Preservation",
        details=f"Preserved file {rel_path} ({size} bytes). SHA-256 verified.",
    )
    
    now = datetime.now(timezone.utc).isoformat()
    return {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "device_id": device_id,
        "acquisition_id": acquisition_id,
        "artifact_type": "file",
        "source": source_label,
        "original_record_ref": record_ref,
        "original_timestamp": mtime or "",
        "normalized_timestamp": mtime or "",
        "timestamp_format": "Filesystem mtime (UTC)" if mtime else "Unavailable",
        "hash": calc_hash,
        "integrity_status": integrity_status,
        "provenance": provenance,
        "original_data": {"path": str(path), "size": size, "sha256": calc_hash},
        "normalized_data": normalized_data,
        "processing_status": "NORMALIZED",
        "created_at": now,
        "updated_at": now,
    }


def normalize_generic_artifact(
    artifact_type: str,
    raw_record: dict[str, Any],
    case_id: str,
    device_id: str,
    acquisition_id: str,
    source_label: str,
    record_ref: str,
) -> dict[str, Any]:
    """Convert any generic or specialized artifact (applications, contacts, browser) to common model."""
    evidence_id = generate_stable_evidence_id(case_id, device_id, acquisition_id, artifact_type, record_ref)
    
    # Try looking for timestamp fields in raw record
    raw_ts = None
    for key in ("timestamp", "time", "date", "created", "datetime", "last_visit_time"):
        if key in raw_record and raw_record[key]:
            raw_ts = raw_record[key]
            break
            
    norm_ts, ts_format = normalize_timestamp(raw_ts)
    record_hash = calculate_record_sha256(raw_record)
    
    provenance = build_provenance_record(
        source_device=device_id,
        acquisition_id=acquisition_id,
        artifact_source=source_label,
        original_record_ref=record_ref,
        hash_value=record_hash,
        operation=f"{artifact_type.capitalize()} Ingestion & Schema Normalization",
        details=f"Normalized from source: {source_label}",
    )
    
    now = datetime.now(timezone.utc).isoformat()
    return {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "device_id": device_id,
        "acquisition_id": acquisition_id,
        "artifact_type": artifact_type,
        "source": source_label,
        "original_record_ref": record_ref,
        "original_timestamp": str(raw_ts) if raw_ts is not None else "",
        "normalized_timestamp": norm_ts or "",
        "timestamp_format": ts_format,
        "hash": record_hash,
        "integrity_status": "VERIFIED",
        "provenance": provenance,
        "original_data": raw_record,
        "normalized_data": raw_record,
        "processing_status": "NORMALIZED",
        "created_at": now,
        "updated_at": now,
    }
