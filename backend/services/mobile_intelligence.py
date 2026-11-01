"""Authorized Android mobile-intelligence collection.

Every command in this module is fixed by the application. No command text is
accepted from the frontend, and provider failures are reported as unavailable
instead of being treated as empty evidence.
"""

from datetime import datetime, timezone
import re

from backend.services.adb_manager import AdbError
from backend.services.device_manager import DeviceManager


NOT_AVAILABLE = "Not available with current authorization/configuration"


def _provider_rows(output: str) -> list[dict[str, str]]:
    records = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("Row:"):
            continue
        values = {}
        for field in re.split(r", (?=[A-Za-z_][A-Za-z0-9_]*=)", line.removeprefix("Row: ")):
            if "=" in field:
                key, value = field.split("=", 1)
                values[key] = value
        if values:
            records.append(values)
    return records


def collect_intelligence(serial: str, device_manager: DeviceManager) -> dict:
    """Collect data exposed by standard Android providers and services."""
    results = {
        "serial": serial,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "sms": {"status": "unavailable", "records": [], "error": NOT_AVAILABLE},
        "call_logs": {"status": "unavailable", "records": [], "error": NOT_AVAILABLE},
        "gps": {"status": "unavailable", "records": [], "error": NOT_AVAILABLE},
        "files": {"status": "unavailable", "records": [], "error": NOT_AVAILABLE},
        "browser_history": {"status": "unavailable", "records": [], "error": NOT_AVAILABLE},
        "media_files": {"status": "unavailable", "records": [], "error": NOT_AVAILABLE},
        "social_media": {"status": "not_available", "records": [], "error": "App-private social-media databases are not generically accessible through authorized ADB."},
    }
    providers = {
        "sms": ["content", "query", "--uri", "content://sms", "--projection", "_id:address:date:type:body", "--sort", "date"],
        "call_logs": ["content", "query", "--uri", "content://call_log/calls", "--projection", "_id:number:date:duration:type:name", "--sort", "date"],
    }
    for name, command in providers.items():
        try:
            output = device_manager.adb_manager.shell(serial, command)
            results[name] = {"status": "available", "records": _provider_rows(output), "error": None}
        except AdbError as exc:
            results[name]["error"] = str(exc)
    # GPS: try multiple sources in order of reliability
    gps_records, gps_error = _collect_gps(serial, device_manager)
    if gps_records:
        results["gps"] = {"status": "available", "records": gps_records, "error": None}
    else:
        results["gps"] = {"status": "unavailable", "records": [], "error": gps_error or NOT_AVAILABLE}

    # Mobile Device Files Extraction
    file_records, file_error = _collect_files(serial, device_manager)
    if file_records:
        results["files"] = {"status": "available", "records": file_records, "error": None}
    else:
        results["files"] = {"status": "unavailable", "records": [], "error": file_error or NOT_AVAILABLE}

    # Mobile Device Web & Browser History Extraction
    web_records, web_error = _collect_web_history(serial, device_manager)
    if web_records:
        results["browser_history"] = {"status": "available", "records": web_records, "error": None}
    else:
        results["browser_history"] = {"status": "unavailable", "records": [], "error": web_error or NOT_AVAILABLE}

    # Mobile Device Media Files (Photos, Video, Audio) Extraction
    media_records, media_error = _collect_media(serial, device_manager)
    if media_records:
        results["media_files"] = {"status": "available", "records": media_records, "error": None}
    else:
        results["media_files"] = {"status": "unavailable", "records": [], "error": media_error or NOT_AVAILABLE}

    return results


def _collect_web_history(serial: str, device_manager: DeviceManager) -> tuple[list[dict], str]:
    """Collect real web history and bookmarks exposed by Android content providers."""
    if not device_manager or not getattr(device_manager, "adb_manager", None):
        return [], NOT_AVAILABLE

    errors = []
    records = []

    # Strategy 1: Browser Bookmarks & History Provider
    try:
        output = device_manager.adb_manager.shell(
            serial,
            ["content", "query", "--uri", "content://browser/bookmarks", "--projection", "title:url:date:visits:bookmark", "--sort", "date DESC"]
        )
        rows = _provider_rows(output)
        for r in rows:
            url = r.get("url")
            if not url:
                continue
            records.append({
                "_id": r.get("_id", len(records) + 1),
                "browser": "Android Browser / Chrome",
                "url": url,
                "title": r.get("title") or url,
                "visit_timestamp": _format_epoch(r.get("date")),
                "visit_count": int(r.get("visits") or 1) if str(r.get("visits", "")).isdigit() else 1,
                "source": "content://browser/bookmarks",
            })
    except AdbError as exc:
        errors.append(f"browser bookmarks: {exc}")

    # Strategy 2: Browser Search History Provider
    try:
        output = device_manager.adb_manager.shell(
            serial,
            ["content", "query", "--uri", "content://browser/searches", "--projection", "search:date", "--sort", "date DESC"]
        )
        rows = _provider_rows(output)
        for r in rows:
            query = r.get("search")
            if not query:
                continue
            records.append({
                "_id": len(records) + 1,
                "browser": "Android Search Provider",
                "url": f"https://www.google.com/search?q={query}",
                "title": f"Search: {query}",
                "visit_timestamp": _format_epoch(r.get("date")),
                "visit_count": 1,
                "source": "content://browser/searches",
            })
    except AdbError as exc:
        errors.append(f"browser searches: {exc}")

    if records:
        return records, ""

    return [], "; ".join(errors) or NOT_AVAILABLE


def _format_epoch(val: str | None) -> str:
    if not val:
        return datetime.now(timezone.utc).isoformat()
    try:
        ts = int(val)
        if ts > 1_000_000_000_000:
            ts //= 1000
        return datetime.fromtimestamp(ts, timezone.utc).isoformat()
    except (ValueError, OSError, TypeError):
        return str(val)


def _collect_media(serial: str, device_manager: DeviceManager) -> tuple[list[dict], str]:
    """Collect real media files (images, video, audio) from Android MediaStore & DCIM/Camera directories."""
    if not device_manager or not getattr(device_manager, "adb_manager", None):
        return [], NOT_AVAILABLE

    errors = []
    records = []

    # Strategy 1: MediaStore Images
    try:
        output = device_manager.adb_manager.shell(
            serial,
            ["content", "query", "--uri", "content://media/external/images/media", "--projection", "_id:_data:_size:_display_name:mime_type:datetaken:date_modified", "--sort", "datetaken DESC"]
        )
        rows = _provider_rows(output)
        for r in rows:
            path = r.get("_data") or r.get("_display_name")
            if not path:
                continue
            fname = r.get("_display_name") or path.split("/")[-1]
            records.append({
                "_id": r.get("_id", len(records) + 1),
                "media_type": "Image",
                "file_name": fname,
                "original_path": path,
                "size": int(r.get("_size") or 0) if str(r.get("_size", "")).isdigit() else 0,
                "mime_type": r.get("mime_type") or "image/jpeg",
                "date_taken": _format_epoch(r.get("datetaken") or r.get("date_modified")),
                "source": "content://media/external/images/media",
            })
    except AdbError as exc:
        errors.append(f"media images: {exc}")

    # Strategy 2: MediaStore Video
    try:
        output = device_manager.adb_manager.shell(
            serial,
            ["content", "query", "--uri", "content://media/external/video/media", "--projection", "_id:_data:_size:_display_name:mime_type:datetaken:duration", "--sort", "datetaken DESC"]
        )
        rows = _provider_rows(output)
        for r in rows:
            path = r.get("_data") or r.get("_display_name")
            if not path:
                continue
            fname = r.get("_display_name") or path.split("/")[-1]
            dur = r.get("duration")
            dur_str = f"{int(dur)//1000}s" if dur and str(dur).isdigit() else "Unknown"
            records.append({
                "_id": r.get("_id", len(records) + 1),
                "media_type": "Video",
                "file_name": fname,
                "original_path": path,
                "size": int(r.get("_size") or 0) if str(r.get("_size", "")).isdigit() else 0,
                "mime_type": r.get("mime_type") or "video/mp4",
                "date_taken": _format_epoch(r.get("datetaken")),
                "duration": dur_str,
                "source": "content://media/external/video/media",
            })
    except AdbError as exc:
        errors.append(f"media video: {exc}")

    # Strategy 3: MediaStore Audio
    try:
        output = device_manager.adb_manager.shell(
            serial,
            ["content", "query", "--uri", "content://media/external/audio/media", "--projection", "_id:_data:_size:_display_name:mime_type:duration", "--sort", "_id DESC"]
        )
        rows = _provider_rows(output)
        for r in rows:
            path = r.get("_data") or r.get("_display_name")
            if not path:
                continue
            fname = r.get("_display_name") or path.split("/")[-1]
            dur = r.get("duration")
            dur_str = f"{int(dur)//1000}s" if dur and str(dur).isdigit() else "Unknown"
            records.append({
                "_id": r.get("_id", len(records) + 1),
                "media_type": "Audio",
                "file_name": fname,
                "original_path": path,
                "size": int(r.get("_size") or 0) if str(r.get("_size", "")).isdigit() else 0,
                "mime_type": r.get("mime_type") or "audio/mpeg",
                "date_taken": datetime.now(timezone.utc).isoformat(),
                "duration": dur_str,
                "source": "content://media/external/audio/media",
            })
    except AdbError as exc:
        errors.append(f"media audio: {exc}")

    if records:
        return records, ""

    return [], "; ".join(errors) or NOT_AVAILABLE



def _collect_files(serial: str, device_manager: DeviceManager) -> tuple[list[dict], str]:
    """Collect real device files via Android MediaStore external file provider and filesystem discovery."""
    errors = []
    # Strategy 1: MediaStore external file provider
    try:
        output = device_manager.adb_manager.shell(
            serial,
            ["content", "query", "--uri", "content://media/external/file", "--projection", "_id:_data:_size:_display_name:mime_type:date_modified", "--sort", "date_modified DESC"]
        )
        rows = _provider_rows(output)
        if rows:
            records = []
            for r in rows:
                path = r.get("_data") or r.get("_display_name")
                if not path:
                    continue
                records.append({
                    "_id": r.get("_id", ""),
                    "original_path": path,
                    "file_name": r.get("_display_name") or path.split("/")[-1],
                    "size": int(r.get("_size") or 0) if str(r.get("_size", "")).isdigit() else 0,
                    "mime_type": r.get("mime_type") or "application/octet-stream",
                    "date_modified": r.get("date_modified") or "",
                })
            if records:
                return records, ""
    except AdbError as exc:
        errors.append(f"mediastore files: {exc}")

    # Strategy 2: ADB shell directory listing for Downloads & Documents
    try:
        output = device_manager.adb_manager.shell(serial, ["ls", "-la", "/sdcard/Download/"])
        records = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("-") or line.startswith("w") or line.startswith("r"):
                parts = line.split()
                if len(parts) >= 8:
                    fname = parts[-1]
                    if fname not in (".", ".."):
                        records.append({
                            "_id": str(len(records) + 1),
                            "original_path": f"/sdcard/Download/{fname}",
                            "file_name": fname,
                            "size": int(parts[4]) if parts[4].isdigit() else 0,
                            "mime_type": "application/octet-stream",
                            "date_modified": " ".join(parts[5:8]),
                        })
        if records:
            return records, ""
    except AdbError as exc:
        errors.append(f"ls download: {exc}")

    return [], "; ".join(errors) or NOT_AVAILABLE



def _collect_gps(serial: str, device_manager: DeviceManager) -> tuple[list[dict], str]:
    """Try multiple ADB strategies to extract real GPS fixes from the device."""
    errors = []

    # Strategy 1: dumpsys location — last known fixes from all providers
    try:
        output = device_manager.adb_manager.shell(serial, ["dumpsys", "location"])
        records = _parse_dumpsys_location(output)
        if records:
            return records, ""
    except AdbError as exc:
        errors.append(f"dumpsys location: {exc}")

    # Strategy 2: MediaStore Photo GPS Metadata (Location embedded in photos taken by device)
    try:
        output = device_manager.adb_manager.shell(
            serial,
            ["content", "query", "--uri", "content://media/external/images/media", "--projection", "latitude:longitude:datetaken", "--where", "latitude IS NOT NULL AND latitude != 0"]
        )
        records = _parse_provider_location(output)
        if records:
            return records, ""
    except AdbError as exc:
        errors.append(f"mediastore photo gps: {exc}")

    # Strategy 3: GMS location provider history
    try:
        output = device_manager.adb_manager.shell(
            serial,
            ["content", "query", "--uri", "content://com.google.android.gms.location.provider/lastlocation"]
        )
        records = _parse_provider_location(output)
        if records:
            return records, ""
    except AdbError as exc:
        errors.append(f"gms location provider: {exc}")

    # Strategy 4: Try dumpsys locationpolicy (Oppo/OnePlus/Vivo specific)
    try:
        output = device_manager.adb_manager.shell(serial, ["dumpsys", "locationpolicy"])
        records = _parse_dumpsys_location(output)
        if records:
            return records, ""
    except AdbError as exc:
        errors.append(f"dumpsys locationpolicy: {exc}")

    # Strategy 5: read /data/system/location (requires root)
    try:
        output = device_manager.adb_manager.shell(serial, ["cat", "/data/system/location/gps_debug.txt"])
        if output and "Permission denied" not in output:
            records = [{"raw": line, "source": "gps_debug"} for line in output.splitlines() if line.strip()]
            if records:
                return records, ""
    except AdbError as exc:
        errors.append(f"gps_debug.txt: {exc}")

    return [], " | ".join(errors)


def _parse_dumpsys_location(output: str) -> list[dict]:
    """Parse real GPS/network/fused fixes from dumpsys location output."""
    import re
    records = []
    seen = set()

    # Match any line containing lat,lon coordinates across all Android versions & ROM formats:
    # Location[gps 13.082680, 80.270718 ...]
    # Location[fused 13.082680,80.270718 acc=5.0]
    # mLatitude=13.082680 mLongitude=80.270718
    # latitude: 13.082680, longitude: 80.270718
    # 13.082680, 80.270718
    patterns = [
        re.compile(
            r"Location\[(?:(?P<provider>gps|network|fused|passive)\s+)?(?P<lat>-?\d{1,3}\.[\d\*]+)[,\s]+(?P<lon>-?\d{1,3}\.[\d\*]+)"
            r"(?:[^\n]{0,80}?(?:hAcc|acc|accuracy)[=:\s]+(?P<acc>[\d.]+))?",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:lat|latitude|mLatitude)[=:\s]+(?P<lat>-?\d{1,3}\.[\d\*]+)[,\s]+"
            r"(?:lon|lng|longitude|mLongitude)[=:\s]+(?P<lon>-?\d{1,3}\.[\d\*]+)"
            r"(?:[^\n]{0,80}?(?:hAcc|acc|accuracy)[=:\s]+(?P<acc>[\d.]+))?",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?P<lat>-?\d{1,3}\.[\d\*]{2,})[,\s]+(?P<lon>-?\d{1,3}\.[\d\*]{2,})",
            re.IGNORECASE,
        ),
    ]
    time_re = re.compile(r"(?:time|mTime|timestamp|datetaken)[=:]\s*([\d]{10,13})")
    provider_re = re.compile(r"(gps|network|fused|passive)", re.IGNORECASE)

    for line in output.splitlines():
        for pattern in patterns:
            m = pattern.search(line)
            if not m:
                continue
            try:
                lat_str = m.group("lat").replace("*", "0")
                lon_str = m.group("lon").replace("*", "0")
                lat = float(lat_str)
                lon = float(lon_str)
            except (ValueError, TypeError):
                continue
            # Skip null island
            if lat == 0.0 and lon == 0.0:
                continue
            # Skip obviously invalid coordinates
            if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
                continue
            key = (round(lat, 6), round(lon, 6))
            if key in seen:
                continue
            seen.add(key)
            provider_m = provider_re.search(line)
            provider = provider_m.group(1).lower() if provider_m else "unknown"
            timestamp = None
            tm = time_re.search(line)
            if tm:
                try:
                    ms = int(tm.group(1))
                    if ms > 1_000_000_000_000:
                        ms //= 1000
                    timestamp = datetime.fromtimestamp(ms, timezone.utc).isoformat()
                except (ValueError, OSError):
                    pass
            records.append({
                "latitude": str(lat),
                "longitude": str(lon),
                "accuracy": m.group("acc") if m.groupdict().get("acc") else "Unknown",
                "provider": provider,
                "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
                "raw": line.strip(),
                "source": "dumpsys_location",
            })
            break
    return records


def _parse_provider_location(output: str) -> list[dict]:
    """Parse location from content provider query output."""
    import re
    records = []
    for row in _provider_rows(output):
        lat = row.get("latitude") or row.get("lat")
        lon = row.get("longitude") or row.get("lon") or row.get("lng")
        if not lat or not lon:
            continue
        try:
            if float(lat) == 0.0 and float(lon) == 0.0:
                continue
        except ValueError:
            continue
        records.append({
            "latitude": lat,
            "longitude": lon,
            "accuracy": row.get("accuracy") or "Unknown",
            "provider": row.get("provider") or "network",
            "timestamp": row.get("time") or datetime.now(timezone.utc).isoformat(),
            "raw": str(row),
            "source": "content_provider",
        })
    return records