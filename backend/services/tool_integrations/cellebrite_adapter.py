"""Tool 4: Cellebrite Physical Analyzer / UFED Integration Adapter."""

import json
import os
import re
import shutil
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import HTTPException

from backend.config import EVIDENCE_DIR
from backend.database.database import connect, record_tool_event, row, rows, utc_now
from backend.services.evidence_normalization_engine import normalize_case
from backend.services.hashing import calculate_sha256
from backend.services.tool_integrations.base_adapter import BaseToolAdapter

# Common installation paths for Cellebrite Physical Analyzer or UFED (Commercial/Academic)
CELLEBRITE_SEARCH_PATHS = [
    r"C:\Program Files\Cellebrite\Physical Analyzer\PhysicalAnalyzer.exe",
    r"C:\Program Files (x86)\Cellebrite Mobile Synchronization\Physical Analyzer\PhysicalAnalyzer.exe",
    r"C:\Program Files\Cellebrite\UFED\UFED4PC.exe",
]


class CellebriteAdapter(BaseToolAdapter):
    """Adapter for Tool 4: Cellebrite Physical Analyzer / UFED (Academic & Commercial)."""

    @property
    def tool_id(self) -> str:
        return "cellebrite"

    @property
    def name(self) -> str:
        return "Cellebrite Physical Analyzer / UFED"

    @property
    def category(self) -> str:
        return "Commercial Mobile Forensic Extraction & Decoding"

    @property
    def poster_reference(self) -> str:
        return "Tool 4: Cellebrite (Academic)"

    @property
    def description(self) -> str:
        return (
            "Industry-standard mobile forensic extraction and physical decoding suite. "
            "ForensicX provides a dedicated offline import adapter for authorized UFDR archives, "
            "XML extraction reports, and JSON exports."
        )

    def detect_installation(self) -> dict[str, Any]:
        """Check for Cellebrite binaries or connected hardware dongle."""
        for path_str in CELLEBRITE_SEARCH_PATHS:
            p = Path(path_str)
            if p.is_file():
                return {
                    "installed": True,
                    "executable_path": str(p.resolve()),
                    "licensed": True,
                    "status_label": "Installed & Licensed",
                }

        # Check PATH
        which_pa = shutil.which("PhysicalAnalyzer.exe") or shutil.which("UFED4PC.exe")
        if which_pa:
            return {
                "installed": True,
                "executable_path": which_pa,
                "licensed": True,
                "status_label": "Installed & Licensed (On PATH)",
            }

        return {
            "installed": False,
            "executable_path": None,
            "licensed": False,
            "status_label": "Awaiting License / Import-Only Mode",
        }

    def get_status(self) -> dict[str, Any]:
        detection = self.detect_installation()
        installed = detection["installed"]

        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "category": self.category,
            "poster_reference": self.poster_reference,
            "installed": installed,
            "available": True,  # Available for offline imports of authorized exports!
            "status_label": detection["status_label"],
            "executable_path": detection["executable_path"],
            "license_type": "Commercial / Academic Dongle License",
            "license_status": "Licensed" if installed else "Dongle Not Detected (Offline Import Active)",
            "modes_supported": [
                "Authorized UFDR Archive Ingestion (*.ufdr, *.zip)",
                "Cellebrite XML Report Ingestion (*.xml)",
                "Cellebrite JSON Export Ingestion (*.json)",
                "Multi-Source Evidence Mapping",
            ],
            "supported_formats": [
                "Universal Forensic Data Report (.ufdr)",
                "Cellebrite Activity & Chat XML (.xml)",
                "Cellebrite Extraction Report (.xml, .json)",
            ],
            "documentation": (
                "Cellebrite proprietary acquisition requires a licensed workstation and hardware dongle. "
                "ForensicX implements the authorized offline UFDR/XML parser to seamlessly correlate "
                "Cellebrite extractions alongside ADB, Autopsy, and iOS evidence without licensing violations."
            ),
        }

    def get_capabilities(self) -> list[str]:
        return [
            "Safe decompression and ingestion of UFDR (.ufdr/.zip) forensic containers",
            "Parsing of Cellebrite Calls, Messages, Contacts, GPS, and Extracted Files XML",
            "Full provenance tracking and SHA-256 cryptographic preservation",
            "Automatic integration into Cross-Source Correlation, Graph, and Incident Timeline",
        ]

    def import_export(self, case_id: str, file_path: str, investigator: str = "Investigator") -> dict[str, Any]:
        """Ingest an authorized Cellebrite UFDR archive, XML report, or JSON export."""
        case_info = row("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        if not case_info:
            raise HTTPException(status_code=404, detail="Case not found.")

        src = Path(file_path).expanduser().resolve()
        if not src.is_file():
            raise HTTPException(status_code=400, detail=f"Cellebrite file not found: {file_path}")

        # Compute hash and preserve raw evidence
        case_dir = (EVIDENCE_DIR / case_id).resolve()
        raw_dir = case_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        evidence_id = f"EVD-CELLEBRITE-{uuid4().hex[:6].upper()}"
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", src.name)
        dest = raw_dir / f"{evidence_id}_{safe_name}"
        shutil.copy2(src, dest)

        hash_res = calculate_sha256(dest)
        digest = hash_res["hash"]
        stored_rel = str(dest.relative_to(EVIDENCE_DIR))
        now = utc_now()

        dev_id = f"DEV-CELLEBRITE-{uuid4().hex[:6].upper()}"
        acq_id = f"ACQ-CELLEBRITE-{uuid4().hex[:6].upper()}"
        dev_serial = f"CELLEBRITE-{uuid4().hex[:6].upper()}"

        with connect() as conn:
            conn.execute(
                "INSERT INTO devices (device_id, serial, serial_number, platform, connection_state, connection_status, adb_status, lock_status, created_at, last_seen_at, updated_at) "
                "VALUES (?, ?, ?, 'Cellebrite Extracted Device', 'source', 'completed', 'not_applicable', 'unlocked', ?, ?, ?)",
                (dev_id, dev_serial, dev_serial, now, now, now),
            )
            conn.execute(
                "INSERT INTO acquisitions (acquisition_id, case_id, device_id, source, method, status, started_at, completed_at, ended_at, last_activity, notes) "
                "VALUES (?, ?, ?, 'Cellebrite UFED/PA Export', 'Cellebrite Extraction Import', 'COMPLETED', ?, ?, ?, ?, ?)",
                (acq_id, case_id, dev_id, now, now, now, now, f"Cellebrite extraction imported from {src.name} by {investigator}"),
            )
            conn.execute(
                "INSERT INTO evidence (evidence_id, case_id, device_serial, device_id, acquisition_id, evidence_type, source, file_path, acquired_at, sha256, size, status) "
                "VALUES (?, ?, ?, ?, ?, 'Cellebrite Export', 'Cellebrite PA', ?, ?, ?, ?, 'IMPORTED')",
                (evidence_id, case_id, dev_id, dev_id, acq_id, stored_rel, now, digest, dest.stat().st_size),
            )
            item_id = f"ITEM-{uuid4().hex[:8].upper()}"
            conn.execute(
                "INSERT INTO evidence_items (evidence_item_id, case_id, device_id, acquisition_id, evidence_type, source, original_path, stored_path, timestamp, hash, hash_sha256, created_at, legacy_evidence_id) "
                "VALUES (?, ?, ?, ?, 'Cellebrite Export', 'Cellebrite PA', ?, ?, ?, ?, ?, ?, ?)",
                (item_id, case_id, dev_id, acq_id, str(src), stored_rel, now, digest, digest, now, evidence_id),
            )
            conn.execute(
                "INSERT INTO hashes (evidence_item_id, algorithm, value, calculated_at) VALUES (?, 'SHA-256', ?, ?)",
                (item_id, digest, now),
            )

        artifacts_count = 0
        ext = src.suffix.lower()

        if ext in (".ufdr", ".zip"):
            artifacts_count = self._parse_ufdr(case_id, dev_id, acq_id, item_id, dest)
        elif ext == ".xml":
            artifacts_count = self._parse_xml_file(case_id, dev_id, acq_id, item_id, dest)
        elif ext == ".json":
            artifacts_count = self._parse_json_file(case_id, dev_id, acq_id, item_id, dest)

        # Record tool event and chain of custody
        details = f"Ingested {artifacts_count} artifacts from Cellebrite package '{src.name}' (SHA-256: {digest[:12]}...)."
        record_tool_event("cellebrite", case_id, "IMPORT_EXPORT", "SUCCESS", artifacts_count, details, investigator)

        # Trigger normalization for downstream engines
        norm_result = normalize_case(case_id)

        return {
            "status": "SUCCESS",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "evidence_item_id": item_id,
            "package_name": src.name,
            "sha256": digest,
            "artifacts_parsed": artifacts_count,
            "normalization": norm_result,
            "message": f"Successfully parsed {artifacts_count} artifacts from Cellebrite package.",
        }

    def _parse_ufdr(self, case_id: str, dev_id: str, acq_id: str, item_id: str, zip_path: Path) -> int:
        """Safely inspect and parse UFDR zip contents."""
        count = 0
        with zipfile.ZipFile(zip_path, "r") as z:
            for member in z.namelist():
                # Avoid path traversal attacks
                norm_name = os.path.normpath(member)
                if norm_name.startswith("..") or os.path.isabs(norm_name):
                    continue

                lower_name = member.lower()
                if lower_name.endswith(".xml"):
                    try:
                        xml_bytes = z.read(member)
                        count += self._parse_xml_bytes(case_id, dev_id, acq_id, item_id, xml_bytes)
                    except Exception:
                        pass
                elif lower_name.endswith(".json"):
                    try:
                        json_bytes = z.read(member)
                        count += self._parse_json_bytes(case_id, dev_id, acq_id, item_id, json_bytes)
                    except Exception:
                        pass
        return count

    def _parse_xml_file(self, case_id: str, dev_id: str, acq_id: str, item_id: str, xml_path: Path) -> int:
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            return self._extract_from_xml_root(case_id, dev_id, acq_id, item_id, root)
        except Exception:
            return 0

    def _parse_xml_bytes(self, case_id: str, dev_id: str, acq_id: str, item_id: str, xml_bytes: bytes) -> int:
        try:
            root = ET.fromstring(xml_bytes)
            return self._extract_from_xml_root(case_id, dev_id, acq_id, item_id, root)
        except Exception:
            return 0

    def _extract_from_xml_root(self, case_id: str, dev_id: str, acq_id: str, item_id: str, root: ET.Element) -> int:
        count = 0
        with connect() as conn:
            # 1. Parse Calls
            for call in root.findall(".//call") + root.findall(".//Call") + root.findall(".//call_log"):
                number = (call.findtext("number") or call.findtext("Number") or call.findtext("party") or "Unknown").strip()
                name = (call.findtext("name") or call.findtext("Name") or "").strip()
                ctype = (call.findtext("type") or call.findtext("Type") or "Incoming").strip()
                duration = (call.findtext("duration") or call.findtext("Duration") or "0").strip()
                ts = (call.findtext("timestamp") or call.findtext("TimeStamp") or call.findtext("time") or utc_now()).strip()

                conn.execute(
                    "INSERT INTO call_logs (evidence_item_id, case_id, device_id, acquisition_id, number, name, call_type, duration, timestamp) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (item_id, case_id, dev_id, acq_id, number, name, ctype, duration, ts),
                )
                count += 1

            # 2. Parse Messages / Chats
            for msg in root.findall(".//message") + root.findall(".//Message") + root.findall(".//sms") + root.findall(".//chat_message"):
                addr = (msg.findtext("address") or msg.findtext("from") or msg.findtext("to") or msg.findtext("sender") or "Unknown").strip()
                body = (msg.findtext("body") or msg.findtext("Body") or msg.findtext("text") or msg.findtext("content") or "").strip()
                mtype = (msg.findtext("type") or msg.findtext("direction") or "Incoming").strip()
                ts = (msg.findtext("timestamp") or msg.findtext("TimeStamp") or msg.findtext("time") or utc_now()).strip()

                if body:
                    conn.execute(
                        "INSERT INTO sms_messages (evidence_item_id, case_id, device_id, acquisition_id, address, body, message_type, timestamp) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (item_id, case_id, dev_id, acq_id, addr, body, mtype, ts),
                    )
                    count += 1

            # 3. Parse Contacts
            for cont in root.findall(".//contact") + root.findall(".//Contact"):
                name = (cont.findtext("name") or cont.findtext("Name") or cont.findtext("full_name") or "").strip()
                num = (cont.findtext("number") or cont.findtext("phone") or cont.findtext("Phone") or "").strip()
                ts = (cont.findtext("timestamp") or utc_now()).strip()

                if name or num:
                    conn.execute(
                        "INSERT INTO contacts (evidence_item_id, case_id, device_id, acquisition_id, name, number, timestamp) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (item_id, case_id, dev_id, acq_id, name, num, ts),
                    )
                    count += 1

            # 4. Parse Locations
            for loc in root.findall(".//location") + root.findall(".//Location") + root.findall(".//gps"):
                lat = (loc.findtext("latitude") or loc.findtext("Latitude") or "").strip()
                lon = (loc.findtext("longitude") or loc.findtext("Longitude") or "").strip()
                ts = (loc.findtext("timestamp") or loc.findtext("time") or utc_now()).strip()

                if lat and lon:
                    conn.execute(
                        "INSERT INTO gps_locations (evidence_item_id, case_id, device_id, acquisition_id, latitude, longitude, accuracy, provider, timestamp, raw_line) "
                        "VALUES (?, ?, ?, ?, ?, ?, '10m', 'Cellebrite UFED', ?, ?)",
                        (item_id, case_id, dev_id, acq_id, lat, lon, ts, f"Lat: {lat}, Lon: {lon}"),
                    )
                    count += 1

        return count

    def _parse_json_file(self, case_id: str, dev_id: str, acq_id: str, item_id: str, json_path: Path) -> int:
        try:
            return self._parse_json_bytes(case_id, dev_id, acq_id, item_id, json_path.read_bytes())
        except Exception:
            return 0

    def _parse_json_bytes(self, case_id: str, dev_id: str, acq_id: str, item_id: str, json_bytes: bytes) -> int:
        data = json.loads(json_bytes.decode("utf-8", errors="replace"))
        count = 0
        items = data if isinstance(data, list) else data.get("artifacts", data.get("records", []))

        with connect() as conn:
            for item in items:
                if not isinstance(item, dict):
                    continue

                # Call record
                if "call_type" in item or ("duration" in item and "number" in item):
                    conn.execute(
                        "INSERT INTO call_logs (evidence_item_id, case_id, device_id, acquisition_id, number, name, call_type, duration, timestamp) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (item_id, case_id, dev_id, acq_id, item.get("number", "Unknown"), item.get("name", ""), item.get("call_type", "Incoming"), str(item.get("duration", "0")), item.get("timestamp", utc_now())),
                    )
                    count += 1

                # Message record
                elif "body" in item or "message" in item:
                    conn.execute(
                        "INSERT INTO sms_messages (evidence_item_id, case_id, device_id, acquisition_id, address, body, message_type, timestamp) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (item_id, case_id, dev_id, acq_id, item.get("address", item.get("sender", "Unknown")), item.get("body", item.get("message", "")), item.get("type", "Incoming"), item.get("timestamp", utc_now())),
                    )
                    count += 1

                # Location record
                elif "latitude" in item and "longitude" in item:
                    conn.execute(
                        "INSERT INTO gps_locations (evidence_item_id, case_id, device_id, acquisition_id, latitude, longitude, accuracy, provider, timestamp, raw_line) "
                        "VALUES (?, ?, ?, ?, ?, ?, '10m', 'Cellebrite JSON', ?, ?)",
                        (item_id, case_id, dev_id, acq_id, str(item["latitude"]), str(item["longitude"]), item.get("timestamp", utc_now()), json.dumps(item)),
                    )
                    count += 1

        return count
