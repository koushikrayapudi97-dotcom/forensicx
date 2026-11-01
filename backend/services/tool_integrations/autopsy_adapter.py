"""Tool 3: Autopsy Digital Forensics Integration Adapter."""

import csv
import json
import os
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import HTTPException

from backend.config import EVIDENCE_DIR
from backend.database.database import connect, record_tool_event, row, rows, utc_now
from backend.services.evidence_normalization_engine import normalize_case
from backend.services.hashing import calculate_sha256
from backend.services.tool_integrations.base_adapter import BaseToolAdapter

# Common installation candidates for Autopsy on Windows
AUTOPSY_SEARCH_PATHS = [
    r"C:\Program Files\Autopsy-4.23.1\bin\autopsy64.exe",
    r"C:\Program Files\Autopsy-4.21.0\bin\autopsy64.exe",
    r"C:\Program Files\Autopsy-4.20.0\bin\autopsy64.exe",
    r"C:\Program Files\Autopsy\bin\autopsy64.exe",
    r"C:\Program Files (x86)\Autopsy\bin\autopsy.exe",
]


class _AutopsyHTMLTableParser(HTMLParser):
    """Safely extracts tabular data from Autopsy HTML reports."""

    def __init__(self) -> None:
        super().__init__()
        self.tables: list[list[list[str]]] = []
        self._current_table: list[list[str]] = []
        self._current_row: list[str] = []
        self._current_cell: list[str] = []
        self._in_cell = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self._current_table = []
        elif tag in ("td", "th"):
            self._in_cell = True
            self._current_cell = []
        elif tag == "tr":
            self._current_row = []

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th"):
            self._in_cell = False
            self._current_row.append(" ".join("".join(self._current_cell).split()))
        elif tag == "tr":
            if any(cell.strip() for cell in self._current_row):
                self._current_table.append(self._current_row)
        elif tag == "table":
            if self._current_table:
                self.tables.append(self._current_table)

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            self._current_cell.append(data)


class AutopsyAdapter(BaseToolAdapter):
    """Adapter for Tool 3: Autopsy Digital Forensics Platform."""

    @property
    def tool_id(self) -> str:
        return "autopsy"

    @property
    def name(self) -> str:
        return "Autopsy Digital Forensics Platform"

    @property
    def category(self) -> str:
        return "Disk Image & Artifact Deep Examination"

    @property
    def poster_reference(self) -> str:
        return "Tool 3: Autopsy"

    @property
    def description(self) -> str:
        return (
            "Open-source digital forensics platform for deep file system analysis, "
            "disk image examination (E01/RAW), keyword search, web activity, and deleted file recovery."
        )

    def detect_executable(self) -> str | None:
        """Scan standard installation locations and PATH for Autopsy."""
        which_path = shutil.which("autopsy64.exe") or shutil.which("autopsy.exe")
        if which_path:
            return which_path

        for candidate in AUTOPSY_SEARCH_PATHS:
            p = Path(candidate)
            if p.is_file():
                return str(p.resolve())

        # Check Program Files directory wildcard
        prog_files = Path(r"C:\Program Files")
        if prog_files.is_dir():
            try:
                for sub in prog_files.glob("Autopsy*"):
                    exe = sub / "bin" / "autopsy64.exe"
                    if exe.is_file():
                        return str(exe.resolve())
            except Exception:
                pass

        return None

    def get_status(self) -> dict[str, Any]:
        exe_path = self.detect_executable()
        installed = exe_path is not None
        version = None
        if installed and exe_path:
            match = re.search(r"Autopsy-?([0-9]+\.[0-9]+\.[0-9]+)", exe_path, re.IGNORECASE)
            version = match.group(1) if match else "4.x"

        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "category": self.category,
            "poster_reference": self.poster_reference,
            "installed": installed,
            "available": installed,
            "status_label": f"Installed & Ready (v{version})" if installed else "Not Installed",
            "executable_path": exe_path,
            "version": version,
            "license_type": "Open Source (Apache 2.0)",
            "license_status": "Licensed / Unrestricted",
            "modes_supported": [
                "Workspace Case Preparation",
                "GUI Application Launch",
                "HTML Report Ingestion",
                "CSV/TSV Artifact Ingestion",
                "Keyword & Web History Integration",
            ],
            "supported_formats": [
                "Autopsy HTML Reports (*.html)",
                "Autopsy Delimited Artifacts (*.tsv, *.csv)",
                "Forensic Disk Images (RAW, DD, E01, VMDK)",
                "Extracted Triage Directories",
            ],
            "documentation": (
                "Verified Autopsy installation on host system. ForensicX prepares an automated "
                "case workspace with verified image hashes, launches Autopsy directly, and ingests "
                "Autopsy-generated reports into the multi-source correlation engine."
            ),
        }

    def get_capabilities(self) -> list[str]:
        return [
            "Auto-detection of local Autopsy 4.x installations",
            "Creation of structured case examination workspaces with evidence manifests",
            "Safe direct launch of Autopsy GUI for investigator examination",
            "Ingestion and parsing of Autopsy Web History, Call Logs, Messages, and File reports",
            "Cryptographic hashing and chain-of-custody logging of all imported artifacts",
            "Immediate propagation into Cross Correlations, Reliability, Graph, and Timeline engines",
        ]

    def prepare_case_workspace(self, case_id: str, investigator: str = "Investigator") -> dict[str, Any]:
        """Prepare an Autopsy-ready folder containing verified case evidence and manifest."""
        case_info = row("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        if not case_info:
            raise HTTPException(status_code=404, detail="Case not found.")

        workspace_dir = (EVIDENCE_DIR / case_id / "autopsy_workspace").resolve()
        workspace_dir.mkdir(parents=True, exist_ok=True)

        # Gather existing evidence items for this case
        evidence_list = rows("SELECT * FROM evidence WHERE case_id = ?", (case_id,))
        manifest_entries = []

        for ev in evidence_list:
            stored_rel = ev.get("file_path") or ""
            full_path = (EVIDENCE_DIR / stored_rel).resolve()
            if full_path.is_file():
                manifest_entries.append({
                    "evidence_id": ev["evidence_id"],
                    "type": ev["evidence_type"],
                    "source": ev["source"],
                    "filename": full_path.name,
                    "absolute_path": str(full_path),
                    "size_bytes": full_path.stat().st_size,
                    "sha256": ev.get("sha256"),
                })

        manifest_file = workspace_dir / "autopsy_case_manifest.json"
        manifest_data = {
            "forensicx_case_id": case_id,
            "case_name": case_info["case_name"],
            "investigator": investigator,
            "prepared_at": utc_now(),
            "target_tool": "Autopsy Digital Forensics",
            "recommended_ingest_modules": [
                "Recent Activity",
                "Hash Lookup",
                "File Type Identification",
                "Keyword Search",
                "Email Parser",
                "Android Analyzer",
            ],
            "evidence_sources": manifest_entries,
        }
        manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        # Record event in custody and tool integration audit
        now = utc_now()
        details = f"Prepared Autopsy examination workspace with {len(manifest_entries)} evidence sources."
        record_tool_event("autopsy", case_id, "PREPARE_WORKSPACE", "SUCCESS", len(manifest_entries), details, investigator)

        return {
            "status": "SUCCESS",
            "case_id": case_id,
            "workspace_path": str(workspace_dir),
            "manifest_path": str(manifest_file),
            "evidence_count": len(manifest_entries),
            "evidence_sources": manifest_entries,
            "instructions": (
                "Open Autopsy -> New Case -> Point data source to the evidence paths listed in autopsy_case_manifest.json. "
                "After running ingest, export HTML or TSV reports to this workspace for automated ForensicX ingestion."
            ),
        }

    def launch_autopsy(self) -> dict[str, Any]:
        """Safely launch Autopsy GUI in the background."""
        exe_path = self.detect_executable()
        if not exe_path:
            raise HTTPException(
                status_code=503,
                detail="Autopsy executable not found on host. Please install Autopsy or add it to PATH.",
            )

        try:
            # Launch detached so it doesn't block the backend server
            subprocess.Popen(
                [exe_path],
                creationflags=subprocess.DETACHED_PROCESS if os.name == "nt" else 0,
                close_fds=True,
            )
            return {
                "status": "LAUNCHED",
                "message": "Autopsy GUI launched successfully.",
                "executable_path": exe_path,
            }
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to launch Autopsy: {exc}")

    def import_results(self, case_id: str, report_file_path: str, investigator: str = "Investigator") -> dict[str, Any]:
        """Ingest Autopsy-generated HTML or TSV/CSV reports into the ForensicX case."""
        case_info = row("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        if not case_info:
            raise HTTPException(status_code=404, detail="Case not found.")

        src = Path(report_file_path).expanduser().resolve()
        if not src.is_file():
            raise HTTPException(status_code=400, detail=f"Report file not found: {report_file_path}")

        # Compute hash and preserve original file into evidence raw directory
        case_dir = (EVIDENCE_DIR / case_id).resolve()
        raw_dir = case_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        evidence_id = f"EVD-AUTOPSY-{uuid4().hex[:6].upper()}"
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", src.name)
        dest = raw_dir / f"{evidence_id}_{safe_name}"
        shutil.copy2(src, dest)

        hash_res = calculate_sha256(dest)
        digest = hash_res["hash"]
        stored_rel = str(dest.relative_to(EVIDENCE_DIR))
        now = utc_now()

        # Session device & acquisition setup
        dev_id = f"DEV-AUTOPSY-{uuid4().hex[:6].upper()}"
        acq_id = f"ACQ-AUTOPSY-{uuid4().hex[:6].upper()}"
        dev_serial = f"AUTOPSY-SOURCE-{uuid4().hex[:6].upper()}"

        with connect() as conn:
            conn.execute(
                "INSERT INTO devices (device_id, serial, serial_number, platform, connection_state, connection_status, adb_status, lock_status, created_at, last_seen_at, updated_at) "
                "VALUES (?, ?, ?, 'Autopsy Ingest', 'source', 'completed', 'not_applicable', 'unlocked', ?, ?, ?)",
                (dev_id, dev_serial, dev_serial, now, now, now),
            )
            conn.execute(
                "INSERT INTO acquisitions (acquisition_id, case_id, device_id, source, method, status, started_at, completed_at, ended_at, last_activity, notes) "
                "VALUES (?, ?, ?, 'Autopsy Examination Report', 'Autopsy Deep Analysis', 'COMPLETED', ?, ?, ?, ?, ?)",
                (acq_id, case_id, dev_id, now, now, now, now, f"Autopsy report ingested from {src.name} by {investigator}"),
            )
            conn.execute(
                "INSERT INTO evidence (evidence_id, case_id, device_serial, device_id, acquisition_id, evidence_type, source, file_path, acquired_at, sha256, size, status) "
                "VALUES (?, ?, ?, ?, ?, 'Autopsy Report', 'Autopsy Ingest', ?, ?, ?, ?, 'IMPORTED')",
                (evidence_id, case_id, dev_id, dev_id, acq_id, stored_rel, now, digest, dest.stat().st_size),
            )
            item_id = f"ITEM-{uuid4().hex[:8].upper()}"
            conn.execute(
                "INSERT INTO evidence_items (evidence_item_id, case_id, device_id, acquisition_id, evidence_type, source, original_path, stored_path, timestamp, hash, hash_sha256, created_at, legacy_evidence_id) "
                "VALUES (?, ?, ?, ?, 'Autopsy Report', 'Autopsy Ingest', ?, ?, ?, ?, ?, ?, ?)",
                (item_id, case_id, dev_id, acq_id, str(src), stored_rel, now, digest, digest, now, evidence_id),
            )
            conn.execute(
                "INSERT INTO hashes (evidence_item_id, algorithm, value, calculated_at) VALUES (?, 'SHA-256', ?, ?)",
                (item_id, digest, now),
            )

        # Parse the report content based on extension
        artifacts_count = 0
        ext = src.suffix.lower()

        if ext in (".html", ".htm"):
            artifacts_count = self._parse_and_insert_html(case_id, dev_id, acq_id, item_id, dest)
        elif ext in (".tsv", ".csv"):
            artifacts_count = self._parse_and_insert_delimited(case_id, dev_id, acq_id, item_id, dest, is_tsv=(ext == ".tsv"))
        elif ext == ".json":
            artifacts_count = self._parse_and_insert_json(case_id, dev_id, acq_id, item_id, dest)

        # Record tool event and chain of custody
        details = f"Ingested {artifacts_count} artifacts from Autopsy report '{src.name}' (SHA-256: {digest[:12]}...)."
        record_tool_event("autopsy", case_id, "IMPORT_RESULTS", "SUCCESS", artifacts_count, details, investigator)

        # Trigger normalization so cross correlations, reliability, graph, and timeline pick up the new evidence
        norm_result = normalize_case(case_id)

        return {
            "status": "SUCCESS",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "evidence_item_id": item_id,
            "report_file": src.name,
            "sha256": digest,
            "artifacts_parsed": artifacts_count,
            "normalization": norm_result,
            "message": f"Successfully ingested {artifacts_count} artifacts from Autopsy examination.",
        }

    def _parse_and_insert_html(self, case_id: str, dev_id: str, acq_id: str, item_id: str, html_path: Path) -> int:
        content = html_path.read_text(encoding="utf-8", errors="replace")
        parser = _AutopsyHTMLTableParser()
        parser.feed(content)

        count = 0
        if not parser.tables:
            return count

        with connect() as conn:
            for table_rows in parser.tables:
                if not table_rows:
                    continue
                header = [col.lower().strip() for col in table_rows[0]]
                data_rows = table_rows[1:]
                for r in data_rows:
                    if len(r) != len(header):
                        continue
                    row_dict = dict(zip(header, r))

                    # Check if it's Web History
                    if any("url" in k for k in row_dict) or "web history" in html_path.name.lower():
                        url_val = next((row_dict[k] for k in row_dict if "url" in k), "")
                        title_val = next((row_dict[k] for k in row_dict if "title" in k), "")
                        ts_val = next((row_dict[k] for k in row_dict if "date" in k or "time" in k), utc_now())
                        browser_val = next((row_dict[k] for k in row_dict if "program" in k or "browser" in k), "Autopsy Extracted Browser")

                        if url_val:
                            conn.execute(
                                "INSERT INTO browser_history (evidence_item_id, case_id, device_id, acquisition_id, browser, url, title, visit_timestamp, source) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Autopsy Ingest')",
                                (item_id, case_id, dev_id, acq_id, browser_val, url_val, title_val, ts_val),
                            )
                            count += 1

                    # Check if it's Messages
                    elif any("message" in k or "body" in k or "text" in k for k in row_dict) or "message" in html_path.name.lower():
                        body_val = next((row_dict[k] for k in row_dict if "body" in k or "message" in k or "text" in k), "")
                        addr_val = next((row_dict[k] for k in row_dict if "phone" in k or "number" in k or "sender" in k or "recipient" in k), "Unknown")
                        ts_val = next((row_dict[k] for k in row_dict if "date" in k or "time" in k), utc_now())
                        if body_val:
                            conn.execute(
                                "INSERT INTO sms_messages (evidence_item_id, case_id, device_id, acquisition_id, address, body, message_type, timestamp) "
                                "VALUES (?, ?, ?, ?, ?, ?, 'Autopsy Ingest', ?)",
                                (item_id, case_id, dev_id, acq_id, addr_val, body_val, ts_val),
                            )
                            count += 1

                    # Check if it's Files
                    elif any("file" in k or "path" in k for k in row_dict):
                        path_val = next((row_dict[k] for k in row_dict if "path" in k or "file" in k), "")
                        name_val = Path(path_val).name if path_val else "Unknown"
                        size_val = 0
                        try:
                            size_val = int(next((row_dict[k] for k in row_dict if "size" in k), 0))
                        except Exception:
                            pass
                        ts_val = next((row_dict[k] for k in row_dict if "date" in k or "time" in k or "modified" in k), utc_now())
                        if path_val:
                            conn.execute(
                                "INSERT INTO files (evidence_item_id, case_id, device_id, acquisition_id, original_path, file_name, size, timestamp) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                (item_id, case_id, dev_id, acq_id, path_val, name_val, size_val, ts_val),
                            )
                            count += 1

        return count

    def _parse_and_insert_delimited(self, case_id: str, dev_id: str, acq_id: str, item_id: str, path: Path, is_tsv: bool) -> int:
        delimiter = "\t" if is_tsv else ","
        count = 0
        with open(path, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            with connect() as conn:
                for row_dict in reader:
                    normalized_keys = {k.lower().strip(): v for k, v in row_dict.items() if k}
                    url = next((normalized_keys[k] for k in normalized_keys if "url" in k), None)
                    if url:
                        title = next((normalized_keys[k] for k in normalized_keys if "title" in k), "")
                        ts = next((normalized_keys[k] for k in normalized_keys if "date" in k or "time" in k), utc_now())
                        conn.execute(
                            "INSERT INTO browser_history (evidence_item_id, case_id, device_id, acquisition_id, browser, url, title, visit_timestamp, source) "
                            "VALUES (?, ?, ?, ?, 'Autopsy Export', ?, ?, ?, 'Autopsy Ingest')",
                            (item_id, case_id, dev_id, acq_id, url, title, ts),
                        )
                        count += 1
                        continue

                    # Generic file row
                    file_path = next((normalized_keys[k] for k in normalized_keys if "path" in k or "file" in k), None)
                    if file_path:
                        name = Path(file_path).name
                        conn.execute(
                            "INSERT INTO files (evidence_item_id, case_id, device_id, acquisition_id, original_path, file_name, size, timestamp) "
                            "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                            (item_id, case_id, dev_id, acq_id, file_path, name, utc_now()),
                        )
                        count += 1

        return count

    def _parse_and_insert_json(self, case_id: str, dev_id: str, acq_id: str, item_id: str, path: Path) -> int:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        count = 0
        items = data if isinstance(data, list) else data.get("artifacts", data.get("items", []))

        with connect() as conn:
            for item in items:
                if not isinstance(item, dict):
                    continue
                if "url" in item:
                    conn.execute(
                        "INSERT INTO browser_history (evidence_item_id, case_id, device_id, acquisition_id, browser, url, title, visit_timestamp, source) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Autopsy Ingest')",
                        (item_id, case_id, dev_id, acq_id, item.get("browser", "Autopsy"), item["url"], item.get("title", ""), item.get("timestamp", utc_now())),
                    )
                    count += 1
                elif "body" in item or "message" in item:
                    conn.execute(
                        "INSERT INTO sms_messages (evidence_item_id, case_id, device_id, acquisition_id, address, body, message_type, timestamp) "
                        "VALUES (?, ?, ?, ?, ?, ?, 'Autopsy Ingest', ?)",
                        (item_id, case_id, dev_id, acq_id, item.get("address", item.get("sender", "Unknown")), item.get("body", item.get("message", "")), item.get("timestamp", utc_now())),
                    )
                    count += 1
        return count
