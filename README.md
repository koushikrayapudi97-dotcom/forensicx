# Digital Forensics Investigation System

This is a local, authorized-access digital forensics dashboard for detecting an Android device through ADB, collecting legitimately accessible data, preserving evidence metadata, verifying SHA-256 integrity, recording chain of custody, and generating PDF reports.

## Safety boundary

Implemented:

- Only use devices for which the investigator has documented authorization.
- Acquisition is read-only and limited to ADB-accessible properties, battery state, and the last 200 accessible logcat lines.
- The system never bypasses lock screens, passwords, PINs, encryption, permissions, or Android security controls.
- Features that require additional authorization are returned as unavailable or failed; the application does not pretend to have access.

## Implemented features

- `GET /api/device` and `GET /api/device/info` with safe ADB error handling.
- `GET /api/device/intelligence` for authorized Android SMS, call-log, and location-service extraction.
- `POST /api/evidence/import` for preserving investigator-supplied `.dd`, `.raw`, `.img`, and `.E01` images.
- `GET /api/evidence/{evidence_id}` for individual evidence records.
- `GET /api/analysis/files/{evidence_id}`, `/metadata/{evidence_id}`, `/timeline/{evidence_id}`, and `/search/{case_id}?q=term` for evidence-backed analysis.
- `GET /api/ai/{case_id}` for optional evidence-grounded AI analysis.
- `GET /api/adapters` for external-tool adapter configuration status.
- SQLite case, evidence, and chain-of-custody persistence.
- Controlled acquisition under `evidence/<case-id>/` with timestamps, command logs, device metadata, SMS, call logs, and location-service output.
- Chunked SHA-256 calculation and verification.
- PDF reports under `reports/` using ReportLab.
- Application events in `logs/application.log`.
- Vanilla JavaScript dashboard for the complete workflow.
- Optional AI provider abstraction (`disabled`, `local`, or `openai`) with no-provider output and no fabricated findings.
- Multi-Source Tool Integrations (`GET /api/integrations/status`): Unified adapter framework connecting Android ADB, Apple iTunes/iOS, Autopsy Deep Forensics, and Cellebrite UFED/PA.
- Autopsy Examination Workspace Preparation (`POST /api/integrations/autopsy/prepare/{case_id}`), direct GUI launch, and HTML/TSV/JSON report ingestion.
- Cellebrite Authorized Package Parser (`POST /api/integrations/cellebrite/import`) for `.ufdr` containers, `report.xml`, and JSON exports.
- Apple iOS / iTunes Backup Extractor (`POST /api/integrations/ios/import`) with automated `Manifest.db` index resolution, `sms.db`, `call_history.db`, Safari `History.db`, and Cocoa timestamp conversion.
- Zero-bypass forensic integrity: encrypted iOS backups are safely detected and rejected pending investigator passphrase input.
- Cross-engine evidence flow: newly imported artifacts from ADB, iOS, Autopsy, or Cellebrite immediately feed the Evidence Normalization Engine, Cross Correlations, Reliability Scoring, Graph Network, and AI Investigation modules.

## Multi-Source Forensic Tool Integration Matrix

ForensicX implements the 8 forensic tools and technologies featured in the system architecture:

| Poster Tool | Integration Category | Host Environment Status | Operational Capabilities |
| :--- | :--- | :--- | :--- |
| **1. Android Debug Bridge (ADB)** | Live Acquisition & Triage | **Installed & Active** (`platform-tools/adb.exe`) | Non-invasive logical extraction, package listing, SMS/call dumps, APK acquisition, battery/state monitoring. |
| **2. iTunes / iOS Acquisition Tools** | Apple iOS Triage & Backup Extractor | **Backup Import Ready** (MobileSync scanner active) | Decodes unencrypted iOS backups (`Manifest.db`), `sms.db`, `call_history.db`, `History.db`, Address Book. Safely rejects encrypted backups. |
| **3. Autopsy** | Deep Disk Image & Artifact Ingest | **Installed & Ready** (`C:\Program Files\Autopsy-4.23.1`) | Automated case workspace creation with evidence manifests, direct GUI launch, and ingestion of Autopsy HTML/TSV/JSON reports. |
| **4. Cellebrite (Academic / PA)** | Commercial Mobile Decoding | **Awaiting License / Import-Only Mode** | Decompresses & parses authorized UFDR containers (`.ufdr`, `.zip`), XML activity reports, and JSON exports with complete provenance. |
| **5. Python** | Core Platform Engine | **Active** (Python 3.14 / FastAPI) | Modular microservices, async routing, data normalization, and static forensic analysis. |
| **6. SQLite** | Evidentiary Storage & WAL | **Active** (`forensics.db`) | ACID relational persistence, foreign key enforcement, WAL mode, immutable chain-of-custody tables. |
| **7. AI / ML** | Forensic Intelligence Engine | **Active** (Multi-Source Pipeline) | Cross-source correlation, explainable reliability scoring (0-100%), relationship graph, chronological incident timeline. |
| **8. Report Generation** | Official Documentation | **Active** (ReportLab PDF / HTML) | Cryptographically verified court-ready investigation reports and malware threat summaries. |

### Tool Integration Endpoints

- `GET /api/integrations/status`: Operational status matrix across all integrated tools.
- `GET /api/integrations/{tool_id}`: Detailed capabilities, licensing, and format specifications.
- `GET /api/integrations/history/recent`: Immutable audit log of tool actions and import operations.
- `POST /api/integrations/autopsy/prepare/{case_id}`: Prepares Autopsy workspace directory with JSON evidence manifest.
- `POST /api/integrations/autopsy/launch`: Safely launches Autopsy GUI on the host workstation.
- `POST /api/integrations/autopsy/import`: Ingests Autopsy HTML or TSV reports into the active case.
- `POST /api/integrations/cellebrite/import`: Ingests authorized Cellebrite UFDR archives or XML reports.
- `POST /api/integrations/ios/detect`: Scans standard local Apple MobileSync backup directories.
- `POST /api/integrations/ios/import`: Extracts and normalizes iOS backups or standalone SQLite databases.

## Requirements

- Windows 10 or later.
- Python 3.10 or later. Python 3.14 is supported by the current environment.
- Android SDK Platform-Tools (`adb`).
- An Android phone and USB cable, when testing with hardware.
- USB debugging enabled by an authorized investigator.

## Setup in VS Code

Open `D:\DF_Project` in VS Code, then run PowerShell commands from the project root:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, run the commands with `.\.venv\Scripts\python.exe` instead, or use:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

ADB can be installed with Windows Package Manager:

```powershell
winget install --id Google.PlatformTools --exact
```

Restart the terminal after installation and verify it:

```powershell
adb version
```

## Connect an authorized phone

1. On the phone, open **Settings > About phone** and tap **Build number** seven times to enable Developer options.
2. Open **Developer options** and enable **USB debugging**.
3. Connect the phone by USB and choose an appropriate USB mode if prompted.
4. Accept the RSA debugging prompt on the phone.
5. Confirm the connection:

```powershell
adb devices
```

Expected authorized output:

```text
List of devices attached
DEVICE_SERIAL    device
```

`unauthorized` means the phone has not accepted the RSA prompt. `offline` means the ADB transport is not ready. An empty list means no device is currently visible.

## Run the server

Using the included Windows script:

```powershell
.\run.bat
```

Or directly:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload
```

Open the dashboard at <http://127.0.0.1:8000>.

## Test the API

In another PowerShell terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/device | ConvertTo-Json
```

With an authorized device, the response resembles:

```json
{
  "connected": true,
  "devices": [
    {
      "serial": "DEVICE_SERIAL",
      "state": "device"
    }
  ]
}
```

Without a device:

```json
{
  "connected": false,
  "devices": []
}
```

If ADB cannot be found, the API returns `connected: false` and an explanatory `error` field instead of exposing a Python traceback.

Device profile:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/device/info | ConvertTo-Json
```

Mobile intelligence:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/device/intelligence | ConvertTo-Json -Depth 6
```

The response reports separate `status`, `records`, and `error` fields for SMS, call logs, GPS/location service output, and social media. SMS/call providers may be inaccessible on some Android builds. Social-media records are not generically extractable because each app owns its private database; the system reports this limitation instead of fabricating data.

Create a case:

```powershell
$case = Invoke-RestMethod http://127.0.0.1:8000/api/cases -Method Post -ContentType 'application/json' -Body '{"case_name":"Example case","investigator":"Investigator name","description":"Authorized examination"}'
$case
```

Start controlled acquisition:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/acquisition -Method Post -ContentType 'application/json' -Body "{\"case_id\":\"$($case.case_id)\",\"serial\":\"DEVICE_SERIAL\"}"
```

Acquisition automatically registers five extracted artifacts under `evidence/<case-id>/acquired/` with SHA-256 hashes and custody records: `device_info.json`, `mobile_intelligence.json`, `getprop.txt`, `battery.txt`, and `logcat.txt`. Additional files can be manually registered, where `file_path` is relative to `evidence/`:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/evidence -Method Post -ContentType 'application/json' -Body "{\"case_id\":\"$($case.case_id)\",\"device_serial\":\"DEVICE_SERIAL\",\"evidence_type\":\"Device metadata\",\"source\":\"Authorized ADB\",\"file_path\":\"$($case.case_id)/device_info.json\"}"
```

Verify evidence with `POST /api/evidence/{evidence_id}/verify`. Generate a report with `GET /api/reports/{case_id}`.

## Run tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The tests cover ADB output parsing, missing-ADB handling, SHA-256, cases, evidence registration, custody, acquisition output boundaries, and PDF reports. They do not require a connected phone.

## Project structure

```text
backend/                 FastAPI application and services
  main.py                App, logging, database initialization, and routing
  services/              ADB, device, acquisition, hashing, image, and report logic
  api/                   Device, case, evidence, image, acquisition, and report routes
  database/              SQLite connection, schema, and request models
frontend/                HTML, CSS, and vanilla JavaScript dashboard
forensic/                Independent filesystem, metadata, timeline, search, AI, and adapter modules
evidence/                Controlled acquisition and registered evidence files
reports/                 Generated PDF reports
logs/                    Application log output
tests/                   Unit and API tests
requirements.txt         Python dependencies
run.bat                  Windows startup script
```

## Troubleshooting

- **`adb` is not recognized:** install Platform-Tools, restart PowerShell, and run `adb version`.
- **`unauthorized`:** unlock the phone, accept the USB debugging prompt, then run `adb devices` again.
- **`offline`:** reconnect the USB cable, restart ADB with `adb kill-server` followed by `adb start-server`, and retry.
- **No device listed:** check the cable, USB mode, Windows drivers, and USB debugging.
- **Port 8000 is busy:** run `python -m uvicorn backend.main:app --reload --port 8001` and open port 8001.
- **Dashboard says backend unavailable:** confirm the Uvicorn process is running and that the page uses the same port.
- **Acquisition returns 409:** confirm the case exists and the serial is currently in `device` state.
- **Evidence returns 400:** use a file that exists inside the `evidence/` directory; absolute paths outside it are rejected.
- **Report returns 404:** use the exact case ID returned by `POST /api/cases`.
