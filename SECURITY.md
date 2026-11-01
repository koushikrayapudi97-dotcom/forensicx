# Security Policy & Architecture Guide: ForensicX

> **ForensicX — Trace the Evidence. Reveal the Truth.**

This document outlines the security architecture, threat model, access control design, defensive mechanisms, and vulnerability reporting procedures for the **ForensicX** digital forensics and incident response platform.

---

## 1. Security Architecture & Evidentiary Threat Model

Digital forensics systems operate under unique and demanding threat models:
1. **Evidentiary Integrity & Non-Repudiation**: Evidence files (SMS, call logs, GPS coordinates, media, browser histories, disk images) must be cryptographically hashed (SHA-256) upon acquisition/import. Any alteration, tampering, or truncation must be immediately detectable.
2. **Chain-of-Custody Auditability**: Every access, analysis, verification, report generation, or custody transfer is recorded immutably in SQLite audit tables (`chain_of_custody` and `acquisition_logs`) with timestamps, actors, and descriptions.
3. **Data Segregation & Case Confidentiality**: In multi-investigator deployments, cases and their associated evidence, timeline events, AI findings, and malware reports must be strictly isolated to authorized investigators.
4. **Host Security Against Untrusted Evidence**: Evidence files analyzed by ForensicX (such as potential malware samples or untrusted SQLite dumps) are handled strictly via safe, static, memory-capped parsers without dynamic script execution or shell invocation.

---

## 2. Authentication & Session Security

- **Password Storage**: Passwords are salted and hashed using **Bcrypt** with a work factor of 12 rounds (`bcrypt.gensalt(rounds=12)`). Plaintext passwords are never logged, cached, or persisted.
- **Account Lockout Policy**: To eliminate online brute-force and credential stuffing threats:
  - Accounts are locked for **15 minutes** after **4 consecutive failed authentication attempts**.
  - Lockout status and remaining time are communicated clearly to the user without disclosing whether the username or password was incorrect.
- **Session Tokens**: Cryptographically secure 256-bit random tokens are generated via `secrets.token_urlsafe(32)`.
- **Session Lifetime & Invalidation**:
  - Active sessions expire automatically after **8 hours**.
  - Explicit logout permanently deletes the session record from the database.
  - **Session Fixation Defense**: Existing session tokens are invalidated and replaced upon successful re-authentication.
- **Cookie Attributes**:
  - `HttpOnly`: Strictly enforced so tokens cannot be accessed by client-side JavaScript.
  - `SameSite=Lax`: Prevents cross-site request forgery (CSRF) in standard browsing flows.
  - `Secure`: Controlled via `FX_SECURE_COOKIES` (enabled by default in production behind HTTPS).
  - Explicit path scoping (`Path=/`).

---

## 3. Object-Level Access Control & Authorization (IDOR Defense)

All case-scoped and evidence-scoped API endpoints implement server-side object-level access control via `check_case_access()`:
- **Case Ownership Enforcement**: Each investigation case tracks an assigned `user_id`. When an authenticated investigator requests case data or evidence, the server verifies that the session's user matches the case's owner or authorized investigator.
- **Unauthorized Access Rejection**: Mismatched access attempts return an HTTP `403 Forbidden` response and trigger an automated security audit entry in `security_events`.
- **Traceability Linkages**: AI findings, timeline events, correlation graphs, and evidence normalization records are strictly constrained by case scope. Evidence inspection endpoints (`/api/forensic-intelligence/evidence-inspect/{id}`) resolve the parent case and perform authorization checks before returning artifact details.

---

## 4. Input Validation & Injection Defenses

- **Strict Identifier Whitelisting**: Case identifiers, evidence IDs, device IDs, and acquisition IDs are validated against strict regex patterns (`^[A-Za-z0-9_\-]+$`) before database queries or filesystem operations are performed.
- **Path Traversal Defense**:
  - File paths provided to `/api/evidence`, file analysis, or import endpoints are normalized and verified using `pathlib.Path.resolve()`.
  - The resolved path is strictly tested with `.relative_to(EVIDENCE_DIR.resolve())` to guarantee it cannot escape the evidence storage root.
  - File names from imports are sanitized with `re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)` to prevent directory manipulation.
- **Safe Subprocess Execution**:
  - Android Debug Bridge (ADB) commands are executed with structured argument lists (`subprocess.run([binary, "-s", serial, ...])`) with `shell=False`.
  - Device serial numbers are strictly validated against `^[A-Za-z0-9_.:\-]+$` and cannot start with `-` (preventing option injection).
- **SQL Table Whitelisting**:
  - Internal references in evidence provenance (`source_ref`) are checked against an explicit set of whitelisted forensic tables (`ALLOWED_SOURCE_TABLES`) with numeric ID validation, preventing arbitrary table queries or SQL injection.

---

## 5. File & Evidence Protection

- **Static-Only Malware Analysis**: The static malware analysis engine caps file sample reads to 1 MB, preventing host memory exhaustion (DoS). Analysis inspects byte patterns, entropy, and extension anomalies without executing untrusted binaries.
- **Report Isolation**: Generated PDF and CSV reports are written directly to designated directory roots (`REPORTS_DIR`) and verified with path containment checks before streaming to clients.
- **Error Sanitization**: Unhandled server exceptions (HTTP 500) log complete diagnostic traces to server-side log files (`logs/application.log`) while returning clean, non-leaking JSON error messages (`{"detail": "An internal server error occurred."}`) to clients.

---

## 6. Production Security Headers & CORS Policy

Every HTTP response includes standard hardening headers:
```http
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; frame-src 'self' https://maps.google.com; img-src 'self' data:; connect-src 'self';
```
- **CORS**: Configured strictly through `FX_ALLOWED_ORIGINS`. Wildcard origins (`*`) combined with credentials are prohibited.

---

## 7. Rate Limiting & DoS Mitigation

- An in-memory sliding-window rate limiter protects public authentication endpoints (`/api/auth/login`, `/api/auth/register`).
- Default thresholds:
  - Login: 15 requests per 60-second window per client IP.
  - Registration: 10 requests per 60-second window per client IP.
- Rate-limited clients receive HTTP `429 Too Many Requests` along with a `Retry-After: <seconds>` header.

---

## 8. Production Deployment Checklist

Before deploying ForensicX to an operational production or law enforcement environment:

- [ ] **TLS / HTTPS**: Deploy behind a hardened reverse proxy (e.g., Nginx, Caddy, or Cloudflare) with modern TLS (TLS 1.3 preferred) and valid certificates.
- [ ] **Environment Variables**: Configure `.env` based on `.env.example`:
  - Set `FX_ENV=production`
  - Set `FX_SECURE_COOKIES=true`
  - Specify explicit, trusted origins in `FX_ALLOWED_ORIGINS`
- [ ] **Storage Permissions**: Restrict filesystem permissions on `evidence/`, `reports/`, and `forensics.db` to the service user executing ForensicX (`chmod 700 / 600` on POSIX systems).
- [ ] **Database Backups**: Schedule automated WAL checkpoints and secure backups of `forensics.db`.
- [ ] **Log Monitoring**: Monitor `logs/application.log` and `security_events` table for unauthorized access alerts (`UNAUTHORIZED_CASE_ACCESS`, `RATE_LIMIT_EXCEEDED`, `LOGIN_BLOCKED`).

---

## 9. Multi-Source Tool Integration Security Standards & Zero-Bypass Protocol

ForensicX integrates external digital forensics platforms (ADB, iTunes/iOS, Autopsy, Cellebrite) under strict forensic and evidentiary standards:

- **Zero-Bypass Policy & Hardware Lockout Respect**:
  - The system never attempts password cracking, lock-screen brute-forcing, device exploitation, or unauthenticated extraction.
  - Encrypted iOS backups (indicated by `IsEncrypted: True` in `Manifest.plist`/`Status.plist`) are detected and rejected with HTTP `422 Unprocessable Entity`, requiring authorized passphrase decryption before SQLite database extraction.
- **Zip-Slip & Path Traversal Prevention**:
  - Archive decompression for Cellebrite UFDR (`.ufdr`, `.zip`) and iOS backup packages strictly validates every member path (`os.path.normpath(name)`) to ensure extracted files cannot escape target temporary workspaces or overwrite system files.
- **Evidentiary Integrity & Cryptographic Provenance**:
  - All imported external evidence packages, HTML reports, TSV files, and SQLite databases are immediately hashed with SHA-256 upon ingest and stored under `evidence/<case_id>/raw/` with immutable timestamping.
  - Original external evidence files are preserved read-only and never modified during parsing or normalization.
- **Truthful Status & Licensing Transparency**:
  - External tool adapters detect installed binaries and license conditions on the host without fabricating examinations, synthetic extractions, or simulated tool states.
  - If commercial software or hardware dongles (e.g. Cellebrite) are unconfigured, ForensicX clearly reports status as "Awaiting License / Import-Only Mode" while supporting offline ingestion of legitimately authorized exports.

---

## 10. Vulnerability Reporting & Coordinated Disclosure

If you discover a potential security vulnerability in ForensicX:
1. **Do not create public GitHub issues or disclose details publicly.**
2. Send a detailed report to the security team at `security@forensicx.local` (or designated internal reporting channel).
3. Include:
   - Vulnerability type and affected component/endpoint
   - Step-by-step reproduction instructions or proof-of-concept
   - Potential impact on evidentiary integrity or confidentiality
4. The security response team will acknowledge receipt within **24 hours** and provide remediation updates according to standard coordinated disclosure timelines.

