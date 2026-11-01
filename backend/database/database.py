"""Small SQLite persistence layer using parameterized queries."""

import sqlite3
import json
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4

from backend.config import DATABASE_PATH, EVIDENCE_DIR


def utc_now() -> str:
	return datetime.now(timezone.utc).isoformat()


def execute_with_retry(func, max_retries: int = 5, initial_delay: float = 0.05):
	"""Execute a callable with automatic retry on SQLite database lock errors."""
	for attempt in range(max_retries):
		try:
			return func()
		except sqlite3.OperationalError as e:
			if ("locked" in str(e).lower() or "busy" in str(e).lower()) and attempt < max_retries - 1:
				time.sleep(initial_delay * (2 ** attempt))
				continue
			raise


@contextmanager
def db_transaction(max_retries: int = 5, initial_delay: float = 0.05):
	"""Context manager for SQLite write transactions with retry on locking errors."""
	for attempt in range(max_retries):
		conn = connect()
		try:
			yield conn
			conn.commit()
			conn.close()
			return
		except sqlite3.OperationalError as e:
			conn.close()
			if ("locked" in str(e).lower() or "busy" in str(e).lower()) and attempt < max_retries - 1:
				time.sleep(initial_delay * (2 ** attempt))
				continue
			raise
		except Exception:
			conn.rollback()
			conn.close()
			raise


def connect() -> sqlite3.Connection:
	connection = sqlite3.connect(DATABASE_PATH, timeout=60.0)
	connection.row_factory = sqlite3.Row
	try:
		connection.execute("PRAGMA busy_timeout = 30000")
		connection.execute("PRAGMA journal_mode = WAL")
		connection.execute("PRAGMA foreign_keys = ON")
	except sqlite3.OperationalError:
		pass
	return connection


def initialize_database() -> None:
	try:
		connection = connect()
	except sqlite3.OperationalError:
		return
	try:
		try:
			connection.execute("PRAGMA journal_mode = WAL")
		except sqlite3.OperationalError:
			pass
		connection.executescript(
				"""
				CREATE TABLE IF NOT EXISTS cases (
				case_id TEXT PRIMARY KEY, case_name TEXT NOT NULL, investigator TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, status TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS evidence (
				evidence_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, device_serial TEXT NOT NULL,
				evidence_type TEXT NOT NULL, source TEXT NOT NULL, file_path TEXT NOT NULL,
				acquired_at TEXT NOT NULL, sha256 TEXT, size INTEGER NOT NULL DEFAULT 0,
				status TEXT NOT NULL, FOREIGN KEY(case_id) REFERENCES cases(case_id)
			);
			CREATE TABLE IF NOT EXISTS custody (
				id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id TEXT NOT NULL, case_id TEXT NOT NULL,
				action TEXT NOT NULL, person TEXT NOT NULL, timestamp TEXT NOT NULL,
				description TEXT NOT NULL, FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id),
				FOREIGN KEY(case_id) REFERENCES cases(case_id)
			);
			CREATE TABLE IF NOT EXISTS devices (
				device_id TEXT PRIMARY KEY, serial TEXT NOT NULL UNIQUE, manufacturer TEXT NOT NULL DEFAULT '',
				model TEXT NOT NULL DEFAULT '', android_version TEXT NOT NULL DEFAULT '', sdk_version TEXT NOT NULL DEFAULT '',
				connection_state TEXT NOT NULL DEFAULT 'disconnected', created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS acquisitions (
				acquisition_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, device_id TEXT NOT NULL,
				status TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT, last_activity TEXT NOT NULL,
				FOREIGN KEY(case_id) REFERENCES cases(case_id), FOREIGN KEY(device_id) REFERENCES devices(device_id)
			);
			CREATE INDEX IF NOT EXISTS idx_acquisitions_case ON acquisitions(case_id);
			CREATE INDEX IF NOT EXISTS idx_acquisitions_device ON acquisitions(device_id);
			CREATE TABLE IF NOT EXISTS evidence_items (
				evidence_item_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, device_id TEXT NOT NULL, acquisition_id TEXT NOT NULL,
				evidence_type TEXT NOT NULL, source TEXT NOT NULL, original_path TEXT, timestamp TEXT, hash TEXT,
				created_at TEXT NOT NULL, legacy_evidence_id TEXT UNIQUE,
				FOREIGN KEY(case_id) REFERENCES cases(case_id), FOREIGN KEY(device_id) REFERENCES devices(device_id),
				FOREIGN KEY(acquisition_id) REFERENCES acquisitions(acquisition_id)
			);
			CREATE INDEX IF NOT EXISTS idx_evidence_items_case ON evidence_items(case_id);
			CREATE INDEX IF NOT EXISTS idx_evidence_items_acquisition ON evidence_items(acquisition_id);
			CREATE TABLE IF NOT EXISTS hashes (
				hash_id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_item_id TEXT NOT NULL, algorithm TEXT NOT NULL,
				value TEXT NOT NULL, calculated_at TEXT NOT NULL, FOREIGN KEY(evidence_item_id) REFERENCES evidence_items(evidence_item_id)
			);
			CREATE TABLE IF NOT EXISTS chain_of_custody (
				custody_id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, device_id TEXT, acquisition_id TEXT,
				evidence_item_id TEXT, action TEXT NOT NULL, person TEXT NOT NULL, timestamp TEXT NOT NULL, description TEXT NOT NULL,
				FOREIGN KEY(case_id) REFERENCES cases(case_id), FOREIGN KEY(device_id) REFERENCES devices(device_id),
				FOREIGN KEY(acquisition_id) REFERENCES acquisitions(acquisition_id), FOREIGN KEY(evidence_item_id) REFERENCES evidence_items(evidence_item_id)
			);
			CREATE INDEX IF NOT EXISTS idx_chain_case ON chain_of_custody(case_id);
			CREATE TABLE IF NOT EXISTS acquisition_logs (
				log_id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, device_id TEXT NOT NULL, acquisition_id TEXT NOT NULL,
				event TEXT NOT NULL, timestamp TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
				FOREIGN KEY(case_id) REFERENCES cases(case_id), FOREIGN KEY(device_id) REFERENCES devices(device_id),
				FOREIGN KEY(acquisition_id) REFERENCES acquisitions(acquisition_id)
			);
			CREATE TABLE IF NOT EXISTS sms_messages (
				id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_item_id TEXT NOT NULL, case_id TEXT NOT NULL, device_id TEXT NOT NULL,
				acquisition_id TEXT NOT NULL, address TEXT, body TEXT, message_type TEXT, timestamp TEXT,
				FOREIGN KEY(evidence_item_id) REFERENCES evidence_items(evidence_item_id), FOREIGN KEY(case_id) REFERENCES cases(case_id),
				FOREIGN KEY(device_id) REFERENCES devices(device_id), FOREIGN KEY(acquisition_id) REFERENCES acquisitions(acquisition_id)
			);
			CREATE TABLE IF NOT EXISTS call_logs (
				id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_item_id TEXT NOT NULL, case_id TEXT NOT NULL, device_id TEXT NOT NULL,
				acquisition_id TEXT NOT NULL, number TEXT, name TEXT, call_type TEXT, duration TEXT, timestamp TEXT,
				FOREIGN KEY(evidence_item_id) REFERENCES evidence_items(evidence_item_id), FOREIGN KEY(case_id) REFERENCES cases(case_id),
				FOREIGN KEY(device_id) REFERENCES devices(device_id), FOREIGN KEY(acquisition_id) REFERENCES acquisitions(acquisition_id)
			);
			CREATE TABLE IF NOT EXISTS contacts (
				id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_item_id TEXT NOT NULL, case_id TEXT NOT NULL, device_id TEXT NOT NULL,
				acquisition_id TEXT NOT NULL, name TEXT, number TEXT, timestamp TEXT,
				FOREIGN KEY(evidence_item_id) REFERENCES evidence_items(evidence_item_id), FOREIGN KEY(case_id) REFERENCES cases(case_id),
				FOREIGN KEY(device_id) REFERENCES devices(device_id), FOREIGN KEY(acquisition_id) REFERENCES acquisitions(acquisition_id)
			);
			CREATE TABLE IF NOT EXISTS applications (
				id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_item_id TEXT NOT NULL, case_id TEXT NOT NULL, device_id TEXT NOT NULL,
				acquisition_id TEXT NOT NULL, package_name TEXT, version TEXT, timestamp TEXT,
				FOREIGN KEY(evidence_item_id) REFERENCES evidence_items(evidence_item_id), FOREIGN KEY(case_id) REFERENCES cases(case_id),
				FOREIGN KEY(device_id) REFERENCES devices(device_id), FOREIGN KEY(acquisition_id) REFERENCES acquisitions(acquisition_id)
			);
			CREATE TABLE IF NOT EXISTS files (
				id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_item_id TEXT NOT NULL, case_id TEXT NOT NULL, device_id TEXT NOT NULL,
				acquisition_id TEXT NOT NULL, original_path TEXT NOT NULL, file_name TEXT, size INTEGER DEFAULT 0, mime_type TEXT, timestamp TEXT,
				FOREIGN KEY(evidence_item_id) REFERENCES evidence_items(evidence_item_id), FOREIGN KEY(case_id) REFERENCES cases(case_id),
				FOREIGN KEY(device_id) REFERENCES devices(device_id), FOREIGN KEY(acquisition_id) REFERENCES acquisitions(acquisition_id)
			);
			CREATE TABLE IF NOT EXISTS users (
				user_id TEXT PRIMARY KEY,
				full_name TEXT NOT NULL,
				email TEXT NOT NULL UNIQUE,
				mobile TEXT NOT NULL UNIQUE,
				password_hash TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'active',
				failed_attempts INTEGER NOT NULL DEFAULT 0,
				locked_until TEXT,
				created_at TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
			CREATE INDEX IF NOT EXISTS idx_users_mobile ON users(mobile);
			CREATE TABLE IF NOT EXISTS sessions (
				session_id TEXT PRIMARY KEY,
				user_id TEXT NOT NULL,
				created_at TEXT NOT NULL,
				expires_at TEXT NOT NULL,
				FOREIGN KEY(user_id) REFERENCES users(user_id)
			);
			CREATE TABLE IF NOT EXISTS security_events (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp TEXT NOT NULL,
				event_type TEXT NOT NULL,
				identifier TEXT NOT NULL,
				user_id TEXT,
				failed_count INTEGER NOT NULL DEFAULT 0,
				source_ip TEXT,
				user_agent TEXT,
				result TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS gps_locations (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				evidence_item_id TEXT NOT NULL,
				case_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				acquisition_id TEXT NOT NULL,
				latitude TEXT,
				longitude TEXT,
				accuracy TEXT,
				provider TEXT,
				timestamp TEXT,
				raw_line TEXT,
				FOREIGN KEY(case_id) REFERENCES cases(case_id)
			);
			CREATE INDEX IF NOT EXISTS idx_gps_case ON gps_locations(case_id);
			CREATE TABLE IF NOT EXISTS browser_history (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				evidence_item_id TEXT NOT NULL,
				case_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				acquisition_id TEXT NOT NULL,
				browser TEXT,
				url TEXT,
				title TEXT,
				visit_timestamp TEXT,
				visit_count INTEGER DEFAULT 1,
				source TEXT,
				FOREIGN KEY(case_id) REFERENCES cases(case_id)
			);
			CREATE INDEX IF NOT EXISTS idx_browser_history_case ON browser_history(case_id);
			CREATE TABLE IF NOT EXISTS media_files (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				evidence_item_id TEXT NOT NULL,
				case_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				acquisition_id TEXT NOT NULL,
				media_type TEXT NOT NULL,
				file_name TEXT NOT NULL,
				original_path TEXT NOT NULL,
				file_size INTEGER DEFAULT 0,
				mime_type TEXT,
				date_taken TEXT,
				duration TEXT,
				source TEXT,
				sha256 TEXT,
				FOREIGN KEY(case_id) REFERENCES cases(case_id)
			);
			CREATE INDEX IF NOT EXISTS idx_media_files_case ON media_files(case_id);

			-- Module 1: Evidence Normalization Engine
			CREATE TABLE IF NOT EXISTS normalized_evidence (
				normalized_id TEXT PRIMARY KEY,
				evidence_item_id TEXT,
				case_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				acquisition_id TEXT NOT NULL,
				artifact_type TEXT NOT NULL,
				source_method TEXT NOT NULL,
				timestamp_utc TEXT,
				original_timestamp TEXT,
				entity_info TEXT NOT NULL DEFAULT '{}',
				content TEXT NOT NULL DEFAULT '{}',
				location_info TEXT NOT NULL DEFAULT '{}',
				source_ref TEXT NOT NULL,
				original_hash TEXT,
				normalization_status TEXT NOT NULL DEFAULT 'SUCCESS',
				provenance TEXT NOT NULL DEFAULT '{}',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				FOREIGN KEY(case_id) REFERENCES cases(case_id)
			);
			CREATE INDEX IF NOT EXISTS idx_norm_ev_case ON normalized_evidence(case_id);
			CREATE INDEX IF NOT EXISTS idx_norm_ev_type ON normalized_evidence(artifact_type);
			CREATE INDEX IF NOT EXISTS idx_norm_ev_status ON normalized_evidence(normalization_status);
			CREATE UNIQUE INDEX IF NOT EXISTS idx_norm_ev_source_ref ON normalized_evidence(case_id, source_ref);

			-- Module 2: Cross-Source Evidence Correlation Engine
			CREATE TABLE IF NOT EXISTS evidence_correlations (
				correlation_id TEXT PRIMARY KEY,
				case_id TEXT NOT NULL,
				evidence_ids TEXT NOT NULL DEFAULT '[]',
				relationship_type TEXT NOT NULL,
				time_difference_seconds REAL,
				matching_attributes TEXT NOT NULL DEFAULT '{}',
				correlation_strength REAL NOT NULL DEFAULT 0.0,
				explanation TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				FOREIGN KEY(case_id) REFERENCES cases(case_id)
			);
			CREATE INDEX IF NOT EXISTS idx_correlations_case ON evidence_correlations(case_id);
			CREATE INDEX IF NOT EXISTS idx_correlations_type ON evidence_correlations(relationship_type);
			CREATE UNIQUE INDEX IF NOT EXISTS idx_correlations_unique ON evidence_correlations(case_id, relationship_type, evidence_ids);

			-- Module 3: Evidence Reliability & Provenance Scoring Engine
			CREATE TABLE IF NOT EXISTS evidence_reliability_scores (
				score_id TEXT PRIMARY KEY,
				case_id TEXT NOT NULL,
				evidence_id TEXT NOT NULL,
				target_type TEXT NOT NULL DEFAULT 'EVIDENCE_ITEM',
				reliability_score REAL NOT NULL DEFAULT 0.0,
				integrity_status TEXT NOT NULL DEFAULT 'UNVERIFIED',
				provenance_status TEXT NOT NULL DEFAULT 'UNKNOWN',
				supporting_evidence_count INTEGER NOT NULL DEFAULT 0,
				factors_affecting_score TEXT NOT NULL DEFAULT '{}',
				explanation TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				FOREIGN KEY(case_id) REFERENCES cases(case_id)
			);
			CREATE INDEX IF NOT EXISTS idx_reliability_case ON evidence_reliability_scores(case_id);
			CREATE INDEX IF NOT EXISTS idx_reliability_ev ON evidence_reliability_scores(evidence_id);
			CREATE UNIQUE INDEX IF NOT EXISTS idx_reliability_unique ON evidence_reliability_scores(case_id, target_type, evidence_id);

			-- Module 4: Evidence Relationship Graph
			CREATE TABLE IF NOT EXISTS graph_nodes (
				node_id TEXT PRIMARY KEY,
				case_id TEXT NOT NULL,
				entity_type TEXT NOT NULL,
				label TEXT NOT NULL,
				properties TEXT NOT NULL DEFAULT '{}',
				source_evidence_id TEXT,
				created_at TEXT NOT NULL,
				FOREIGN KEY(case_id) REFERENCES cases(case_id)
			);
			CREATE INDEX IF NOT EXISTS idx_graph_nodes_case ON graph_nodes(case_id);
			CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(entity_type);
			CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_nodes_unique ON graph_nodes(case_id, entity_type, label);

			CREATE TABLE IF NOT EXISTS graph_edges (
				edge_id TEXT PRIMARY KEY,
				case_id TEXT NOT NULL,
				source_node_id TEXT NOT NULL,
				target_node_id TEXT NOT NULL,
				relationship_label TEXT NOT NULL,
				correlation_id TEXT,
				evidence_id TEXT,
				weight REAL NOT NULL DEFAULT 1.0,
				properties TEXT NOT NULL DEFAULT '{}',
				created_at TEXT NOT NULL,
				FOREIGN KEY(case_id) REFERENCES cases(case_id),
				FOREIGN KEY(source_node_id) REFERENCES graph_nodes(node_id),
				FOREIGN KEY(target_node_id) REFERENCES graph_nodes(node_id)
			);
			CREATE INDEX IF NOT EXISTS idx_graph_edges_case ON graph_edges(case_id);
			CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_edges_unique ON graph_edges(case_id, source_node_id, target_node_id, relationship_label);

			-- Module 5: Incident Timeline
			CREATE TABLE IF NOT EXISTS incident_timeline (
				timeline_id TEXT PRIMARY KEY,
				case_id TEXT NOT NULL,
				sequence_number INTEGER NOT NULL,
				event_category TEXT NOT NULL,
				event_timestamp TEXT NOT NULL,
				title TEXT NOT NULL,
				description TEXT NOT NULL,
				primary_evidence_id TEXT,
				correlated_evidence_ids TEXT NOT NULL DEFAULT '[]',
				reliability_score REAL NOT NULL DEFAULT 0.0,
				suspicious_flag INTEGER NOT NULL DEFAULT 0,
				flag_reason TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				FOREIGN KEY(case_id) REFERENCES cases(case_id)
			);
			CREATE INDEX IF NOT EXISTS idx_timeline_case ON incident_timeline(case_id);
			CREATE UNIQUE INDEX IF NOT EXISTS idx_timeline_unique ON incident_timeline(case_id, sequence_number, primary_evidence_id);

			-- Module 6: AI-Assisted Analytical Findings Engine
			CREATE TABLE IF NOT EXISTS ai_findings (
				finding_id TEXT PRIMARY KEY,
				case_id TEXT NOT NULL,
				title TEXT NOT NULL,
				category TEXT NOT NULL,
				description TEXT NOT NULL,
				supporting_evidence_ids TEXT NOT NULL DEFAULT '[]',
				related_correlation_ids TEXT NOT NULL DEFAULT '[]',
				timeline_event_ids TEXT NOT NULL DEFAULT '[]',
				relationship_summary TEXT NOT NULL DEFAULT '',
				reliability_info TEXT NOT NULL DEFAULT '{}',
				analysis_explanation TEXT NOT NULL DEFAULT '',
				severity TEXT NOT NULL DEFAULT 'Informational',
				recommended_action TEXT NOT NULL DEFAULT '',
				ai_confidence TEXT NOT NULL DEFAULT '90%',
				created_at TEXT NOT NULL,
				FOREIGN KEY(case_id) REFERENCES cases(case_id)
			);
			CREATE INDEX IF NOT EXISTS idx_findings_case ON ai_findings(case_id);
			CREATE INDEX IF NOT EXISTS idx_findings_category ON ai_findings(category);

			-- Multi-Source Tool Integration Events
			CREATE TABLE IF NOT EXISTS tool_integration_events (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				event_id TEXT UNIQUE,
				tool_id TEXT NOT NULL,
				case_id TEXT NOT NULL,
				action TEXT NOT NULL,
				status TEXT NOT NULL,
				artifacts_count INTEGER NOT NULL DEFAULT 0,
				details TEXT NOT NULL DEFAULT '',
				actor TEXT NOT NULL DEFAULT 'Investigator',
				timestamp TEXT NOT NULL,
				FOREIGN KEY(case_id) REFERENCES cases(case_id)
			);
			CREATE INDEX IF NOT EXISTS idx_tool_events_case ON tool_integration_events(case_id);
			CREATE INDEX IF NOT EXISTS idx_tool_events_tool ON tool_integration_events(tool_id);
			"""
		)


		columns = {item[1] for item in connection.execute("PRAGMA table_info(cases)").fetchall()}
		if "organization" not in columns:
			connection.execute("ALTER TABLE cases ADD COLUMN organization TEXT NOT NULL DEFAULT ''")
		if "updated_at" not in columns:
			connection.execute("ALTER TABLE cases ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
		_add_columns(connection, "cases", {
			"id": "INTEGER",
			"title": "TEXT NOT NULL DEFAULT ''",
			"user_id": "TEXT",
		})
		connection.execute("UPDATE cases SET id = rowid WHERE id IS NULL")
		connection.execute("UPDATE cases SET title = case_name WHERE title = ''")
		_add_columns(connection, "devices", {
			"id": "INTEGER",
			"case_id": "TEXT",
			"platform": "TEXT NOT NULL DEFAULT 'Android'",
			"serial_number": "TEXT",
			"connection_status": "TEXT",
			"lock_status": "TEXT NOT NULL DEFAULT 'unknown'",
			"adb_status": "TEXT",
			"updated_at": "TEXT",
		})
		connection.execute("UPDATE devices SET id = rowid, serial_number = COALESCE(serial_number, serial), connection_status = COALESCE(connection_status, connection_state), adb_status = COALESCE(adb_status, connection_state), updated_at = COALESCE(updated_at, last_seen_at)")
		_add_columns(connection, "acquisitions", {
			"id": "INTEGER",
			"source": "TEXT NOT NULL DEFAULT 'ADB'",
			"method": "TEXT NOT NULL DEFAULT 'ADB'",
			"completed_at": "TEXT",
			"notes": "TEXT NOT NULL DEFAULT ''",
		})
		connection.execute("UPDATE acquisitions SET id = rowid, source = COALESCE(source, method), completed_at = ended_at WHERE id IS NULL")
		_add_columns(connection, "evidence_items", {
			"id": "INTEGER",
			"stored_path": "TEXT",
			"hash_sha256": "TEXT",
		})
		connection.execute("UPDATE evidence_items SET id = rowid, stored_path = COALESCE(stored_path, original_path), hash_sha256 = COALESCE(hash_sha256, hash)")
		_add_columns(connection, "chain_of_custody", {
			"id": "INTEGER",
			"event_type": "TEXT",
			"actor": "TEXT",
		})
		connection.execute("UPDATE chain_of_custody SET id = rowid, event_type = COALESCE(event_type, action), actor = COALESCE(actor, person)")
		_add_columns(connection, "acquisition_logs", {
			"id": "INTEGER",
			"status": "TEXT NOT NULL DEFAULT 'INFO'",
			"message": "TEXT",
		})
		_add_columns(connection, "files", {
			"file_name": "TEXT",
			"size": "INTEGER DEFAULT 0",
			"mime_type": "TEXT",
		})
		evidence_columns = {item[1] for item in connection.execute("PRAGMA table_info(evidence)").fetchall()}
		if "device_id" not in evidence_columns:
			connection.execute("ALTER TABLE evidence ADD COLUMN device_id TEXT")
		if "acquisition_id" not in evidence_columns:
			connection.execute("ALTER TABLE evidence ADD COLUMN acquisition_id TEXT")

		_add_columns(connection, "evidence_correlations", {
			"evidence_id_a": "TEXT NOT NULL DEFAULT ''",
			"evidence_id_b": "TEXT NOT NULL DEFAULT ''",
			"reason": "TEXT NOT NULL DEFAULT ''",
			"timestamp_relationship": "TEXT NOT NULL DEFAULT ''",
			"supporting_attributes": "TEXT NOT NULL DEFAULT '{}'",
		})
		_add_columns(connection, "evidence_reliability_scores", {
			"factors_list": "TEXT NOT NULL DEFAULT '[]'",
			"warnings": "TEXT NOT NULL DEFAULT '[]'",
			"missing_information": "TEXT NOT NULL DEFAULT '[]'",
		})
		_add_columns(connection, "graph_edges", {
			"reason": "TEXT NOT NULL DEFAULT ''",
			"evidence_ids": "TEXT NOT NULL DEFAULT '[]'",
			"supporting_attributes": "TEXT NOT NULL DEFAULT '{}'",
		})
		_add_columns(connection, "incident_timeline", {
			"event_id": "TEXT NOT NULL DEFAULT ''",
			"source": "TEXT NOT NULL DEFAULT ''",
			"device_id": "TEXT NOT NULL DEFAULT ''",
			"correlation_ids": "TEXT NOT NULL DEFAULT '[]'",
		})
		_add_columns(connection, "ai_findings", {
			"finding_id": "TEXT PRIMARY KEY",
			"case_id": "TEXT NOT NULL DEFAULT ''",
			"title": "TEXT NOT NULL DEFAULT ''",
			"category": "TEXT NOT NULL DEFAULT ''",
			"description": "TEXT NOT NULL DEFAULT ''",
			"supporting_evidence_ids": "TEXT NOT NULL DEFAULT '[]'",
			"related_correlation_ids": "TEXT NOT NULL DEFAULT '[]'",
			"timeline_event_ids": "TEXT NOT NULL DEFAULT '[]'",
			"relationship_summary": "TEXT NOT NULL DEFAULT ''",
			"reliability_info": "TEXT NOT NULL DEFAULT '{}'",
			"analysis_explanation": "TEXT NOT NULL DEFAULT ''",
			"severity": "TEXT NOT NULL DEFAULT 'Informational'",
			"recommended_action": "TEXT NOT NULL DEFAULT ''",
			"ai_confidence": "TEXT NOT NULL DEFAULT '90%'",
			"created_at": "TEXT NOT NULL DEFAULT ''",
		})
		_migrate_legacy_evidence(connection)
		_backfill_structured_mobile_records(connection)
		connection.commit()
	except sqlite3.OperationalError:
		pass
	finally:
		connection.close()


def _add_columns(connection: sqlite3.Connection, table: str, definitions: dict[str, str]) -> None:
	columns = {item[1] for item in connection.execute(f"PRAGMA table_info({table})").fetchall()}
	for name, definition in definitions.items():
		if name not in columns:
			connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def _migrate_legacy_evidence(connection: sqlite3.Connection) -> None:
	"""Attach pre-existing evidence rows to durable device and acquisition records."""
	now = utc_now()
	legacy_rows = connection.execute("SELECT * FROM evidence WHERE device_id IS NULL OR acquisition_id IS NULL").fetchall()
	for evidence in legacy_rows:
		device = connection.execute("SELECT device_id FROM devices WHERE serial = ?", (evidence["device_serial"],)).fetchone()
		if device is None:
			device_id = f"DEV-{uuid4().hex[:8].upper()}"
			connection.execute("INSERT INTO devices (device_id, serial, connection_state, created_at, last_seen_at) VALUES (?, ?, 'disconnected', ?, ?)", (device_id, evidence["device_serial"], now, now))
		else:
			device_id = device[0]
		acquisition = connection.execute("SELECT acquisition_id FROM acquisitions WHERE case_id = ? AND device_id = ? ORDER BY started_at LIMIT 1", (evidence["case_id"], device_id)).fetchone()
		if acquisition is None:
			acquisition_id = f"ACQ-{uuid4().hex[:8].upper()}"
			connection.execute("INSERT INTO acquisitions (acquisition_id, case_id, device_id, status, started_at, ended_at, last_activity) VALUES (?, ?, ?, 'LEGACY_COMPLETED', ?, ?, ?)", (acquisition_id, evidence["case_id"], device_id, evidence["acquired_at"], evidence["acquired_at"], evidence["acquired_at"]))
		else:
			acquisition_id = acquisition[0]
		connection.execute("UPDATE evidence SET device_id = ?, acquisition_id = ? WHERE evidence_id = ?", (device_id, acquisition_id, evidence["evidence_id"]))
		item = connection.execute("SELECT evidence_item_id FROM evidence_items WHERE legacy_evidence_id = ?", (evidence["evidence_id"],)).fetchone()
		if item is None:
			item_id = f"ITEM-{uuid4().hex[:8].upper()}"
			connection.execute("INSERT INTO evidence_items (evidence_item_id, case_id, device_id, acquisition_id, evidence_type, source, original_path, timestamp, hash, created_at, legacy_evidence_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (item_id, evidence["case_id"], device_id, acquisition_id, evidence["evidence_type"], evidence["source"], evidence["file_path"], evidence["acquired_at"], evidence["sha256"], evidence["acquired_at"], evidence["evidence_id"]))
			if evidence["sha256"]:
				connection.execute("INSERT INTO hashes (evidence_item_id, algorithm, value, calculated_at) VALUES (?, 'SHA-256', ?, ?)", (item_id, evidence["sha256"], evidence["acquired_at"]))


def _backfill_structured_mobile_records(connection: sqlite3.Connection) -> None:
	"""Index preserved mobile-intelligence JSON without rewriting raw evidence."""
	items = connection.execute("SELECT evidence_item_id, case_id, device_id, acquisition_id, original_path FROM evidence_items WHERE original_path LIKE '%mobile_intelligence.json'").fetchall()
	for item in items:
		if connection.execute("SELECT 1 FROM sms_messages WHERE evidence_item_id = ? LIMIT 1", (item["evidence_item_id"],)).fetchone() or connection.execute("SELECT 1 FROM call_logs WHERE evidence_item_id = ? LIMIT 1", (item["evidence_item_id"],)).fetchone():
			continue
		path = EVIDENCE_DIR / item["original_path"]
		try:
			data = json.loads(path.read_text(encoding="utf-8"))
		except (OSError, json.JSONDecodeError):
			continue
		for record in data.get("sms", {}).get("records", []):
			connection.execute("INSERT INTO sms_messages (evidence_item_id, case_id, device_id, acquisition_id, address, body, message_type, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (item["evidence_item_id"], item["case_id"], item["device_id"], item["acquisition_id"], record.get("address"), record.get("body"), record.get("type"), record.get("date")))
		for record in data.get("call_logs", {}).get("records", []):
			connection.execute("INSERT INTO call_logs (evidence_item_id, case_id, device_id, acquisition_id, number, name, call_type, duration, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (item["evidence_item_id"], item["case_id"], item["device_id"], item["acquisition_id"], record.get("number"), record.get("name"), record.get("type"), record.get("duration"), record.get("date")))
		for record in data.get("files", {}).get("records", []):
			orig_path = record.get("original_path") or record.get("_data") or ""
			if not orig_path:
				continue
			fname = record.get("file_name") or orig_path.split("/")[-1]
			fsize = record.get("size") or record.get("_size") or 0
			fmime = record.get("mime_type") or "application/octet-stream"
			ftstamp = record.get("date_modified") or record.get("timestamp") or utc_now()
			connection.execute(
				"INSERT INTO files (evidence_item_id, case_id, device_id, acquisition_id, original_path, file_name, size, mime_type, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
				(item["evidence_item_id"], item["case_id"], item["device_id"], item["acquisition_id"], orig_path, fname, fsize, fmime, ftstamp)
			)
		for record in data.get("browser_history", {}).get("records", []):
			url_val = record.get("url") or ""
			if not url_val:
				continue
			connection.execute(
				"INSERT INTO browser_history (evidence_item_id, case_id, device_id, acquisition_id, browser, url, title, visit_timestamp, visit_count, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				(
					item["evidence_item_id"],
					item["case_id"],
					item["device_id"],
					item["acquisition_id"],
					record.get("browser") or "Unknown Browser",
					url_val,
					record.get("title") or url_val,
					record.get("visit_timestamp") or record.get("date") or utc_now(),
					int(record.get("visit_count") or record.get("visits") or 1),
					record.get("source") or "content://browser",
				),
			)




def rows(query: str, parameters: tuple = ()) -> list[dict]:
	def _op():
		with connect() as connection:
			return [dict(r) for r in connection.execute(query, parameters).fetchall()]
	return execute_with_retry(_op)


def row(query: str, parameters: tuple = ()) -> dict | None:
	result = rows(query, parameters)
	return result[0] if result else None


def record_chain_event(
	case_id: str,
	action: str,
	description: str,
	person: str = "System",
	device_id: str | None = None,
	acquisition_id: str | None = None,
	evidence_item_id: str | None = None,
) -> None:
	"""Record an immutable audit / chain-of-custody event for evidence or module action."""
	now = utc_now()
	def _op():
		with connect() as connection:
			connection.execute(
				"INSERT INTO chain_of_custody "
				"(case_id, device_id, acquisition_id, evidence_item_id, event_type, action, actor, person, timestamp, description) "
				"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				(case_id, device_id, acquisition_id, evidence_item_id, action, action, person, person, now, description),
			)
	try:
		execute_with_retry(_op)
	except Exception:
		pass

def record_tool_event(
	tool_id: str,
	case_id: str,
	action: str,
	status: str,
	artifacts_count: int = 0,
	details: str = "",
	actor: str = "Investigator",
) -> dict:
	"""Record a multi-source tool integration activity or import event."""
	from uuid import uuid4
	event_id = f"TEVT-{uuid4().hex[:8].upper()}"
	now = utc_now()
	def _op():
		with connect() as connection:
			connection.execute(
				"INSERT INTO tool_integration_events "
				"(event_id, tool_id, case_id, action, status, artifacts_count, details, actor, timestamp) "
				"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
				(event_id, tool_id, case_id, action, status, artifacts_count, details, actor, now),
			)
			connection.execute(
				"INSERT INTO chain_of_custody "
				"(case_id, event_type, action, actor, person, timestamp, description) "
				"VALUES (?, ?, ?, ?, ?, ?, ?)",
				(case_id, f"TOOL_{action.upper()}", action, actor, actor, now, f"[{tool_id.upper()}] {action}: {status}. {details}"),
			)
	try:
		execute_with_retry(_op)
	except Exception:
		pass
	return {
		"event_id": event_id,
		"tool_id": tool_id,
		"case_id": case_id,
		"action": action,
		"status": status,
		"artifacts_count": artifacts_count,
		"details": details,
		"actor": actor,
		"timestamp": now,
	}


def get_tool_events(case_id: str | None = None, limit: int = 50) -> list[dict]:
	"""Fetch recent tool integration events."""
	if case_id:
		return rows(
			"SELECT * FROM tool_integration_events WHERE case_id = ? ORDER BY id DESC LIMIT ?",
			(case_id, limit),
		)
	return rows(
		"SELECT * FROM tool_integration_events ORDER BY id DESC LIMIT ?",
		(limit,),
	)

