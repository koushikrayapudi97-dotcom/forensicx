"""Module 5: Automatic Incident Timeline + Evidence-Linked AI Report Engine for ForensicX.

Groups normalized evidence, correlations, reliability scores, and graph relationships
into chronological activity sequences, with strict separation of FACT, CORRELATION, and AI INTERPRETATION.
Adheres strictly to patent guidelines:
- Every timeline event is grounded in real, verifiable evidence.
- Full metadata: Event ID, Timestamp, Event Type, Description, Evidence IDs, Source, Device, Case, Correlation IDs, Reliability.
- Never generates artificial events.
"""

from datetime import datetime, timezone
import json

from backend.database.database import connect, row, rows, utc_now
from backend.services.evidence_correlation_engine import get_evidence_correlations, run_correlation_engine
from backend.services.evidence_graph_engine import build_evidence_graph, get_graph_data
from backend.services.evidence_normalization_engine import get_normalized_evidence, normalize_case
from backend.services.evidence_reliability_engine import get_reliability_scores, run_reliability_engine

SUSPICIOUS_KEYWORDS = [
    "wipe", "factory reset", "spoof", "fake gps", "darkweb", "phishing",
    "malware", "delete logcat", "root", "bypass pin", "crypto mixer",
    "tor", "vault", "burner", "signal", "telegram", "encrypted",
]


def build_incident_timeline(case_id: str) -> dict:
    """Build and persist chronological incident timeline for a case.
    
    Operations are idempotent and saved to SQLite.
    """
    normalize_case(case_id)
    correlations = get_evidence_correlations(case_id)
    if not correlations:
        run_correlation_engine(case_id)
        correlations = get_evidence_correlations(case_id)

    scores = get_reliability_scores(case_id)
    if not scores:
        run_reliability_engine(case_id)
        scores = get_reliability_scores(case_id)

    items = get_normalized_evidence(case_id)

    score_map = {s["evidence_id"]: s for s in scores if s["target_type"] == "EVIDENCE_ITEM"}

    # Map evidence IDs to correlated evidence IDs and correlation IDs
    corr_ev_map: dict[str, list[str]] = {}
    corr_id_map: dict[str, list[str]] = {}
    for c in correlations:
        cid = c["correlation_id"]
        eids = c.get("evidence_ids", [])
        for eid in eids:
            other_eids = [x for x in eids if x != eid]
            corr_ev_map.setdefault(eid, []).extend(other_eids)
            corr_id_map.setdefault(eid, []).append(cid)

    # Sort timestamped items chronologically
    timestamped_items = []
    untimestamped_items = []

    for item in items:
        ts_utc = item.get("timestamp_utc")
        if ts_utc:
            timestamped_items.append((ts_utc, item))
        else:
            untimestamped_items.append(item)

    timestamped_items.sort(key=lambda x: x[0])

    all_timeline_items = ([x[1] for x in timestamped_items] + untimestamped_items)[:500]
    timeline_records = []
    now = utc_now()

    for seq_num, item in enumerate(all_timeline_items, 1):
        eid = item["normalized_id"]
        art_type = item["artifact_type"]
        ts_utc = item.get("timestamp_utc") or item.get("original_timestamp") or "Not Available"
        dev_id = item.get("device_id") or "DEV-UNKNOWN"
        source_ref = item.get("source_ref") or item.get("source_method") or "Unknown Source"

        sc_obj = score_map.get(eid, {})
        rel_score = sc_obj.get("reliability_score", 80.0)
        c_eids = list(set(corr_ev_map.get(eid, [])))
        c_ids = list(set(corr_id_map.get(eid, [])))
        all_eids = [eid] + c_eids

        cnt = item.get("content") or {}
        e_info = item.get("entity_info") or {}
        loc = item.get("location_info") or {}

        suspicious_flag = 0
        flag_reason = ""
        category = "SYSTEM_EVENT"
        title = ""
        desc = ""

        if art_type == "sms":
            category = "SMS"
            addr = e_info.get("address") or "Unknown"
            direction = e_info.get("message_direction") or "SMS"
            body = cnt.get("body") or ""
            title = f"{direction} Message ({addr})"
            desc = f"SMS {direction.lower()} with contact {addr}: {body[:80]}"
            if any(kw in body.lower() for kw in SUSPICIOUS_KEYWORDS):
                suspicious_flag = 1
                flag_reason = "SMS content contains high-risk security / evasion terminology."

        elif art_type == "call":
            category = "Call"
            num = e_info.get("phone_number") or "Unknown"
            name = e_info.get("contact_name") or "Unknown"
            c_dir = e_info.get("call_direction") or "Call"
            dur = cnt.get("duration_formatted") or "00:00"
            contact_str = f"{name} ({num})" if name != "Unknown" else num
            title = f"{c_dir} Call ({contact_str})"
            desc = f"{c_dir} call log recorded with {contact_str}. Duration: {dur}."

        elif art_type == "gps":
            category = "GPS"
            lat = loc.get("latitude")
            lon = loc.get("longitude")
            prov = (loc.get("provider") or "gps").upper()
            title = f"GPS Fix ({lat}, {lon})"
            desc = f"Location fix ({prov}) recorded at Latitude {lat}, Longitude {lon}."

        elif art_type == "web_history":
            category = "Browser/Web"
            url_val = cnt.get("url") or e_info.get("url") or ""
            url_title = cnt.get("title") or url_val
            browser_name = e_info.get("browser") or "Browser"
            title = f"Web Visit ({url_title[:35]})"
            desc = f"Browser ({browser_name}) visit to '{url_title}' at URL: {url_val}."
            if any(kw in url_val.lower() or kw in url_title.lower() for kw in SUSPICIOUS_KEYWORDS):
                suspicious_flag = 1
                flag_reason = "Web history contains query / domain associated with security evasion or data wiping."

        elif art_type in ("file", "image", "video", "document"):
            category = "File"
            fname = cnt.get("file_name") or "File"
            path = cnt.get("original_path") or ""
            mime = cnt.get("mime_type") or "file"
            title = f"File Artifact ({fname})"
            desc = f"File artifact ({mime}) preserved at path: {path}."

        elif art_type == "application":
            category = "Application"
            pkg = cnt.get("package_name") or "Application"
            title = f"Application ({pkg})"
            desc = f"Installed package artifact recorded: {pkg}."

        t_id = f"TL-{case_id}-{seq_num:04d}"
        event_id = f"EVT-{seq_num:04d}"
        timeline_records.append({
            "timeline_id": t_id,
            "event_id": event_id,
            "case_id": case_id,
            "device_id": dev_id,
            "source": source_ref,
            "sequence_number": seq_num,
            "event_category": category,
            "event_timestamp": ts_utc,
            "title": title,
            "description": desc,
            "primary_evidence_id": eid,
            "evidence_ids": all_eids,
            "correlated_evidence_ids": json.dumps(c_eids),
            "correlation_ids": json.dumps(c_ids),
            "reliability_score": rel_score,
            "suspicious_flag": suspicious_flag,
            "flag_reason": flag_reason,
            "created_at": now,
        })

    # Persist timeline records into SQLite in batch
    batch_params = [
        (
            r["timeline_id"], r["case_id"], r["sequence_number"], r["event_category"],
            r["event_timestamp"], r["title"], r["description"], r["primary_evidence_id"],
            r["correlated_evidence_ids"], r["reliability_score"], r["suspicious_flag"],
            r["flag_reason"], r["created_at"],
            r["event_id"], r["source"], r["device_id"], r["correlation_ids"],
        )
        for r in timeline_records
    ]

    if batch_params:
        with connect() as connection:
            connection.executemany(
                """
                INSERT INTO incident_timeline (
                    timeline_id, case_id, sequence_number, event_category, event_timestamp,
                    title, description, primary_evidence_id, correlated_evidence_ids,
                    reliability_score, suspicious_flag, flag_reason, created_at,
                    event_id, source, device_id, correlation_ids
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id, sequence_number, primary_evidence_id) DO UPDATE SET
                    event_category = excluded.event_category,
                    event_timestamp = excluded.event_timestamp,
                    title = excluded.title,
                    description = excluded.description,
                    correlated_evidence_ids = excluded.correlated_evidence_ids,
                    reliability_score = excluded.reliability_score,
                    suspicious_flag = excluded.suspicious_flag,
                    flag_reason = excluded.flag_reason,
                    event_id = excluded.event_id,
                    source = excluded.source,
                    device_id = excluded.device_id,
                    correlation_ids = excluded.correlation_ids
                """,
                batch_params,
            )

    return {
        "case_id": case_id,
        "total_events": len(timeline_records),
        "suspicious_events": sum(1 for r in timeline_records if r["suspicious_flag"] == 1),
    }


def get_incident_timeline(case_id: str) -> list[dict]:
    """Retrieve the incident timeline for a case with all structured metadata."""
    rows_rec = rows("SELECT * FROM incident_timeline WHERE case_id = ? ORDER BY sequence_number ASC", (case_id,))
    results = []
    for r in rows_rec:
        item = dict(r)
        try:
            item["correlated_evidence_ids"] = json.loads(item.get("correlated_evidence_ids") or "[]")
        except json.JSONDecodeError:
            item["correlated_evidence_ids"] = []
        try:
            item["correlation_ids"] = json.loads(item.get("correlation_ids") or "[]")
        except json.JSONDecodeError:
            item["correlation_ids"] = []

        if not item.get("event_id"):
            item["event_id"] = f"EVT-{item.get('sequence_number', 1):04d}"

        # Combine all evidence IDs
        prim = item.get("primary_evidence_id")
        corr = item.get("correlated_evidence_ids", [])
        item["evidence_ids"] = ([prim] if prim else []) + [x for x in corr if x != prim]

        results.append(item)
    return results


def generate_evidence_linked_report(case_id: str) -> dict:
    """Generate structured AI investigation report payload with strict separation of FACT, CORRELATION, and AI INTERPRETATION."""
    build_incident_timeline(case_id)

    case_rec = dict(row("SELECT * FROM cases WHERE case_id = ?", (case_id,)) or {})
    items = get_normalized_evidence(case_id)
    correlations = get_evidence_correlations(case_id)
    scores = get_reliability_scores(case_id)
    timeline = get_incident_timeline(case_id)
    graph_data = get_graph_data(case_id)

    # 1. Facts (Direct Evidence Items)
    facts = []
    for item in items:
        facts.append({
            "evidence_id": item["normalized_id"],
            "artifact_type": item["artifact_type"],
            "timestamp": item.get("timestamp_utc") or item.get("original_timestamp") or "Not Available",
            "source_ref": item["source_ref"],
            "summary": f"{item['artifact_type'].upper()} preserved from {item['source_method']} ({item['source_ref']}).",
            "entity_info": item.get("entity_info") or {},
            "content": item.get("content") or {},
        })

    # 2. Correlations (Module 2 Output)
    corr_list = []
    for c in correlations:
        corr_list.append({
            "correlation_id": c["correlation_id"],
            "evidence_id_a": c.get("evidence_id_a"),
            "evidence_id_b": c.get("evidence_id_b"),
            "relationship_type": c["relationship_type"],
            "reason": c.get("reason") or c.get("explanation"),
            "timestamp_relationship": c.get("timestamp_relationship"),
            "strength": f"{int(c['correlation_strength'] * 100)}%",
            "supporting_evidence_ids": c.get("evidence_ids", []),
            "explanation": c["explanation"],
        })

    # 3. AI Analytical Interpretation (Objective synthesis, never claiming guilt)
    interpretations = []
    suspicious_events = [t for t in timeline if t["suspicious_flag"] == 1]

    if suspicious_events:
        for s_evt in suspicious_events:
            interpretations.append({
                "finding": f"Suspicious Activity Pattern: {s_evt['title']}",
                "why_flagged": s_evt["flag_reason"],
                "supporting_evidence_ids": [s_evt["primary_evidence_id"]] + s_evt.get("correlated_evidence_ids", []),
                "classification": "SUSPICIOUS_PATTERN",
            })
    else:
        interpretations.append({
            "finding": "Standard Device Usage Pattern",
            "why_flagged": "No anti-forensic, data wiping, or high-risk domain activity was observed in preserved evidence.",
            "supporting_evidence_ids": [t["primary_evidence_id"] for t in timeline[:3]] if timeline else [],
            "classification": "NORMAL_USAGE",
        })

    avg_reliability = round(sum(s["reliability_score"] for s in scores if s["target_type"] == "EVIDENCE_ITEM") / len(scores), 1) if scores else 100.0

    return {
        "case": case_rec,
        "summary": {
            "total_normalized_items": len(items),
            "total_correlations": len(correlations),
            "average_reliability_score": avg_reliability,
            "total_timeline_events": len(timeline),
            "graph_nodes_count": len(graph_data["nodes"]),
            "graph_edges_count": len(graph_data["edges"]),
        },
        "facts": facts,
        "correlations": corr_list,
        "interpretations": interpretations,
        "timeline": timeline,
        "scores": scores,
    }
