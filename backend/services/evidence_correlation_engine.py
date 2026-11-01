"""Module 2: Cross-Source Evidence Correlation Engine for ForensicX.

Analyzes normalized evidence from SMS, calls, GPS, web history, files, contacts,
and applications to discover factual, verifiable cross-source relationships.
Adheres strictly to patent guidelines:
- Never asserts causality automatically.
- Uses objective forensic relationship terminology.
- Explicitly binds Evidence ID A and Evidence ID B.
- Provides factual reasons, temporal deltas, and supporting attributes.
"""

from datetime import datetime, timezone
import hashlib
import json

from backend.database.database import connect, rows, utc_now
from backend.services.evidence_normalization_engine import get_normalized_evidence, normalize_case


def _generate_correlation_id(case_id: str, rel_type: str, evidence_ids: list[str]) -> str:
    """Generate a deterministic correlation ID based on case ID, type, and involved evidence IDs."""
    sorted_ids = ",".join(sorted(evidence_ids))
    digest = hashlib.sha256(f"{case_id}::{rel_type}::{sorted_ids}".encode("utf-8")).hexdigest()[:10].upper()
    return f"CORR-{digest}"


def _format_time_rel(dt1: datetime | None, dt2: datetime | None, diff_sec: float | None) -> str:
    """Format an objective timestamp relationship description."""
    if dt1 and dt2 and diff_sec is not None:
        return f"Temporal Relationship: Occurred {int(abs(diff_sec))}s apart ({dt1.isoformat()} ↔ {dt2.isoformat()})"
    elif dt1 and dt2:
        return f"Temporal Relationship: Co-recorded ({dt1.isoformat()} and {dt2.isoformat()})"
    return "Temporal Relationship: One or both records lack precise timestamp."


def run_correlation_engine(case_id: str) -> dict:
    """Execute cross-source evidence correlation analysis for a case.
    
    Operations are idempotent, strictly objective, and store deterministic correlations into SQLite.
    """
    normalize_case(case_id)
    items = get_normalized_evidence(case_id)

    correlations = []
    seen_pairs = set()

    # Pre-parse timestamps where available
    item_dt_map: dict[str, datetime | None] = {}
    for item in items:
        eid = item["normalized_id"]
        ts_str = item.get("timestamp_utc")
        dt_val = None
        if ts_str:
            try:
                dt_val = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                dt_val = None
        item_dt_map[eid] = dt_val

    # 1. Communication & Entity Correlation (Phone Numbers / Contacts / Addresses)
    phone_map: dict[str, list[dict]] = {}
    for item in items:
        e_info = item.get("entity_info") or {}
        num = e_info.get("phone_number") or e_info.get("address") or e_info.get("sender_receiver")
        if num and str(num).lower() not in ("unknown", "null", "none", "") and len(str(num).strip()) >= 3:
            clean_num = str(num).replace(" ", "").replace("-", "")
            phone_map.setdefault(clean_num, []).append(item)

    for num, group in phone_map.items():
        if len(correlations) >= 300:
            break
        subgroup = group[:25]
        if len(subgroup) >= 2:
            for i in range(len(subgroup)):
                for j in range(i + 1, len(subgroup)):
                    item_a = subgroup[i]
                    item_b = subgroup[j]
                    id_a = item_a["normalized_id"]
                    id_b = item_b["normalized_id"]
                    pair_key = tuple(sorted([id_a, id_b]))

                    dt_a = item_dt_map.get(id_a)
                    dt_b = item_dt_map.get(id_b)
                    diff_sec = abs((dt_b - dt_a).total_seconds()) if (dt_a and dt_b) else None

                    type_a = item_a["artifact_type"]
                    type_b = item_b["artifact_type"]

                    # Determine correlation type
                    if diff_sec is not None and diff_sec <= 900:
                        corr_type = "Communication Correlation"
                        type_label = "Temporal + Communication Correlation"
                        reason = f"Both records involve the same phone number/contact identifier '{num}' and occur within {int(diff_sec)} seconds of each other."
                        strength = 0.95
                    elif type_a in ("sms", "call") and type_b in ("sms", "call"):
                        corr_type = "Communication Correlation"
                        type_label = "Communication Correlation"
                        reason = f"Both records involve common phone number/contact communication with '{num}'."
                        strength = 0.88
                    else:
                        corr_type = "Entity Correlation"
                        type_label = "Entity Correlation"
                        reason = f"Related Evidence: Both evidence items share common phone number or contact identifier '{num}'."
                        strength = 0.85

                    time_rel = _format_time_rel(dt_a, dt_b, diff_sec)
                    ev_ids = [id_a, id_b]
                    corr_id = _generate_correlation_id(case_id, corr_type, ev_ids)

                    correlations.append({
                        "correlation_id": corr_id,
                        "case_id": case_id,
                        "evidence_id_a": id_a,
                        "evidence_id_b": id_b,
                        "evidence_ids": ev_ids,
                        "relationship_type": type_label,
                        "time_difference_seconds": diff_sec,
                        "timestamp_relationship": time_rel,
                        "matching_attributes": {
                            "matched_phone_number": num,
                            "matched_identifier": num,
                            "artifact_type_a": type_a,
                            "artifact_type_b": type_b,
                            "device_a": item_a.get("device_id"),
                            "device_b": item_b.get("device_id"),
                        },
                        "supporting_attributes": {
                            "matched_phone_number": num,
                            "matched_identifier": num,
                            "artifact_type_a": type_a,
                            "artifact_type_b": type_b,
                        },
                        "correlation_strength": strength,
                        "explanation": reason,
                        "reason": reason,
                    })
                    seen_pairs.add(pair_key)

    # 2. File Correlation (Identical SHA-256 Hashes)
    hash_map: dict[str, list[dict]] = {}
    for item in items:
        h_val = item.get("original_hash")
        if h_val and len(h_val) >= 16:
            hash_map.setdefault(h_val.lower(), []).append(item)

    for h_val, group in hash_map.items():
        if len(correlations) >= 350:
            break
        subgroup = group[:25]
        if len(subgroup) >= 2:
            for i in range(len(subgroup)):
                for j in range(i + 1, len(subgroup)):
                    item_a = subgroup[i]
                    item_b = subgroup[j]
                    id_a = item_a["normalized_id"]
                    id_b = item_b["normalized_id"]
                    pair_key = tuple(sorted([id_a, id_b]))

                    dt_a = item_dt_map.get(id_a)
                    dt_b = item_dt_map.get(id_b)
                    diff_sec = abs((dt_b - dt_a).total_seconds()) if (dt_a and dt_b) else None
                    time_rel = _format_time_rel(dt_a, dt_b, diff_sec)

                    reason = f"File Relationship: Verified identical cryptographic SHA-256 hash ({h_val[:16]}...) across distinct evidence items."
                    ev_ids = [id_a, id_b]
                    corr_id = _generate_correlation_id(case_id, "File Correlation", ev_ids)

                    correlations.append({
                        "correlation_id": corr_id,
                        "case_id": case_id,
                        "evidence_id_a": id_a,
                        "evidence_id_b": id_b,
                        "evidence_ids": ev_ids,
                        "relationship_type": "File Correlation",
                        "time_difference_seconds": diff_sec,
                        "timestamp_relationship": time_rel,
                        "matching_attributes": {
                            "sha256": h_val,
                            "source_a": item_a.get("source_ref"),
                            "source_b": item_b.get("source_ref"),
                        },
                        "supporting_attributes": {"sha256": h_val},
                        "correlation_strength": 1.00,
                        "explanation": reason,
                        "reason": reason,
                    })
                    seen_pairs.add(pair_key)

    # 3. Temporal & Cross-Source Correlation (Within 15-minute window)
    timestamped_items = [(item_dt_map[item["normalized_id"]], item) for item in items if item_dt_map.get(item["normalized_id"])]
    timestamped_items.sort(key=lambda x: x[0])
    t_items = timestamped_items[:300] if len(timestamped_items) > 300 else timestamped_items

    for i in range(len(t_items)):
        if len(correlations) >= 400:
            break
        dt_a, item_a = t_items[i]
        id_a = item_a["normalized_id"]
        type_a = item_a["artifact_type"]

        for j in range(i + 1, min(i + 30, len(t_items))):
            dt_b, item_b = t_items[j]
            id_b = item_b["normalized_id"]
            type_b = item_b["artifact_type"]

            diff_sec = (dt_b - dt_a).total_seconds()
            if diff_sec > 900:  # 15 minutes window limit
                break

            pair_key = tuple(sorted([id_a, id_b]))
            if pair_key in seen_pairs:
                continue

            # Don't create trivial correlations between identical consecutive items from the exact same source
            if item_a.get("source_ref") == item_b.get("source_ref"):
                continue

            ev_ids = [id_a, id_b]
            time_rel = _format_time_rel(dt_a, dt_b, diff_sec)

            # Check if this is a cross-source sequence (Communication <-> Web / Location / File)
            if type_a in ("sms", "call") and type_b in ("web_history", "gps", "file", "image", "video", "application"):
                corr_type = "Cross-Source Correlation"
                strength = max(0.65, round(0.92 - (diff_sec / 1800), 2))
                reason = f"Cross-Source Relationship: {type_a.upper()} communication was temporally followed within {int(diff_sec)} seconds by {type_b.replace('_', ' ').upper()} activity."
            elif type_a != type_b:
                corr_type = "Cross-Source Correlation"
                strength = max(0.55, round(0.85 - (diff_sec / 1500), 2))
                reason = f"Cross-Source Relationship: Different artifact types ({type_a.upper()} and {type_b.upper()}) occurred within {int(diff_sec)} seconds in the same temporal window."
            else:
                corr_type = "Temporal Correlation"
                strength = max(0.50, round(0.80 - (diff_sec / 1200), 2))
                reason = f"Temporal Relationship: Evidence records occurred within {int(diff_sec)} seconds of each other."

            corr_id = _generate_correlation_id(case_id, corr_type, ev_ids)

            correlations.append({
                "correlation_id": corr_id,
                "case_id": case_id,
                "evidence_id_a": id_a,
                "evidence_id_b": id_b,
                "evidence_ids": ev_ids,
                "relationship_type": corr_type,
                "time_difference_seconds": diff_sec,
                "timestamp_relationship": time_rel,
                "matching_attributes": {
                    "artifact_type_a": type_a,
                    "artifact_type_b": type_b,
                    "time_difference_seconds": diff_sec,
                },
                "supporting_attributes": {
                    "artifact_types": [type_a, type_b],
                    "delta_seconds": diff_sec,
                },
                "correlation_strength": strength,
                "explanation": reason,
                "reason": reason,
            })
            seen_pairs.add(pair_key)

    # 4. Location Correlation (GPS Coordinates Proximity)
    gps_items = [item for item in items if item["artifact_type"] == "gps"][:40]
    for i in range(len(gps_items)):
        if len(correlations) >= 450:
            break
        g1 = gps_items[i]
        id_1 = g1["normalized_id"]
        loc1 = g1.get("location_info") or {}
        lat1, lon1 = loc1.get("latitude"), loc1.get("longitude")
        if not lat1 or not lon1:
            continue

        for j in range(i + 1, len(gps_items)):
            g2 = gps_items[j]
            id_2 = g2["normalized_id"]
            pair_key = tuple(sorted([id_1, id_2]))
            if pair_key in seen_pairs:
                continue

            loc2 = g2.get("location_info") or {}
            lat2, lon2 = loc2.get("latitude"), loc2.get("longitude")
            if not lat2 or not lon2:
                continue

            try:
                d_lat = abs(float(lat1) - float(lat2))
                d_lon = abs(float(lon1) - float(lon2))
                if d_lat < 0.005 and d_lon < 0.005:  # within ~500m
                    dt_1 = item_dt_map.get(id_1)
                    dt_2 = item_dt_map.get(id_2)
                    diff_sec = abs((dt_2 - dt_1).total_seconds()) if (dt_1 and dt_2) else None
                    time_rel = _format_time_rel(dt_1, dt_2, diff_sec)

                    ev_ids = [id_1, id_2]
                    corr_id = _generate_correlation_id(case_id, "Location Correlation", ev_ids)
                    reason = f"Location Relationship: GPS fixes occur in close spatial proximity ({lat1},{lon1} ↔ {lat2},{lon2})."

                    correlations.append({
                        "correlation_id": corr_id,
                        "case_id": case_id,
                        "evidence_id_a": id_1,
                        "evidence_id_b": id_2,
                        "evidence_ids": ev_ids,
                        "relationship_type": "Location Correlation",
                        "time_difference_seconds": diff_sec,
                        "timestamp_relationship": time_rel,
                        "matching_attributes": {
                            "coords_a": f"{lat1},{lon1}",
                            "coords_b": f"{lat2},{lon2}",
                        },
                        "supporting_attributes": {
                            "proximity_delta": f"d_lat={d_lat:.4f}, d_lon={d_lon:.4f}",
                        },
                        "correlation_strength": 0.88,
                        "explanation": reason,
                        "reason": reason,
                    })
                    seen_pairs.add(pair_key)
            except (ValueError, TypeError):
                continue

    # 5. Application Correlation (Shared Package Name / App Context)
    app_map: dict[str, list[dict]] = {}
    for item in items:
        cnt = item.get("content") or {}
        e_info = item.get("entity_info") or {}
        pkg = cnt.get("package_name") or e_info.get("package_name") or cnt.get("app")
        if pkg and str(pkg).lower() not in ("unknown", "null", "none", "") and "." in str(pkg):
            app_map.setdefault(str(pkg), []).append(item)

    for pkg, group in app_map.items():
        if len(correlations) >= 480:
            break
        subgroup = group[:25]
        if len(subgroup) >= 2:
            for i in range(len(subgroup)):
                for j in range(i + 1, len(subgroup)):
                    item_a = subgroup[i]
                    item_b = subgroup[j]
                    id_a = item_a["normalized_id"]
                    id_b = item_b["normalized_id"]
                    pair_key = tuple(sorted([id_a, id_b]))
                    if pair_key in seen_pairs:
                        continue

                    dt_a = item_dt_map.get(id_a)
                    dt_b = item_dt_map.get(id_b)
                    diff_sec = abs((dt_b - dt_a).total_seconds()) if (dt_a and dt_b) else None
                    time_rel = _format_time_rel(dt_a, dt_b, diff_sec)

                    ev_ids = [id_a, id_b]
                    corr_id = _generate_correlation_id(case_id, "Application Correlation", ev_ids)
                    reason = f"Application Relationship: Both evidence items are linked with application package '{pkg}'."

                    correlations.append({
                        "correlation_id": corr_id,
                        "case_id": case_id,
                        "evidence_id_a": id_a,
                        "evidence_id_b": id_b,
                        "evidence_ids": ev_ids,
                        "relationship_type": "Application Correlation",
                        "time_difference_seconds": diff_sec,
                        "timestamp_relationship": time_rel,
                        "matching_attributes": {"package_name": pkg},
                        "supporting_attributes": {"package_name": pkg},
                        "correlation_strength": 0.82,
                        "explanation": reason,
                        "reason": reason,
                    })
                    seen_pairs.add(pair_key)

    # Persist correlations into SQLite in batch
    correlations = correlations[:500]
    now = utc_now()
    batch_params = []
    for c in correlations:
        ev_json = json.dumps(c["evidence_ids"])
        match_json = json.dumps(c["matching_attributes"], ensure_ascii=False)
        supp_json = json.dumps(c["supporting_attributes"], ensure_ascii=False)
        batch_params.append((
            c["correlation_id"], c["case_id"], ev_json, c["relationship_type"],
            c["time_difference_seconds"], match_json, c["correlation_strength"],
            c["explanation"], now, c["evidence_id_a"], c["evidence_id_b"],
            c["reason"], c["timestamp_relationship"], supp_json,
        ))

    if batch_params:
        with connect() as connection:
            connection.executemany(
                """
                INSERT INTO evidence_correlations (
                    correlation_id, case_id, evidence_ids, relationship_type,
                    time_difference_seconds, matching_attributes, correlation_strength,
                    explanation, created_at, evidence_id_a, evidence_id_b,
                    reason, timestamp_relationship, supporting_attributes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id, relationship_type, evidence_ids) DO UPDATE SET
                    time_difference_seconds = excluded.time_difference_seconds,
                    matching_attributes = excluded.matching_attributes,
                    correlation_strength = excluded.correlation_strength,
                    explanation = excluded.explanation,
                    evidence_id_a = excluded.evidence_id_a,
                    evidence_id_b = excluded.evidence_id_b,
                    reason = excluded.reason,
                    timestamp_relationship = excluded.timestamp_relationship,
                    supporting_attributes = excluded.supporting_attributes
                """,
                batch_params,
            )

    return {
        "case_id": case_id,
        "total_correlations": len(correlations),
        "correlations": correlations,
        "status_message": "Correlations computed successfully" if correlations else "Insufficient evidence for correlation",
    }


def get_evidence_correlations(case_id: str) -> list[dict]:
    """Retrieve all stored evidence correlations for a case."""
    rows_rec = rows("SELECT * FROM evidence_correlations WHERE case_id = ? ORDER BY correlation_strength DESC", (case_id,))
    results = []
    for r in rows_rec:
        item = dict(r)
        try:
            item["evidence_ids"] = json.loads(item.get("evidence_ids") or "[]")
        except json.JSONDecodeError:
            pass
        try:
            item["matching_attributes"] = json.loads(item.get("matching_attributes") or "{}")
        except json.JSONDecodeError:
            pass
        try:
            item["supporting_attributes"] = json.loads(item.get("supporting_attributes") or "{}")
        except json.JSONDecodeError:
            pass

        # Ensure evidence_id_a and evidence_id_b are populated
        if not item.get("evidence_id_a") and len(item["evidence_ids"]) >= 1:
            item["evidence_id_a"] = item["evidence_ids"][0]
        if not item.get("evidence_id_b") and len(item["evidence_ids"]) >= 2:
            item["evidence_id_b"] = item["evidence_ids"][1]
        if not item.get("reason"):
            item["reason"] = item.get("explanation") or ""

        results.append(item)
    return results
