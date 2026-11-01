"""Module 4: Evidence Relationship Graph Engine for ForensicX.

Constructs an interactive evidence graph representing entities (Device, Person/Phone,
Account, Application, File, Location, SMS, Call, Web Visit) and traceable relationships.
Adheres strictly to patent guidelines:
- Nodes represent actual stored evidence entities.
- Edges represent verified structural or correlated relationships.
- Full inspection metadata for both nodes and edges.
- Never creates unsupported relationships.
"""

import hashlib
import json

from backend.database.database import connect, rows, utc_now
from backend.services.evidence_correlation_engine import get_evidence_correlations, run_correlation_engine
from backend.services.evidence_normalization_engine import get_normalized_evidence, normalize_case


def _make_node_id(case_id: str, entity_type: str, label: str) -> str:
    """Generate a deterministic node ID."""
    digest = hashlib.sha256(f"{case_id}::{entity_type}::{label}".encode("utf-8")).hexdigest()[:12].upper()
    return f"NODE-{entity_type[:4]}-{digest}"


def _make_edge_id(case_id: str, src: str, tgt: str, rel: str) -> str:
    """Generate a deterministic edge ID."""
    digest = hashlib.sha256(f"{case_id}::{src}::{tgt}::{rel}".encode("utf-8")).hexdigest()[:12].upper()
    return f"EDGE-{digest}"


def build_evidence_graph(case_id: str) -> dict:
    """Build and persist the complete Evidence Relationship Graph for a case.
    
    Operations are fully idempotent. Re-running clears and updates existing nodes and edges.
    """
    normalize_case(case_id)
    correlations = get_evidence_correlations(case_id)
    if not correlations:
        run_correlation_engine(case_id)
        correlations = get_evidence_correlations(case_id)

    items = get_normalized_evidence(case_id)
    correlated_eids = set()
    for c in correlations:
        for eid in c.get("evidence_ids", []):
            correlated_eids.add(eid)

    priority_items = [it for it in items if it["normalized_id"] in correlated_eids]
    other_items = [it for it in items if it["normalized_id"] not in correlated_eids]
    items = (priority_items + other_items)[:150]

    nodes = {}  # key: (entity_type, label) -> node dict
    edges = {}  # key: edge_id -> edge dict
    now = utc_now()

    # Pre-map correlation partners
    corr_partners_map: dict[str, list[str]] = {}
    for c in correlations:
        eids = c.get("evidence_ids", [])
        for eid in eids:
            others = [x for x in eids if x != eid]
            corr_partners_map.setdefault(eid, []).extend(others)

    # 1. Device Nodes (Root entities for each device in case)
    distinct_devices = list(dict.fromkeys(it.get("device_id") for it in items if it.get("device_id")))
    if not distinct_devices:
        distinct_devices = ["DEV-UNKNOWN"]

    dev_node_ids: dict[str, str] = {}
    for dev_id in distinct_devices:
        dev_label = f"Device ({dev_id})"
        d_node_id = _make_node_id(case_id, "DEVICE", dev_label)
        dev_node_ids[dev_id] = d_node_id
        dev_key = ("DEVICE", dev_label)
        dev_items = [it for it in items if it.get("device_id") == dev_id]
        nodes[dev_key] = {
            "node_id": d_node_id,
            "case_id": case_id,
            "entity_type": "DEVICE",
            "label": dev_label,
            "properties": json.dumps({
                "device_id": dev_id,
                "case_id": case_id,
                "entity": dev_label,
                "source": "Physical / ADB Device",
                "provenance": {"device_id": dev_id, "status": "Acquired"},
                "evidence_ids": [it["normalized_id"] for it in dev_items[:5]],
                "related_evidence": [it["normalized_id"] for it in dev_items[:5]],
                "timestamp": dev_items[0].get("timestamp_utc", "") if dev_items else "",
            }, ensure_ascii=False),
            "source_evidence_id": dev_items[0]["normalized_id"] if dev_items else None,
            "created_at": now,
        }

    # Map evidence item IDs to their node IDs
    ev_node_map = {}

    for item in items:
        eid = item["normalized_id"]
        art_type = item["artifact_type"]
        item_dev_id = item.get("device_id") or "DEV-UNKNOWN"
        e_info = item.get("entity_info") or {}
        cnt = item.get("content") or {}
        loc = item.get("location_info") or {}
        related_eids = list(set(corr_partners_map.get(eid, [])))

        if art_type == "sms":
            addr = e_info.get("address") or e_info.get("sender_receiver") or "Unknown"
            body = cnt.get("body") or ""
            label = f"SMS ({addr}): {body[:25]}"
            entity_type = "SMS"
        elif art_type == "call":
            num = e_info.get("phone_number") or "Unknown"
            name = e_info.get("contact_name") or "Unknown"
            dur = cnt.get("duration_formatted") or "00:00"
            display_name = name if name != "Unknown" else num
            label = f"Call ({display_name}) {dur}"
            entity_type = "CALL"
        elif art_type == "gps":
            lat, lon = loc.get("latitude"), loc.get("longitude")
            label = f"GPS Fix ({lat}, {lon})"
            entity_type = "LOCATION"
        elif art_type == "web_history":
            url_val = e_info.get("url") or cnt.get("url") or ""
            title_val = cnt.get("title") or url_val
            label = f"Web Visit: {title_val[:30]}"
            entity_type = "WEB_ACTIVITY"
        elif art_type in ("file", "image", "video", "document"):
            fname = cnt.get("file_name") or e_info.get("file_name") or "File"
            label = f"File ({fname})"
            entity_type = "FILE"
        elif art_type == "application":
            pkg = cnt.get("package_name") or "Application"
            label = f"App ({pkg})"
            entity_type = "APPLICATION"
        else:
            label = f"{art_type.upper()} ({eid[:8]})"
            entity_type = art_type.upper()

        key = (entity_type, label)
        if key in nodes:
            label = f"{label} [{eid[-6:]}]"
            key = (entity_type, label)

        ev_node_id = _make_node_id(case_id, entity_type, label)
        node_props = {
            "entity": label,
            "entity_type": entity_type,
            "evidence_id": eid,
            "evidence_ids": [eid],
            "related_evidence": related_eids,
            "case_id": case_id,
            "device_id": item_dev_id,
            "timestamp": item.get("timestamp_utc") or item.get("original_timestamp") or "Not Available",
            "source": item.get("source_method") or item.get("source_ref"),
            "provenance": item.get("provenance") or {},
            "raw_payload_preview": cnt or e_info,
        }

        nodes[key] = {
            "node_id": ev_node_id,
            "case_id": case_id,
            "entity_type": entity_type,
            "label": label,
            "properties": json.dumps(node_props, ensure_ascii=False),
            "source_evidence_id": eid,
            "created_at": now,
        }
        ev_node_map[eid] = ev_node_id

        # Structural edge: Device -> Evidence Node
        rel_map = {
            "SMS": "ORIGINATED_FROM",
            "CALL": "ORIGINATED_FROM",
            "LOCATION": "RECORDED_AT",
            "WEB_ACTIVITY": "ACCESSED_URL",
            "FILE": "PRESERVED_FILE",
            "APPLICATION": "EXECUTED_PACKAGE",
        }
        rel = rel_map.get(entity_type, "ASSOCIATED_WITH")
        item_dev_id = item.get("device_id") or "DEV-UNKNOWN"
        item_dev_node_id = dev_node_ids.get(item_dev_id) or list(dev_node_ids.values())[0]
        e_id = _make_edge_id(case_id, item_dev_node_id, ev_node_id, rel)
        edges[e_id] = {
            "edge_id": e_id,
            "case_id": case_id,
            "source_node_id": item_dev_node_id,
            "target_node_id": ev_node_id,
            "relationship_label": rel,
            "correlation_id": None,
            "evidence_id": eid,
            "evidence_ids": json.dumps([eid]),
            "reason": f"Hardware artifact {eid} originated from device {item_dev_id}.",
            "supporting_attributes": json.dumps({"device_id": item_dev_id, "artifact_type": art_type}),
            "weight": 1.0,
            "properties": json.dumps({"timestamp": item.get("timestamp_utc"), "source": item.get("source_ref")}),
            "created_at": now,
        }

        # Sub-entities (Contact / Phone Number)
        if art_type in ("sms", "call"):
            num = e_info.get("phone_number") or e_info.get("address") or e_info.get("sender_receiver")
            name = e_info.get("contact_name")
            if num and num != "Unknown":
                p_label = f"Contact ({name if name and name != 'Unknown' else num})"
                p_key = ("PHONE_NUMBER", p_label)
                if p_key not in nodes:
                    p_node_id = _make_node_id(case_id, "PHONE_NUMBER", p_label)
                    nodes[p_key] = {
                        "node_id": p_node_id,
                        "case_id": case_id,
                        "entity_type": "PHONE_NUMBER",
                        "label": p_label,
                        "properties": json.dumps({
                            "entity": p_label,
                            "entity_type": "PHONE_NUMBER",
                            "phone_number": num,
                            "contact_name": name,
                            "evidence_ids": [eid],
                            "case_id": case_id,
                            "device_id": item_dev_id,
                            "timestamp": item.get("timestamp_utc"),
                            "source": "Contacts / Communication Database",
                            "provenance": {"identifier": num, "associated_evidence": eid},
                        }, ensure_ascii=False),
                        "source_evidence_id": eid,
                        "created_at": now,
                    }
                else:
                    p_node_id = nodes[p_key]["node_id"]

                e_id2 = _make_edge_id(case_id, ev_node_id, p_node_id, "COMMUNICATED_WITH")
                edges[e_id2] = {
                    "edge_id": e_id2,
                    "case_id": case_id,
                    "source_node_id": ev_node_id,
                    "target_node_id": p_node_id,
                    "relationship_label": "COMMUNICATED_WITH",
                    "correlation_id": None,
                    "evidence_id": eid,
                    "evidence_ids": json.dumps([eid]),
                    "reason": f"Direct communication recorded with contact identifier '{num}'.",
                    "supporting_attributes": json.dumps({"phone_number": num, "contact_name": name}),
                    "weight": 1.0,
                    "properties": json.dumps({"address": num}),
                    "created_at": now,
                }

    # Add edges derived from Module 2 Correlations
    for c in correlations:
        cid = c["correlation_id"]
        rel_type = c["relationship_type"]
        ev_ids = c.get("evidence_ids", [])
        reason = c.get("reason") or c.get("explanation") or "Factual correlation"
        supp_attrs = c.get("supporting_attributes") or c.get("matching_attributes") or {}

        if len(ev_ids) >= 2:
            n1 = ev_node_map.get(ev_ids[0])
            n2 = ev_node_map.get(ev_ids[1])
            if n1 and n2:
                e_id = _make_edge_id(case_id, n1, n2, rel_type)
                edges[e_id] = {
                    "edge_id": e_id,
                    "case_id": case_id,
                    "source_node_id": n1,
                    "target_node_id": n2,
                    "relationship_label": rel_type,
                    "correlation_id": cid,
                    "evidence_id": ev_ids[0],
                    "evidence_ids": json.dumps(ev_ids),
                    "reason": reason,
                    "supporting_attributes": json.dumps(supp_attrs, ensure_ascii=False),
                    "weight": c.get("correlation_strength", 1.0),
                    "properties": json.dumps(c.get("matching_attributes", {}), ensure_ascii=False),
                    "created_at": now,
                }

    # Persist nodes & edges into SQLite cleanly in batch
    now = utc_now()
    node_params = [
        (n["node_id"], n["case_id"], n["entity_type"], n["label"], n["properties"], n["source_evidence_id"], now)
        for n in list(nodes.values())[:250]
    ]
    edge_params = [
        (
            e["edge_id"], e["case_id"], e["source_node_id"], e["target_node_id"], e["relationship_label"],
            e["correlation_id"], e["evidence_id"], e["weight"], e["properties"], now,
            e.get("reason", ""), e.get("evidence_ids", "[]"), e.get("supporting_attributes", "{}"),
        )
        for e in list(edges.values())[:400]
    ]

    with connect() as connection:
        connection.execute("DELETE FROM graph_edges WHERE case_id = ?", (case_id,))
        connection.execute("DELETE FROM graph_nodes WHERE case_id = ?", (case_id,))
        if node_params:
            connection.executemany(
                """
                INSERT INTO graph_nodes (
                    node_id, case_id, entity_type, label, properties, source_evidence_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                node_params,
            )
        if edge_params:
            connection.executemany(
                """
                INSERT INTO graph_edges (
                    edge_id, case_id, source_node_id, target_node_id, relationship_label,
                    correlation_id, evidence_id, weight, properties, created_at,
                    reason, evidence_ids, supporting_attributes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                edge_params,
            )

    return {
        "case_id": case_id,
        "nodes_count": len(nodes),
        "edges_count": len(edges),
    }


def get_graph_data(case_id: str) -> dict:
    """Retrieve full graph node and edge objects for visualization and inspection."""
    nodes_rec = rows("SELECT * FROM graph_nodes WHERE case_id = ?", (case_id,))
    edges_rec = rows("SELECT * FROM graph_edges WHERE case_id = ?", (case_id,))

    nodes_list = []
    for r in nodes_rec:
        n = dict(r)
        try:
            n["properties"] = json.loads(n.get("properties") or "{}")
        except (json.JSONDecodeError, TypeError):
            n["properties"] = {}
        nodes_list.append(n)

    edges_list = []
    for r in edges_rec:
        e = dict(r)
        try:
            e["properties"] = json.loads(e.get("properties") or "{}")
        except (json.JSONDecodeError, TypeError):
            e["properties"] = {}
        try:
            e["evidence_ids"] = json.loads(e.get("evidence_ids") or "[]")
        except (json.JSONDecodeError, TypeError):
            e["evidence_ids"] = [e["evidence_id"]] if e.get("evidence_id") else []
        try:
            e["supporting_attributes"] = json.loads(e.get("supporting_attributes") or "{}")
        except (json.JSONDecodeError, TypeError):
            e["supporting_attributes"] = {}
        edges_list.append(e)

    return {
        "case_id": case_id,
        "nodes": nodes_list,
        "edges": edges_list,
    }


def trace_graph_path(case_id: str, source_node_id: str, target_node_id: str) -> dict:
    """Find the shortest path connecting two nodes in the Evidence Relationship Graph."""
    data = get_graph_data(case_id)
    nodes_by_id = {n["node_id"]: n for n in data["nodes"]}
    edges = data["edges"]

    if source_node_id not in nodes_by_id or target_node_id not in nodes_by_id:
        return {"found": False, "message": "Source or target node not found in graph.", "path": []}

    # Build adjacency list
    adj = {}
    edge_map = {}
    for e in edges:
        u, v = e["source_node_id"], e["target_node_id"]
        adj.setdefault(u, []).append(v)
        adj.setdefault(v, []).append(u)
        edge_map[(u, v)] = e
        edge_map[(v, u)] = e

    # BFS for shortest path
    queue = [[source_node_id]]
    visited = {source_node_id}

    while queue:
        path = queue.pop(0)
        curr = path[-1]
        if curr == target_node_id:
            steps = []
            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]
                edge_info = edge_map.get((u, v))
                rel = edge_info["relationship_label"] if edge_info else "CONNECTED_TO"
                reason = edge_info.get("reason") if edge_info else ""
                steps.append({
                    "from_node": nodes_by_id[u]["label"],
                    "from_id": u,
                    "relationship": rel,
                    "to_node": nodes_by_id[v]["label"],
                    "to_id": v,
                    "reason": reason,
                })
            return {
                "found": True,
                "length": len(path) - 1,
                "node_ids": path,
                "path": path,
                "steps": steps,
            }

        for neighbor in adj.get(curr, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(path + [neighbor])

    return {"found": False, "message": "No connecting relationship path found between the selected nodes.", "path": []}
