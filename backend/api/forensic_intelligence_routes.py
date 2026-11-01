"""API Routes for ForensicX Modules 1 through 5."""

import json

from fastapi import APIRouter, HTTPException, Query, Request

from backend.config import IDENTIFIER_PATTERN
from backend.database.database import row, rows
from backend.services.auth_service import check_case_access, get_session_user
from backend.services.evidence_correlation_engine import get_evidence_correlations, run_correlation_engine
from backend.services.evidence_graph_engine import build_evidence_graph, get_graph_data, trace_graph_path
from backend.services.evidence_normalization_engine import get_normalized_evidence, normalize_case
from backend.services.evidence_reliability_engine import get_reliability_scores, run_reliability_engine
from backend.services.incident_timeline_engine import build_incident_timeline, generate_evidence_linked_report, get_incident_timeline
from backend.api.auth_routes import SESSION_COOKIE

router = APIRouter(tags=["forensic_intelligence"])

ALLOWED_SOURCE_TABLES = {
    "sms_messages", "call_logs", "contacts", "applications",
    "files", "gps_locations", "browser_history", "media_files",
    "evidence_items", "evidence",
}


def _caller_user(request: Request) -> dict | None:
    session_id = request.cookies.get(SESSION_COOKIE, "")
    return get_session_user(session_id)



@router.post("/api/intelligence/process/{case_id}")
def process_full_intelligence(case_id: str, request: Request) -> dict:
    """Run full 5-module forensic intelligence pipeline for a case."""
    user = _caller_user(request)
    check_case_access(case_id, user)

    n_res = normalize_case(case_id)
    c_res = run_correlation_engine(case_id)
    r_res = run_reliability_engine(case_id)
    g_res = build_evidence_graph(case_id)
    t_res = build_incident_timeline(case_id)

    return {
        "status": "success",
        "case_id": case_id,
        "normalization": n_res,
        "correlations": c_res,
        "reliability": r_res,
        "graph": g_res,
        "timeline": t_res,
    }


# ── Module 1: Evidence Normalization Endpoints ─────────────────────────────────
@router.post("/api/normalization/run/{case_id}")
def run_normalization_endpoint(case_id: str, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    return normalize_case(case_id)


@router.get("/api/normalization/{case_id}")
def get_normalization_endpoint(
    case_id: str,
    request: Request,
    artifact_type: str | None = Query(None),
    status: str | None = Query(None),
    query: str | None = Query(None),
) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)

    items = get_normalized_evidence(case_id, artifact_type=artifact_type, status=status, query=query)
    all_items = get_normalized_evidence(case_id)
    if not all_items:
        normalize_case(case_id)
        items = get_normalized_evidence(case_id, artifact_type=artifact_type, status=status, query=query)
        all_items = get_normalized_evidence(case_id)

    counts = {"total": len(all_items), "success": 0, "partial": 0, "failed": 0, "unsupported": 0}
    by_type = {}

    for it in all_items:
        st = it.get("normalization_status", "SUCCESS")
        counts[st.lower()] = counts.get(st.lower(), 0) + 1
        art = it.get("artifact_type", "unknown")
        by_type[art] = by_type.get(art, 0) + 1

    return {
        "case_id": case_id,
        "summary": counts,
        "by_type": by_type,
        "count": len(items),
        "items": items,
    }


@router.get("/api/normalization/{case_id}/detail/{normalized_id}")
def get_normalized_item_detail(case_id: str, normalized_id: str, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    rec = row("SELECT * FROM normalized_evidence WHERE case_id = ? AND normalized_id = ?", (case_id, normalized_id))
    if not rec:
        raise HTTPException(status_code=404, detail="Normalized evidence item not found.")

    item = dict(rec)
    for k in ("entity_info", "content", "location_info", "provenance"):
        try:
            item[k] = json.loads(item.get(k) or "{}")
        except Exception:
            pass

    # Fetch corresponding raw evidence record if source_ref points to a DB table
    source_ref = item.get("source_ref", "")
    raw_data = None
    if "#" in source_ref:
        tbl, row_id = source_ref.split("#", 1)
        if tbl in ALLOWED_SOURCE_TABLES and row_id.isdigit():
            raw_rec = row(f"SELECT * FROM {tbl} WHERE id = ?", (int(row_id),))
            if raw_rec:
                raw_data = dict(raw_rec)

    # Fetch associated reliability score
    score_rec = row("SELECT * FROM evidence_reliability_scores WHERE case_id = ? AND evidence_id = ?", (case_id, normalized_id))
    score_data = dict(score_rec) if score_rec else None
    if score_data and "factors_affecting_score" in score_data:
        try:
            score_data["factors_affecting_score"] = json.loads(score_data["factors_affecting_score"])
        except Exception:
            pass

    return {
        "case_id": case_id,
        "normalized_item": item,
        "raw_record": raw_data,
        "reliability_score": score_data,
    }


# ── Module 2: Cross-Source Correlations Endpoints ──────────────────────────────
@router.post("/api/correlations/run/{case_id}")
def run_correlations_endpoint(case_id: str, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    return run_correlation_engine(case_id)


@router.get("/api/correlations/{case_id}")
def get_correlations_endpoint(case_id: str, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    corrs = get_evidence_correlations(case_id)
    if not corrs:
        run_correlation_engine(case_id)
        corrs = get_evidence_correlations(case_id)
    return {"case_id": case_id, "count": len(corrs), "correlations": corrs}


# ── Module 3: Reliability & Provenance Scoring Endpoints ───────────────────────
@router.post("/api/reliability/run/{case_id}")
def run_reliability_endpoint(case_id: str, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    return run_reliability_engine(case_id)


@router.get("/api/reliability/{case_id}")
def get_reliability_endpoint(case_id: str, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    scores = get_reliability_scores(case_id)
    if not scores:
        run_reliability_engine(case_id)
        scores = get_reliability_scores(case_id)
    return {"case_id": case_id, "count": len(scores), "scores": scores}


# ── Module 4: Relationship Graph Endpoints ────────────────────────────────────
@router.post("/api/graph/run/{case_id}")
def run_graph_endpoint(case_id: str, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    return build_evidence_graph(case_id)


@router.get("/api/graph/{case_id}")
def get_graph_endpoint(case_id: str, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    
    graph_data = get_graph_data(case_id)
    if not graph_data.get("nodes"):
        build_evidence_graph(case_id)
        graph_data = get_graph_data(case_id)
    return graph_data


@router.get("/api/graph/{case_id}/trace")
def trace_graph_endpoint(case_id: str, request: Request, source: str = Query(...), target: str = Query(...)) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    return trace_graph_path(case_id, source, target)


# ── Module 5: Incident Timeline & AI Report Endpoints ─────────────────────────
@router.post("/api/timeline/run/{case_id}")
def run_timeline_endpoint(case_id: str, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    return build_incident_timeline(case_id)


@router.get("/api/timeline/{case_id}")
def get_timeline_endpoint(case_id: str, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    events = get_incident_timeline(case_id)
    if not events:
        build_incident_timeline(case_id)
        events = get_incident_timeline(case_id)
    return {"case_id": case_id, "count": len(events), "timeline": events}


@router.get("/api/intelligence/report-payload/{case_id}")
def get_intelligence_report_payload(case_id: str, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    return generate_evidence_linked_report(case_id)


@router.get("/api/forensic-intelligence/dashboard-stats/{case_id}")
def get_dashboard_intelligence_stats(case_id: str, request: Request) -> dict:
    user = _caller_user(request)
    check_case_access(case_id, user)
    norm_cnt = row("SELECT COUNT(*) as c FROM normalized_evidence WHERE case_id = ?", (case_id,))
    corr_cnt = row("SELECT COUNT(*) as c FROM evidence_correlations WHERE case_id = ?", (case_id,))
    rel_cnt = row("SELECT COUNT(*) as c FROM evidence_reliability_scores WHERE case_id = ?", (case_id,))
    node_cnt = row("SELECT COUNT(*) as c FROM graph_nodes WHERE case_id = ?", (case_id,))
    tl_cnt = row("SELECT COUNT(*) as c FROM incident_timeline WHERE case_id = ?", (case_id,))
    ai_cnt = row("SELECT COUNT(*) as c FROM ai_findings WHERE case_id = ?", (case_id,))
    if not ai_cnt or ai_cnt["c"] == 0:
        ai_cnt = row("SELECT COUNT(*) as c FROM incident_timeline WHERE case_id = ? AND suspicious_flag = 1", (case_id,))
    return {
        "case_id": case_id,
        "normalized_evidence": norm_cnt["c"] if norm_cnt else 0,
        "correlations": corr_cnt["c"] if corr_cnt else 0,
        "reliability_assessments": rel_cnt["c"] if rel_cnt else 0,
        "graph_entities": node_cnt["c"] if node_cnt else 0,
        "timeline_events": tl_cnt["c"] if tl_cnt else 0,
        "ai_findings": ai_cnt["c"] if ai_cnt else 0,
    }


@router.get("/api/forensic-intelligence/evidence-inspect/{evidence_id}")
def inspect_evidence_item_direct(evidence_id: str, request: Request) -> dict:
    """Lookup an evidence item by its normalized Evidence ID with authorization verification."""
    if not IDENTIFIER_PATTERN.match(evidence_id):
        raise HTTPException(status_code=400, detail="Invalid evidence identifier format.")

    rec = row("SELECT * FROM normalized_evidence WHERE normalized_id = ?", (evidence_id,))
    if not rec:
        raise HTTPException(status_code=404, detail=f"Evidence ID '{evidence_id}' not found.")

    user = _caller_user(request)
    check_case_access(rec["case_id"], user)

    item = dict(rec)
    for k in ("entity_info", "content", "location_info", "provenance"):
        try:
            item[k] = json.loads(item.get(k) or "{}")
        except Exception:
            pass

    # Fetch raw record if available from whitelisted table
    raw_data = None
    source_ref = item.get("source_ref", "")
    if "#" in source_ref:
        tbl, row_id = source_ref.split("#", 1)
        if tbl in ALLOWED_SOURCE_TABLES and row_id.isdigit():
            raw_rec = row(f"SELECT * FROM {tbl} WHERE id = ?", (int(row_id),))
            if raw_rec:
                raw_data = dict(raw_rec)

    # Fetch reliability score
    score_rec = row("SELECT * FROM evidence_reliability_scores WHERE evidence_id = ?", (evidence_id,))
    score_data = dict(score_rec) if score_rec else None
    if score_data:
        for sk in ("factors_affecting_score", "factors_list", "warnings", "missing_information"):
            try:
                score_data[sk] = json.loads(score_data.get(sk) or ("[]" if "s" in sk or "list" in sk else "{}"))
            except Exception:
                pass

    # Fetch correlated evidence IDs
    corrs = rows("SELECT * FROM evidence_correlations WHERE case_id = ? AND (evidence_ids LIKE ? OR evidence_id_a = ? OR evidence_id_b = ?)", 
                 (item["case_id"], f"%{evidence_id}%", evidence_id, evidence_id))
    correlated_eids = set()
    for c in corrs:
        try:
            for eid in json.loads(c.get("evidence_ids") or "[]"):
                if eid != evidence_id:
                    correlated_eids.add(eid)
        except Exception:
            pass

    return {
        "evidence_id": evidence_id,
        "case_id": item["case_id"],
        "device_id": item["device_id"],
        "normalized_item": item,
        "raw_record": raw_data,
        "reliability": score_data,
        "correlated_evidence_ids": list(correlated_eids),
    }


