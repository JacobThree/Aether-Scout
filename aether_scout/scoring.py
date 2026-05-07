from __future__ import annotations

from typing import Any


FATAL_BLOCKERS = {"out_of_scope", "policy_blocked", "no_authorization"}


def score_surface(surface: dict[str, Any]) -> dict[str, Any]:
    indicators = [str(item).lower() for item in surface.get("indicators", [])]
    evidence = surface.get("evidence_metadata") if isinstance(surface.get("evidence_metadata"), dict) else {}
    surface_type = str(surface.get("surface_type") or "")
    policy = str(evidence.get("program_policy") or "unknown").lower()
    blockers: list[str] = []
    score = 0.0

    if surface.get("scope_status") not in (None, "accepted"):
        blockers.append("out_of_scope")
    if policy == "blocked":
        blockers.append("policy_blocked")
    if any(blocker in blockers for blocker in FATAL_BLOCKERS):
        score = 0.0
    else:
        if surface_type in {"rag_chat", "ai_chat", "graphql_ai", "websocket_chat"}:
            score += 0.25
        if surface_type in {"document_upload", "openapi_schema"}:
            score += 0.18
        if _has_any(indicators, ("chat", "assistant", "copilot", "ask", "ai")):
            score += 0.18
        if _has_any(indicators, ("rag", "source", "citation", "document", "search")):
            score += 0.18
        if _has_any(indicators, ("tenant", "workspace", "team", "org")):
            score += 0.12
        if evidence.get("auth_required") is True:
            score += 0.06
        if evidence.get("api_schema_confidence"):
            score += min(float(evidence["api_schema_confidence"]), 1.0) * 0.1
        if policy == "allowed":
            score += 0.08
        if not indicators and surface_type == "unknown_ai_surface":
            blockers.append("weak_indicators")

    score = max(0.0, min(round(score, 2), 1.0))
    out = dict(surface)
    out["viability_score"] = score
    out["blockers"] = blockers
    out["recommended_next_step"] = _next_step(score, blockers)
    out["evidence_metadata"] = evidence
    return out


def score_surfaces(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [score_surface(row) for row in rows]


def _has_any(values: list[str], needles: tuple[str, ...]) -> bool:
    return any(needle in value for value in values for needle in needles)


def _next_step(score: float, blockers: list[str]) -> str:
    if any(blocker in blockers for blocker in FATAL_BLOCKERS):
        return "do_not_test"
    if score >= 0.7:
        return "manual_review_high_priority"
    if score >= 0.35:
        return "manual_review"
    return "collect_more_metadata"
