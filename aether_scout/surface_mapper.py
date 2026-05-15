from __future__ import annotations

from hashlib import sha256
from typing import Any
from urllib import error, request
from urllib.parse import urljoin, urlparse

from .audit import RejectedCandidate, rejected_candidate
from .config import ScoutSettings
from .discovery import discover_assets_with_audit
from .models.asset import Asset
from .models.scope import ScopeConfig
from .models.surface import Surface
from .throttle import RateLimiter


AI_INDICATOR_PATHS = (
    "/api/chat",
    "/chat",
    "/assistant",
    "/copilot",
    "/ask",
    "/api/ask",
    "/api/ai",
    "/api/search",
    "/mcp",
    "/api/mcp",
    "/.well-known/ai-plugin.json",
    "/openapi.json",
)

KEYWORDS = {
    "rag": "rag_chat",
    "chat": "ai_chat",
    "assistant": "support_assistant",
    "copilot": "copilot",
    "helpdesk": "helpdesk_bot",
    "support": "support_assistant",
    "mcp": "mcp_endpoint",
    "openapi": "openapi_schema",
    "swagger": "openapi_schema",
    "graphql": "graphql_ai",
    "upload": "document_upload",
    "document": "document_upload",
}


def map_surfaces(scope: ScopeConfig, settings: ScoutSettings) -> tuple[list[Surface], list[str], list[RejectedCandidate]]:
    assets, logs, rejected = discover_assets_with_audit(scope, settings)
    surfaces, surface_rejected = map_surfaces_from_assets(scope, assets, settings)
    rejected.extend(surface_rejected)
    return surfaces, logs, rejected


def map_surfaces_from_assets(scope: ScopeConfig, assets: list[Asset], settings: ScoutSettings) -> tuple[list[Surface], list[RejectedCandidate]]:
    scope.validate_for_run()
    surfaces: list[Surface] = []
    rejected: list[RejectedCandidate] = []
    rate_limiter = RateLimiter(settings.requests_per_minute)

    for asset in assets:
        base_url = _asset_base_url(asset)
        for candidate in _metadata_candidates(asset, base_url):
            _accept_or_reject(scope, asset, candidate, surfaces, rejected)
        if base_url and not settings.passive_only:
            for candidate in _active_indicator_candidates(base_url, settings, rate_limiter):
                _accept_or_reject(scope, asset, candidate, surfaces, rejected)

    return _dedupe_surfaces(surfaces), rejected


def _metadata_candidates(asset: Asset, base_url: str | None) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for path in asset.interesting_paths:
        if base_url:
            candidates.append({"url": urljoin(base_url.rstrip("/") + "/", path.lstrip("/")), "indicators": [path], "source": "asset_path"})
    for hit in asset.metadata.get("mcp_candidates", []):
        if isinstance(hit, dict) and hit.get("url"):
            candidates.append({"url": str(hit["url"]), "indicators": [str(hit.get("path") or "mcp")], "source": "mcp_detector", "metadata": hit})
    for url in asset.metadata.get("network_hints", []):
        if isinstance(url, str):
            candidates.append({"url": url, "indicators": ["network_hint"], "source": "network_hint"})

    text_parts: list[str] = []
    for key in ("title",):
        value = getattr(asset, key, None)
        if value:
            text_parts.append(str(value))
    for key in ("page_text", "scripts", "openapi_tags"):
        value = asset.metadata.get(key)
        if isinstance(value, str):
            text_parts.append(value)
        if isinstance(value, list):
            text_parts.extend(str(item) for item in value)
    if base_url and _surface_type_for_text(" ".join(text_parts)) != "unknown_ai_surface":
        candidates.append({"url": base_url, "indicators": text_parts[:10], "source": "page_metadata"})
    return candidates


def _active_indicator_candidates(base_url: str, settings: ScoutSettings, rate_limiter: RateLimiter) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for path in AI_INDICATOR_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        status, content_type = _head_or_get(url, user_agent=settings.user_agent, timeout=settings.timeout_seconds, rate_limiter=rate_limiter)
        if status and status < 500 and status not in {404, 405}:
            candidates.append({
                "url": url,
                "indicators": [path],
                "source": "ai_path_indicator",
                "metadata": {"status_code": status, "content_type": content_type},
            })
    return candidates


def _accept_or_reject(
    scope: ScopeConfig,
    asset: Asset,
    candidate: dict[str, Any],
    surfaces: list[Surface],
    rejected: list[RejectedCandidate],
) -> None:
    url = str(candidate.get("url") or "")
    if not url or not scope.is_url_allowed(url):
        rejected.append(rejected_candidate(
            url,
            str(candidate.get("source") or "surface_mapper"),
            "url_out_of_scope",
            candidate_type="surface",
            scope_context={"program_id": scope.program_id},
            confidence=0.0,
        ))
        return
    indicators = [str(item) for item in candidate.get("indicators", []) if str(item)]
    surface_type = _surface_type_for_text(" ".join([url, *indicators]))
    if surface_type == "unknown_ai_surface":
        return
    surfaces.append(Surface(
        surface_id=_stable_id("surface", scope.program_id, url, surface_type),
        program_id=scope.program_id,
        asset_id=_asset_id(asset),
        surface_type=surface_type,
        url=url,
        method="GET",
        confidence=_confidence(surface_type, candidate),
        evidence_metadata={k: v for k, v in (candidate.get("metadata") or {}).items() if v not in (None, [], {})},
        indicators=indicators,
    ))


def _head_or_get(url: str, *, user_agent: str, timeout: int, rate_limiter: RateLimiter) -> tuple[int | None, str | None]:
    for method in ("HEAD", "GET"):
        rate_limiter.wait()
        req = request.Request(url, headers={"user-agent": user_agent}, method=method)
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                return int(resp.status), resp.headers.get("content-type")
        except error.HTTPError as exc:
            if exc.code == 405 and method == "HEAD":
                continue
            if exc.code in {401, 403, 404, 405}:
                return int(exc.code), exc.headers.get("content-type")
        except (OSError, error.URLError):
            return None, None
    return None, None


def _asset_base_url(asset: Asset) -> str | None:
    if asset.url:
        parsed = urlparse(asset.url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    if asset.host:
        scheme = asset.scheme or "https"
        port = f":{asset.port}" if asset.port else ""
        return f"{scheme}://{asset.host}{port}"
    return None


def _surface_type_for_text(text: str) -> str:
    lower = text.lower()
    if "websocket" in lower or lower.startswith("ws://") or lower.startswith("wss://"):
        return "websocket_chat"
    for keyword, surface_type in KEYWORDS.items():
        if keyword in lower:
            return surface_type
    if "ai" in lower:
        return "ai_chat"
    return "unknown_ai_surface"


def _confidence(surface_type: str, candidate: dict[str, Any]) -> float:
    if surface_type in {"mcp_endpoint", "openapi_schema"}:
        return 0.86
    if candidate.get("source") == "ai_path_indicator":
        return 0.78
    if surface_type == "unknown_ai_surface":
        return 0.45
    return 0.72


def _asset_id(asset: Asset) -> str:
    return _stable_id("asset", asset.program_id, asset.url or asset.host or asset.ip or "unknown")


def _stable_id(*parts: str) -> str:
    return sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _dedupe_surfaces(surfaces: list[Surface]) -> list[Surface]:
    out: dict[str, Surface] = {}
    for surface in surfaces:
        current = out.get(surface.surface_id)
        if current is None or surface.confidence > current.confidence:
            out[surface.surface_id] = surface
    return list(out.values())
