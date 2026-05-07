from __future__ import annotations

from urllib.parse import urlparse

from .asset_builder import from_http_row, host_asset
from .config import ScoutSettings
from .dedupe import dedupe_assets
from .models.asset import Asset
from .models.scope import ScopeConfig
from .throttle import RateLimiter
from .tools import dnsx, httpx, mcp_detector, robots, subfinder


def discover_assets(scope: ScopeConfig, settings: ScoutSettings) -> tuple[list[Asset], list[str]]:
    scope.validate_for_run()
    logs: list[str] = []
    root_domains = scope.root_domains()
    candidate_hosts = list(root_domains)

    if settings.passive_only:
        assets = [host_asset(scope.program_id, host, ["scope_seed"]) for host in _allowed_hosts(candidate_hosts, scope)]
        return dedupe_assets(assets), ["passive_only=true; skipped DNS, HTTP, robots, sitemap, and MCP probes"]

    if not settings.passive_only:
        discovered, sub_logs = subfinder.discover(root_domains, subfinder_path=settings.subfinder_path, timeout=settings.timeout_seconds)
        logs.extend(sub_logs)
        candidate_hosts.extend(discovered)

    candidate_hosts = _allowed_hosts(candidate_hosts, scope)
    dns_results, dns_logs = dnsx.resolve(candidate_hosts, dnsx_path=settings.dnsx_path, timeout=settings.timeout_seconds)
    logs.extend(dns_logs)

    assets: list[Asset] = []
    for host in candidate_hosts:
        ips = dns_results.get(host, {}).get("ips", [])
        allowed_ips = [ip for ip in ips if scope.is_resolved_ip_allowed(ip)]
        if ips and not allowed_ips:
            logs.append(f"rejected host={host} reason=resolved_ip_out_of_scope")
            continue
        assets.append(host_asset(scope.program_id, host, ["scope_seed" if host in root_domains else "subfinder", "dnsx"], ip=allowed_ips[0] if allowed_ips else None))

    rate_limiter = RateLimiter(settings.requests_per_minute)
    http_rows, http_logs = httpx.probe(
        candidate_hosts,
        httpx_path=settings.httpx_path,
        timeout=settings.timeout_seconds,
        rate_limiter=rate_limiter,
    )
    logs.extend(http_logs)
    for row in http_rows:
        url = str(row.get("url") or "")
        host = row.get("host") or urlparse(url).hostname
        if not host or not scope.is_url_allowed(url):
            continue
        if not scope.is_resolved_ip_allowed(dns_results.get(host, {}).get("ips", [None])[0]):
            logs.append(f"rejected url={url} reason=resolved_ip_out_of_scope")
            continue
        asset = from_http_row(scope.program_id, row, ["httpx"])
        paths = robots.discover(url, user_agent=settings.user_agent, timeout=settings.timeout_seconds, rate_limiter=rate_limiter)
        if paths:
            asset.interesting_paths.extend(paths)
            asset.discovery_methods.append("robots_sitemap")
            asset.confidence = max(asset.confidence, 0.78)
        mcp_hits = mcp_detector.detect(url, user_agent=settings.user_agent, timeout=settings.timeout_seconds, rate_limiter=rate_limiter)
        if mcp_hits:
            asset.interesting_paths.extend([hit["path"] for hit in mcp_hits])
            asset.discovery_methods.append("mcp_detector")
            asset.metadata["mcp_candidates"] = mcp_hits
            asset.confidence = max(asset.confidence, 0.82)
        assets.append(asset)

    return dedupe_assets(assets), logs


def _allowed_hosts(hosts: list[str], scope: ScopeConfig) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        normalized = (host or "").lower().rstrip(".")
        if normalized and normalized not in seen and scope.is_host_allowed(normalized):
            seen.add(normalized)
            out.append(normalized)
    return out
