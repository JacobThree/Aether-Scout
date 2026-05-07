from __future__ import annotations

from .robots import discover as discover_robots_and_sitemaps


def discover(base_url: str, *, user_agent: str, timeout: int = 10, rate_limiter=None) -> list[str]:
    return discover_robots_and_sitemaps(base_url, user_agent=user_agent, timeout=timeout, rate_limiter=rate_limiter)
