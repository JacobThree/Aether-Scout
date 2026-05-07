from __future__ import annotations

from urllib import request, error
from urllib.parse import urljoin, urlparse


def discover(base_url: str, *, user_agent: str, timeout: int = 10) -> list[str]:
    paths: list[str] = []
    robots = _fetch(urljoin(base_url.rstrip("/") + "/", "robots.txt"), user_agent=user_agent, timeout=timeout)
    if robots:
        for line in robots.splitlines():
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key in {"allow", "disallow"} and value.startswith("/") and value != "/":
                paths.append(value)
            if key == "sitemap" and value.startswith("http"):
                paths.extend(_sitemap_paths(value, user_agent=user_agent, timeout=timeout))
    paths.extend(_sitemap_paths(urljoin(base_url.rstrip("/") + "/", "sitemap.xml"), user_agent=user_agent, timeout=timeout))
    return _dedupe(paths)[:50]


def _sitemap_paths(url: str, *, user_agent: str, timeout: int) -> list[str]:
    body = _fetch(url, user_agent=user_agent, timeout=timeout)
    if not body:
        return []
    paths: list[str] = []
    for part in body.split("<loc>")[1:]:
        loc = part.split("</loc>", 1)[0].strip()
        parsed = urlparse(loc)
        if parsed.path:
            paths.append(parsed.path)
    return paths


def _fetch(url: str, *, user_agent: str, timeout: int) -> str:
    req = request.Request(url, headers={"user-agent": user_agent})
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            if int(resp.status) >= 400:
                return ""
            return resp.read(512_000).decode("utf-8", errors="ignore")
    except (OSError, error.URLError):
        return ""


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
