from __future__ import annotations

from urllib import request, error
from urllib.parse import urljoin, urlparse


MCP_CANDIDATE_PATHS = (
    "/.well-known/ai-plugin.json",
    "/.well-known/openapi.json",
    "/mcp",
    "/api/mcp",
    "/tools",
    "/openapi.json",
    "/swagger.json",
)


def detect(base_url: str, *, user_agent: str, timeout: int = 10) -> list[dict]:
    found: list[dict] = []
    for path in MCP_CANDIDATE_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        status, content_type = _head_or_get(url, user_agent=user_agent, timeout=timeout)
        if status and status < 500:
            found.append({"url": url, "path": urlparse(url).path, "status_code": status, "content_type": content_type})
    return found


def _head_or_get(url: str, *, user_agent: str, timeout: int) -> tuple[int | None, str | None]:
    for method in ("HEAD", "GET"):
        req = request.Request(url, headers={"user-agent": user_agent}, method=method)
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                return int(resp.status), resp.headers.get("content-type")
        except error.HTTPError as exc:
            if exc.code in {401, 403, 404, 405}:
                return int(exc.code), exc.headers.get("content-type")
        except (OSError, error.URLError):
            return None, None
    return None, None
