from __future__ import annotations

from urllib.parse import urlparse

from .common import iter_json_lines, parse_urls, run_cmd, tool_available


def probe(hosts: list[str], *, httpx_path: str = "httpx", timeout: int = 10, rate_limiter=None) -> tuple[list[dict], list[str]]:
    logs: list[str] = []
    if not hosts:
        return [], logs
    if not tool_available(httpx_path):
        return _fallback_urls(hosts), [f"httpx unavailable: {httpx_path}; emitted conservative https candidates"]
    if rate_limiter is not None:
        rate_limiter.wait()
    cmd = [
        httpx_path,
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
        "-content-type",
        "-follow-redirects",
    ]
    result = run_cmd(cmd, input_text="\n".join(hosts) + "\n", timeout=timeout)
    logs.append(f"httpx exit={result.exit_code}")
    if result.exit_code != 0:
        return [], logs
    rows = [_row_from_json(item) for item in iter_json_lines(result.stdout)]
    rows = [row for row in rows if row.get("url")]
    if rows:
        return rows, logs
    return [{"url": url, "host": urlparse(url).hostname, "scheme": urlparse(url).scheme} for url in parse_urls(result.stdout)], logs


def _row_from_json(item: dict) -> dict:
    url = str(item.get("url") or item.get("input") or "")
    parsed = urlparse(url)
    technologies = item.get("tech") or item.get("technologies") or []
    if isinstance(technologies, str):
        technologies = [technologies]
    return {
        "url": url,
        "host": parsed.hostname,
        "scheme": parsed.scheme or None,
        "port": parsed.port,
        "status_code": _int(item.get("status_code")),
        "title": item.get("title"),
        "technologies": sorted({str(t).lower() for t in technologies if str(t).strip()}),
        "metadata": {
            "server": item.get("webserver") or item.get("server"),
            "content_type": item.get("content_type"),
            "redirects_to": item.get("final_url"),
        },
    }


def _fallback_urls(hosts: list[str]) -> list[dict]:
    return [{"url": f"https://{host}", "host": host, "scheme": "https", "confidence": 0.35} for host in hosts]


def _int(value) -> int | None:
    if value is None or value == "":
        return None
    return int(value)
