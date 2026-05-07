from __future__ import annotations

from urllib.parse import urlparse

from .common import iter_json_lines, parse_urls, run_cmd, tool_available


def probe(
    hosts: list[str],
    *,
    httpx_path: str = "httpx",
    timeout: int = 10,
    rate_limiter=None,
    max_concurrent_probes: int = 5,
) -> tuple[list[dict], list[str]]:
    logs: list[str] = []
    if not hosts:
        return [], logs
    if not tool_available(httpx_path):
        return _fallback_urls(hosts), [f"httpx unavailable: {httpx_path}; emitted conservative https candidates"]
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
        "-threads",
        str(max(1, max_concurrent_probes)),
    ]
    rows: list[dict] = []
    for host in hosts:
        if rate_limiter is not None:
            rate_limiter.wait()
        result = run_cmd(cmd, input_text=f"{host}\n", timeout=timeout)
        logs.append(f"httpx host={host} exit={result.exit_code}")
        if result.exit_code != 0:
            continue
        parsed_rows = [_row_from_json(item) for item in iter_json_lines(result.stdout)]
        parsed_rows = [row for row in parsed_rows if row.get("url")]
        if parsed_rows:
            rows.extend(parsed_rows)
            continue
        rows.extend({"url": url, "host": urlparse(url).hostname, "scheme": urlparse(url).scheme} for url in parse_urls(result.stdout))
    return rows, logs


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
