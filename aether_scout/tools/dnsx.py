from __future__ import annotations

import socket

from .common import iter_json_lines, parse_hosts, run_cmd, tool_available


def resolve(hosts: list[str], *, dnsx_path: str = "dnsx", timeout: int = 10) -> tuple[dict[str, dict], list[str]]:
    logs: list[str] = []
    results: dict[str, dict] = {}
    if tool_available(dnsx_path):
        result = run_cmd([dnsx_path, "-silent", "-a", "-aaaa", "-cname"], input_text="\n".join(hosts) + "\n", timeout=timeout)
        logs.append(f"dnsx exit={result.exit_code}")
        if result.exit_code == 0:
            results.update(_parse_dnsx_output(result.stdout))
    else:
        logs.append(f"dnsx unavailable: {dnsx_path}; using socket resolver")
        for host in hosts:
            try:
                infos = socket.getaddrinfo(host, None)
            except OSError:
                continue
            ips = sorted({item[4][0] for item in infos})
            results[host] = {"host": host, "ips": ips}
    return results, logs


def _parse_dnsx_output(output: str) -> dict[str, dict]:
    parsed: dict[str, dict] = {}
    json_rows = list(iter_json_lines(output))
    if json_rows:
        for row in json_rows:
            host = str(row.get("host") or row.get("input") or "").lower().rstrip(".")
            if not host:
                continue
            ips = _values(row.get("a")) + _values(row.get("aaaa"))
            cname = _values(row.get("cname"))
            parsed[host] = {"host": host, "ips": sorted(set(ips)), "cname": cname}
        return parsed

    for line in output.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        host = parse_hosts(tokens[0])[0] if parse_hosts(tokens[0]) else ""
        if not host:
            continue
        ips = [token.strip("[],") for token in tokens[1:] if _is_ip(token.strip("[],"))]
        cnames = [token.strip("[],") for token in tokens[1:] if token.strip("[],").endswith(".")]
        parsed[host] = {"host": host, "ips": sorted(set(ips)), "cname": cnames}
    return parsed


def _values(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _is_ip(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except OSError:
            return False
