from __future__ import annotations

import socket

from .common import parse_hosts, run_cmd, tool_available


def resolve(hosts: list[str], *, dnsx_path: str = "dnsx", timeout: int = 10) -> tuple[dict[str, dict], list[str]]:
    logs: list[str] = []
    results: dict[str, dict] = {}
    if tool_available(dnsx_path):
        result = run_cmd([dnsx_path, "-silent", "-a", "-aaaa", "-cname"], input_text="\n".join(hosts) + "\n", timeout=timeout)
        logs.append(f"dnsx exit={result.exit_code}")
        if result.exit_code == 0:
            for host in parse_hosts(result.stdout):
                results.setdefault(host, {"host": host, "ips": []})
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
