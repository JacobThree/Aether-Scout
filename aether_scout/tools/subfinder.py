from __future__ import annotations

from .common import parse_hosts, run_cmd, tool_available


def discover(root_domains: list[str], *, subfinder_path: str = "subfinder", timeout: int = 10) -> tuple[list[str], list[str]]:
    hosts: list[str] = []
    logs: list[str] = []
    if not tool_available(subfinder_path):
        return [], [f"subfinder unavailable: {subfinder_path}"]
    for domain in root_domains:
        result = run_cmd([subfinder_path, "-silent", "-d", domain], timeout=timeout)
        logs.append(f"subfinder {domain} exit={result.exit_code}")
        if result.exit_code == 0:
            hosts.extend(parse_hosts(result.stdout))
    return _dedupe(hosts), logs


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
