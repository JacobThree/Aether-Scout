from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from ..asset_builder import from_http_row, host_asset
from ..audit import RejectedCandidate, rejected_candidate
from ..models.asset import Asset
from ..models.scope import ScopeConfig
from ..models.surface import Surface
from ..surface_mapper import _asset_id, _stable_id


@dataclass(frozen=True, slots=True)
class Adapter:
    adapter_name: str
    supported_input_format: str
    output_type: str
    safety_mode: str
    loader: Callable[[Path, ScopeConfig], tuple[list[dict[str, Any]], list[RejectedCandidate]]]

    def to_dict(self) -> dict[str, str]:
        return {
            "adapter_name": self.adapter_name,
            "supported_input_format": self.supported_input_format,
            "output_type": self.output_type,
            "safety_mode": self.safety_mode,
        }


def list_adapters() -> list[dict[str, str]]:
    return [adapter.to_dict() for adapter in ADAPTERS.values()]


def import_with_adapter(adapter_name: str, input_path: str | Path, scope: ScopeConfig) -> tuple[str, list[dict[str, Any]], list[RejectedCandidate]]:
    scope.validate_for_run()
    adapter = ADAPTERS.get(adapter_name)
    if adapter is None:
        raise ValueError(f"unknown adapter: {adapter_name}")
    rows, rejected = adapter.loader(Path(input_path), scope)
    return adapter.output_type, rows, rejected


def _httpx_jsonl(path: Path, scope: ScopeConfig) -> tuple[list[dict[str, Any]], list[RejectedCandidate]]:
    assets: list[Asset] = []
    rejected: list[RejectedCandidate] = []
    for row in _read_jsonl(path, rejected, "httpx"):
        url = str(row.get("url") or row.get("input") or "")
        if not url or not scope.is_url_allowed(url):
            rejected.append(_reject(url or str(row), "httpx", "url_out_of_scope", "asset"))
            continue
        assets.append(from_http_row(scope.program_id, row | {"url": url}, ["adapter:httpx"]))
    return [asset.to_dict() for asset in assets], rejected


def _subfinder_text(path: Path, scope: ScopeConfig) -> tuple[list[dict[str, Any]], list[RejectedCandidate]]:
    assets: list[Asset] = []
    rejected: list[RejectedCandidate] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        host = line.strip().lower().rstrip(".")
        if not host or host in seen:
            continue
        seen.add(host)
        if not scope.is_host_allowed(host):
            rejected.append(_reject(host, "subfinder", "host_out_of_scope", "asset"))
            continue
        assets.append(host_asset(scope.program_id, host, ["adapter:subfinder"]))
    return [asset.to_dict() for asset in assets], rejected


def _url_list(path: Path, scope: ScopeConfig) -> tuple[list[dict[str, Any]], list[RejectedCandidate]]:
    assets: list[Asset] = []
    rejected: list[RejectedCandidate] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        url = line.strip()
        if not url:
            continue
        if not scope.is_url_allowed(url):
            rejected.append(_reject(url, "url_list", "url_out_of_scope", "asset"))
            continue
        parsed = urlparse(url)
        assets.append(Asset(program_id=scope.program_id, url=url, host=parsed.hostname, scheme=parsed.scheme, port=parsed.port, discovery_methods=["adapter:url-list"], confidence=0.55))
    return [asset.to_dict() for asset in assets], rejected


def _openapi_json(path: Path, scope: ScopeConfig) -> tuple[list[dict[str, Any]], list[RejectedCandidate]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    servers = data.get("servers") if isinstance(data, dict) else []
    paths = data.get("paths") if isinstance(data, dict) else {}
    rows: list[dict[str, Any]] = []
    rejected: list[RejectedCandidate] = []
    for server in servers if isinstance(servers, list) else []:
        base_url = str(server.get("url") if isinstance(server, dict) else "")
        if not base_url:
            continue
        for api_path, methods in (paths.items() if isinstance(paths, dict) else []):
            url = base_url.rstrip("/") + "/" + str(api_path).lstrip("/")
            if not scope.is_url_allowed(url):
                rejected.append(_reject(url, "openapi", "url_out_of_scope", "surface"))
                continue
            method = next(iter(methods.keys()), "GET").upper() if isinstance(methods, dict) and methods else "GET"
            asset = Asset(program_id=scope.program_id, url=base_url, host=urlparse(base_url).hostname)
            rows.append(Surface(
                surface_id=_stable_id("surface", scope.program_id, url, "openapi_schema"),
                program_id=scope.program_id,
                asset_id=_asset_id(asset),
                surface_type="openapi_schema",
                url=url,
                method=method,
                confidence=0.82,
                indicators=["openapi"],
                evidence_metadata={"source": "adapter:openapi"},
            ).to_dict())
    return rows, rejected


def _har_json(path: Path, scope: ScopeConfig) -> tuple[list[dict[str, Any]], list[RejectedCandidate]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", []) if isinstance(data, dict) else []
    temp = path.with_suffix(".urls")
    urls = []
    for entry in entries if isinstance(entries, list) else []:
        request_data = entry.get("request") if isinstance(entry, dict) else {}
        if isinstance(request_data, dict) and request_data.get("url"):
            urls.append(str(request_data["url"]))
    temp.write_text("\n".join(urls), encoding="utf-8")
    try:
        return _url_list(temp, scope)
    finally:
        temp.unlink(missing_ok=True)


def _read_jsonl(path: Path, rejected: list[RejectedCandidate], source: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            rejected.append(_reject(line, source, "malformed_json", "asset"))
            continue
        if isinstance(row, dict):
            rows.append(row)
        else:
            rejected.append(_reject(str(row), source, "malformed_record", "asset"))
    return rows


def _reject(candidate: str, source: str, reason: str, candidate_type: str) -> RejectedCandidate:
    return rejected_candidate(candidate, f"adapter:{source}", reason, candidate_type=candidate_type)


ADAPTERS = {
    "httpx": Adapter("httpx", "jsonl", "assets", "import_only", _httpx_jsonl),
    "subfinder": Adapter("subfinder", "text", "assets", "import_only", _subfinder_text),
    "openapi": Adapter("openapi", "json", "surfaces", "import_only", _openapi_json),
    "url-list": Adapter("url-list", "text", "assets", "import_only", _url_list),
    "har": Adapter("har", "json", "assets", "import_only", _har_json),
}
