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

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}


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
    return _dedupe_rows([asset.to_dict() for asset in assets]), rejected


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
    return _dedupe_rows([asset.to_dict() for asset in assets]), rejected


def _url_list(path: Path, scope: ScopeConfig) -> tuple[list[dict[str, Any]], list[RejectedCandidate]]:
    return _urls_to_assets(path.read_text(encoding="utf-8").splitlines(), scope, "url-list")


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
            asset = Asset(program_id=scope.program_id, url=base_url, host=urlparse(base_url).hostname)
            for method in _openapi_methods(methods):
                rows.append(Surface(
                    surface_id=_stable_id("surface", scope.program_id, url, "openapi_schema", method),
                    program_id=scope.program_id,
                    asset_id=_asset_id(asset),
                    surface_type="openapi_schema",
                    url=url,
                    method=method,
                    confidence=0.82,
                    indicators=["openapi"],
                    evidence_metadata={"source": "adapter:openapi"},
                ).to_dict())
    return _dedupe_rows(rows), rejected


def _har_json(path: Path, scope: ScopeConfig) -> tuple[list[dict[str, Any]], list[RejectedCandidate]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", []) if isinstance(data, dict) else []
    urls = []
    for entry in entries if isinstance(entries, list) else []:
        request_data = entry.get("request") if isinstance(entry, dict) else {}
        if isinstance(request_data, dict) and request_data.get("url"):
            urls.append(str(request_data["url"]))
    return _urls_to_assets(urls, scope, "har")


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


def _urls_to_assets(urls: list[str], scope: ScopeConfig, source: str) -> tuple[list[dict[str, Any]], list[RejectedCandidate]]:
    assets: list[Asset] = []
    rejected: list[RejectedCandidate] = []
    for raw_url in urls:
        url = raw_url.strip()
        if not url:
            continue
        if not scope.is_url_allowed(url):
            rejected.append(_reject(url, source, "url_out_of_scope", "asset"))
            continue
        parsed = urlparse(url)
        assets.append(Asset(program_id=scope.program_id, url=url, host=parsed.hostname, scheme=parsed.scheme, port=parsed.port, discovery_methods=[f"adapter:{source}"], confidence=0.55).to_dict())
    return _dedupe_rows(assets), rejected


def _openapi_methods(methods: Any) -> list[str]:
    if not isinstance(methods, dict):
        return ["GET"]
    out = [str(method).upper() for method in methods if str(method).upper() in HTTP_METHODS]
    return out or ["GET"]


def _dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = (
            row.get("url"),
            row.get("host"),
            row.get("surface_id") or row.get("schema_id"),
            row.get("method"),
        )
        current = out.get(key)
        if current is None or float(row.get("confidence", 0)) > float(current.get("confidence", 0)):
            out[key] = row
    return list(out.values())


def _reject(candidate: str, source: str, reason: str, candidate_type: str) -> RejectedCandidate:
    return rejected_candidate(candidate, f"adapter:{source}", reason, candidate_type=candidate_type)


ADAPTERS = {
    "httpx": Adapter("httpx", "jsonl", "assets", "import_only", _httpx_jsonl),
    "subfinder": Adapter("subfinder", "text", "assets", "import_only", _subfinder_text),
    "openapi": Adapter("openapi", "json", "surfaces", "import_only", _openapi_json),
    "url-list": Adapter("url-list", "text", "assets", "import_only", _url_list),
    "har": Adapter("har", "json", "assets", "import_only", _har_json),
}
