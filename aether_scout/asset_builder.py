from __future__ import annotations

from urllib.parse import urlparse

from .models.asset import Asset
from .tools.tech_fingerprint import from_http_metadata


def from_http_row(program_id: str, row: dict, methods: list[str]) -> Asset:
    url = str(row.get("url") or "")
    parsed = urlparse(url)
    metadata = row.get("metadata", {}) if isinstance(row.get("metadata"), dict) else {}
    return Asset(
        program_id=program_id,
        url=url or None,
        host=row.get("host") or parsed.hostname,
        port=row.get("port") or parsed.port,
        scheme=row.get("scheme") or parsed.scheme or None,
        status_code=row.get("status_code"),
        title=row.get("title"),
        technologies=from_http_metadata(row),
        discovered_by="aether-scout",
        discovery_methods=methods,
        confidence=float(row.get("confidence") or 0.72),
        metadata=metadata,
    )


def host_asset(program_id: str, host: str, methods: list[str], ip: str | None = None) -> Asset:
    return Asset(program_id=program_id, host=host, ip=ip, discovery_methods=methods, confidence=0.45)
