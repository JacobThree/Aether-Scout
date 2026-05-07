from __future__ import annotations

from urllib.parse import urlparse

from .models.asset import Asset


def dedupe_assets(assets: list[Asset]) -> list[Asset]:
    merged: dict[str, Asset] = {}
    for asset in assets:
        key = _key(asset)
        current = merged.get(key)
        if not current:
            merged[key] = asset
            continue
        current.confidence = max(current.confidence, asset.confidence)
        current.discovery_methods = sorted(set(current.discovery_methods + asset.discovery_methods))
        current.technologies = sorted(set(current.technologies + asset.technologies))
        current.interesting_paths = sorted(set(current.interesting_paths + asset.interesting_paths))
        current.metadata.update(asset.metadata)
        current.status_code = current.status_code or asset.status_code
        current.title = current.title or asset.title
        current.ip = current.ip or asset.ip
    return list(merged.values())


def _key(asset: Asset) -> str:
    if asset.url:
        parsed = urlparse(asset.url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else "")
        return f"url:{parsed.scheme}:{parsed.hostname}:{port}{parsed.path.rstrip('/') or '/'}"
    return f"host:{asset.host or ''}:{asset.ip or ''}"
