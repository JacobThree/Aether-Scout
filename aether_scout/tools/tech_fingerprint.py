from __future__ import annotations


def from_http_metadata(row: dict) -> list[str]:
    tech: set[str] = {str(t).lower() for t in row.get("technologies", []) if str(t).strip()}
    metadata = row.get("metadata", {}) if isinstance(row.get("metadata"), dict) else {}
    server = str(metadata.get("server") or "").lower()
    content_type = str(metadata.get("content_type") or "").lower()
    for name in ("cloudflare", "nginx", "apache", "fastapi", "express", "next.js", "vercel"):
        if name in server or name in content_type:
            tech.add(name)
    return sorted(tech)
