from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(slots=True)
class Asset:
    program_id: str
    url: str | None = None
    host: str | None = None
    ip: str | None = None
    port: int | None = None
    scheme: str | None = None
    status_code: int | None = None
    title: str | None = None
    technologies: list[str] = field(default_factory=list)
    interesting_paths: list[str] = field(default_factory=list)
    discovered_by: str = "aether-scout"
    discovery_methods: list[str] = field(default_factory=list)
    confidence: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, [], {})}
