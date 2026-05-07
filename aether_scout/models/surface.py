from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..tools.common import now_iso


SURFACE_TYPES = {
    "rag_chat",
    "ai_chat",
    "copilot",
    "helpdesk_bot",
    "support_assistant",
    "mcp_endpoint",
    "openapi_schema",
    "websocket_chat",
    "graphql_ai",
    "document_upload",
    "unknown_ai_surface",
}


@dataclass(slots=True)
class Surface:
    surface_id: str
    program_id: str
    asset_id: str
    surface_type: str
    url: str
    method: str | None = None
    confidence: float = 0.5
    evidence_metadata: dict[str, Any] = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)
    scope_status: str = "accepted"
    discovered_at: str = field(default_factory=now_iso)

    def __post_init__(self) -> None:
        if self.surface_type not in SURFACE_TYPES:
            raise ValueError(f"unknown surface_type: {self.surface_type}")

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, [], {})}
