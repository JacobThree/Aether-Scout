from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..tools.common import now_iso


@dataclass(slots=True)
class SchemaCandidate:
    schema_id: str
    program_id: str
    url: str
    method: str | None = None
    prompt_key: str | None = None
    tenant_key: str | None = None
    workspace_key: str | None = None
    org_key: str | None = None
    response_text_path: str | None = None
    sources_path: str | None = None
    citations_path: str | None = None
    streaming: bool | None = None
    upload_endpoint: str | None = None
    confidence: float = 0.5
    ambiguity: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    discovered_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, [], {})}
