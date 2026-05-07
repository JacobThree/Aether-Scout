from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .tools.common import now_iso


@dataclass(slots=True)
class RejectedCandidate:
    candidate: str
    source_module: str
    reason: str
    scope_context: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=now_iso)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, [], {})}


def rejected_candidate(
    candidate: str,
    source_module: str,
    reason: str,
    *,
    scope_context: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> RejectedCandidate:
    return RejectedCandidate(
        candidate=candidate,
        source_module=source_module,
        reason=reason,
        scope_context=scope_context or {},
        metadata=metadata or {},
    )
