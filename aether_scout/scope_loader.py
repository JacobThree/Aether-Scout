from __future__ import annotations

from pathlib import Path
from typing import Any
import tomllib

from .models.scope import ScopeConfig, ScopeRule


def load_scope_file(path: str | Path) -> ScopeConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"scope file not found: {p}")
    data = tomllib.loads(p.read_text(encoding="utf-8"))
    scope = scope_from_mapping(data)
    scope.validate_for_run()
    return scope


def scope_from_mapping(data: dict[str, Any]) -> ScopeConfig:
    program_id = _str(data.get("program_id")) or _str(data.get("program")) or "program_unknown"
    default_decision = (_str(data.get("default_decision")) or "deny").lower()
    raw_rules = data.get("rules", [])
    rules: list[ScopeRule] = []
    if isinstance(raw_rules, list):
        for item in raw_rules:
            if not isinstance(item, dict):
                continue
            pattern = _str(item.get("pattern") or item.get("value"))
            if not pattern:
                continue
            rule_type = (_str(item.get("type") or item.get("rule_type")) or "include").lower()
            if rule_type in {"allow", "in_scope"}:
                rule_type = "include"
            if rule_type in {"deny", "out_of_scope"}:
                rule_type = "exclude"
            rules.append(ScopeRule(pattern=pattern, rule_type=rule_type, notes=_str(item.get("notes"))))
    scope = ScopeConfig(program_id=program_id, default_decision=default_decision, rules=rules)
    return scope


def scope_from_link_current(payload: dict[str, Any]) -> ScopeConfig:
    if "scope" in payload and isinstance(payload["scope"], dict):
        return scope_from_mapping(payload["scope"])
    if "current_scope" in payload and isinstance(payload["current_scope"], dict):
        return scope_from_mapping(payload["current_scope"])
    if "rules" in payload:
        return scope_from_mapping(payload)
    configs = payload.get("configs")
    if isinstance(configs, list) and configs:
        program_id = _str(configs[0].get("program_id")) or "program_unknown"
    else:
        program_id = "program_unknown"
    return ScopeConfig(program_id=program_id, default_decision="deny", rules=[])


def _str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
