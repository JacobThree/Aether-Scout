from __future__ import annotations

from hashlib import sha256
from typing import Any

from .audit import RejectedCandidate, rejected_candidate
from .models.schema import SchemaCandidate
from .models.scope import ScopeConfig


SECRET_KEYS = {"authorization", "cookie", "set-cookie", "token", "api_key", "apikey", "secret", "password", "access_token", "refresh_token"}
PROMPT_KEYS = {"prompt", "query", "question", "message", "input"}
TENANT_KEYS = {"tenant_id", "tenant", "team_id"}
WORKSPACE_KEYS = {"workspace_id", "workspace", "project_id"}
ORG_KEYS = {"org_id", "organization_id", "organization"}
RESPONSE_TEXT_KEYS = {"answer", "response", "text", "content", "message"}
SOURCES_KEYS = {"sources", "source_documents", "documents"}
CITATIONS_KEYS = {"citations", "references"}


def import_request_shapes(records: Any, scope: ScopeConfig) -> tuple[list[SchemaCandidate], list[RejectedCandidate]]:
    scope.validate_for_run()
    schemas: list[SchemaCandidate] = []
    rejected: list[RejectedCandidate] = []
    for raw in _iter_records(records):
        if not isinstance(raw, dict):
            rejected.append(rejected_candidate(str(raw), "request_shapes", "malformed_record", candidate_type="schema"))
            continue
        url = str(raw.get("url") or raw.get("request_url") or "")
        if not url or not scope.is_url_allowed(url):
            rejected.append(rejected_candidate(
                url or "<missing-url>",
                "request_shapes",
                "url_out_of_scope" if url else "missing_url",
                candidate_type="schema",
                scope_context={"program_id": scope.program_id},
            ))
            continue
        schemas.append(_schema_from_record(scope.program_id, raw, url))
    return _dedupe_schemas(schemas), rejected


def redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if str(key).lower() in SECRET_KEYS:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_secrets(item)
        return redacted
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


def _schema_from_record(program_id: str, raw: dict[str, Any], url: str) -> SchemaCandidate:
    request_data = raw.get("request") if isinstance(raw.get("request"), dict) else raw
    response_data = raw.get("response") if isinstance(raw.get("response"), dict) else {}
    request_paths = _key_paths(request_data, "request")
    response_paths = _key_paths(response_data, "response")
    upload_endpoint = _upload_endpoint(raw)
    ambiguity: list[str] = []
    prompt_key = _first_path(request_paths, PROMPT_KEYS)
    if prompt_key is None:
        ambiguity.append("prompt_key_not_detected")
    return SchemaCandidate(
        schema_id=_stable_id("schema", program_id, url, str(raw.get("method") or raw.get("request_method") or "GET")),
        program_id=program_id,
        url=url,
        method=str(raw.get("method") or raw.get("request_method") or "GET").upper(),
        prompt_key=prompt_key,
        tenant_key=_first_path(request_paths, TENANT_KEYS),
        workspace_key=_first_path(request_paths, WORKSPACE_KEYS),
        org_key=_first_path(request_paths, ORG_KEYS),
        response_text_path=_first_path(response_paths, RESPONSE_TEXT_KEYS),
        sources_path=_first_path(response_paths, SOURCES_KEYS),
        citations_path=_first_path(response_paths, CITATIONS_KEYS),
        streaming=_detect_streaming(raw),
        upload_endpoint=upload_endpoint,
        confidence=0.76 if prompt_key else 0.45,
        ambiguity=ambiguity,
        metadata=redact_secrets({
            "headers": raw.get("headers") or raw.get("request_headers") or {},
            "content_type": raw.get("content_type"),
            "upload_related": bool(upload_endpoint),
        }),
    )


def _iter_records(records: Any) -> list[Any]:
    if isinstance(records, list):
        return records
    if isinstance(records, dict):
        for key in ("requests", "records", "items", "entries"):
            value = records.get(key)
            if isinstance(value, list):
                return value
        return [records]
    return [records]


def _key_paths(value: Any, prefix: str = "") -> dict[str, str]:
    paths: dict[str, str] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            paths[str(key).lower()] = path
            paths.update(_key_paths(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value[:3]):
            paths.update(_key_paths(item, f"{prefix}[{index}]"))
    return paths


def _first_path(paths: dict[str, str], keys: set[str]) -> str | None:
    for key in keys:
        if key in paths:
            return paths[key]
    return None


def _detect_streaming(raw: dict[str, Any]) -> bool | None:
    if isinstance(raw.get("streaming"), bool):
        return raw["streaming"]
    content_type = str(raw.get("content_type") or raw.get("response_content_type") or "").lower()
    if "event-stream" in content_type or "ndjson" in content_type:
        return True
    return None


def _upload_endpoint(raw: dict[str, Any]) -> str | None:
    url = str(raw.get("url") or raw.get("request_url") or "")
    method = str(raw.get("method") or raw.get("request_method") or "").upper()
    text = " ".join(str(raw.get(key) or "") for key in ("url", "content_type", "body", "request_body")).lower()
    if method in {"POST", "PUT"} and ("upload" in text or "multipart/form-data" in text or "document" in text):
        return url
    return None


def _stable_id(*parts: str) -> str:
    return sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _dedupe_schemas(schemas: list[SchemaCandidate]) -> list[SchemaCandidate]:
    out: dict[str, SchemaCandidate] = {}
    for schema in schemas:
        current = out.get(schema.schema_id)
        if current is None or schema.confidence > current.confidence:
            out[schema.schema_id] = schema
    return list(out.values())
