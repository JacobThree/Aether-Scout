from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(slots=True)
class ScoutSettings:
    link_url: str | None = None
    api_token: str | None = None
    worker_id: str = "scout_local_001"
    scope_file: str | None = None
    output_file: str = "./assets.jsonl"
    passive_only: bool = False
    max_concurrent_probes: int = 5
    requests_per_minute: int = 30
    timeout_seconds: int = 10
    link_batch_size: int = 50
    user_agent: str = "Aether-Scout authorized-recon"
    subfinder_path: str = "subfinder"
    dnsx_path: str = "dnsx"
    httpx_path: str = "httpx"


def settings_from_env() -> ScoutSettings:
    return ScoutSettings(
        link_url=_env("AETHER_LINK_URL"),
        api_token=_env("AETHER_API_TOKEN"),
        worker_id=_env("AETHER_SCOUT_WORKER_ID") or "scout_local_001",
        scope_file=_env("AETHER_SCOUT_SCOPE_FILE"),
        output_file=_env("AETHER_SCOUT_OUTPUT_FILE") or "./assets.jsonl",
        passive_only=_bool("AETHER_SCOUT_PASSIVE_ONLY", False),
        max_concurrent_probes=_bounded_int("AETHER_SCOUT_MAX_CONCURRENT_PROBES", 5, minimum=1),
        requests_per_minute=_bounded_int("AETHER_SCOUT_REQUESTS_PER_MINUTE", 30, minimum=1),
        timeout_seconds=_int("AETHER_SCOUT_TIMEOUT_SECONDS", 10),
        link_batch_size=_bounded_int("AETHER_SCOUT_LINK_BATCH_SIZE", 50, minimum=1, maximum=100),
        user_agent=_env("AETHER_SCOUT_USER_AGENT") or "Aether-Scout authorized-recon",
    )


def _env(name: str) -> str | None:
    value = os.getenv(name)
    return value.strip() if value and value.strip() else None


def _bool(name: str, default: bool) -> bool:
    value = _env(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    value = _env(name)
    if value is None:
        return default
    return int(value)


def _bounded_int(name: str, default: int, *, minimum: int, maximum: int | None = None) -> int:
    value = _int(name, default)
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return value
