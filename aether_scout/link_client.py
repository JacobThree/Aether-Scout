from __future__ import annotations

from typing import Any
from urllib import request, error
import json


class LinkClient:
    def __init__(self, base_url: str, api_token: str | None = None, timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def current_config(self) -> dict[str, Any]:
        return self._request("GET", "/configs/current")

    def post_asset(self, asset: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/assets", asset)

    def post_assets(self, assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.post_asset(asset) for asset in assets]

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload, sort_keys=True).encode("utf-8")
        headers = {"accept": "application/json"}
        if body is not None:
            headers["content-type"] = "application/json"
        if self.api_token:
            headers["authorization"] = f"Bearer {self.api_token}"
        req = request.Request(f"{self.base_url}{path}", data=body, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            raise RuntimeError(f"aether-link {method} {path} failed: {exc.code} {raw}") from exc
