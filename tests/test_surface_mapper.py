import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aether_scout.cli import main
from aether_scout.config import ScoutSettings
from aether_scout.models.asset import Asset
from aether_scout.models.scope import ScopeConfig, ScopeRule
from aether_scout.surface_mapper import map_surfaces_from_assets


class SurfaceMapperTests(unittest.TestCase):
    def scope(self) -> ScopeConfig:
        return ScopeConfig(program_id="p1", rules=[ScopeRule("*.example.com", "include")])

    def test_maps_metadata_surfaces(self):
        asset = Asset(
            program_id="p1",
            url="https://app.example.com",
            host="app.example.com",
            title="AI support assistant",
            interesting_paths=["/chat", "/openapi.json"],
            metadata={"mcp_candidates": [{"url": "https://app.example.com/mcp", "path": "/mcp", "status_code": 200}]},
        )
        settings = ScoutSettings(passive_only=True)

        surfaces, rejected = map_surfaces_from_assets(self.scope(), [asset], settings)

        self.assertEqual(rejected, [])
        surface_types = {surface.surface_type for surface in surfaces}
        self.assertIn("ai_chat", surface_types)
        self.assertIn("openapi_schema", surface_types)
        self.assertIn("mcp_endpoint", surface_types)
        self.assertTrue(all(surface.scope_status == "accepted" for surface in surfaces))

    def test_rejects_out_of_scope_network_hints(self):
        asset = Asset(
            program_id="p1",
            url="https://app.example.com",
            host="app.example.com",
            metadata={"network_hints": ["https://evil.test/chat"]},
        )
        settings = ScoutSettings(passive_only=True)

        surfaces, rejected = map_surfaces_from_assets(self.scope(), [asset], settings)

        self.assertEqual(surfaces, [])
        self.assertEqual(rejected[0].candidate_type, "surface")
        self.assertEqual(rejected[0].reason, "url_out_of_scope")

    @patch("aether_scout.surface_mapper._head_or_get")
    def test_active_indicator_paths_are_checked(self, head_or_get):
        head_or_get.side_effect = lambda url, **_kwargs: (200, "application/json") if url.endswith("/api/chat") else (404, None)
        asset = Asset(program_id="p1", url="https://app.example.com", host="app.example.com")
        settings = ScoutSettings(requests_per_minute=1000)

        surfaces, rejected = map_surfaces_from_assets(self.scope(), [asset], settings)

        self.assertEqual(rejected, [])
        self.assertEqual([surface.url for surface in surfaces], ["https://app.example.com/api/chat"])
        self.assertGreaterEqual(head_or_get.call_count, 12)

    @patch("aether_scout.cli.map_surfaces")
    def test_cli_writes_surface_jsonl_and_audit(self, map_surfaces):
        from aether_scout.audit import rejected_candidate
        from aether_scout.models.surface import Surface

        map_surfaces.return_value = (
            [Surface(surface_id="s1", program_id="p1", asset_id="a1", surface_type="ai_chat", url="https://app.example.com/chat")],
            [],
            [rejected_candidate("https://evil.test/chat", "surface_mapper", "url_out_of_scope", candidate_type="surface")],
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "surfaces.jsonl"
            audit = Path(tmp) / "audit.jsonl"
            code = main(["map-surfaces", "--scope", "./examples/scope.toml", "--out", str(out), "--audit-log", str(audit)])

            self.assertEqual(code, 0)
            surface_rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            audit_rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(surface_rows[0]["surface_id"], "s1")
        self.assertEqual(audit_rows[0]["candidate_type"], "surface")


if __name__ == "__main__":
    unittest.main()
