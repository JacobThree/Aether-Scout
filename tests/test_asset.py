import unittest

from aether_scout.asset_builder import from_http_row
from aether_scout.audit import rejected_candidate
from aether_scout.dedupe import dedupe_assets
from aether_scout.models.asset import Asset


class AssetTests(unittest.TestCase):
    def test_asset_to_dict_omits_empty_fields(self):
        data = Asset(program_id="p1", host="api.example.com").to_dict()
        self.assertEqual(data["program_id"], "p1")
        self.assertEqual(data["host"], "api.example.com")
        self.assertNotIn("url", data)
        self.assertNotIn("technologies", data)

    def test_from_http_row_sets_schema_fields(self):
        asset = from_http_row(
            "p1",
            {
                "url": "https://api.example.com:8443/mcp",
                "status_code": 200,
                "title": "API",
                "technologies": ["FastAPI"],
                "metadata": {"server": "cloudflare", "content_type": "application/json"},
                "confidence": 0.8,
            },
            ["httpx"],
        )
        self.assertEqual(asset.scheme, "https")
        self.assertEqual(asset.host, "api.example.com")
        self.assertEqual(asset.port, 8443)
        self.assertEqual(asset.status_code, 200)
        self.assertEqual(asset.title, "API")
        self.assertIn("fastapi", asset.technologies)
        self.assertIn("cloudflare", asset.technologies)
        self.assertEqual(asset.discovery_methods, ["httpx"])
        self.assertEqual(asset.metadata["content_type"], "application/json")

    def test_dedupe_preserves_high_confidence_metadata(self):
        low = Asset(program_id="p1", url="https://api.example.com/mcp", confidence=0.4, discovery_methods=["httpx"])
        high = Asset(
            program_id="p1",
            url="https://api.example.com/mcp",
            confidence=0.9,
            discovery_methods=["mcp_detector"],
            technologies=["fastapi"],
            interesting_paths=["/mcp"],
            metadata={"content_type": "application/json"},
        )
        merged = dedupe_assets([low, high])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].confidence, 0.9)
        self.assertEqual(merged[0].discovery_methods, ["httpx", "mcp_detector"])
        self.assertEqual(merged[0].interesting_paths, ["/mcp"])
        self.assertEqual(merged[0].metadata["content_type"], "application/json")

    def test_rejected_candidate_record_shape(self):
        record = rejected_candidate(
            "admin.example.com",
            "subfinder",
            "host_out_of_scope",
            scope_context={"program_id": "p1"},
        ).to_dict()
        self.assertEqual(record["candidate"], "admin.example.com")
        self.assertEqual(record["source_module"], "subfinder")
        self.assertEqual(record["reason"], "host_out_of_scope")
        self.assertEqual(record["scope_context"]["program_id"], "p1")
        self.assertIn("timestamp", record)


if __name__ == "__main__":
    unittest.main()
