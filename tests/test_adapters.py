import json
import tempfile
import unittest
from pathlib import Path

from aether_scout.adapters import import_with_adapter, list_adapters
from aether_scout.cli import main
from aether_scout.models.scope import ScopeConfig, ScopeRule


class AdapterTests(unittest.TestCase):
    def scope(self) -> ScopeConfig:
        return ScopeConfig(program_id="p1", rules=[ScopeRule("*.example.com", "include")])

    def test_lists_import_only_adapters(self):
        rows = list_adapters()
        names = {row["adapter_name"] for row in rows}
        self.assertIn("httpx", names)
        self.assertTrue(all(row["safety_mode"] == "import_only" for row in rows))

    def test_httpx_import_scope_filters_and_audits(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "httpx.jsonl"
            path.write_text(
                json.dumps({"url": "https://app.example.com", "status_code": 200}) + "\n" +
                json.dumps({"url": "https://evil.test", "status_code": 200}) + "\n" +
                "not-json\n",
                encoding="utf-8",
            )

            output_type, rows, rejected = import_with_adapter("httpx", path, self.scope())

        self.assertEqual(output_type, "assets")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["host"], "app.example.com")
        self.assertCountEqual([record.reason for record in rejected], ["url_out_of_scope", "malformed_json"])

    def test_openapi_import_outputs_surfaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "openapi.json"
            path.write_text(json.dumps({
                "servers": [{"url": "https://api.example.com"}],
                "paths": {"/api/chat": {"post": {"tags": ["ai"]}}},
            }), encoding="utf-8")

            output_type, rows, rejected = import_with_adapter("openapi", path, self.scope())

        self.assertEqual(output_type, "surfaces")
        self.assertEqual(rejected, [])
        self.assertEqual(rows[0]["surface_type"], "openapi_schema")
        self.assertEqual(rows[0]["method"], "POST")

    def test_cli_adapter_import_writes_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "urls.txt"
            out = Path(tmp) / "assets.jsonl"
            audit = Path(tmp) / "audit.jsonl"
            input_path.write_text("https://app.example.com\nhttps://evil.test\n", encoding="utf-8")

            code = main(["adapters", "import", "--adapter", "url-list", "--input", str(input_path), "--scope", "./examples/scope.toml", "--out", str(out), "--audit-log", str(audit)])

            self.assertEqual(code, 0)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            rejected = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rejected[0]["candidate_type"], "asset")

    def test_har_import_does_not_touch_sibling_urls_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "capture.har"
            sibling = Path(tmp) / "capture.urls"
            sibling.write_text("keep me", encoding="utf-8")
            path.write_text(json.dumps({
                "log": {"entries": [
                    {"request": {"url": "https://app.example.com/api/chat"}},
                    {"request": {"url": "https://evil.test/api/chat"}},
                ]}
            }), encoding="utf-8")

            output_type, rows, rejected = import_with_adapter("har", path, self.scope())
            sibling_text = sibling.read_text(encoding="utf-8")

        self.assertEqual(output_type, "assets")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rejected[0].reason, "url_out_of_scope")
        self.assertEqual(sibling_text, "keep me")


if __name__ == "__main__":
    unittest.main()
