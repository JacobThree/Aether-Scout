import tempfile
import unittest
from pathlib import Path

from aether_scout.scope_loader import load_scope_file, scope_from_link_current


class ScopeLoaderTests(unittest.TestCase):
    def test_load_scope_file_parses_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.toml"
            path.write_text(
                """
program_id = "p1"
default_decision = "deny"

[[rules]]
type = "include"
pattern = "*.example.com"

[[rules]]
type = "exclude"
pattern = "admin.example.com"
""",
                encoding="utf-8",
            )
            scope = load_scope_file(path)

        self.assertEqual(scope.program_id, "p1")
        self.assertTrue(scope.is_host_allowed("app.example.com"))
        self.assertFalse(scope.is_host_allowed("admin.example.com"))

    def test_scope_from_link_payload_shapes(self):
        payloads = [
            {"scope": {"program_id": "p1", "rules": [{"type": "include", "pattern": "*.example.com"}]}},
            {"current_scope": {"program_id": "p1", "rules": [{"type": "include", "pattern": "*.example.com"}]}},
            {"program_id": "p1", "rules": [{"type": "include", "pattern": "*.example.com"}]},
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                scope = scope_from_link_current(payload)
                scope.validate_for_run()
                self.assertEqual(scope.root_domains(), ["example.com"])

    def test_empty_link_config_refuses_run(self):
        scope = scope_from_link_current({"configs": [{"program_id": "p1"}]})
        with self.assertRaises(ValueError):
            scope.validate_for_run()


if __name__ == "__main__":
    unittest.main()
