import unittest

from aether_scout.models.scope import ScopeConfig, ScopeRule, detect_scope_type, normalize_scope_values


class ScopeTests(unittest.TestCase):
    def test_detect_scope_type(self):
        self.assertEqual(detect_scope_type("*.example.com"), "wildcard")
        self.assertEqual(detect_scope_type("example.com"), "domain")
        self.assertEqual(detect_scope_type("https://example.com/api"), "url")
        self.assertEqual(detect_scope_type("10.0.0.0/24"), "cidr")

    def test_normalize_scope_values(self):
        values = ["", "  ", "#comment", "example.com", "example.com", "*.x.com"]
        self.assertEqual(normalize_scope_values(values), ["example.com", "*.x.com"])

    def test_url_scope_prefix_enforced_for_same_host(self):
        scope = ScopeConfig(
            program_id="p1",
            rules=[
                ScopeRule("*.example.com", "include"),
                ScopeRule("https://app.example.com/allowed", "include"),
            ],
        )
        self.assertTrue(scope.is_url_allowed("https://app.example.com/allowed/path"))
        self.assertFalse(scope.is_url_allowed("https://app.example.com/admin"))

    def test_default_deny_required(self):
        scope = ScopeConfig(program_id="p1", default_decision="allow", rules=[ScopeRule("example.com")])
        with self.assertRaises(ValueError):
            scope.validate_for_run()


if __name__ == "__main__":
    unittest.main()
