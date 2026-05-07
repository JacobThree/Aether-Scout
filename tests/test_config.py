import os
import unittest
from unittest.mock import patch

from aether_scout.config import ScoutSettings, settings_from_env
from aether_scout.discovery import discover_assets, discover_assets_with_audit
from aether_scout.models.scope import ScopeConfig, ScopeRule


class ConfigTests(unittest.TestCase):
    def test_settings_from_env(self):
        env = {
            "AETHER_LINK_URL": "http://link",
            "AETHER_API_TOKEN": "token",
            "AETHER_SCOUT_WORKER_ID": "worker1",
            "AETHER_SCOUT_SCOPE_FILE": "./scope.toml",
            "AETHER_SCOUT_OUTPUT_FILE": "./assets.jsonl",
            "AETHER_SCOUT_PASSIVE_ONLY": "true",
            "AETHER_SCOUT_MAX_CONCURRENT_PROBES": "3",
            "AETHER_SCOUT_REQUESTS_PER_MINUTE": "12",
            "AETHER_SCOUT_TIMEOUT_SECONDS": "7",
            "AETHER_SCOUT_LINK_BATCH_SIZE": "75",
            "AETHER_SCOUT_USER_AGENT": "ua",
        }
        with patch.dict(os.environ, env, clear=True):
            settings = settings_from_env()

        self.assertEqual(settings.link_url, "http://link")
        self.assertEqual(settings.api_token, "token")
        self.assertEqual(settings.worker_id, "worker1")
        self.assertEqual(settings.scope_file, "./scope.toml")
        self.assertEqual(settings.output_file, "./assets.jsonl")
        self.assertTrue(settings.passive_only)
        self.assertEqual(settings.max_concurrent_probes, 3)
        self.assertEqual(settings.requests_per_minute, 12)
        self.assertEqual(settings.timeout_seconds, 7)
        self.assertEqual(settings.link_batch_size, 75)
        self.assertEqual(settings.user_agent, "ua")

    def test_invalid_int_fails_clearly(self):
        with patch.dict(os.environ, {"AETHER_SCOUT_REQUESTS_PER_MINUTE": "0"}, clear=True):
            with self.assertRaisesRegex(ValueError, "AETHER_SCOUT_REQUESTS_PER_MINUTE must be >= 1"):
                settings_from_env()

    def test_batch_size_upper_bound(self):
        with patch.dict(os.environ, {"AETHER_SCOUT_LINK_BATCH_SIZE": "101"}, clear=True):
            with self.assertRaisesRegex(ValueError, "AETHER_SCOUT_LINK_BATCH_SIZE must be <= 100"):
                settings_from_env()

    def test_defaults_keep_passive_discovery_enabled(self):
        settings = ScoutSettings()
        self.assertFalse(settings.passive_only)
        self.assertEqual(settings.max_concurrent_probes, 5)
        self.assertEqual(settings.requests_per_minute, 30)

    @patch("aether_scout.discovery.httpx.probe", return_value=([], []))
    @patch("aether_scout.discovery.dnsx.resolve", return_value=({}, []))
    @patch("aether_scout.discovery.subfinder.discover", return_value=([], []))
    def test_active_probe_settings_are_enforced(self, _subfinder, _dns, httpx_probe):
        scope = ScopeConfig(program_id="p1", rules=[ScopeRule("*.example.com", "include")])
        discover_assets(scope, ScoutSettings(requests_per_minute=15, max_concurrent_probes=4))
        self.assertEqual(httpx_probe.call_args.kwargs["max_concurrent_probes"], 4)
        self.assertEqual(httpx_probe.call_args.kwargs["rate_limiter"].interval_seconds, 4.0)

    @patch("aether_scout.discovery.httpx.probe")
    @patch("aether_scout.discovery.dnsx.resolve")
    @patch("aether_scout.discovery.subfinder.discover")
    def test_passive_only_skips_active_modules(self, subfinder, dns, httpx_probe):
        scope = ScopeConfig(program_id="p1", rules=[ScopeRule("*.example.com", "include")])
        assets, logs = discover_assets(scope, ScoutSettings(passive_only=True))
        self.assertEqual([asset.host for asset in assets], ["example.com"])
        self.assertIn("passive_only=true", logs[0])
        subfinder.assert_not_called()
        dns.assert_not_called()
        httpx_probe.assert_not_called()

    @patch("aether_scout.discovery.httpx.probe", return_value=([], []))
    @patch("aether_scout.discovery.dnsx.resolve")
    @patch("aether_scout.discovery.subfinder.discover", return_value=(["admin.example.com", "api.example.com"], []))
    def test_scope_filtered_candidates_are_audited(self, _subfinder, dns, _httpx_probe):
        dns.return_value = ({"api.example.com": {"ips": []}}, [])
        scope = ScopeConfig(
            program_id="p1",
            rules=[ScopeRule("*.example.com", "include"), ScopeRule("admin.example.com", "exclude")],
        )
        _assets, _logs, rejected = discover_assets_with_audit(scope, ScoutSettings())
        self.assertIn(("admin.example.com", "host_out_of_scope"), [(row.candidate, row.reason) for row in rejected])

    @patch("aether_scout.discovery.httpx.probe", return_value=([], []))
    @patch("aether_scout.discovery.dnsx.resolve")
    @patch("aether_scout.discovery.subfinder.discover", return_value=([], []))
    def test_cidr_rejected_hosts_are_not_http_probed(self, _subfinder, dns, httpx_probe):
        dns.return_value = ({"example.com": {"ips": ["198.51.100.10"]}}, [])
        scope = ScopeConfig(
            program_id="p1",
            rules=[ScopeRule("example.com", "include"), ScopeRule("203.0.113.0/24", "include")],
        )
        _assets, _logs, rejected = discover_assets_with_audit(scope, ScoutSettings())
        self.assertEqual(httpx_probe.call_args.args[0], [])
        self.assertIn(("example.com", "resolved_ip_out_of_scope"), [(row.candidate, row.reason) for row in rejected])


if __name__ == "__main__":
    unittest.main()
