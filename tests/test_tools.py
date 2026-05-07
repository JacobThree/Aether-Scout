import unittest
from unittest.mock import Mock, patch

from aether_scout.config import ScoutSettings
from aether_scout.discovery import discover_assets
from aether_scout.models.scope import ScopeConfig, ScopeRule
from aether_scout.throttle import RateLimiter
from aether_scout.tools.common import CommandResult
from aether_scout.tools import dnsx, httpx, subfinder


def result(stdout: str, exit_code: int = 0) -> CommandResult:
    return CommandResult(exit_code=exit_code, stdout=stdout, stderr="", started_at="s", completed_at="e")


class ToolTests(unittest.TestCase):
    @patch("aether_scout.tools.subfinder.run_cmd")
    @patch("aether_scout.tools.subfinder.tool_available", return_value=True)
    def test_subfinder_returns_unique_hosts(self, _available, run_cmd):
        run_cmd.return_value = result("a.example.com\nhttps://b.example.com/path\na.example.com\n")
        hosts, logs = subfinder.discover(["example.com"])
        self.assertEqual(hosts, ["a.example.com", "b.example.com"])
        self.assertEqual(logs, ["subfinder example.com exit=0"])

    @patch("aether_scout.tools.dnsx.run_cmd")
    @patch("aether_scout.tools.dnsx.tool_available", return_value=True)
    def test_dnsx_json_output_captures_ips_and_cname(self, _available, run_cmd):
        run_cmd.return_value = result('{"host":"api.example.com","a":["203.0.113.10"],"aaaa":["2001:db8::1"],"cname":["edge.example.net."]}\n')
        rows, _logs = dnsx.resolve(["api.example.com"])
        self.assertEqual(rows["api.example.com"]["ips"], ["2001:db8::1", "203.0.113.10"])
        self.assertEqual(rows["api.example.com"]["cname"], ["edge.example.net."])

    @patch("aether_scout.tools.httpx.run_cmd")
    @patch("aether_scout.tools.httpx.tool_available", return_value=True)
    def test_httpx_json_output_captures_metadata(self, _available, run_cmd):
        run_cmd.return_value = result(
            '{"url":"https://api.example.com","status_code":200,"title":"API","tech":["FastAPI"],"webserver":"nginx","content_type":"application/json","final_url":"https://api.example.com/v1"}\n'
        )
        rows, _logs = httpx.probe(["api.example.com"])
        self.assertEqual(rows[0]["url"], "https://api.example.com")
        self.assertEqual(rows[0]["status_code"], 200)
        self.assertEqual(rows[0]["title"], "API")
        self.assertEqual(rows[0]["technologies"], ["fastapi"])
        self.assertEqual(rows[0]["metadata"]["server"], "nginx")
        self.assertEqual(rows[0]["metadata"]["content_type"], "application/json")
        self.assertEqual(rows[0]["metadata"]["redirects_to"], "https://api.example.com/v1")

    @patch("aether_scout.tools.httpx.run_cmd")
    @patch("aether_scout.tools.httpx.tool_available", return_value=True)
    def test_httpx_active_probe_uses_rate_limiter(self, _available, run_cmd):
        limiter = Mock()
        run_cmd.return_value = result("")
        httpx.probe(["api.example.com"], rate_limiter=limiter)
        limiter.wait.assert_called_once()

    @patch("aether_scout.discovery.httpx.probe", return_value=([], []))
    @patch("aether_scout.discovery.dnsx.resolve", return_value=({}, []))
    @patch("aether_scout.discovery.subfinder.discover")
    def test_passive_discovery_runs_by_default(self, subfinder_discover, _dns, _http):
        subfinder_discover.return_value = ([], [])
        scope = ScopeConfig(program_id="p1", rules=[ScopeRule("*.example.com", "include")])
        discover_assets(scope, ScoutSettings())
        subfinder_discover.assert_called_once()

    def test_rate_limiter_sleeps_between_requests(self):
        times = iter([0.0, 0.5, 60.5])
        sleeps: list[float] = []
        limiter = RateLimiter(60, monotonic=lambda: next(times), sleep=sleeps.append)
        limiter.wait()
        limiter.wait()
        self.assertEqual(sleeps, [0.5])


if __name__ == "__main__":
    unittest.main()
