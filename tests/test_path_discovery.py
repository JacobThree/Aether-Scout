import unittest
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from unittest.mock import Mock, patch

from aether_scout.tools import mcp_detector, robots


class Response:
    def __init__(self, body: str = "", status: int = 200, headers: dict | None = None) -> None:
        self.body = body.encode("utf-8")
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit: int | None = None):
        return self.body


class PathDiscoveryTests(unittest.TestCase):
    @patch("aether_scout.tools.robots.request.urlopen")
    def test_robots_and_sitemap_paths_are_conservative(self, urlopen):
        def fake_open(req, timeout):
            url = req.full_url
            if url.endswith("/robots.txt"):
                return Response("Disallow: /admin\nAllow: /api\nSitemap: https://example.com/custom.xml\n")
            if url.endswith("/custom.xml"):
                return Response("<urlset><url><loc>https://example.com/from-custom</loc></url></urlset>")
            if url.endswith("/sitemap.xml"):
                return Response("<urlset><url><loc>https://example.com/from-default</loc></url></urlset>")
            raise URLError("unexpected")

        urlopen.side_effect = fake_open
        paths = robots.discover("https://example.com", user_agent="test")
        self.assertEqual(paths, ["/admin", "/api", "/from-custom", "/from-default"])

    @patch("aether_scout.tools.robots.request.urlopen", side_effect=URLError("down"))
    def test_robots_network_errors_degrade_cleanly(self, _urlopen):
        self.assertEqual(robots.discover("https://example.com", user_agent="test"), [])

    @patch("aether_scout.tools.mcp_detector.request.urlopen")
    def test_mcp_detector_checks_only_indicator_paths_and_uses_limiter(self, urlopen):
        seen_paths: list[str] = []
        limiter = Mock()

        def fake_open(req, timeout):
            seen_paths.append(req.full_url.replace("https://example.com", ""))
            if urlparse(req.full_url).path == "/mcp":
                return Response(status=200, headers={"content-type": "application/json"})
            raise HTTPError(req.full_url, 404, "missing", {}, None)

        urlopen.side_effect = fake_open
        hits = mcp_detector.detect("https://example.com", user_agent="test", rate_limiter=limiter)
        self.assertEqual([hit["path"] for hit in hits], ["/mcp"])
        self.assertEqual(seen_paths, list(mcp_detector.MCP_CANDIDATE_PATHS))
        self.assertEqual(limiter.wait.call_count, len(mcp_detector.MCP_CANDIDATE_PATHS))

    @patch("aether_scout.tools.mcp_detector.request.urlopen", side_effect=URLError("down"))
    def test_mcp_detector_network_errors_degrade_cleanly(self, _urlopen):
        self.assertEqual(mcp_detector.detect("https://example.com", user_agent="test"), [])


if __name__ == "__main__":
    unittest.main()
