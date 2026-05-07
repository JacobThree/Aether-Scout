import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aether_scout.cli import main
from aether_scout.models.asset import Asset


class LinkRunTests(unittest.TestCase):
    @patch.dict(os.environ, {"AETHER_SCOUT_LINK_BATCH_SIZE": "2"}, clear=True)
    @patch("aether_scout.cli.discover_assets_with_audit")
    @patch("aether_scout.link_client.request.urlopen")
    def test_run_to_link_fetches_scope_and_posts_chunks(self, urlopen, discover):
        discover.return_value = (
            [
                Asset(program_id="p1", host="api1.example.com"),
                Asset(program_id="p1", host="api2.example.com"),
                Asset(program_id="p1", host="api3.example.com"),
            ],
            [],
            [],
        )
        calls: list[tuple[str, str, dict | None]] = []

        class Response:
            def __init__(self, body: str) -> None:
                self.body = body.encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return self.body

        def fake_urlopen(req, timeout):
            payload = json.loads(req.data.decode("utf-8")) if req.data else None
            calls.append((req.method, req.full_url, payload))
            if req.full_url.endswith("/health"):
                return Response("{}")
            if req.full_url.endswith("/configs/current"):
                return Response('{"scope":{"program_id":"p1","default_decision":"deny","rules":[{"type":"include","pattern":"*.example.com"}]}}')
            if req.full_url.endswith("/assets"):
                return Response('{"ok":true}')
            raise AssertionError(req.full_url)

        urlopen.side_effect = fake_urlopen
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "assets.jsonl"
            code = main(["run", "--link-url", "http://link", "--out", str(out)])

        self.assertEqual(code, 0)
        self.assertEqual([call[1] for call in calls], ["http://link/health", "http://link/configs/current", "http://link/assets", "http://link/assets"])
        self.assertEqual([len(call[2]["assets"]) for call in calls if call[1].endswith("/assets")], [2, 1])
        discover.assert_called_once()


if __name__ == "__main__":
    unittest.main()
