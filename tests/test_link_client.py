import json
import unittest
from urllib.error import HTTPError
from unittest.mock import Mock, patch

from aether_scout.link_client import LinkClient


class Response:
    def __init__(self, body: str = "{}") -> None:
        self.body = body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


class LinkClientTests(unittest.TestCase):
    @patch("aether_scout.link_client.request.urlopen", return_value=Response('{"ok": true}'))
    def test_get_paths_and_auth_header(self, urlopen):
        client = LinkClient("http://link", api_token="token")
        self.assertEqual(client.health(), {"ok": True})
        self.assertEqual(client.current_config(), {"ok": True})

        paths = [call.args[0].full_url for call in urlopen.call_args_list]
        auth = [call.args[0].headers["Authorization"] for call in urlopen.call_args_list]
        self.assertEqual(paths, ["http://link/health", "http://link/configs/current"])
        self.assertEqual(auth, ["Bearer token", "Bearer token"])

    @patch("aether_scout.link_client.request.urlopen", return_value=Response('{"accepted": true}'))
    def test_post_assets_batches_payloads(self, urlopen):
        client = LinkClient("http://link", batch_size=2)
        responses = client.post_assets([{"id": 1}, {"id": 2}, {"id": 3}])

        self.assertEqual(responses, [{"accepted": True}, {"accepted": True}])
        payloads = [json.loads(call.args[0].data.decode("utf-8")) for call in urlopen.call_args_list]
        self.assertEqual(payloads, [{"assets": [{"id": 1}, {"id": 2}]}, {"assets": [{"id": 3}]}])

    def test_batch_size_bounds(self):
        with self.assertRaises(ValueError):
            LinkClient("http://link", batch_size=0)
        with self.assertRaises(ValueError):
            LinkClient("http://link", batch_size=101)

    @patch("aether_scout.link_client.request.urlopen")
    def test_http_errors_include_context(self, urlopen):
        error = HTTPError("http://link/assets", 500, "bad", {}, None)
        error.read = Mock(return_value=b"nope")
        urlopen.side_effect = error
        with self.assertRaisesRegex(RuntimeError, "aether-link POST /assets failed: 500 nope"):
            LinkClient("http://link").post_assets([{"id": 1}])


if __name__ == "__main__":
    unittest.main()
