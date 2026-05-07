import unittest

from aether_scout.tools.common import parse_hosts, parse_urls


class ParseTests(unittest.TestCase):
    def test_parse_hosts(self):
        raw = "a.example.com\nhttps://b.example.com/path\nc.example.com 1.2.3.4\n"
        self.assertEqual(parse_hosts(raw), ["a.example.com", "b.example.com", "c.example.com"])

    def test_parse_urls(self):
        raw = "https://a.example.com\nhttp://b.example.com x\nnot-a-url\n"
        self.assertEqual(parse_urls(raw), ["https://a.example.com", "http://b.example.com"])


if __name__ == "__main__":
    unittest.main()
