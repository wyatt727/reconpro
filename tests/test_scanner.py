# File: tests/test_scanner.py
import unittest
from core import scanner

class TestScanner(unittest.TestCase):
    def test_extract_parameterized_urls(self):
        urls = [
            "http://example.com",
            "http://example.com/?id=123",
            "http://example.com/?id=123&name=abc",
            "http://example.com/path?foo=bar"
        ]
        result = scanner.extract_parameterized_urls(urls)
        expected = [
            ("http://example.com/?id=123", ["id"]),
            ("http://example.com/?id=123&name=abc", ["id", "name"]),
            ("http://example.com/path?foo=bar", ["foo"])
        ]
        self.assertEqual(len(result), len(expected))
        for (url, params), (exp_url, exp_params) in zip(result, expected):
            self.assertEqual(url, exp_url)
            self.assertListEqual(sorted(params), sorted(exp_params))

if __name__ == '__main__':
    unittest.main()