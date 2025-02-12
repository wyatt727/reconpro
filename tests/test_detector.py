# File: tests/test_detector.py
import unittest
from core import detector

class TestDetector(unittest.TestCase):
    def test_is_method_not_allowed(self):
        response = {"status": 405}
        self.assertTrue(detector.is_method_not_allowed(response))
        response = {"status": 200}
        self.assertFalse(detector.is_method_not_allowed(response))

    def test_is_api_endpoint(self):
        response = {"headers": {"Content-Type": "application/json; charset=utf-8"}}
        self.assertTrue(detector.is_api_endpoint(response))
        response = {"headers": {"Content-Type": "text/html"}}
        self.assertFalse(detector.is_api_endpoint(response))
        response = {}
        self.assertFalse(detector.is_api_endpoint(response))

if __name__ == '__main__':
    unittest.main()


