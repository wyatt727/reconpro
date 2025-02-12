# File: tests/test_scraper.py
import unittest
from core import scraper

class TestScraper(unittest.TestCase):
    def test_extract_links(self):
        html_content = """
        <html>
            <head><title>Test</title></head>
            <body>
                <a href="http://example.com">Example</a>
                <a href="http://example.org">Example Org</a>
            </body>
        </html>
        """
        links = scraper.extract_links(html_content)
        expected_links = {"http://example.com", "http://example.org"}
        self.assertEqual(links, expected_links)

if __name__ == '__main__':
    unittest.main()


