
# File: tests/test_file_helpers.py
import os
import json
import unittest
import shutil
from utils import file_helpers

class TestFileHelpers(unittest.TestCase):
    def setUp(self):
        # Create a temporary reports directory
        self.reports_dir = "temp_reports"
        os.makedirs(self.reports_dir, exist_ok=True)
        self.original_reports_dir = file_helpers.REPORT_DIR
        file_helpers.REPORT_DIR = self.reports_dir
        # Prepare a dummy scan_results.json
        self.scan_results_path = os.path.join(self.reports_dir, "scan_results.json")
        dummy_results = [
            {"url": "http://example.com", "gf_results": "dummy_gf", "nuclei_results": "dummy_nuclei", "timestamp": "2023-01-01T00:00:00"}
        ]
        with open(self.scan_results_path, "w", encoding="utf-8") as f:
            json.dump(dummy_results, f, indent=4)

    def tearDown(self):
        if os.path.exists(self.reports_dir):
            shutil.rmtree(self.reports_dir)
        file_helpers.REPORT_DIR = self.original_reports_dir

    def test_generate_report(self):
        test_domain = "testdomain"
        report_file = os.path.join(self.reports_dir, f"{test_domain}_report.html")
        if os.path.exists(report_file):
            os.remove(report_file)
        file_helpers.generate_report(test_domain)
        self.assertTrue(os.path.exists(report_file))
        with open(report_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("ReconPro Report for testdomain", content)
        self.assertIn("http://example.com", content)

if __name__ == '__main__':
    unittest.main()


