# File: tests/test_fuzz.py
import os
import tempfile
import unittest
from core import fuzz
from config import DATA_DIR, PAYLOADS_DIR

class TestFuzz(unittest.TestCase):
    def setUp(self):
        # Create temporary directory for data
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_data_dir = DATA_DIR
        self.original_payloads_dir = PAYLOADS_DIR
        import config
        config.DATA_DIR = self.temp_dir.name
        config.PAYLOADS_DIR = os.path.join(self.temp_dir.name, "payloads")
        os.makedirs(config.PAYLOADS_DIR, exist_ok=True)
        self.payload_file_path = os.path.join(config.PAYLOADS_DIR, "test.txt")
        with open(self.payload_file_path, "w", encoding="utf-8") as f:
            f.write("test_payload")

    def tearDown(self):
        self.temp_dir.cleanup()
        import config
        config.DATA_DIR = self.original_data_dir
        config.PAYLOADS_DIR = self.original_payloads_dir

    def test_load_payloads(self):
        payloads = fuzz.load_payloads()
        self.assertIn("test_payload", payloads)

if __name__ == '__main__':
    unittest.main()