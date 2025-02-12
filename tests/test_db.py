# File: tests/test_db.py
import os
import sqlite3
import unittest
from core import db

class TestDB(unittest.TestCase):
    def setUp(self):
        # Use an in-memory database for testing
        self.conn = sqlite3.connect(":memory:")
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                parameter TEXT,
                payload TEXT,
                method TEXT,
                similarity REAL,
                gf_matches TEXT,
                nuclei_output TEXT,
                timestamp TEXT
            )
        """)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_insert_and_fetch_vulnerability(self):
        db.insert_vulnerability(self.conn, "http://example.com", "id", "payload", "GET", 0.85, "gf", "nuclei")
        cursor = self.conn.cursor()
        cursor.execute("SELECT url, parameter, payload, method, similarity, gf_matches, nuclei_output FROM vulnerabilities")
        records = cursor.fetchall()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record[0], "http://example.com")
        self.assertEqual(record[1], "id")
        self.assertEqual(record[2], "payload")
        self.assertEqual(record[3], "GET")
        self.assertAlmostEqual(record[4], 0.85)
        self.assertEqual(record[5], "gf")
        self.assertEqual(record[6], "nuclei")

if __name__ == '__main__':
    unittest.main()

