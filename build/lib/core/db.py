# reconpro/core/db.py
import sqlite3
from datetime import datetime

DATABASE = "reconpro_results.db"

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
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
    conn.commit()
    return conn

def insert_vulnerability(conn, url, parameter, payload, method, similarity, gf_matches, nuclei_output):
    cursor = conn.cursor()
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO vulnerabilities (url, parameter, payload, method, similarity, gf_matches, nuclei_output, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (url, parameter, payload, method, similarity, gf_matches, nuclei_output, timestamp))
    conn.commit()

def fetch_all(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vulnerabilities")
    return cursor.fetchall()

def close_db(conn):
    conn.close()
