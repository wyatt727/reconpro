# reconpro/core/db.py
import sqlite3
import aiosqlite
import json
import logging
import asyncio
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class ScanResult:
    """Data class for scan results"""
    id: Optional[int]
    url: str
    parameter: str
    payload: str
    method: str
    similarity: float
    response_time: float
    status_code: int
    content_length: int
    gf_matches: List[str]
    nuclei_output: str
    reflection_count: int
    error_patterns: List[str]
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
        if isinstance(self.gf_matches, str):
            self.gf_matches = json.loads(self.gf_matches)
        if isinstance(self.error_patterns, str):
            self.error_patterns = json.loads(self.error_patterns)

class DatabaseManager:
    """Advanced database manager with async support"""
    def __init__(self, db_path: str = "reconpro_results.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._connection_pool = {}
        self._init_db()

    def _init_db(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    parameter TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    method TEXT NOT NULL,
                    similarity REAL NOT NULL,
                    response_time REAL NOT NULL,
                    status_code INTEGER NOT NULL,
                    content_length INTEGER NOT NULL,
                    gf_matches TEXT NOT NULL,
                    nuclei_output TEXT NOT NULL,
                    reflection_count INTEGER NOT NULL,
                    error_patterns TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    subdomains_found INTEGER NOT NULL,
                    urls_collected INTEGER NOT NULL,
                    parameters_found INTEGER NOT NULL,
                    vulnerabilities_found INTEGER NOT NULL,
                    timestamp TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scan_results_url ON scan_results(url);
                CREATE INDEX IF NOT EXISTS idx_scan_results_method ON scan_results(method);
                CREATE INDEX IF NOT EXISTS idx_scan_results_timestamp ON scan_results(timestamp);
                CREATE INDEX IF NOT EXISTS idx_scan_metadata_domain ON scan_metadata(domain);
                CREATE INDEX IF NOT EXISTS idx_scan_metadata_timestamp ON scan_metadata(timestamp);
            """)

    @asynccontextmanager
    async def get_connection(self) -> aiosqlite.Connection:
        """Get a database connection from the pool"""
        task_id = id(asyncio.current_task())
        if task_id not in self._connection_pool:
            self._connection_pool[task_id] = await aiosqlite.connect(self.db_path)
            self._connection_pool[task_id].row_factory = aiosqlite.Row

        try:
            yield self._connection_pool[task_id]
        except Exception as e:
            self.logger.error("Database error: %s", e)
            raise
        finally:
            if len(self._connection_pool) > 10:  # Limit pool size
                await self._connection_pool[task_id].close()
                del self._connection_pool[task_id]

    async def save_result(self, result: ScanResult) -> int:
        """Save a scan result to the database"""
        async with self.get_connection() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute("""
                    INSERT INTO scan_results (
                        url, parameter, payload, method, similarity,
                        response_time, status_code, content_length,
                        gf_matches, nuclei_output, reflection_count,
                        error_patterns, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.url, result.parameter, result.payload,
                    result.method, result.similarity, result.response_time,
                    result.status_code, result.content_length,
                    json.dumps(result.gf_matches), result.nuclei_output,
                    result.reflection_count, json.dumps(result.error_patterns),
                    result.timestamp
                ))
                await conn.commit()
                return cursor.lastrowid

    async def get_results(
        self,
        method: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 1000
    ) -> List[ScanResult]:
        """Get scan results with filtering"""
        query = "SELECT * FROM scan_results WHERE 1=1"
        params = []

        if method:
            query += " AND method = ?"
            params.append(method)
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        async with self.get_connection() as conn:
            async with conn.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [ScanResult(**dict(row)) for row in rows]

    async def get_statistics(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get scan statistics"""
        async with self.get_connection() as conn:
            async with conn.execute("""
                SELECT 
                    COUNT(*) as total_vulns,
                    SUM(CASE WHEN method = 'GET' THEN 1 ELSE 0 END) as get_count,
                    SUM(CASE WHEN method = 'POST' THEN 1 ELSE 0 END) as post_count,
                    AVG(similarity) as avg_similarity,
                    AVG(response_time) as avg_response_time,
                    COUNT(DISTINCT url) as unique_urls
                FROM scan_results
                WHERE (:start_date IS NULL OR timestamp >= :start_date)
                AND (:end_date IS NULL OR timestamp <= :end_date)
            """, {"start_date": start_date, "end_date": end_date}) as cursor:
                stats = dict(await cursor.fetchone())

            # Get vulnerability trends
            async with conn.execute("""
                SELECT DATE(timestamp) as date, COUNT(*) as count
                FROM scan_results
                WHERE (:start_date IS NULL OR timestamp >= :start_date)
                AND (:end_date IS NULL OR timestamp <= :end_date)
                GROUP BY DATE(timestamp)
                ORDER BY date
            """, {"start_date": start_date, "end_date": end_date}) as cursor:
                stats['trends'] = [dict(row) for row in await cursor.fetchall()]

            return stats

    async def cleanup_old_results(self, days: int = 30):
        """Clean up old scan results"""
        async with self.get_connection() as conn:
            await conn.execute("""
                DELETE FROM scan_results
                WHERE timestamp < datetime('now', '-' || ? || ' days')
            """, (days,))
            await conn.commit()

    async def export_results(self, output_file: str):
        """Export scan results to JSON"""
        results = await self.get_results()
        data = {
            'scan_results': [asdict(result) for result in results],
            'statistics': await self.get_statistics(),
            'export_time': datetime.utcnow().isoformat()
        }
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

# Global database instance
db = DatabaseManager()

# Convenience functions
async def save_scan_result(result: Union[ScanResult, Dict[str, Any]]) -> int:
    """Save a scan result"""
    if isinstance(result, dict):
        result = ScanResult(**result)
    return await db.save_result(result)

async def get_scan_results(**kwargs) -> List[ScanResult]:
    """Get scan results with filtering"""
    return await db.get_results(**kwargs)

async def get_scan_statistics(**kwargs) -> Dict[str, Any]:
    """Get scan statistics"""
    return await db.get_statistics(**kwargs)
