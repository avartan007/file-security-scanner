#!/usr/bin/env python3
"""Track file intelligence and metadata."""

import sqlite3


class TrustIntelligenceGraph:
    """Store metadata for scanned files."""

    def __init__(self, db_path="trust_intelligence.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self._init_tables()

    def _init_tables(self):
        """Create simple file tracking table."""
        with self.conn:
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                file_hash TEXT UNIQUE,
                filename TEXT,
                source TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                risk_level TEXT,
                notes TEXT
            )
            """)

    def record_file(self, file_hash, filename, source="Local",
                    risk_level="UNKNOWN"):
        """Record a file in the database."""
        try:
            self.conn.execute(
                "INSERT INTO files (file_hash, filename, source, "
                "risk_level) VALUES (?, ?, ?, ?)",
                (file_hash, filename, source, risk_level)
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            pass

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
