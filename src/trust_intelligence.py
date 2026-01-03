import json
import sqlite3
from datetime import datetime


class TrustIntelligenceGraph:
    """Build threat intelligence network tracking file origins."""

    def __init__(self, db_path="trust_intelligence.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self._init_tables()

    def _init_tables(self):
        """Create tables for tracking files, origins, and relationships."""
        with self.conn:
            # Files table
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT UNIQUE NOT NULL,
                filename TEXT,
                source_origin TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                vt_score INTEGER,
                risk_level TEXT,
                trust_score REAL DEFAULT 0.5,
                notes TEXT
            )
            """)

            # Sources table
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT UNIQUE NOT NULL,
                source_type TEXT,
                first_observed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                file_count INTEGER DEFAULT 0,
                malware_count INTEGER DEFAULT 0,
                trust_rating REAL DEFAULT 0.5,
                notes TEXT
            )
            """)

            # File relationships
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash1 TEXT NOT NULL,
                file_hash2 TEXT NOT NULL,
                relationship_type TEXT,
                similarity_score REAL,
                detected_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)

            # Audit trail
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT NOT NULL,
                action TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
            """)

    def record_file(self, file_hash, filename, source_origin,
                    vt_score=None, risk_level="UNKNOWN"):
        """Record a file with its origin and initial assessment."""
        with self.conn:
            self.conn.execute("""
            INSERT OR REPLACE INTO files
            (file_hash, filename, source_origin, vt_score,
             risk_level, last_seen)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (file_hash, filename, source_origin, vt_score,
                  risk_level))

        details = f"Source: {source_origin}, Risk: {risk_level}"
        self._log_audit(file_hash, "RECORDED", details)

    def record_source(self, source_name, source_type="UNKNOWN"):
        """Register a file source."""
        with self.conn:
            self.conn.execute("""
            INSERT OR IGNORE INTO sources (source_name, source_type)
            VALUES (?, ?)
            """, (source_name, source_type))

    def link_relationship(self, hash1, hash2, relationship_type,
                          similarity_score=None):
        """Track relationships between files."""
        with self.conn:
            self.conn.execute("""
            INSERT INTO relationships
            (file_hash1, file_hash2, relationship_type, similarity_score)
            VALUES (?, ?, ?, ?)
            """, (hash1, hash2, relationship_type, similarity_score))

        details = (f"Related to {hash2[:8]}... "
                   f"({relationship_type})")
        self._log_audit(hash1, "LINKED", details)

    def update_trust_score(self, file_hash, score):
        """Update trust score for a file."""
        with self.conn:
            self.conn.execute("""
            UPDATE files SET trust_score = ? WHERE file_hash = ?
            """, (score, file_hash))

        self._log_audit(file_hash, "TRUST_UPDATED", f"Score: {score}")

    def update_source_trust(self, source_name, trust_rating):
        """Update trust rating for a source."""
        with self.conn:
            self.conn.execute("""
            UPDATE sources SET trust_rating = ? WHERE source_name = ?
            """, (trust_rating, source_name))

    def _log_audit(self, file_hash, action, details=""):
        """Log action to audit trail."""
        with self.conn:
            self.conn.execute("""
            INSERT INTO audit_log (file_hash, action, details)
            VALUES (?, ?, ?)
            """, (file_hash, action, details))

    def get_file_history(self, file_hash):
        """Get complete history and timeline for a file."""
        cursor = self.conn.execute("""
        SELECT filename, source_origin, first_seen, last_seen,
               vt_score, risk_level, trust_score, notes
        FROM files WHERE file_hash = ?
        """, (file_hash,))

        row = cursor.fetchone()
        if row:
            return {
                "filename": row[0],
                "source": row[1],
                "first_seen": row[2],
                "last_seen": row[3],
                "vt_score": row[4],
                "risk_level": row[5],
                "trust_score": row[6],
                "notes": row[7]
            }
        return None

    def get_source_reputation(self, source_name):
        """Get reputation and statistics for a source."""
        cursor = self.conn.execute("""
        SELECT source_type, first_observed, file_count,
               malware_count, trust_rating, notes
        FROM sources WHERE source_name = ?
        """, (source_name,))

        row = cursor.fetchone()
        if row:
            return {
                "type": row[0],
                "first_observed": row[1],
                "file_count": row[2],
                "malware_count": row[3],
                "trust_rating": row[4],
                "notes": row[5]
            }
        return None

    def get_related_files(self, file_hash):
        """Get all files related to a given file."""
        cursor = self.conn.execute("""
        SELECT file_hash2, relationship_type, similarity_score
        FROM relationships WHERE file_hash1 = ?
        UNION ALL
        SELECT file_hash1, relationship_type, similarity_score
        FROM relationships WHERE file_hash2 = ?
        """, (file_hash, file_hash))

        return [{"hash": row[0], "type": row[1], "similarity": row[2]}
                for row in cursor.fetchall()]

    def get_audit_trail(self, file_hash):
        """Get complete audit log for a file."""
        cursor = self.conn.execute("""
        SELECT action, timestamp, details FROM audit_log
        WHERE file_hash = ? ORDER BY timestamp ASC
        """, (file_hash,))

        return [{"action": row[0], "timestamp": row[1],
                "details": row[2]} for row in cursor.fetchall()]

    def generate_report(self, output_file="trust_report.json"):
        """Generate comprehensive threat intelligence report."""
        # Get top risky sources
        cursor = self.conn.execute("""
        SELECT source_name, file_count, malware_count, trust_rating
        FROM sources ORDER BY malware_count DESC LIMIT 10
        """)
        risky_sources = cursor.fetchall()

        # Get high-risk files
        cursor = self.conn.execute("""
        SELECT file_hash, filename, source_origin, risk_level, vt_score
        FROM files WHERE risk_level IN ('MALICIOUS', 'SUSPICIOUS')
        ORDER BY vt_score DESC LIMIT 20
        """)
        high_risk_files = cursor.fetchall()

        report = {
            "generated": datetime.now().isoformat(),
            "risky_sources": [
                {
                    "name": r[0],
                    "files": r[1],
                    "malware": r[2],
                    "trust_rating": r[3]
                } for r in risky_sources
            ],
            "high_risk_files": [
                {
                    "hash": f[0][:16] + "...",
                    "name": f[1],
                    "source": f[2],
                    "risk": f[3],
                    "vt_score": f[4]
                } for f in high_risk_files
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        return output_file

    def close(self):
        """Close database connection."""
        self.conn.close()
