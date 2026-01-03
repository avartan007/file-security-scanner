#!/usr/bin/env python3
"""Audit logging for file operations."""

import csv
from datetime import datetime
from pathlib import Path


class AuditLogger:
    """Log file operations for chain of custody."""

    def __init__(self, log_file="audit_trail.csv"):
        self.log_file = log_file
        self._init_log()

    def _init_log(self):
        """Initialize audit log with headers."""
        if not Path(self.log_file).exists():
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Timestamp", "File Hash", "Filename",
                    "Action", "Risk Level", "Status"
                ])

    def log_action(self, file_hash, filename, action,
                   risk_level="UNKNOWN", status="OK"):
        """Log an action to the audit trail."""
        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                file_hash,
                filename,
                action,
                risk_level,
                status
            ])
