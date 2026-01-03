#!/usr/bin/env python3
"""Minimal, readable file scanner.

This simplified scanner computes SHA-256 hashes, does a lightweight
extension-based risk check, and can save results to JSON. It omits
network calls and complex logic to keep the code concise and easy to
maintain.
"""

import json
import hashlib
import os
import zipfile
from pathlib import Path

# Basic configuration
MAX_FILE_SIZE_MB = 32

SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
SAFE_EXTENSIONS = {".pdf", ".txt", ".jpg", ".png", ".zip"}


class FileScanner:
    """Lightweight file scanner for local use."""

    def __init__(self, api_key=None, auto_extract_archives=True):
        self.api_key = api_key
        self.auto_extract_archives = auto_extract_archives
        self.scan_results = []
        self._seen_hashes = set()

    def get_file_hash(self, file_path):
        """Return SHA-256 hex digest for a file, or None on error."""
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    def check_extension(self, file_path):
        """Return risk label inferred from file extension."""
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            return "SUSPICIOUS"
        if ext in SAFE_EXTENSIONS:
            return "CLEAN"
        return "UNKNOWN"

    def extract_zip(self, zip_path, dest_dir):
        """Extract zip into dest_dir; returns list of extracted files."""
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(dest_dir)
                return [str(Path(dest_dir) / p) for p in z.namelist()]
        except zipfile.BadZipFile:
            return []

    def analyze_file(self, file_path):
        """Analyze a single file and return a concise result dict."""
        file_path = str(file_path)
        filename = os.path.basename(file_path)

        try:
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
        except OSError:
            size_mb = None

        if size_mb is not None and size_mb > MAX_FILE_SIZE_MB:
            result = {
                "file": file_path,
                "filename": filename,
                "status": "SKIPPED",
                "reason": "file too large",
                "risk_level": "UNKNOWN",
            }
            self.scan_results.append(result)
            return result

        fh = self.get_file_hash(file_path)
        if not fh:
            result = {
                "file": file_path,
                "filename": filename,
                "status": "ERROR",
                "reason": "cannot read",
                "risk_level": "UNKNOWN",
            }
            self.scan_results.append(result)
            return result

        if fh in self._seen_hashes:
            result = {
                "file": file_path,
                "filename": filename,
                "status": "DUPLICATE",
                "hash": fh,
                "risk_level": "CLEAN",
            }
            self.scan_results.append(result)
            return result

        self._seen_hashes.add(fh)

        risk = self.check_extension(file_path)
        status = "SCANNED"

        result = {
            "file": file_path,
            "filename": filename,
            "hash": fh,
            "status": status,
            "risk_level": risk,
        }

        self.scan_results.append(result)
        return result

    def scan_directory(self, directory, recursive=True):
        """Scan files in `directory`. Returns collected results."""
        p = Path(directory)
        if recursive:
            files = [f for f in p.rglob("*") if f.is_file()]
        else:
            files = [f for f in p.glob("*") if f.is_file()]

        for f in files:
            res = self.analyze_file(str(f))
            if (
                self.auto_extract_archives
                and str(f).lower().endswith(".zip")
                and res.get("status") == "SCANNED"
            ):
                dest = str(Path(directory) / (Path(f).stem + "_extracted"))
                _ = self.extract_zip(str(f), dest)

        return self.scan_results

    def save_results(self, out_file):
        os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
        with open(out_file, "w", encoding="utf8") as f:
            json.dump(self.scan_results, f, indent=2)

    def get_results(self):
        return list(self.scan_results)
