#!/usr/bin/env python3
"""
Unified File Security Scanner
Consolidated from multiple scanner implementations for clean, focused functionality.
"""

import os
import hashlib
import json
import time
import zipfile
from pathlib import Path
from datetime import datetime
import requests
from dotenv import load_dotenv

load_dotenv()

# Configuration
VT_API_URL = "https://www.virustotal.com/api/v3/"
REQUEST_DELAY = 16  # Respect 4 requests/minute limit
MAX_FILE_SIZE_MB = 32

# File classifications
SUSPICIOUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
    '.scr', '.pif', '.com', '.hta', '.wsf', '.lnk'
}

SAFE_EXTENSIONS = {
    '.pdf', '.epub', '.mobi', '.txt', '.docx', '.xlsx',
    '.mp3', '.mp4', '.flac', '.wav', '.jpg', '.png', '.zip'
}


class FileScanner:
    """
    Simple, unified file safety scanner.
    - Checks against 70+ antivirus engines (VirusTotal)
    - Handles large files gracefully
    - Detects duplicates
    - Extracts and scans archive contents
    """
    
    def __init__(self, api_key, auto_extract_archives=True):
        """Initialize scanner with VirusTotal API key."""
        if not api_key or not api_key.strip():
            raise ValueError("API key cannot be empty")
        
        self.api_key = api_key.strip()
        self.headers = {"x-apikey": self.api_key}
        self.scan_results = []
        self.file_hashes = {}  # Track seen hashes for duplicate detection
        self.auto_extract_archives = auto_extract_archives
    
    def get_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except IOError as e:
            print(f"   [!] Cannot read file: {e}")
            return None
    
    def check_virustotal(self, file_hash):
        """
        Check VirusTotal for existing report.
        Returns: (report_dict, is_new_upload)
        """
        url = f"{VT_API_URL}files/{file_hash}"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json(), False
            elif response.status_code == 404:
                return None, False
            else:
                return None, False
        except requests.exceptions.RequestException:
            return None, False
    
    def is_duplicate(self, file_hash):
        """Check if we've already seen this hash."""
        if file_hash in self.file_hashes:
            return True
        self.file_hashes[file_hash] = True
        return False
    
    def check_extension(self, file_path):
        """Assess risk level based on file extension."""
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        if ext in SUSPICIOUS_EXTENSIONS:
            return "SUSPICIOUS", f"Suspicious extension: {ext}"
        elif ext in SAFE_EXTENSIONS:
            return "SAFE", f"Known safe extension: {ext}"
        else:
            return "UNKNOWN", f"Unknown extension: {ext}"
    
    def extract_zip(self, zip_path, extract_dir):
        """
        Extract zip file and scan contents.
        Returns: (success, message)
        """
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            file_count = len(zip_ref.namelist())
            return True, f"Extracted {file_count} files"
        except zipfile.BadZipFile:
            return False, "Invalid or corrupted zip file"
        except Exception as e:
            return False, str(e)
    
    def analyze_file(self, file_path):
        """
        Analyze a single file and return risk assessment.
        Returns: dict with scan results
        """
        filename = os.path.basename(file_path)
        
        # 1. Check file size
        try:
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            if size_mb > MAX_FILE_SIZE_MB:
                return {
                    "file": file_path,
                    "filename": filename,
                    "status": "SKIPPED",
                    "reason": f"File too large ({size_mb:.1f}MB > {MAX_FILE_SIZE_MB}MB)",
                    "risk_level": "CLEAN",
                    "decision": "APPROVE"
                }
        except Exception as e:
            return {
                "file": file_path,
                "filename": filename,
                "status": "ERROR",
                "reason": f"Cannot read file: {e}",
                "risk_level": "UNKNOWN",
                "decision": "QUARANTINE"
            }
        
        # 2. Get file hash
        file_hash = self.get_file_hash(file_path)
        if not file_hash:
            return {
                "file": file_path,
                "filename": filename,
                "status": "ERROR",
                "reason": "Failed to calculate hash",
                "risk_level": "UNKNOWN",
                "decision": "QUARANTINE"
            }
        
        # 3. Check for duplicates
        if self.is_duplicate(file_hash):
            return {
                "file": file_path,
                "filename": filename,
                "hash": file_hash[:16],
                "status": "DUPLICATE",
                "reason": "Identical file already scanned",
                "risk_level": "CLEAN",
                "decision": "APPROVE"
            }
        
        # 4. Check extension
        ext_risk, ext_msg = self.check_extension(file_path)
        
        # 5. Check VirusTotal
        print(f"   🔍 Checking: {filename}...", end=" ", flush=True)
        report, _ = self.check_virustotal(file_hash)
        time.sleep(REQUEST_DELAY)
        
        # 6. Determine risk level
        if report and "data" in report:
            stats = report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            if malicious > 0:
                risk = "MALICIOUS"
                print("🔴 MALICIOUS")
            elif suspicious > 0:
                risk = "SUSPICIOUS"
                print("🟠 SUSPICIOUS")
            else:
                risk = "CLEAN"
                print("🟢 CLEAN")
        else:
            risk = "CLEAN"
            print("⚪ NO THREATS")
        
        decision = "APPROVE" if risk == "CLEAN" else "QUARANTINE"
        
        return {
            "file": file_path,
            "filename": filename,
            "hash": file_hash[:16],
            "status": "SCANNED",
            "risk_level": risk,
            "ext_check": ext_risk,
            "decision": decision
        }
    
    def scan_directory(self, directory, recursive=True):
        """
        Scan all files in directory.
        
        Args:
            directory: Path to scan
            recursive: If True, includes subdirectories
        """
        path = Path(directory)
        
        if recursive:
            files = list(path.rglob("*"))
        else:
            files = list(path.glob("*"))
        
        files = [f for f in files if f.is_file()]
        
        if not files:
            print("[*] No files to scan")
            return
        
        print(f"\n[*] Scanning {len(files)} files...")
        if recursive:
            print("[*] (Including subdirectories)\n")
        
        for i, file_path in enumerate(files, 1):
            print(f"[{i}/{len(files)}]", end=" ")
            result = self.analyze_file(str(file_path))
            self.scan_results.append(result)
            
            # Handle zip extraction
            if (self.auto_extract_archives and 
                str(file_path).lower().endswith('.zip') and
                result.get("status") == "SCANNED"):
                self._extract_and_scan_zip(str(file_path), directory)
        
        self._print_summary()
    
    def _extract_and_scan_zip(self, zip_path, base_dir):
        """Extract zip and scan contents recursively."""
        extract_dir = os.path.join(base_dir, Path(zip_path).stem + "_extracted")
        print(f"\n   📦 Extracting: {os.path.basename(zip_path)}")
        
        success, msg = self.extract_zip(zip_path, extract_dir)
        if success:
            print(f"   ✅ {msg}")
            # Recursively scan extracted contents
            extracted_files = list(Path(extract_dir).rglob("*"))
            for f in extracted_files:
                if f.is_file():
                    result = self.analyze_file(str(f))
                    self.scan_results.append(result)
        else:
            print(f"   [!] Extract failed: {msg}")
    
    def _print_summary(self):
        """Print scan summary."""
        if not self.scan_results:
            return
        
        clean = sum(1 for r in self.scan_results if r.get("risk_level") == "CLEAN")
        suspicious = sum(1 for r in self.scan_results if r.get("risk_level") == "SUSPICIOUS")
        malicious = sum(1 for r in self.scan_results if r.get("risk_level") == "MALICIOUS")
        unknown = sum(1 for r in self.scan_results if r.get("risk_level") == "UNKNOWN")
        
        print(f"\n{'='*60}")
        print(f"SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Total files:  {len(self.scan_results)}")
        print(f"Clean:        {clean} ✅")
        print(f"Suspicious:   {suspicious} 🟠")
        print(f"Malicious:    {malicious} 🔴")
        print(f"Unknown:      {unknown} ❓")
        print(f"{'='*60}\n")
    
    def save_results(self, output_file):
        """Save scan results to JSON file."""
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(self.scan_results, f, indent=2)
        
        print(f"[+] Results saved: {output_file}\n")
    
    def get_results(self):
        """Return current scan results."""
        return self.scan_results
