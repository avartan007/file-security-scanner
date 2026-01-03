#!/usr/bin/env python3
"""Route scanned files to safety folders."""

import os
import json
import shutil


class FileRouter:
    """Organize files by safety level."""

    def __init__(self, books_dir="./books", files_dir="./files"):
        self.books_dir = books_dir
        self.approved_dir = os.path.join(files_dir, "approved")
        self.suspicious_dir = os.path.join(files_dir, "suspicious")

        os.makedirs(self.approved_dir, exist_ok=True)
        os.makedirs(self.suspicious_dir, exist_ok=True)

    def organize(self, results_file):
        """Organize files based on scan results."""
        if not os.path.exists(results_file):
            print("[!] No scan results found")
            return 0, 0

        with open(results_file, 'r') as f:
            results = json.load(f)

        print(f"\n[*] Organizing {len(results)} files...\n")

        approved = 0
        suspicious = 0

        for result in results:
            file_path = result.get("file")
            filename = result.get("filename", os.path.basename(file_path))
            risk = result.get("risk_level", "CLEAN")

            if not os.path.exists(file_path):
                continue

            if risk == "CLEAN":
                dst = os.path.join(self.approved_dir, filename)
                shutil.copy2(file_path, dst)
                print(f"  ✅ {filename}")
                approved += 1
            else:
                dst = os.path.join(self.suspicious_dir, filename)
                shutil.copy2(file_path, dst)
                print(f"  ⚠️  {filename}")
                suspicious += 1

        print(f"\n[+] Organized {approved + suspicious} files")
        print(f"    Approved:   {approved}")
        print(f"    Suspicious: {suspicious}\n")

        return approved, suspicious
