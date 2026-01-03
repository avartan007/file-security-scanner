#!/usr/bin/env python3
"""File Security Scanner - Main Entry Point"""

import os
import sys
import json
from dotenv import load_dotenv
from .file_scanner import FileScanner
from .file_router import FileRouter
from .trust_intelligence import TrustIntelligenceGraph

load_dotenv()


class SecurityPipeline:
    """Main workflow controller - orchestrates scanning and organization."""

    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.books_dir = "./books"
        self.files_dir = "./files"
        self.results_file = "./scan_results.json"

        if not self.api_key:
            print("[!] ERROR: VT_API_KEY not set in .env")
            sys.exit(1)

        # Create directories
        os.makedirs(self.books_dir, exist_ok=True)
        os.makedirs(self.files_dir, exist_ok=True)
        os.makedirs(os.path.join(self.files_dir, "approved"),
                    exist_ok=True)
        os.makedirs(os.path.join(self.files_dir, "suspicious"),
                    exist_ok=True)

    def show_menu(self):
        """Display main menu."""
        print("\n" + "="*60)
        print("FILE SECURITY SCANNER")
        print("="*60)
        print("\n1. Scan files (recursive)")
        print("2. Organize files")
        print("3. View results")
        print("4. Exit\n")

    def option_scan(self):
        """Scan files recursively."""
        print("\n[*] Scanning files in ./books/ "
              "(including subdirectories)\n")

        scanner = FileScanner(self.api_key, auto_extract_archives=True)
        scanner.scan_directory(self.books_dir, recursive=True)
        scanner.save_results(self.results_file)

    def option_organize(self):
        """Organize scanned files."""
        if not os.path.exists(self.results_file):
            print("[!] No scan results. Run scan first.")
            return

        print("\n[*] Organizing files...\n")

        router = FileRouter(self.books_dir, self.files_dir)
        approved, suspicious = router.organize(self.results_file)

        # Record in trust intelligence
        ti = TrustIntelligenceGraph()
        with open(self.results_file, 'r') as f:
            results = json.load(f)

        for result in results:
            file_hash = result.get("hash", "unknown")[:16]
            filename = result.get("file")
            risk = result.get("risk_level", "UNKNOWN")
            ti.record_file(file_hash, filename, "Local_Scan",
                           risk_level=risk)

        ti.close()
        print("[+] Intelligence database updated")

    def option_results(self):
        """Show scan results."""
        if not os.path.exists(self.results_file):
            print("[!] No results yet")
            return

        with open(self.results_file, 'r') as f:
            results = json.load(f)

        clean = sum(1 for r in results
                    if r.get("risk_level") == "CLEAN")
        suspicious = sum(1 for r in results
                         if r.get("risk_level") != "CLEAN")

        print("\n[*] Scan Results")
        print(f"    Total files: {len(results)}")
        print(f"    Safe: {clean}")
        print(f"    Suspicious: {suspicious}\n")

        # Show files
        print("Files by status:")
        for r in results:
            status = "✅" if r.get("risk_level") == "CLEAN" else "⚠️"
            print(f"  {status} {r.get('file')} - {r.get('risk_level')}")

    def run(self):
        """Main loop."""
        while True:
            self.show_menu()
            choice = input("Enter choice (1-4): ").strip()

            if choice == "1":
                self.option_scan()
            elif choice == "2":
                self.option_organize()
            elif choice == "3":
                self.option_results()
            elif choice == "4":
                print("[+] Goodbye!")
                sys.exit(0)
            else:
                print("[!] Invalid choice")


def main():
    pipeline = SecurityPipeline()
    pipeline.run()


if __name__ == "__main__":
    main()
