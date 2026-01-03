import os
import json
import shutil
import argparse
from pathlib import Path

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
            # Support both old format (just filename) and new format (full path)
            file_path = result.get("file")
            filename = result.get("filename", os.path.basename(file_path))
            risk = result.get("risk_level", "CLEAN")
            
            # Try to find file (check if it's full path first, then just filename)
            src = None
            if os.path.exists(file_path):
                src = file_path
            elif os.path.exists(os.path.join(self.books_dir, filename)):
                src = os.path.join(self.books_dir, filename)
            
            if not src:
                print(f"  [!] File not found: {filename}")
                continue
            
            if risk == "CLEAN":
                dst = os.path.join(self.approved_dir, filename)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.move(src, dst)
                print(f"✅ {filename}")
                approved += 1
            else:
                dst = os.path.join(self.suspicious_dir, filename)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.move(src, dst)
                print(f"⚠️  {filename}")
                suspicious += 1
        
        print(f"\n[+] Complete: {approved} safe, {suspicious} suspicious\n")
        return approved, suspicious

def main():
    parser = argparse.ArgumentParser(description="Route scanned files to appropriate folders")
    parser.add_argument("-r", "--results", default="./scan_results.json", help="Scan results file")
    parser.add_argument("-d", "--directory", default="./books", help="Source directory")
    parser.add_argument("-b", "--base", default="./files", help="Base routing directory")
    args = parser.parse_args()
    
    router = FileRouter(args.directory, args.base)
    router.organize(args.results)

if __name__ == "__main__":
    main()
