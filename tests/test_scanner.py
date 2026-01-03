"""Unit tests for file scanner"""

import unittest
import os
import tempfile
from src import FileScanner


class TestFileScanner(unittest.TestCase):
    """Test cases for file scanner"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.api_key = os.getenv("VT_API_KEY", "test_key")
        self.scanner = FileScanner(self.api_key)
    
    def test_scanner_initialization(self):
        """Test scanner initializes correctly"""
        self.assertIsNotNone(self.scanner)
        self.assertEqual(self.scanner.api_key, self.api_key)
    
    def test_file_hash_calculation(self):
        """Test SHA-256 hash calculation"""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test content")
            tmp.flush()
            
            file_hash = self.scanner.get_file_hash(tmp.name)
            self.assertIsNotNone(file_hash)
            self.assertEqual(len(file_hash), 64)  # SHA-256 is 64 hex chars
            
            os.unlink(tmp.name)
    
    def test_scan_results_structure(self):
        """Test scan results have proper structure"""
        result = {
            "file": "test.pdf",
            "hash": "abc123",
            "status": "SCANNED",
            "risk_level": "CLEAN"
        }
        
        self.assertIn("file", result)
        self.assertIn("hash", result)
        self.assertIn("status", result)
        self.assertIn("risk_level", result)


if __name__ == "__main__":
    unittest.main()
