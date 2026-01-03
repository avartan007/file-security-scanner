# File Security Scanner

A lightweight Python tool to scan files against 70+ antivirus engines using the VirusTotal API.

## Features

- **Recursive scanning** - Scan all files in directories and subdirectories
- **VirusTotal integration** - Check against 70+ antivirus engines
- **Duplicate detection** - Identify identical files by hash
- **ZIP handling** - Automatically extract and scan archive contents
- **Auto-organization** - Sort files by safety level (approved/suspicious)
- **Audit trails** - Track chain of custody for scanned files
- **Threat database** - Personal threat intelligence records

## Installation

```bash
git clone https://github.com/yourusername/file-security-scanner.git
cd file-security-scanner
pip install -r requirements.txt
```

## Configuration

1. Get a free API key from [VirusTotal](https://www.virustotal.com/gui/)
2. Copy `.env.example` to `.env`
3. Add your API key to `.env`:
   ```
   VT_API_KEY=your_api_key_here
   ```

## Usage

### Interactive Mode
```bash
python run.py
```

Menu options:
1. Scan files recursively
2. Organize files by safety level
3. View scan results
4. Exit

### As a Library
```python
from src import FileScanner

scanner = FileScanner(api_key="your_key")
scanner.scan_directory("./files", recursive=True)
scanner.save_results("results.json")
```

## Project Structure

```
src/
├── file_scanner.py      # Core scanning engine
├── main.py              # Interactive menu
├── file_router.py       # File organization
├── trust_intelligence.py # Threat database
├── audit_logger.py      # Audit trails
└── __init__.py

books/                   # Files to scan
files/
├── approved/           # Safe files
└── suspicious/         # Flagged files
```

## Results

Files are classified as:
- **CLEAN** ✅ - No threats detected
- **SUSPICIOUS** 🟠 - Malware detected
- **MALICIOUS** 🔴 - High risk file
- **SKIPPED** ⏭️ - File too large (>32MB)

## Requirements

- Python 3.9+
- requests
- python-dotenv

## Testing

```bash
python -m pytest tests/
```

## License

MIT

## Disclaimer

This tool is for authorized security testing only. Always have proper authorization before scanning files you don't own.

