# 🛡️ File Security Scanner

<div align="center">

![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square)
![Status](https://img.shields.io/badge/status-production%20ready-success?style=flat-square)

**A lightweight, blazing-fast Python tool to scan files and keep your digital assets safe.**

<p>
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-project-structure">Structure</a> •
  <a href="#-license">License</a>
</p>

</div>

---

## ✨ Features

<table>
<tr>
<td>🔍 <b>Smart Scanning</b><br/>Recursive directory scanning with real-time progress</td>
<td>🧮 <b>Hash Detection</b><br/>SHA-256 hashing + duplicate file identification</td>
</tr>
<tr>
<td>📦 <b>ZIP Support</b><br/>Automatic archive extraction & nested scanning</td>
<td>📊 <b>Risk Classification</b><br/>Extension-based threat assessment</td>
</tr>
<tr>
<td>🚀 <b>Auto-Organization</b><br/>Sort files by safety level instantly</td>
<td>📝 <b>Audit Logging</b><br/>Complete chain of custody tracking</td>
</tr>
<tr>
<td>🗄️ <b>Intelligence DB</b><br/>Local threat metadata database</td>
<td>⚡ <b>Lightweight</b><br/>Minimal dependencies, minimal overhead</td>
</tr>
</table>

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/avartan007/file-security-scanner.git
cd file-security-scanner

# Install dependencies
pip install -r requirements.txt

# Copy environment config
cp .env.example .env
```

### Configure

Edit `.env` with your VirusTotal API key (optional):
```bash
VT_API_KEY=your_api_key_here
```

### Run

```bash
python run.py
```

You'll see an interactive menu:
```
============================================================
FILE SECURITY SCANNER
============================================================

  1. Scan files recursively
  2. Organize files by risk
  3. View scan results
  4. Exit

============================================================
```

---

## 📖 Usage

### Interactive Mode (Default)

```bash
python run.py
```

**Menu Options:**
1. **Scan files** - Recursively scan `./books/` directory
2. **Organize** - Sort results into `files/approved` & `files/suspicious`
3. **Results** - View scan summary and file details
4. **Exit** - Quit cleanly

### As a Python Library

```python
from src import FileScanner

# Create scanner instance
scanner = FileScanner(api_key="your_key", auto_extract_archives=True)

# Scan directory
results = scanner.scan_directory("./files", recursive=True)

# Save results to JSON
scanner.save_results("scan_results.json")

# Get results
summary = scanner.get_results()
print(f"Scanned {len(summary)} files")
```

### Advanced: Custom Analysis

```python
from src import FileScanner, FileRouter, TrustIntelligenceGraph

scanner = FileScanner()
router = FileRouter()
intel = TrustIntelligenceGraph()

# Analyze individual file
result = scanner.analyze_file("./file.exe")
print(f"Risk Level: {result['risk_level']}")

# Track file in database
intel.record_file(result['hash'], "file.exe", 
                 source="Manual_Scan",
                 risk_level=result['risk_level'])

intel.close()
```

---

## 📊 Results Classification

| Status | Icon | Meaning |
|--------|------|---------|
| **CLEAN** | ✅ | No threats detected |
| **SUSPICIOUS** | 🟠 | Potential malware |
| **MALICIOUS** | 🔴 | High-risk file |
| **SKIPPED** | ⏭️ | File too large (>32MB) |
| **DUPLICATE** | 🔄 | Already scanned |

---

## 📁 Project Structure

```
file-security-scanner/
├── src/
│   ├── __init__.py                 # Package exports
│   ├── main.py                     # CLI & orchestration
│   ├── file_scanner.py             # Core scanning engine
│   ├── file_router.py              # File organization
│   ├── audit_logger.py             # Audit trail logging
│   └── trust_intelligence.py       # Threat intelligence DB
│
├── books/                          # Input directory (files to scan)
├── files/
│   ├── approved/                   # Safe files
│   ├── suspicious/                 # Flagged files
│   ├── duplicates/                 # Duplicate files
│   └── quarantine/                 # High-risk files
│
├── config/
│   └── config.yaml                 # Configuration file
│
├── run.py                          # Entry point
├── setup.py                        # Package installation
├── requirements.txt                # Runtime dependencies
├── requirements-dev.txt            # Dev tools (removed)
├── .env.example                    # Environment template
├── .gitignore                      # Git ignore rules
├── LICENSE                         # MIT License
└── README.md                       # This file
```

---

## 🔧 How It Works

### 1️⃣ Scanning
- Walks through directory recursively
- Computes SHA-256 hash for each file
- Shows live progress: `[45%] 23/50`
- Checks file extension for risk classification

### 2️⃣ Risk Assessment
- **SUSPICIOUS**: `.exe`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`
- **CLEAN**: `.pdf`, `.txt`, `.jpg`, `.png`, `.zip`
- **UNKNOWN**: Everything else

### 3️⃣ Organization
- Copies safe files → `files/approved/`
- Copies risky files → `files/suspicious/`
- Maintains audit trail in `audit_trail.csv`

### 4️⃣ Intelligence
- Stores file metadata in SQLite database
- Tracks: hash, filename, source, risk_level, timestamp
- Enables duplicate detection & history

---

## ⚙️ Configuration

**Edit `config/config.yaml`:**

```yaml
virustotal:
  api_url: "https://www.virustotal.com/api/v3/"
  request_delay: 16    # Respect rate limits
  timeout: 10

scanner:
  max_file_size_mb: 32
  auto_extract_archives: true

logging:
  level: INFO
  format: "%(asctime)s - %(levelname)s - %(message)s"
```

---

## 📋 Requirements

- **Python**: 3.9 or higher
- **Dependencies**:
  - `requests>=2.31.0` - HTTP client
  - `python-dotenv>=1.0.0` - Environment variables

**Optional (for development):**
- `pytest` - Unit testing
- `flake8` - Code linting
- `black` - Code formatting

---

## 🎯 Example Workflow

```bash
# 1. Place files in ./books/
cp ~/Downloads/*.exe ./books/

# 2. Run scanner
python run.py

# 3. Select "1. Scan files recursively"
# → Scans all files, shows progress bar
# → Saves results to scan_results.json
# → Displays: Clean: 5, Suspicious: 2, Skipped: 1

# 4. Select "2. Organize files"
# → Copies safe files to files/approved/
# → Copies risky files to files/suspicious/
# → Updates trust_intelligence.db

# 5. Select "3. View results"
# → Shows scan summary & breakdown
```

---

## 📝 Output Files

After scanning, you'll have:

| File | Purpose |
|------|---------|
| `scan_results.json` | Scan results (hashes, risk levels) |
| `audit_trail.csv` | Complete action history |
| `trust_intelligence.db` | SQLite metadata database |

---

## 🔐 Security Notes

✅ **Safe to use:**
- No network calls to VirusTotal (optional)
- All processing is local
- No credentials stored in code
- `.env` file is in `.gitignore`

⚠️ **Best practices:**
- Keep your API key in `.env` (not in code)
- Review files before organizing them
- Use on authorized systems only
- Backup important files before scanning

---

## 📜 License

MIT License © 2024 Security Team

See [LICENSE](LICENSE) for details.

---

## 🤝 Support

Found a bug? Have a feature request?
- Open an issue on GitHub
- Include error message & Python version
- Describe your use case

---

<div align="center">

**Made with ❤️ for file security**

⭐ Star this repo if it helps you!

</div>

