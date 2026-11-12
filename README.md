
# Sentinel Security

**Version:** 0.5.0 (Release Candidate)

Sentinel Security is a Python-based command-line cybersecurity tool designed to analyze files and URLs for potential security threats.

The project demonstrates file hashing, static URL analysis, threat intelligence integration, error handling, and automated testing.

## Features

### 1. File Scanning
- Calculates SHA-256 hashes of files.
- Compares hashes against a local JSON threat database.
- Identifies files matching known malicious hashes.
- Handles invalid file paths.
- Performs local analysis without uploading files.

### 2. URL Scanning
- Validates HTTP and HTTPS URLs.
- Detects unencrypted HTTP connections.
- Flags IP addresses used as hostnames.
- Identifies URLs containing user information.
- Detects unusually long URLs.
- Flags Punycode domains.
- Validates hostname structure and DNS label formatting.
- Rejects malformed URLs.

URL scanning is static and does not visit the target website.

### 3. VirusTotal Threat Intelligence
- Integrates with VirusTotal API v3.
- Retrieves existing URL reputation reports.
- Displays malicious, suspicious, harmless, and undetected counts.
- Requests user permission before each lookup.
- Handles missing API keys, unavailable reports, rate limits, and network errors.

**Note:** Live API verification is pending. The integration has been tested with mocked API responses.

VirusTotal lookups require an API key and transmit URL information to VirusTotal. Avoid submitting private or sensitive URLs.

The integration does not submit URLs for new scans.

### 4. Automated Testing
- Uses Python's built-in unittest framework.
- Includes tests for file scanning, URL scanning, and threat intelligence.
- Uses mocked network responses to test API behavior.

**Current status: 19 automated tests passing.**

## Requirements

- Python 3.14 or a compatible Python 3 version
- Internet access for optional VirusTotal lookups
- VirusTotal API key for reputation lookups

The project uses Python's standard library and does not require additional Python packages.

## Installation

Clone the repository:

```bash
git clone https://github.com/KaidenRanger/Sentinel.git
cd Sentinel
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Running Sentinel

```powershell
python main.py
```

Main menu:

```text
===== MAIN MENU =====
1. Scan a File
2. Scan a URL
3. Exit Sentinel
```

## Configuring VirusTotal

Create a VirusTotal account and obtain an API key.

In PowerShell, configure the key for the current terminal session:

```powershell
$env:VT_API_KEY = Read-Host "Enter VirusTotal API key" -AsSecureString | ConvertFrom-SecureString -AsPlainText
```

Do not commit API keys to GitHub or store them in source code.

The key must be configured again when starting a new terminal session.

## Running Tests

Run all automated tests:

```powershell
python -m unittest discover -v
```

Expected result:

```text
Ran 19 tests in ...

OK
```

## Project Structure

```text
Sentinel/
├── main.py
├── scanner.py
├── url_scanner.py
├── threat_intel.py
├── test_scanner.py
├── test_url_scanner.py
├── test_threat_intel.py
├── hashes.json
├── sentinel_test.txt
├── .gitignore
└── README.md
```

## Security Limitations

Sentinel is an educational cybersecurity project, not a replacement for professional antivirus or endpoint protection.

- A clean hash lookup does not prove a file is safe.
- A URL without suspicious indicators may still be malicious.
- VirusTotal detection counts do not guarantee safety.
- VirusTotal reports may be unavailable or outdated.
- Static URL analysis does not inspect website content.

## Version History

### v0.5.0 - Threat Intelligence Integration (Release Candidate)
- Added VirusTotal API v3 integration.
- Added user consent before external lookups.
- Added API error handling.
- Improved URL validation.
- Added explicit URL validation return values.
- Expanded automated testing to 19 tests.

### v0.4.0 - URL Scanner Improvements
- Improved URL parsing and hostname validation.
- Added phishing-related URL warning indicators.
- Expanded URL scanning tests.

## Planned Improvements

- Scan history
- JSON scan reports
- Improved threat reporting
- Additional automated tests

## Disclaimer

Sentinel Security is intended for educational and authorized security analysis only.
