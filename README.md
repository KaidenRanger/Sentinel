Sentinel Security

A Python-Based File and URL Threat Detection Project

About the Project

Sentinel Security is a Python-based cybersecurity application being developed as a personal portfolio project to explore malware detection, file analysis, URL security, and threat intelligence.

The goal is to build a desktop security tool capable of analyzing files and URLs for potential threats.

This project combines cybersecurity principles with software engineering practices, including modular programming, error handling, automated testing, and version control.

Current Features

File Scanner

SHA-256 file hashing

File name and size analysis

Local JSON malware hash database

Hash-based threat detection

File path validation and error handling

URL Scanner

HTTP and HTTPS URL parsing

Basic URL validation

Detection of unencrypted HTTP links

Identification of IP-based URLs

Detection of URLs containing user information (@ symbol)

Detection of unusually long URLs

Identification of Punycode domain names

Basic phishing risk indicators

The URL scanner performs static analysis without visiting websites or downloading content.

Application Interface

Interactive command-line menu

File and URL scanning options

Ability to perform multiple scans

Error handling and exit functionality

Automated Testing

Unit tests using Python's unittest framework

File scanner tests

URL scanner tests

9 automated tests passing as of version 0.4.0

Technologies

Python 3.14

JSON

Git and GitHub

Python unittest framework

Python standard library (hashlib, pathlib, urllib.parse, ipaddress)

Getting Started

Requirements

Python 3.14

Git (optional, for cloning the repository)

Installation

Clone the repository or download the project files.

Open a terminal inside the Sentinel project directory.

Create a virtual environment:

py -3.14 -m venv .venv

Activate the virtual environment in PowerShell:

.\.venv\Scripts\Activate.ps1

Run Sentinel Security:

python main.py

Using Sentinel

After launching the application, select an option from the main menu:

Scan a File

Scan a URL

Exit Sentinel

For file scanning, enter the path to a local file.

For URL scanning, enter a complete URL beginning with http:// or https://.

Sentinel will analyze the input and display its findings.

Running Automated Tests

Run the complete test suite from the project directory:

python -m unittest discover -v

The test suite checks file hash detection and URL security indicators.

Planned Features

Threat intelligence API integration

Graphical user interface (GUI)

Advanced file analysis

Scan history and reporting

Expanded URL security checks

Additional automated tests

Project Status

Current Version: 0.4.0 — File and URL Scanning

Sentinel Security is under active development.

Development Milestones

v0.1.0: Initial project setup

v0.2.0: File scanning and SHA-256 hashing

v0.3.x: File validation, error handling, and scanning improvements

v0.4.0: URL scanning, interactive menu, and expanded automated testing

Security Disclaimer

Sentinel Security is an educational cybersecurity project and should not be used as a replacement for established antivirus or endpoint protection software.

Hash-based detection identifies only files matching entries in the local database. Similarly, URL scanning identifies basic risk indicators but cannot guarantee that a website is safe.

A result showing no known threats or risk indicators does not mean that a file or URL is harmless.

Developer Notes

This project is being developed as part of my independent learning in cybersecurity and computer science.

Its purpose is to strengthen my understanding of threat detection, secure programming, Python development, software testing, and software engineering.

Sentinel Security is an ongoing portfolio project, with additional security capabilities planned for future releases.