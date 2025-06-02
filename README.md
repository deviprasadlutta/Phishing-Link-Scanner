# Phishing-Link-Scanner

A simple tool to detect and analyze potentially malicious phishing URLs using the VirusTotal API. This repository includes both the original Python script (Phishing_Scanner.py) and a compiled Windows executable (Phishing_Scanner.exe) for ease of use.

Features
Scans URLs for phishing, malware, and suspicious activity using the VirusTotal API

Aggregates results from multiple security vendors

Provides a clear risk assessment

Easy to use: just run and enter the URL

Getting Started
1. Clone the Repository
'''bash
git clone https://github.com/deviprasadlutta/Phishing-Link-Scanner.git

cd phishing-link-scanner
3. Files Included
Phishing_Scanner.py — The main Python script

Phishing_Scanner.exe — Compiled Windows executable

Usage
Run with Python
Simply execute the script:

'''bash
python Phishing_Scanner.py
Run the Executable
Double-click Phishing_Scanner.exe and follow the on-screen instructions.

How It Works
Enter the URL you want to check when prompted.

The tool uses the embedded VirusTotal API to analyze the URL.

Results are displayed, indicating whether the link is safe or potentially malicious.

Note: The VirusTotal API key is already embedded in the code. No additional setup is required.

License
Distributed under the MIT License. See LICENSE for details.

Author: Deviprasadlutta
Project Link: https://github.com/deviprasadlutta/Phishing-Link-Scanner
