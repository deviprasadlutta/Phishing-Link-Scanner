Phishing Link Scanner
A simple tool to detect and analyze potentially malicious phishing URLs using the VirusTotal API. This repository includes both the original Python script (Phishing_Scanner.py) and a compiled Windows executable (Phishing_Scanner.exe).

Features
Scans URLs for phishing, malware, and suspicious activity using the VirusTotal API

Aggregates results from multiple security vendors

Provides a clear risk assessment

Easy to use: just run and enter the URL

Getting Started
Files Included
Phishing_Scanner.py — The main Python script

Phishing_Scanner.exe — Compiled Windows executable

Usage
Option 1: Run the Executable (Recommended for Windows)
Locate Phishing_Scanner.exe in the project folder.

Double-click the file to launch the scanner.

Enter the URL you want to check when prompted.

View the results directly in the window.

Option 2: Run the Python Script
Make sure you have Python 3 installed.

Double-click Phishing_Scanner.py
or
Right-click the file and choose Open with > Python.

Alternatively, you can open Command Prompt, navigate to the folder, and type:

text
python Phishing_Scanner.py
Enter the URL you want to check when prompted.

How It Works
Enter the URL you want to check.

The tool uses the embedded VirusTotal API to analyze the URL.

Results are displayed, indicating whether the link is safe or potentially malicious.

Note: The VirusTotal API key is already embedded in the code. No additional setup is required.

License
Distributed under the MIT License. See LICENSE for details.

Author: [Your Name]
Project Link: https://github.com/your_username/phishing-link-scanner
