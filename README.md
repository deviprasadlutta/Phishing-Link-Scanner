Phishing Link Scanner

Phishing Link Scanner is a Python-based tool designed to detect and analyze potentially malicious URLs. It utilizes the VirusTotal API to check URLs against a large database of known threats, helping users identify phishing and malicious links. A standalone .exe file is also provided for users who prefer not to install Python or dependencies.

Features
Scans URLs for phishing indicators

Integration with the VirusTotal API for threat intelligence

User-friendly GUI built with Tkinter

Available as both a Python script and standalone Windows executable

VirusTotal API Integration
This tool uses the VirusTotal Public API to analyze URLs. The API returns reputation scores and threat classifications from multiple antivirus engines and URL scanning services.

To use the tool, you need to generate your own VirusTotal API key:

Create a free account at https://www.virustotal.com

Navigate to your profile and copy your API key

Paste the API key into the script (phishing_scanner.py) where indicated:

python
Copy
Edit
API_KEY = "your_api_key_here"
Prerequisites
To run the Python script, ensure you have the following:

Python 3.x

Required packages:

bash
Copy
Edit
pip install requests tkinter
How to Use
Running the Python Script
Clone or download this repository.

Install dependencies using pip.

Add your VirusTotal API key to the script.

Run the tool:

bash
Copy
Edit
python phishing_scanner.py
Running the Executable
Download PhishingLinkScanner.exe from the dist or release folder.

Launch the application by double-clicking the file.

Enter any URL to scan using VirusTotal.

Future Enhancements
Add support for other threat intelligence APIs

Save scan results locally

Add command-line interface (CLI) mode

Convert to cross-platform GUI application (e.g., using PyQt)

Author
Deviprasad

License
This project is licensed under the MIT License. See the LICENSE file for more information.
