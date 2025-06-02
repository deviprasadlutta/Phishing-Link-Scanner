import os
import time
import requests
from dotenv import load_dotenv
import tkinter as tk
from tkinter import messagebox

# Load .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    raise Exception("VirusTotal API key not found. Make sure it's set in the .env file.")

# Submit the URL to VirusTotal
def scan_url(url):
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.post(endpoint, headers=headers, data={"url": url})
    
    if response.status_code == 200:
        return response.json()["data"]["id"]
    else:
        raise Exception(f"Error submitting URL: {response.json()}")

# Get the analysis result
def get_report(scan_id):
    endpoint = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {"x-apikey": VT_API_KEY}
    
    time.sleep(15)  # Wait for analysis
    
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["stats"]
        return stats
    else:
        raise Exception(f"Error getting report: {response.json()}")

# On button click
def start_scan():
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL to scan.")
        return

    try:
        scan_id = scan_url(url)
        result = get_report(scan_id)

        message = (
            f"Scan Result for {url}\n\n"
            f"Malicious: {result.get('malicious', 0)}\n"
            f"Suspicious: {result.get('suspicious', 0)}\n"
            f"Harmless: {result.get('harmless', 0)}\n"
            f"Undetected: {result.get('undetected', 0)}"
        )
        messagebox.showinfo("Scan Complete", message)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Setup
root = tk.Tk()
root.title("VirusTotal URL Scanner")
root.geometry("400x200")

tk.Label(root, text="Enter URL to Scan:").pack(pady=10)
url_entry = tk.Entry(root, width=50)
url_entry.pack(pady=5)

tk.Button(root, text="Scan URL", command=start_scan).pack(pady=20)

root.mainloop()
