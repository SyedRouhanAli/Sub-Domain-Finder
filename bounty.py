import requests
import json
import argparse
import re
import sys
from flask import Flask, render_template, request

DEBUG = True  # Set to False to disable debug prints

app = Flask(__name__)

# Function to get subdomains from VirusTotal API with error handling and debug prints
def virustotal_scan(domain, api_key):
    url = f"https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}&apikey={api_key}"
    if DEBUG: print(f"[DEBUG] VirusTotal URL: {url}")
    try:
        response = requests.get(url, timeout=10)
        if DEBUG: print(f"[DEBUG] VirusTotal response status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            if DEBUG: print(f"[DEBUG] VirusTotal data: {data}")
            if 'subdomains' in data and data['subdomains']:
                return data['subdomains']
            else:
                if DEBUG: print("[DEBUG] No subdomains key found or empty subdomains list in VirusTotal response.")
    except Exception as e:
        print(f"[!] Error in VirusTotal API: {e}")
    return []

# Function to get subdomains from Crt.sh with error handling and debug prints
def crtsh_scan(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    if DEBUG: print(f"[DEBUG] crt.sh URL: {url}")
    try:
        response = requests.get(url, timeout=10)
        if DEBUG: print(f"[DEBUG] crt.sh response status: {response.status_code}")
        if response.status_code == 200:
            try:
                crtsh_data = response.json()
                if DEBUG: print(f"[DEBUG] crt.sh data: {crtsh_data}")
                subdomains = set(entry['name_value'] for entry in crtsh_data if 'name_value' in entry)
                return list(subdomains)
            except json.JSONDecodeError as e:
                print(f"[!] JSON Decode Error from crt.sh: {e}")
                return []
    except Exception as e:
        print(f"[!] Error in crt.sh: {e}")
    return []

# Function to get subdomains from Shodan API with error handling and debug prints
def shodan_scan(domain, shodan_api_key):
    url = f"https://api.shodan.io/dns/domain/{domain}?key={shodan_api_key}"
    if DEBUG: print(f"[DEBUG] Shodan URL: {url}")
    try:
        response = requests.get(url, timeout=10)
        if DEBUG: print(f"[DEBUG] Shodan response status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            if DEBUG: print(f"[DEBUG] Shodan data: {data}")
            if 'subdomains' in data and data['subdomains']:
                return [f"{sub}.{domain}" for sub in data['subdomains']]
            else:
                if DEBUG: print("[DEBUG] No subdomains key found or empty subdomains list in Shodan response.")
    except Exception as e:
        print(f"[!] Error in Shodan API: {e}")
    return []

# Function to get subdomains from Wayback Machine with error handling and debug prints
def wayback_scan(domain):
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original"
    if DEBUG: print(f"[DEBUG] Wayback Machine URL: {url}")
    try:
        response = requests.get(url, timeout=10)
        if DEBUG: print(f"[DEBUG] Wayback Machine response status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            if DEBUG: print(f"[DEBUG] Wayback Machine data: {data}")
            subdomains = set()
            # Skip header row if present
            for item in data[1:]:
                if item and len(item) > 0:
                    matches = re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')', item[0])
                    if DEBUG and matches:
                        print(f"[DEBUG] Wayback Machine found matches: {matches}")
                    subdomains.update(matches)
            return list(subdomains)
    except Exception as e:
        print(f"[!] Error in Wayback Machine API: {e}")
    return []

# Combined function to get all subdomains with debug prints
def get_all_subdomains(domain, virustotal_api_key, shodan_api_key):
    if DEBUG: print(f"[DEBUG] Starting subdomain enumeration for: {domain}")
    virustotal_subdomains = virustotal_scan(domain, virustotal_api_key)
    crtsh_subdomains = crtsh_scan(domain)
    shodan_subdomains = shodan_scan(domain, shodan_api_key)
    wayback_subdomains = wayback_scan(domain)
    
    if DEBUG:
        print(f"[DEBUG] VirusTotal returned: {virustotal_subdomains}")
        print(f"[DEBUG] crt.sh returned: {crtsh_subdomains}")
        print(f"[DEBUG] Shodan returned: {shodan_subdomains}")
        print(f"[DEBUG] Wayback Machine returned: {wayback_subdomains}")
    
    all_subdomains = set(virustotal_subdomains + crtsh_subdomains + shodan_subdomains + wayback_subdomains)
    if DEBUG: print(f"[DEBUG] Combined subdomains: {all_subdomains}")
    return list(all_subdomains)

# CLI Main function
def main_cli(domain, virustotal_api_key, shodan_api_key):
    subdomains = get_all_subdomains(domain, virustotal_api_key, shodan_api_key)
    print("\n[+] Subdomains Found:")
    if subdomains:
        for sub in subdomains:
            print(f"  - {sub}")
    else:
        print("  No subdomains found.")

    try:
        with open("subdomains.txt", "w") as f:
            for sub in subdomains:
                f.write(sub + "\n")
        print("\n[+] Subdomains saved to subdomains.txt")
    except Exception as e:
        print(f"[!] Error saving to file: {e}")

# Flask web UI
@app.route('/', methods=['GET', 'POST'])
def index():
    result = {}
    if request.method == 'POST':
        domain = request.form.get('domain')
        virustotal_api_key = request.form.get('virustotal_api_key')
        shodan_api_key = request.form.get('shodan_api_key')
        if domain and virustotal_api_key and shodan_api_key:
            subdomains = get_all_subdomains(domain, virustotal_api_key, shodan_api_key)
            result['subdomains'] = subdomains
            try:
                with open("subdomains.txt", "w") as f:
                    for sub in subdomains:
                        f.write(sub + "\n")
                result['message'] = "Subdomains saved to subdomains.txt"
            except Exception as e:
                result['error'] = f"Error saving file: {e}"
        else:
            result['error'] = "All fields are required."
    return render_template('index.html', result=result)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Subdomain Finder Tool")
    parser.add_argument("--mode", choices=["cli", "web"], default="cli", help="Mode: CLI or web")
    parser.add_argument("-d", "--domain", help="Target Domain")
    parser.add_argument("-v", "--virustotal_api_key", help="VirusTotal API Key")
    parser.add_argument("-s", "--shodan_api_key", help="Shodan API Key")
    args = parser.parse_args()

    if args.mode == "cli":
        if not (args.domain and args.virustotal_api_key and args.shodan_api_key):
            parser.error("For CLI mode, -d, -v, and -s are required.")
        main_cli(args.domain, args.virustotal_api_key, args.shodan_api_key)
    else:
        # Run the web server on port 5000
        app.run(host='0.0.0.0', port=5000, debug=True)
