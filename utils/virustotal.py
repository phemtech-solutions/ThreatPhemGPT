import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set VirusTotal API key
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
headers = {
    "x-apikey": VT_API_KEY
}

# Lookup IP reputation
def lookup_ip(ip):
    url = f"{VT_BASE_URL}/ip_addresses/{ip}"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return parse_vt_response(data)
    except Exception as e:
        return f"Error fetching VirusTotal data for IP: {str(e)}"

# Lookup domain reputation
def lookup_domain(domain):
    url = f"{VT_BASE_URL}/domains/{domain}"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return parse_vt_response(data)
    except Exception as e:
        return f"Error fetching VirusTotal data for domain: {str(e)}"

# Parse common VT response
def parse_vt_response(data):
    attributes = data.get("data", {}).get("attributes", {})
    return {
        "Malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
        "Suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
        "Harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
        "Undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
        "Categories": attributes.get("categories", {}),
        "First Seen": attributes.get("first_seen", "N/A"),
        "Last Seen": attributes.get("last_analysis_date", "N/A")
    }
