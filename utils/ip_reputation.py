import requests
import streamlit as st

def check_ip_reputation(ip):
    api_key = st.secrets.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return "No AbuseIPDB API key found."

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()["data"]
        result = {
            "IP": data["ipAddress"],
            "Country": data["countryCode"],
            "Abuse Score": data["abuseConfidenceScore"],
            "Last Reported": data.get("lastReportedAt", "N/A")
        }
        return result
    except Exception as e:
        return f"Error: {e}"
