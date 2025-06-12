import requests
import os
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

def explain_threat(input_text):
    api_key = os.getenv("OPENROUTER_API_KEY") or st.secrets.get("OPENROUTER_API_KEY")
    
    prompt = f"""
Analyze the following threat input and respond in markdown with the following sections:

### Threat Type
What kind of threat is this (e.g. botnet, ransomware, phishing, APT)?

### Indicators of Compromise (IOCs)
List any IPs, domains, file names, or behaviors that may be IOCs.

### MITRE ATT&CK Techniques
List possible techniques with IDs (e.g., T1059 - Command and Scripting Interpreter)

### Risk Assessment
How severe or targeted is this?

### Suggested Analyst Action
What should a SOC analyst or sysadmin do next?

Input:
\"\"\"
{input_text}
\"\"\"
"""

    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "mistralai/mistral-7b-instruct:free",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7
            }
        )

        data = response.json()
        # Debug output to your terminal/logs
        print("🔍 AI RAW RESPONSE:")
        print(data)

        if "choices" in data and len(data["choices"]) > 0:
            return data["choices"][0]["message"]["content"]
        elif "error" in data:
            return f"❌ AI Error: {data['error'].get('message', 'Unknown error')}"
        else:
            return f"❌ Unexpected response structure from AI: {data}"

    except Exception as e:
        return f"❌ Exception while contacting AI: {e}"
