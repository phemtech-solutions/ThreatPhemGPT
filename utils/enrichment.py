import pandas as pd
import socket

# ---------------- MITRE ATT&CK Mapping ----------------
def get_mitre_chain(threat_type):
    # Extend this as you add more threat types
    threat_type = threat_type.lower()

    if "brute-force" in threat_type and "ssh" in threat_type:
        return pd.DataFrame([
            {"TID": "T1110", "Technique": "Brute Force", "Tactic": "Credential Access"},
            {"TID": "T1078", "Technique": "Valid Accounts", "Tactic": "Persistence"}
        ])

    return pd.DataFrame(columns=["TID", "Technique", "Tactic"])


# ---------------- Sigma Rule Generator ----------------
def generate_sigma_rule(text: str, score: int) -> str:
    if score > 70:
        risk_level = "high"
    elif score > 40:
        risk_level = "moderate"
    else:
        risk_level = "low"

    return f"""title: Possible {risk_level.capitalize()} Threat Detected
logsource:
  product: linux
  service: ssh
detection:
  selection:
    message|contains: "{text}"
  condition: selection
level: {risk_level}
"""


# ---------------- IP Metadata Lookup (Dummy) ----------------
def get_ip_metadata(ip):
    # Replace this with a real API call if needed (ipinfo.io, ip-api.com, etc.)
    return {
        "asn": "AS12345",
        "org": "ExampleOrg ISP",
        "city": "Frankfurt",
        "country": "Germany"
    }


# ---------------- Reverse DNS Lookup ----------------
def get_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ---------------- Playbook Generator ----------------
def generate_playbook(threat_text: str) -> str:
    return f"""
### Incident Response Playbook

**Threat Summary:**  
{threat_text}

**Recommended Actions:**
1. Verify the source IP or domain reputation using threat intelligence services.
2. Block the IP/domain if confirmed malicious.
3. Check logs for repeated or abnormal access patterns.
4. Alert relevant security teams.
5. Capture packets or forensic data if needed.
6. Consider updating firewall or IDS rules based on indicators found.

**Post-Incident:**
- Document all findings and actions taken.
- Conduct a lessons-learned session.
"""
