import streamlit as st
from utils.enrichment import get_mitre_chain, generate_sigma_rule, get_ip_metadata, get_reverse_dns, generate_playbook
from utils.ai import explain_threat
from utils.ip_reputation import check_ip_reputation
from utils.virustotal import lookup_ip, lookup_domain
import re
import socket

st.set_page_config(page_title="ThreatGPT – AI-Powered Threat Intel Explainer", layout="wide")

st.title("🛡️ ThreatGPT – AI-Powered Threat Intel Explainer")
st.markdown("Paste an IP, domain, or snippet from a threat report to get AI-driven analysis.")

user_input = st.text_area("📥 Enter threat data (IP, domain, or report text):", height=150)

if st.button("🔍 Analyze Threat"):
    if user_input.strip() == "":
        st.warning("Please enter a valid input.")
    else:
        with st.spinner("Analyzing threat intelligence..."):
            input_lower = user_input.lower()
            score = 0

            # Suspicious indicators
            if any(word in input_lower for word in ["ssh", "brute force", "failed login", "exploit", "reverse shell"]):
                score += 40
            if any(tld in input_lower for tld in [".xyz", ".top", ".link", ".ru", ".cn", ".tk", ".pw"]):
                score += 25
            if re.search(r"[a-z0-9\-]{25,}\.(com|net|org|info)", input_lower):
                score += 15
            if any(ip_prefix in input_lower for ip_prefix in ["185.", "45.", "222.", "102."]):
                score += 15
            if "127.0.0.1" in input_lower:
                score = 0

            score = max(0, min(score, 100))

            # Extract IP or resolve domain
            ip = None
            domain_match = re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", user_input)
            if domain_match:
                try:
                    ip = socket.gethostbyname(domain_match.group())
                except socket.gaierror:
                    ip = None
            if not ip:
                ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", user_input)
                if ip_match:
                    ip = ip_match.group()

            if ip:
                st.subheader("🌐 IP Reputation Check (AbuseIPDB)")
                rep = check_ip_reputation(ip)
                if isinstance(rep, dict):
                    st.markdown(f"- **IP**: {rep['IP']}")
                    st.markdown(f"- **Country**: {rep['Country']}")
                    st.markdown(f"- **Abuse Confidence Score**: {rep['Abuse Score']} / 100")
                    st.markdown(f"- **Last Reported**: {rep['Last Reported']}")
                else:
                    st.error(rep)

                # --- VirusTotal Reputation Check ---
                st.subheader("🧪 VirusTotal Reputation")
                vt_result = None

                if ip:
                    vt_result = lookup_ip(ip)
                elif domain_match:
                    vt_result = lookup_domain(domain_match.group())

                if isinstance(vt_result, dict):
                    for k, v in vt_result.items():
                        st.markdown(f"- **{k}**: {v}")
                else:
                    st.error(vt_result)

                meta = get_ip_metadata(ip)
                if meta:
                    st.subheader("📍 IP Metadata")
                    st.markdown(f"- **ASN**: {meta['asn']}")
                    st.markdown(f"- **Org**: {meta['org']}")
                    st.markdown(f"- **Location**: {meta['city']}, {meta['country']}")

                hostname = get_reverse_dns(ip)
                if hostname:
                    st.markdown(f"- **Reverse DNS**: {hostname}")

            st.subheader("📊 Threat Score")
            st.progress(score)
            st.metric("Estimated Risk Level", f"{score}/100")
            if score >= 80:
                st.warning("🚨 High threat confidence")
            elif score >= 50:
                st.info("⚠️ Moderate threat confidence")
            else:
                st.success("✅ Low threat indication")

            st.subheader("🧠 AI Threat Analysis")
            response = explain_threat(user_input)
            st.markdown(response)

            st.markdown(response)

            # 🔍 Smart threat type extraction for MITRE mapping
            r = response.lower()
            if "brute force" in r or "password guessing" in r or "ssh login" in r:
                threat_type = "brute-force attack on ssh login"
            elif "phishing" in r:
                threat_type = "phishing attempt"
            elif "malware" in r or "payload" in r:
                threat_type = "malware delivery"
            else:
                threat_type = "unknown"

            # 🧩 MITRE ATT&CK Mapping
            st.subheader("🧩 MITRE ATT&CK Mapping")
            chain = get_mitre_chain(threat_type)
            if not chain.empty:
                st.dataframe(chain)
            else:
                st.info("No specific MITRE techniques matched.")

            # Extract simplified threat type (very basic)
            if "brute force" in response.lower() or "brute-force" in response.lower():
                threat_type = "brute-force attack on ssh login"
            else:
                threat_type = "unknown"

            # Extract simplified threat type (very basic)
            if "brute force" in response.lower() or "brute-force" in response.lower():
                threat_type = "brute-force attack on ssh login"
            else:
                threat_type = "unknown"

            st.subheader("🛠️ Sigma Detection Rule")
            sigma = generate_sigma_rule(user_input, score)
            st.code(sigma, language="yaml")

            st.subheader("📘 Mitigation Playbook")
            playbook = generate_playbook(response)
            st.markdown(playbook)

            st.download_button("📥 Download Full Analysis", response, file_name="threat_analysis.md")

st.markdown('<div style="text-align: center; color: grey; font-size: 0.9em; margin-top: 50px;">Designed by <b>Ajijola Oluwafemi Blessing</b></div>', unsafe_allow_html=True)
