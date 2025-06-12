# 🛡️ ThreatPhemGPT – AI-Powered Threat Intelligence Explainer

**ThreatPhemGPT** is an AI-enhanced threat analysis tool that allows security analysts, blue teams, and SOC engineers to quickly assess suspicious IPs, domains, or incident snippets using threat intelligence APIs and LLM-based explanations.

> 🚀 Built with: Python · Streamlit · VirusTotal API · AbuseIPDB · OpenRouter (LLM)

## 🔍 Key Features

- 🌐 **IP/Domain Reputation Checks** via **AbuseIPDB** and **VirusTotal**
- 📈 **Threat Score Heuristics** based on smart keyword and IOC analysis
- 🧠 **AI-Powered Threat Explanation** using OpenRouter (Mistral 7B or other LLMs)
- 🧩 **MITRE ATT&CK Mapping** of techniques and tactics
- 🛠️ **Sigma Rule Generation** for detection
- 📘 **SOC Analyst Playbook** auto-generated for mitigation
- 📥 **Export** threat analysis results as Markdown

## 🚦 Example Use Cases

- Detect and analyze brute-force SSH attacks  
- Check if a suspicious IP is known for abuse or malware  
- Map indicators to MITRE ATT&CK techniques  
- Automatically generate SOC-ready detection rules  

## ⚙️ Installation & Setup

```bash
git clone https://github.com/<your-username>/ThreatPhemGPT.git
cd ThreatPhemGPT
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create a .env file in the project root:
echo "VT_API_KEY=your_virustotal_api_key" >> .env
echo "ABUSEIPDB_API_KEY=your_abuseipdb_key" >> .env
echo "OPENROUTER_API_KEY=your_openrouter_key" >> .env

# Run the app
streamlit run app.py
```

## 👨‍💻 Author

**Ajijola Oluwafemi Blessing**  
Cybersecurity | Software | IT | Research

- GitHub: [phemtech-solutions](https://github.com/oluwafemiab/ajijola.github.io)  
- LinkedIn: [https://www.linkedin.com/in/ajijola-oluwafemi-ba839712a/)
