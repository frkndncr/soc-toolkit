<div align="center">

# 🛡️ SOC Toolkit v3.0.0 Enterprise

```
███████╗ ██████╗  ██████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝██╔═══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
███████╗██║   ██║██║            ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
╚════██║██║   ██║██║            ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
███████║╚██████╔╝╚██████╗       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
╚══════╝ ╚═════╝  ╚═════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
```

### Enterprise SOC Analyst Workbench - Threat Intelligence, Incident Response Playbooks & Log Triage

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Providers](https://img.shields.io/badge/providers-35+-orange.svg)](#-providers)
[![Version](https://img.shields.io/badge/version-3.0.0--enterprise-blue.svg)](#)
[![CI Status](https://github.com/frkndncr/soc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/frkndncr/soc-toolkit/actions)

**🔍 35+ Threat Intel Sources | 🛡️ IR Playbooks | 🌐 Cyber Web GUI | 🪵 Log Triage | 🔓 Payload Decoder | 📜 YARA/Sigma Rules**

</div>

---

## ⭐ Why Enterprise SOC Toolkit v3.0.0?

Standard threat intelligence tools often generate alert fatigue and lack actionable incident response steps. **SOC Toolkit v3.0.0** is built for real-world SOC operations:

- 🛡️ **Incident Response Playbook Generator**: Step-by-step containment (`iptables` / endpoint isolation), eradication, and recovery guidelines for every alert.
- 🟢 **False Positive & Cloud Infrastructure Filter**: Automatically detects Google DNS, Cloudflare, Akamai, and AWS infrastructure to eliminate false alarms.
- 🌐 **Interactive Cyber Web GUI (`soc web`)**: Zero-dependency dark-mode dashboard for web-based triage.
- 🪵 **Automated Log & Forensics Triage (`soc triage file.log`)**: Scans log dumps, refangs IOCs, ranks critical threats, and outputs executive threat summaries.
- 🔓 **PowerShell & Defang Decoder (`soc decode`)**: Instantly decodes `powershell -enc` base64 payloads and defanged URLs (`hXXps://`).
- 📜 **SIEM & NIDS Rule Generation**: Auto-generates Sigma rules, YARA rules, and Snort/Suricata drop statements.
- 🐍 **Python SDK (`import soc_toolkit`)**: Easily embed into SOAR workflows (Shuffle, DFIR-IRIS, Cortex) or Jupyter Notebooks.

---

## 🚀 Quick Start

```bash
# Install package
pip install soc-toolkit

# Analyze an IP address
soc 185.220.101.45

# Generate Incident Containment Playbook
soc 185.220.101.45 --playbook

# Perform Automated Log Triage
soc triage firewall.log

# Decode Obfuscated PowerShell Command
soc decode "powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACc="

# Launch Interactive Cyber Web Dashboard
soc web
```

---

## 🔌 Threat Intelligence Providers (35+ Total)

### 🆓 FREE - No API Key Required
- **Pulsedive**: Risk score & indicator properties
- **ThreatFox Direct API**: Official abuse.ch C2 & IOC database
- **URLhaus Direct API**: Official abuse.ch malware URL database
- **MalwareBazaar Direct API**: Official abuse.ch malware sample hash lookup
- **Tranco Top 1M Rank**: Popular domain validation to suppress false positives
- **Shodan InternetDB**: Open ports & CVEs
- **IP-API**: GeoIP & proxy detection
- **GreyNoise Community**: Scanner detection
- **StopForumSpam**: Spam database
- **URLScan.io**: Web page analysis
- **IPInfo**: Geolocation
- **CIRCL Hashlookup**: Known file database
- **DNSBL**: 6 major DNS blacklists (Spamhaus, SpamCop, SORBS, Barracuda, CBL, UCEProtect)
- **17 Blocklist Feeds**: EmergingThreats, CINS Army, Blocklist.de, Feodo Tracker, SSLBL, Tor Exit Nodes, Spamhaus DROP, Binary Defense, GreenSnow, IPsum L3+, DShield, BruteForce Blocker, PhishingDB, OpenPhish.

### 🔑 Premium - API Key Supported
- **VirusTotal**: Multi-engine AV scanning
- **AbuseIPDB**: IP abuse reports
- **AlienVault OTX**: Threat pulses

---

## 🛠️ CLI Usage & Features

### 1. Single IOC Analysis & Playbook
```bash
soc 185.220.101.45 --playbook --osint
```

### 2. Export Formats (HTML & STIX 2.1)
```bash
# Interactive HTML Report
soc 185.220.101.45 --html report.html

# STIX 2.1 JSON Bundle
soc 185.220.101.45 --stix report.stix.json

# JSON / CSV / Markdown
soc 185.220.101.45 --json report.json --csv report.csv
```

### 3. Generate SIEM Detection Rules
```bash
# Generate Sigma Rule
soc 185.220.101.45 --sigma

# Generate YARA Rule
soc 44d88612fea8a8f36de82e1278abb02f --yara
```

### 4. Defang / Refang URLs & Obfuscated Command Decoding
```bash
# Defang URL
soc defang "https://evil.com/payload"
# Output: hXXps://evil[.]com/payload

# Refang URL
soc refang "hXXps://evil[.]com/payload"
# Output: https://evil.com/payload
```

---

## 🐍 Python SDK Integration

Embed **SOC Toolkit** into your Python scripts or SOAR pipelines:

```python
from soc_toolkit import SOCToolkitSDK

sdk = SOCToolkitSDK()

# Perform full threat analysis
result = sdk.analyze("185.220.101.45")

print("Threat Level:", result["threat_level"])
print("Playbook Containment:", result["playbook"].containment_actions)
print("Sigma Rule:", result["sigma_rule"])
```

---

## 📜 License & Author

- **Author**: Furkan Dinçer ([@frkndncr](https://github.com/frkndncr))
- **License**: MIT License
