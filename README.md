<div align="center">

# 🛡️ SOC Toolkit v7.0.1

```text
███████╗ ██████╗  ██████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝██╔═══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
███████╗██║   ██║██║            ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
╚════██║██║   ██║██║            ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
███████║╚██████╔╝╚██████╗       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
╚══════╝ ╚═════╝  ╚═════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
```

### ⚡ Global Enterprise Threat Intelligence & Incident Response Platform

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-7.0.1-blue?style=for-the-badge)](#)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](Dockerfile)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)](k8s/deployment.yaml)

</div>

---

## ⚡ Quick Start

```bash
# 1. Install via pip
pip install soc-toolkit

# 2. Perform instant Zero-Key Threat Intel Lookup with AI Triage
soc 185.220.101.45

# 3. Launch Next-Gen Interactive Analyst Command Center Shell
soc shell

# 4. Perform Multithreaded Batch Log File Triage
soc batch logs.txt

# 5. Check Whitelist & False Positive Status
soc whitelist 10.0.0.1

# 6. Render 14-Tactic MITRE ATT&CK Visual Matrix
soc mitre 185.220.101.45

# 7. Start Enterprise REST API Server
soc server --port 8000
```

---

## 🔥 Features at a Glance

| Feature | Description | Command |
| :--- | :--- | :--- |
| **💻 Interactive Analyst Shell** | Next-Gen prompt with SIEM log triage (`scan`), notes (`note`), dual comparison (`compare`), SOAR blocks (`block`) & CTI Q&A (`ask`) | `soc shell` |
| **📁 Multithreaded Batch Scanner** | Parses log files, emails, or raw dumps, extracts IOCs & runs parallel threat triage | `soc batch <file>` |
| **🟢 Whitelist & False Positive Filter** | RFC1918 private IPs (`10.0.0.0/8`), loopbacks, and trusted DNS infrastructure filter | `soc whitelist <ioc>` |
| **🗺️ MITRE ATT&CK Visual Matrix** | Renders color-coded 14-tactic ATT&CK heatmap grid across active threat TTPs | `soc mitre <ioc>` |
| **🦠 Zero-Key VirusTotal / Shodan / AbuseIPDB** | API Key-Free public VirusTotal, Shodan (CVEs & Risk Grade A-F), AbuseIPDB & Cisco Talos | `soc <ioc>` |
| **🤖 Autonomous AI Analyst** | Root Cause Analysis (RCA) & Cyber Kill Chain Attribution | `soc ai <ioc>` |
| **📡 Live Syslog Stream** | Real-time UDP 514 Syslog listener with Slack/Teams Webhook alerts | `soc stream` |
| **🧬 Memory & Mimikatz Forensics** | Process memory dump parser & LSASS credential theft hunter | `soc mem <file>` |
| **🔌 Enterprise EDR Collector** | CrowdStrike Falcon, Defender & SentinelOne process tree telemetry | `soc edr <host>` |
| **🌐 Attack Surface Management (EASM)** | Subdomain discovery, open ports, HSTS/CSP security headers & Shadow IT | `soc asm <domain>` |
| **💀 Ransomware Gang Matcher** | LockBit 3.0, BlackCat/ALPHV, Clop & RansomHub TTP matching | `soc ransomware <ioc>` |
| **📄 Executive Incident Tickets** | 1-Click Jira & ServiceNow Incident Response ticket generator | `soc report <ioc>` |
| **⏱️ C2 Beaconing Calculator** | Connection interval delta variance & heartbeat detection | `soc beacon` |
| **🗣️ Multi-Language Reports** | Generates reports in English, Turkish, German, French, Spanish & Japanese | `soc i18n <ioc> de` |
| **🔄 Automated SOAR Engine** | Executes containment, host isolation & firewall bans | `soc soar <ioc>` |
| **📜 Regulatory Compliance** | Maps findings to **PCI-DSS 4.0**, **ISO 27001**, **SOC 2** & **NIST CSF** | `soc audit <ioc>` |

---

## 💻 Next-Gen Interactive Analyst Shell Commands (`soc shell`)

Inside `soc shell`, analysts can run real-time triage without leaving the command prompt:

```text
soc-shell> scan "Failed login attempt from 185.220.101.45 on port 22"
soc-shell> note 185.220.101.45 "Confirmed Cobalt Strike C2 IP"
soc-shell> compare 185.220.101.45 8.8.8.8
soc-shell> block 185.220.101.45
soc-shell> mitre 185.220.101.45
soc-shell> ask Is 185.220.101.45 associated with LockBit ransomware?
soc-shell> export-session shift_report.html
```

---

## 🤖 Autonomous AI Security Analyst

Run instant AI triage on any IP, Domain, Hash, or URL:

```bash
soc ai 185.220.101.45
```

```json
{
  "ioc": "185.220.101.45",
  "threat_level": "CRITICAL",
  "cyber_kill_chain_phase": "Command and Control (C2) / Exfiltration",
  "root_cause_analysis": "Autonomous AI Analysis concluded an overall risk score of CRITICAL. Attribution indicates active alignment with Cyber Kill Chain phase: 'Command and Control (C2)'. Network containment recommended.",
  "ciso_executive_summary": "EXECUTIVE SUMMARY: Indicator 185.220.101.45 poses a CRITICAL risk to enterprise operations. Authorize automated SOAR containment."
}
```

---

## 📜 Regulatory Compliance Frameworks Supported

| Framework | Controls Mapped | Command |
| :--- | :--- | :--- |
| **PCI-DSS 4.0** | Req 6.4 (App Security), Req 10.4 (Audit Telemetry), Req 11.4 (Threat Defense) | `soc audit <ioc>` |
| **ISO/IEC 27001:2022** | Control A.8.7 (Malware Defense), A.8.16 (Monitoring), A.8.23 (Web Filtering) | `soc audit <ioc>` |
| **SOC 2 Type II** | CC6.1 (Access Controls), CC6.8 (Threat Detection), CC7.2 (Incident Response) | `soc audit <ioc>` |
| **NIST CSF 2.0** | DE.CM-01 (Continuous Monitoring), RS.AN-01 (Incident Analysis) | `soc audit <ioc>` |

---

## 🐳 1-Click Container Deployment

```bash
# Docker Compose 1-Click Launch
docker-compose up -d

# Kubernetes Production Deployment
kubectl apply -f k8s/deployment.yaml
```

---

## 🐍 Python SDK

```python
from soc_toolkit import SOCToolkitSDK, AIThreatAnalyst, SOAREngine, IOCType, ThreatLevel

sdk = SOCToolkitSDK()

# Analyze IOC
report = sdk.analyze("185.220.101.45")

# Autonomous AI Triage
ai_triage = AIThreatAnalyst.analyze_threat("185.220.101.45", IOCType.IP, ThreatLevel.CRITICAL)
print("Kill Chain Phase:", ai_triage["cyber_kill_chain_phase"])
```

---

## 👤 Author & License

- **Author**: Furkan Dinçer ([@frkndncr](https://github.com/frkndncr))
- **License**: [MIT License](LICENSE)
