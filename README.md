<div align="center">

# 🛡️ SOC Toolkit v6.0.0 Military & Enterprise Security Suite

```
███████╗ ██████╗  ██████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝██╔═══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
███████╗██║   ██║██║            ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
╚════██║██║   ██║██║            ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
███████║╚██████╔╝╚██████╗       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
╚══════╝ ╚═════╝  ╚═════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
```

### Autonomous AI Threat Intelligence, Active Defense, SIEM Correlation & SOAR Platform

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Providers](https://img.shields.io/badge/providers-35+-orange.svg)](#-providers)
[![Version](https://img.shields.io/badge/version-6.0.0--suite-blue.svg)](#)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)
[![Kubernetes](https://img.shields.io/badge/k8s-ready-326ce5.svg)](k8s/deployment.yaml)
[![CI Status](https://github.com/frkndncr/soc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/frkndncr/soc-toolkit/actions)

**🤖 Autonomous AI Analyst | ⚡ Active Deception | 🔄 SOAR Playbooks | 📜 Compliance Engine | 🕸️ 3D Threat Map**

</div>

---

## ⭐ Why SOC Toolkit v6.0.0 is the Ultimate Cyber Warfare Platform

**SOC Toolkit v6.0.0** combines Threat Intelligence, AI Root Cause Analysis, Active Defense Deception, SIEM Event Correlation, and SOAR Playbook Execution into a single, unified cyber security platform:

- 🤖 **Autonomous AI Security Analyst (`soc ai <ioc>`)**: Generates Root Cause Analysis (RCA), Cyber Kill Chain Phase Attribution (Recon -> Delivery -> Exploitation -> C2 -> Exfiltration), and CISO Triage Summaries.
- ⚡ **Active Defense & HoneyTokens (`ActiveDefenseEngine`)**: Deploys Canary URLs, decoy AWS keys, and executes active OS firewall banning (`netsh`, `iptables`, `nftables`, `pfctl`, Fortinet/Palo Alto APIs).
- 💻 **Interactive Terminal Analyst Shell (`soc shell`)**: Interactive threat hunting shell console with live telemetry feeds and continuous prompt mode.
- 🔄 **Built-in SOAR Automation Engine (`soc soar <ioc>`)**: Executes automated action workflows (isolate endpoint, generate firewall drop rules, alert SIEM bus).
- 📜 **Regulatory Compliance Audit (`soc audit <ioc>`)**: Maps findings to **PCI-DSS 4.0**, **ISO/IEC 27001:2022**, **SOC 2 Type II**, and **NIST CSF 2.0**.
- ⚡ **Production REST API Backend (`soc server --port 8000`)**: JSON API backend supporting API key auth and CORS headers.
- 🕸️ **3D Cyber Threat Map Dashboard (`soc web --port 8080`)**: Live WebGL cyber threat map with attack vectors and threat gauges.
- 📦 **PCAP Packet Forensics & PE Malware Analysis**: Native network capture inspection and binary ImpHash / entropy analysis.

---

## 🚀 Quick Start

```bash
# Install package
pip install soc-toolkit

# Launch Interactive Analyst Terminal Shell
soc shell

# Autonomous AI Security Analyst Triage
soc ai 185.220.101.45

# Trigger SOAR Automated Action Workflow
soc soar 185.220.101.45

# Run PCI-DSS & ISO 27001 Compliance Audit
soc audit 185.220.101.45

# Start Production Enterprise REST API Server
soc server --port 8000

# Start 3D Cyber Threat Dashboard
soc web --port 8080

# Analyze PCAP Packet Capture
soc pcap network.pcap

# Static PE Binary Analysis
soc analyze malware.exe
```

---

## 🐍 Python SDK Integration

```python
from soc_toolkit import SOCToolkitSDK, AIThreatAnalyst, SOAREngine, ActiveDefenseEngine, IOCType, ThreatLevel

sdk = SOCToolkitSDK()

# Perform AI Triage
ai_report = AIThreatAnalyst.analyze_threat("185.220.101.45", IOCType.IP, ThreatLevel.CRITICAL)
print("Kill Chain Phase:", ai_report["cyber_kill_chain_phase"])

# Trigger SOAR Automated Playbook
soar_res = SOAREngine.execute_workflow("185.220.101.45", "CRITICAL")
print("Actions Taken:", soar_res["actions_taken"])
```

---

## 📜 License & Author

- **Author**: Furkan Dinçer ([@frkndncr](https://github.com/frkndncr))
- **License**: MIT License
