<div align="center">

# 🛡️ Enterprise SOC Toolkit v4.0.0 NextGen

```
███████╗ ██████╗  ██████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝██╔═══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
███████╗██║   ██║██║            ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
╚════██║██║   ██║██║            ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
███████║╚██████╔╝╚██████╗       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
╚══════╝ ╚═════╝  ╚═════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
```

### World-Class Cyber Threat Hunting, Malware Analysis & Network Forensics Platform

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Providers](https://img.shields.io/badge/providers-35+-orange.svg)](#-providers)
[![Version](https://img.shields.io/badge/version-4.0.0--nextgen-blue.svg)](#)
[![CI Status](https://github.com/frkndncr/soc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/frkndncr/soc-toolkit/actions)

**🔍 35+ TI Sources | 📦 PCAP Forensics | 🔬 PE Malware Analysis | 🎯 C2 Beacon Decoder | 🔍 Multi-SIEM Query Gen | 🗺️ MITRE Navigator**

</div>

---

## ⭐ Why SOC Toolkit v4.0.0 NextGen?

**SOC Toolkit v4.0.0** elevates threat intelligence into a full-spectrum Cyber Threat Hunting and Malware Analysis platform:

- 📦 **PCAP Network Packet Forensics (`soc pcap capture.pcap`)**: Parses network captures in pure Python, extracts DNS, HTTP, User-Agents, and cross-references extracted IOCs against 35+ Threat Intel providers.
- 🔬 **Malware Static & PE Analyzer (`soc analyze sample.exe`)**: Calculates SHA256, MD5, SHA1, ImpHash (Import Hash), section entropy, suspicious API calls (`VirtualAlloc`, `WriteProcessMemory`), and detects packed binaries.
- 🎯 **C2 Beacon Config Extractor (`soc c2-decode`)**: Decodes Cobalt Strike Malleable C2 configs (Watermark, Public Key, C2 endpoints) and AsyncRAT/Meterpreter configs.
- 🔍 **Multi-SIEM Search Query Generator (`--siem-queries`)**: Generates instant copy-paste queries for **Splunk SPL**, **Elastic KQL**, **Microsoft Sentinel**, **IBM QRadar AQL**, and **CrowdStrike Falcon**.
- 🗺️ **MITRE ATT&CK Navigator Layer Exporter (`--mitre-layer`)**: Exports JSON layer heatmaps for [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
- 🕸️ **Interactive Threat Graph Visualizer (`--graph`)**: Generates interactive SVG & HTML relationship graphs mapping IOCs to threat sources.
- 🛡️ **Incident Response Playbooks & False Positive Suppression**: Generates `iptables` containment rules while automatically whitelisting Google DNS, Cloudflare, Akamai, and AWS infrastructure.

---

## 🚀 Quick Start

```bash
# Install package
pip install soc-toolkit

# Analyze an IP address with SIEM queries & Playbook
soc 185.220.101.45 --siem-queries --playbook

# Network PCAP Packet Forensics
soc pcap network.pcap

# Malware Executable Static Analysis & ImpHash
soc analyze malware.exe

# Extract Cobalt Strike / AsyncRAT C2 Config
soc c2-decode "watermark=1234567"

# Perform Automated Log Triage
soc triage firewall.log

# Decode Obfuscated PowerShell Command
soc decode "powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACc="

# Launch Interactive Cyber Web Dashboard
soc web
```

---

## 🛠️ Advanced CLI Examples

### 1. Multi-SIEM Query Generation
```bash
soc 185.220.101.45 --siem-queries
```
*Outputs instant SPL (Splunk), KQL (Elastic & Sentinel), AQL (QRadar), and CrowdStrike queries.*

### 2. Export MITRE ATT&CK Navigator Heatmap Layer
```bash
soc 185.220.101.45 --mitre-layer attack_layer.json
```

### 3. Interactive Threat Relationship Graph
```bash
soc 185.220.101.45 --graph threat_graph.html
```

---

## 🐍 Python SDK Integration

```python
from soc_toolkit import SOCToolkitSDK, PCAPAnalyzer, PEAnalyzer

sdk = SOCToolkitSDK()

# Threat Analysis
result = sdk.analyze("185.220.101.45")
print("SIEM Queries:", result["siem_queries"])

# Static Binary Malware Analysis
pe_info = PEAnalyzer.analyze_file("payload.exe")
print("ImpHash / Hashes:", pe_info["sha256"], pe_info["entropy"])
```

---

## 📜 License & Author

- **Author**: Furkan Dinçer ([@frkndncr](https://github.com/frkndncr))
- **License**: MIT License
