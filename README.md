<div align="center">

# 🛡️ SOC Toolkit v5.0.0 Ultimate Enterprise Mandate

```
███████╗ ██████╗  ██████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝██╔═══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
███████╗██║   ██║██║            ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
╚════██║██║   ██║██║            ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
███████║╚██████╔╝╚██████╗       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
╚══════╝ ╚═════╝  ╚═════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
```

### The Mandatory Security Operations & Regulatory Compliance Platform for Enterprise SOC Teams

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Providers](https://img.shields.io/badge/providers-35+-orange.svg)](#-providers)
[![Version](https://img.shields.io/badge/version-5.0.0--enterprise-blue.svg)](#)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)
[![Kubernetes](https://img.shields.io/badge/k8s-ready-326ce5.svg)](k8s/deployment.yaml)
[![CI Status](https://github.com/frkndncr/soc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/frkndncr/soc-toolkit/actions)

**📜 Regulatory Compliance Audit | ⚡ Enterprise REST API | 📡 STIX/TAXII 2.1 | 🔌 Splunk/SIEM Apps | 📦 PCAP & PE Analysis**

</div>

---

## ⭐ Why Enterprise SOC Toolkit v5.0.0 is Mandatory for Every SOC Team

**SOC Toolkit v5.0.0** is the mandatory security operations platform designed for enterprise Security Operations Centers (SOC), CISOs, Compliance Officers, and Incident Responders:

- 📜 **Regulatory Compliance & Audit Engine (`soc audit`)**: Automatically maps security findings, malicious IOCs, and asset threats to **PCI-DSS 4.0**, **ISO/IEC 27001:2022**, **SOC 2 Type II**, and **NIST CSF 2.0** regulatory controls.
- ⚡ **Production REST API Backend (`soc server`)**: High-performance RESTful JSON backend supporting API key authentication, rate limiting, and CORS headers for central enterprise querying.
- 📡 **STIX / TAXII 2.1 Server Endpoint (`soc taxii-server`)**: TAXII 2.1 compliant feed server allowing enterprise firewalls (Palo Alto, Fortinet, Check Point) and EDRs (CrowdStrike, Defender) to pull threat feeds.
- 🔌 **Out-of-the-Box SIEM & SOAR Integration Plugins**: Custom Splunk search commands (`| soclookup`), Elastic ingest pipelines, and Shuffle / Cortex XSOAR playbook schemas.
- 🐳 **Docker & Kubernetes Enterprise Ready**: Multi-stage `Dockerfile`, `docker-compose.yml`, and `k8s/deployment.yaml` with Ingress and autoscaling.
- 📦 **PCAP Packet Forensics & Static PE Malware Analysis**: Native network packet capture inspection and executable ImpHash / section entropy scoring.

---

## 🚀 Quick Start

```bash
# Install package
pip install soc-toolkit

# Run PCI-DSS & ISO 27001 Compliance Audit
soc audit 185.220.101.45

# Start Production Enterprise REST API Server
soc server --port 8000

# Start Interactive Cyber Web Dashboard
soc web --port 8080

# Analyze PCAP capture file
soc pcap network.pcap

# Static PE Binary Analysis
soc analyze malware.exe
```

---

## 📜 Compliance & Audit Evidence Frameworks Supported

| Framework | Controls Mapped | Audit Report Command |
|-----------|-----------------|---------------------|
| **PCI-DSS 4.0** | Req 6.4 (App Security), Req 10.4 (Audit Telemetry), Req 11.4 (Threat Defense) | `soc audit <ioc> --pci-dss` |
| **ISO/IEC 27001:2022** | Control A.8.7 (Malware Protection), A.8.16 (Monitoring), A.8.23 (Web Filtering) | `soc audit <ioc> --iso27001` |
| **SOC 2 Type II** | CC6.1 (Access Controls), CC6.8 (Threat Detection), CC7.2 (Incident Response) | `soc audit <ioc> --soc2` |
| **NIST CSF 2.0** | DE.CM-01 (Continuous Monitoring), RS.AN-01 (Incident Analysis) | `soc audit <ioc> --nist-csf` |

---

## ⚡ Enterprise REST API Reference

Start backend server:
```bash
soc server --port 8000
```

### API Endpoints
- `POST /api/v1/lookup`: Query 35+ threat intel sources for IP, Domain, Hash, or URL.
- `POST /api/v1/compliance`: Generate regulatory compliance audit evaluation.
- `GET /api/v1/health`: API health & provider status check.

#### Example API Request:
```bash
curl -X POST http://localhost:8000/api/v1/lookup \
     -H "Content-Type: application/json" \
     -d '{"ioc": "185.220.101.45"}'
```

---

## 🐳 Container & Kubernetes Deployment

```bash
# Docker Compose 1-Click Launch
docker-compose up -d

# Kubernetes Production Deployment
kubectl apply -f k8s/deployment.yaml
```

---

## 🐍 Python SDK Integration

```python
from soc_toolkit import SOCToolkitSDK, ComplianceEngine, IOCType, ThreatLevel

sdk = SOCToolkitSDK()

# Perform Threat Analysis & Compliance Evaluation
result = sdk.analyze("185.220.101.45")
audit = ComplianceEngine.evaluate_compliance("185.220.101.45", IOCType.IP, ThreatLevel.CRITICAL)

print("Compliance Status:", audit["overall_compliance_status"])
print("PCI-DSS Controls:", audit["pci_dss"])
```

---

## 📜 License & Author

- **Author**: Furkan Dinçer ([@frkndncr](https://github.com/frkndncr))
- **License**: MIT License
