<div align="center">

# 🛡️ SOC Toolkit

```
███████╗ ██████╗  ██████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝██╔═══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
███████╗██║   ██║██║            ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
╚════██║██║   ██║██║            ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
███████║╚██████╔╝╚██████╗       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
╚══════╝ ╚═════╝  ╚═════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
```

### SOC Analyst Workbench - All-in-One Threat Intelligence Tool

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Providers](https://img.shields.io/badge/providers-28-orange.svg)](#-providers)
[![Free](https://img.shields.io/badge/free%20sources-25-brightgreen.svg)](#-providers)
[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)](#)

**🔍 28 Threat Intel Sources | 🆓 25 FREE (No API Key!) | 🎯 MITRE ATT&CK | ⚡ Parallel Queries**

</div>

---

## ⭐ Why SOC Toolkit?

Most threat intelligence tools require API keys for every source. **SOC Toolkit is different:**

- ✅ **25 sources work without any API key**
- ✅ **Instant setup** - just `pip install` and go
- ✅ **Real blocklists** from abuse.ch, Spamhaus, EmergingThreats, and more
- ✅ **One command** queries all sources in parallel

---

## 🚀 Quick Start

```bash
# Install
pip install soc-toolkit

# Analyze an IP
soc 185.220.101.45

# That's it! No API keys needed.
```

---

## 📊 Example Output

```
╔════════════════════════════════════════════════════════════════╗
║ 🔍 IOC: 185.220.101.45                                         ║
║ 📋 Type: IP                                                    ║
║ 🔴 CRITICAL - Known malicious indicator!                       ║
║ 📊 Found in 8/23 sources | ⚠️  2 sources flagged as malicious   ║
╚════════════════════════════════════════════════════════════════╝

┌─────────────────┬──────────┬──────────┬─────────────────────────┐
│ Source          │ Status   │ Threat   │ Details                 │
├─────────────────┼──────────┼──────────┼─────────────────────────┤
│ DNSBL           │ ✅ Found │ 🔴 Crit  │ 3/6 blacklists          │
│ IPsum           │ ✅ Found │ 🔴 Crit  │ 3+ blacklist hits       │
│ TorExit         │ ✅ Found │ 🟡 Med   │ TOR EXIT NODE           │
│ GreyNoise       │ ✅ Found │ 🔵 Low   │ suspicious, noise=True  │
│ Shodan          │ ✅ Found │ 🔵 Low   │ ports: 80               │
│ IP-API          │ ✅ Found │ 🟢 Clean │ Germany, Brandenburg    │
└─────────────────┴──────────┴──────────┴─────────────────────────┘
```

---

## 🔌 Providers (28 Total)

### 🆓 FREE - No API Key Required (25)

#### API-Based (7)
| Provider | Types | Description |
|----------|-------|-------------|
| Shodan InternetDB | IP | Open ports, CVEs |
| IP-API | IP | GeoIP, proxy detection |
| GreyNoise | IP | Scanner detection |
| StopForumSpam | IP, Email | Spam database |
| URLScan.io | URL, Domain | URL analysis |
| IPInfo | IP | Geolocation |
| CIRCL Hashlookup | Hash | Known file database |

#### DNS Blacklist (1)
| Provider | Types | Description |
|----------|-------|-------------|
| DNSBL | IP | Checks 6 major blacklists (Spamhaus, SpamCop, SORBS, Barracuda, CBL, UCEProtect) |

#### Blocklist Downloads (17)
| Provider | Source | Description |
|----------|--------|-------------|
| EmergingThreats | Proofpoint | Compromised IPs |
| CINS Army | Sentinel IPS | Bad reputation IPs |
| Blocklist.de | Community | Attack source IPs |
| Feodo Tracker | abuse.ch | Botnet C2 servers |
| SSLBL | abuse.ch | Malicious SSL certs |
| Tor Exit Nodes | torproject.org | Tor exit detection |
| Spamhaus DROP | Spamhaus | Hijacked networks |
| Binary Defense | BinaryDefense | Threat IPs |
| GreenSnow | GreenSnow | Attack IPs |
| IPsum | stamparm | 3+ blacklist aggregator |
| DShield | SANS ISC | Top attackers |
| BruteForce Blocker | danger.rulez.sk | SSH/FTP attackers |
| URLhaus | abuse.ch | Malware URLs |
| ThreatFox | abuse.ch | IOC database |
| MalwareBazaar | abuse.ch | Malware hashes |
| Phishing Database | Community | Phishing domains |
| OpenPhish | OpenPhish | Phishing URLs |

### 🔑 Premium - API Key Required (3)

| Provider | Free Tier | Get Key |
|----------|-----------|---------|
| VirusTotal | 500/day | [virustotal.com](https://virustotal.com) |
| AbuseIPDB | 1000/day | [abuseipdb.com](https://abuseipdb.com) |
| AlienVault OTX | Unlimited | [otx.alienvault.com](https://otx.alienvault.com) |

---

## 💡 Usage

```bash
# IP Analysis
soc 185.220.101.45

# Domain Analysis
soc evil-domain.com

# Hash Analysis
soc 44d88612fea8a8f36de82e1278abb02f

# MITRE ATT&CK Mapping
soc 185.220.101.45 --mitre

# WHOIS & DNS Enrichment
soc evil.com --enrich

# Extract IOCs from log file
soc -e /var/log/firewall.log

# Batch analysis
soc -f iocs.txt -o ./reports/

# Interactive mode
soc -i

# Export formats
soc 1.2.3.4 --json out.json
soc 1.2.3.4 --md report.md
```

---

## 🔑 Optional: Add API Keys

For even more coverage, add these free API keys:

```bash
export VIRUSTOTAL_API_KEY="your-key"
export ABUSEIPDB_API_KEY="your-key"
export OTX_API_KEY="your-key"
```

---

## 🎯 MITRE ATT&CK Mapping

```bash
soc 185.220.101.45 --mitre
```

```
🎯 MITRE ATT&CK Mapping

  📌 Credential Access
    🔴 T1110: Brute Force

  📌 Command and Control
    🟡 T1071: Application Layer Protocol

  📌 Initial Access
    🟢 T1190: Exploit Public-Facing Application
```

---

## 📦 Installation

```bash
# From PyPI
pip install soc-toolkit

# From source
git clone https://github.com/frkndncr/soc-toolkit.git
cd soc-toolkit
pip install -e .

# Verify
soc --version
soc --providers
```

---

## 📝 Changelog

### v2.1.0 (December 2025) 🆕
- 🔥 **25 FREE providers** - no API key required!
- ➕ Added 17 blocklist-based providers
- ➕ EmergingThreats, CINS Army, Blocklist.de
- ➕ Spamhaus DROP, Binary Defense, GreenSnow
- ➕ IPsum, DShield, BruteForce Blocker
- ➕ Phishing Database, OpenPhish
- 🔄 Smart blocklist caching (1 hour)
- ⚡ Parallel queries for faster results

### v2.0.0 (December 2025)
- Updated all providers to latest APIs
- Added MITRE ATT&CK mapping
- Added WHOIS & DNS enrichment

### v1.0.0
- Initial release with 19 providers

---

## 🤝 Contributing

Contributions welcome! Feel free to submit issues and pull requests.

---

## 👨‍💻 Author

**Furkan Dinçer** - Security Engineer

[![GitHub](https://img.shields.io/badge/GitHub-frkndncr-black?logo=github)](https://github.com/frkndncr)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)](https://linkedin.com/in/frkndncr)

---

## 📄 License

MIT License - feel free to use in your projects!

---

<div align="center">

**⭐ Star this repo if you find it useful!**

</div>
