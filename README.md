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

### All-in-One IOC Lookup & Extraction Tool

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Providers](https://img.shields.io/badge/providers-19-orange.svg)](#-providers)

**🔍 19 Threat Intel Sources | 📂 IOC Extraction | 🔄 Interactive Mode | ⚡ Parallel Queries**

</div>

---

## ✨ Features

- 🔍 **19 Intel Sources** - Query 19 threat intelligence providers in parallel
- 📂 **IOC Extraction** - Extract IOCs from log files (firewall, syslog, IDS)
- 🔄 **Interactive Mode** - Continuous analysis without retyping commands
- ⚡ **Parallel Queries** - 10x faster with concurrent API calls
- 🛡️ **Rate Limiting** - Built-in rate limiting to prevent API bans
- 💾 **Smart Caching** - Cache results to reduce API calls
- 📝 **Logging** - Comprehensive logging for debugging
- 📊 **Multiple Exports** - JSON, Markdown, CSV formats

---

## 🚀 Installation

```bash
pip install soc-toolkit

# Or from source
git clone https://github.com/frkndncr/soc-toolkit.git
cd soc-toolkit
pip install -e .

soc --version
```

## 🗑️ Uninstall

```bash
pip uninstall soc-toolkit
rm -rf ~/.soc-toolkit  # Remove config/cache (optional)
```

---

## 💡 Usage

```bash
# Basic lookup
soc 185.220.101.45                      # IP
soc evil-domain.com                      # Domain
soc 44d88612fea8a8f36de82e1278abb02f    # Hash

# IOC Extraction
soc -e /var/log/firewall.log            # Extract IOCs
soc -e access.log --analyze             # Extract + analyze

# Enrichment (NEW!)
soc evil.com --whois                    # WHOIS lookup
soc evil.com --dns                      # DNS records
soc evil.com --enrich                   # Full enrichment

# MITRE ATT&CK Mapping (NEW!)
soc 185.220.101.45 --mitre              # Show ATT&CK techniques

# Interactive Mode
soc -i

# Batch & Export
soc -f iocs.txt -o ./reports/
soc 1.2.3.4 --json out.json
```

---

## ✨ New in v1.2.0

| Feature | Command | Description |
|---------|---------|-------------|
| 🎯 **MITRE ATT&CK** | `--mitre` | Map IOCs to ATT&CK techniques |
| 📋 **WHOIS Lookup** | `--whois` | Domain/IP registration info |
| 🌐 **DNS Records** | `--dns` | A, MX, NS, TXT records |
| 🔍 **Full Enrichment** | `--enrich` | WHOIS + DNS combined |

---

## 🔌 Providers (19 Total)

### Free (15)
ThreatFox, URLHaus, MalwareBazaar, FeodoTracker, Shodan, IP-API, AlienVault OTX, Pulsedive, GreyNoise, BGPView, ThreatMiner, URLScan, Maltiverse, PhishStats, StopForumSpam

### Premium (4)
VirusTotal, AbuseIPDB, HybridAnalysis, Censys

---

## 🔑 API Keys

```bash
export VIRUSTOTAL_API_KEY="your-key"
export ABUSEIPDB_API_KEY="your-key"
```

---

## 🧪 Testing

```bash
chmod +x test_soc.sh
./test_soc.sh
```

---

## 👨‍💻 Author

**Furkan Dinçer** - [@frkndncr](https://github.com/frkndncr)

## 📄 License

MIT License
