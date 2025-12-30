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

### SOC Analyst Workbench - All-in-One IOC Analysis Tool

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Providers](https://img.shields.io/badge/providers-22-orange.svg)](#-providers)
[![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)](#)

**🔍 22 Threat Intel Sources | 🎯 MITRE ATT&CK | 📂 IOC Extraction | ⚡ Parallel Queries**

</div>

---

## ✨ Features

- 🔍 **22 Intel Sources** - Query threat intelligence providers in parallel
- 🎯 **MITRE ATT&CK** - Map IOCs to ATT&CK techniques automatically
- 📂 **IOC Extraction** - Extract IOCs from log files (firewall, syslog, IDS)
- 🔄 **Interactive Mode** - Continuous analysis session
- 📋 **WHOIS & DNS** - Domain/IP enrichment
- ⚡ **Parallel Queries** - 10x faster with concurrent API calls
- 💾 **Smart Caching** - Cache results to reduce API calls
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

# MITRE ATT&CK Mapping
soc 185.220.101.45 --mitre              # Show ATT&CK techniques

# Enrichment
soc evil.com --whois                    # WHOIS lookup
soc evil.com --dns                      # DNS records
soc evil.com --enrich                   # Full enrichment (WHOIS + DNS)

# IOC Extraction
soc -e /var/log/firewall.log            # Extract IOCs from log
soc -e access.log --analyze             # Extract + analyze

# Interactive Mode
soc -i

# Batch & Export
soc -f iocs.txt -o ./reports/
soc 1.2.3.4 --json out.json
soc 1.2.3.4 --md report.md
```

---

## 🔌 Providers (22 Total)

### ✅ Free - No API Key Required (10)

| Provider | Types | Description |
|----------|-------|-------------|
| Shodan InternetDB | IP | Open ports, vulnerabilities |
| IP-API | IP | GeoIP, ISP, proxy detection |
| GreyNoise | IP | Internet scanner detection |
| Pulsedive | IP, Domain, URL | Community threat intel |
| Maltiverse | IP, Domain, URL, Hash | IOC classification |
| StopForumSpam | IP, Email | Spam database |
| URLScan.io | URL, Domain | URL analysis |
| IPInfo | IP | GeoIP information |
| ThreatCrowd | IP, Domain, Email | Open threat intel |
| CIRCL Hashlookup | Hash | Known file database |

### 🔑 Premium - Free API Key Available (12)

| Provider | Types | Free Tier | Get Key |
|----------|-------|-----------|---------|
| VirusTotal | All | 500/day | [virustotal.com](https://virustotal.com) |
| AbuseIPDB | IP | 1000/day | [abuseipdb.com](https://abuseipdb.com) |
| HybridAnalysis | Hash | 200/day | [hybrid-analysis.com](https://hybrid-analysis.com) |
| Censys | IP, Domain | 250/day | [censys.io](https://censys.io) |
| AlienVault OTX | All | Unlimited | [otx.alienvault.com](https://otx.alienvault.com) |
| ThreatFox | IP, Domain, Hash | Unlimited | [auth.abuse.ch](https://auth.abuse.ch) |
| URLHaus | URL, Domain, IP | Unlimited | [auth.abuse.ch](https://auth.abuse.ch) |
| MalwareBazaar | Hash | Unlimited | [auth.abuse.ch](https://auth.abuse.ch) |
| BinaryEdge | IP, Domain | 250/month | [binaryedge.io](https://binaryedge.io) |
| CriminalIP | IP, Domain | 100/day | [criminalip.io](https://criminalip.io) |
| IPQualityScore | IP, Email | 5000/month | [ipqualityscore.com](https://ipqualityscore.com) |

> ⚠️ **Note:** abuse.ch services (ThreatFox, URLHaus, MalwareBazaar) require a free API key since May 2025. Get one key for all services at [auth.abuse.ch](https://auth.abuse.ch)

---

## 🔑 API Keys Configuration

```bash
# Set via environment variables
export VIRUSTOTAL_API_KEY="your-key"
export ABUSEIPDB_API_KEY="your-key"
export OTX_API_KEY="your-key"
export HYBRID_ANALYSIS_API_KEY="your-key"

# abuse.ch services (single key for all)
export THREATFOX_API_KEY="your-abuse-ch-key"
export URLHAUS_API_KEY="your-abuse-ch-key"
export MALWAREBAZAAR_API_KEY="your-abuse-ch-key"
```

Or create `~/.soc-toolkit/config.ini`:

```ini
[api_keys]
virustotal = your-key
abuseipdb = your-key
otx = your-key
threatfox = your-abuse-ch-key
```

---

## 🎯 MITRE ATT&CK Mapping

```bash
soc 185.220.101.45 --mitre
```

Output:
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

## 📊 Example Output

```
╔══════════════════════════════════════════════════════════════╗
║ 🔍 IOC: 185.220.101.45                                       ║
║ 📋 Type: IP                                                  ║
║ 🔴 CRITICAL - Known malicious indicator!                     ║
║ 📊 Found in 8/22 sources | ⚠️  3 sources flagged as malicious ║
╚══════════════════════════════════════════════════════════════╝

┌─────────────┬──────────┬──────────┬─────────────────────────┐
│ Source      │ Status   │ Threat   │ Details                 │
├─────────────┼──────────┼──────────┼─────────────────────────┤
│ Maltiverse  │ ✅ Found │ 🔴 Crit  │ classification: malicio │
│ GreyNoise   │ ✅ Found │ 🔵 Low   │ classification: suspici │
│ Shodan      │ ✅ Found │ 🔵 Low   │ ports: 80, 443          │
│ IP-API      │ ✅ Found │ 🟢 Clean │ country: Germany        │
└─────────────┴──────────┴──────────┴─────────────────────────┘
```

---

## 🧪 Testing

```bash
chmod +x test_soc.sh
./test_soc.sh
```

---

## 📝 Changelog

### v2.0.0 (December 2025)
- 🔄 Updated all providers to latest APIs
- ➕ Added 3 new providers (CIRCL, CriminalIP, IPQualityScore)
- ⚠️ abuse.ch services now require free API key
- 🎯 MITRE ATT&CK mapping
- 📋 WHOIS & DNS enrichment
- 🐛 Fixed deprecated API endpoints

### v1.2.0
- Added MITRE ATT&CK mapping
- Added WHOIS/DNS enrichment
- 19 providers

---

## 👨‍💻 Author

**Furkan Dinçer** - [@frkndncr](https://github.com/frkndncr)

## 📄 License

MIT License
