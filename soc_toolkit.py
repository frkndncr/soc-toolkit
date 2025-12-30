#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ███████╗ ██████╗  ██████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗ ║
║   ██╔════╝██╔═══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝ ║
║   ███████╗██║   ██║██║            ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║    ║
║   ╚════██║██║   ██║██║            ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║    ║
║   ███████║╚██████╔╝╚██████╗       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║    ║
║   ╚══════╝ ╚═════╝  ╚═════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝    ║
║                                                                               ║
║   SOC Analyst Workbench - All-in-One IOC Lookup Tool                         ║
║   Author: SOC Toolkit Project                                                 ║
║   Version: 1.0.0                                                              ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import json
import re
import sys
import hashlib
import socket
import urllib.parse
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import concurrent.futures

# HTTP requests
try:
    import requests
except ImportError:
    print("❌ 'requests' kütüphanesi gerekli. Yüklemek için: pip install requests")
    sys.exit(1)

# Rich for beautiful CLI output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.text import Text
    from rich.markdown import Markdown
    from rich import box
    from rich.style import Style
    from rich.columns import Columns
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  'rich' kütüphanesi önerilir. Yüklemek için: pip install rich")


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

class Config:
    """Configuration settings"""
    VERSION = "1.0.0"
    TIMEOUT = 10  # API request timeout
    USER_AGENT = "SOC-Toolkit/1.0"
    
    # API Keys (optional - set via environment or config file)
    VIRUSTOTAL_API_KEY = ""
    ABUSEIPDB_API_KEY = ""
    SHODAN_API_KEY = ""
    
    # Cache settings
    CACHE_DIR = Path.home() / ".soc-toolkit" / "cache"
    CACHE_EXPIRY_HOURS = 24


# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS & DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class LookupResult:
    """Single source lookup result"""
    source: str
    found: bool
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    response_time: float = 0.0


@dataclass 
class IOCReport:
    """Complete IOC analysis report"""
    ioc: str
    ioc_type: IOCType
    timestamp: str
    results: List[LookupResult] = field(default_factory=list)
    overall_threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    summary: str = ""
    

# ═══════════════════════════════════════════════════════════════════════════════
# IOC TYPE DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

class IOCDetector:
    """Detect IOC type from input string"""
    
    # Regex patterns
    IPV4_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    IPV6_PATTERN = re.compile(
        r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
        r'^(?:[0-9a-fA-F]{1,4}:){1,7}:$|'
        r'^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$'
    )
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    URL_PATTERN = re.compile(
        r'^https?://[^\s/$.?#].[^\s]*$', re.IGNORECASE
    )
    MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
    SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
    SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    @classmethod
    def detect(cls, ioc: str) -> IOCType:
        """Detect the type of IOC"""
        ioc = ioc.strip()
        
        # Check URL first (contains protocol)
        if cls.URL_PATTERN.match(ioc):
            return IOCType.URL
            
        # Check hashes by length
        if cls.SHA256_PATTERN.match(ioc):
            return IOCType.HASH_SHA256
        if cls.SHA1_PATTERN.match(ioc):
            return IOCType.HASH_SHA1
        if cls.MD5_PATTERN.match(ioc):
            return IOCType.HASH_MD5
            
        # Check IP addresses
        if cls.IPV4_PATTERN.match(ioc) or cls.IPV6_PATTERN.match(ioc):
            return IOCType.IP
            
        # Check email
        if cls.EMAIL_PATTERN.match(ioc):
            return IOCType.EMAIL
            
        # Check domain
        if cls.DOMAIN_PATTERN.match(ioc):
            return IOCType.DOMAIN
            
        return IOCType.UNKNOWN


# ═══════════════════════════════════════════════════════════════════════════════
# LOOKUP PROVIDERS
# ═══════════════════════════════════════════════════════════════════════════════

class BaseLookupProvider:
    """Base class for all lookup providers"""
    
    name: str = "Base"
    supported_types: List[IOCType] = []
    requires_api_key: bool = False
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.USER_AGENT})
        
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        """Perform lookup - override in subclass"""
        raise NotImplementedError
        
    def _make_request(self, url: str, method: str = "GET", **kwargs) -> requests.Response:
        """Make HTTP request with error handling"""
        kwargs.setdefault("timeout", Config.TIMEOUT)
        return self.session.request(method, url, **kwargs)


class AbuseIPDBProvider(BaseLookupProvider):
    """AbuseIPDB lookup provider"""
    
    name = "AbuseIPDB"
    supported_types = [IOCType.IP]
    requires_api_key = True
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        import time
        start = time.time()
        
        if not Config.ABUSEIPDB_API_KEY:
            return LookupResult(
                source=self.name,
                found=False,
                error="API key gerekli. ABUSEIPDB_API_KEY environment variable'ı ayarlayın."
            )
            
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": Config.ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            params = {"ipAddress": ioc, "maxAgeInDays": 90}
            
            response = self._make_request(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json().get("data", {})
            
            abuse_score = data.get("abuseConfidenceScore", 0)
            
            # Determine threat level
            if abuse_score == 0:
                threat_level = ThreatLevel.CLEAN
            elif abuse_score < 25:
                threat_level = ThreatLevel.LOW
            elif abuse_score < 50:
                threat_level = ThreatLevel.MEDIUM
            elif abuse_score < 75:
                threat_level = ThreatLevel.HIGH
            else:
                threat_level = ThreatLevel.CRITICAL
                
            return LookupResult(
                source=self.name,
                found=True,
                threat_level=threat_level,
                data={
                    "abuse_score": abuse_score,
                    "country": data.get("countryCode", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "domain": data.get("domain", "N/A"),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported": data.get("lastReportedAt", "N/A"),
                    "is_tor": data.get("isTor", False),
                    "is_public": data.get("isPublic", True)
                },
                response_time=time.time() - start
            )
            
        except requests.exceptions.RequestException as e:
            return LookupResult(
                source=self.name,
                found=False,
                error=str(e),
                response_time=time.time() - start
            )


class VirusTotalProvider(BaseLookupProvider):
    """VirusTotal lookup provider"""
    
    name = "VirusTotal"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, 
                       IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    requires_api_key = True
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        import time
        start = time.time()
        
        if not Config.VIRUSTOTAL_API_KEY:
            return LookupResult(
                source=self.name,
                found=False,
                error="API key gerekli. VIRUSTOTAL_API_KEY environment variable'ı ayarlayın."
            )
            
        try:
            headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
            
            # Determine endpoint based on IOC type
            if ioc_type == IOCType.IP:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            elif ioc_type == IOCType.DOMAIN:
                url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
            elif ioc_type == IOCType.URL:
                url_id = hashlib.sha256(ioc.encode()).hexdigest()
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            else:  # Hash
                url = f"https://www.virustotal.com/api/v3/files/{ioc}"
                
            response = self._make_request(url, headers=headers)
            
            if response.status_code == 404:
                return LookupResult(
                    source=self.name,
                    found=False,
                    threat_level=ThreatLevel.UNKNOWN,
                    data={"message": "IOC bulunamadı"},
                    response_time=time.time() - start
                )
                
            response.raise_for_status()
            data = response.json().get("data", {}).get("attributes", {})
            
            # Get detection stats
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            
            # Determine threat level
            if total == 0:
                threat_level = ThreatLevel.UNKNOWN
            elif malicious == 0 and suspicious == 0:
                threat_level = ThreatLevel.CLEAN
            elif malicious < 3:
                threat_level = ThreatLevel.LOW
            elif malicious < 10:
                threat_level = ThreatLevel.MEDIUM
            elif malicious < 20:
                threat_level = ThreatLevel.HIGH
            else:
                threat_level = ThreatLevel.CRITICAL
                
            return LookupResult(
                source=self.name,
                found=True,
                threat_level=threat_level,
                data={
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": total,
                    "detection_ratio": f"{malicious}/{total}" if total > 0 else "N/A",
                    "reputation": data.get("reputation", "N/A"),
                    "tags": data.get("tags", [])[:5]
                },
                response_time=time.time() - start
            )
            
        except requests.exceptions.RequestException as e:
            return LookupResult(
                source=self.name,
                found=False,
                error=str(e),
                response_time=time.time() - start
            )


class ThreatFoxProvider(BaseLookupProvider):
    """ThreatFox (abuse.ch) lookup provider - FREE, no API key needed"""
    
    name = "ThreatFox"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL,
                       IOCType.HASH_MD5, IOCType.HASH_SHA256]
    requires_api_key = False
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        import time
        start = time.time()
        
        try:
            url = "https://threatfox-api.abuse.ch/api/v1/"
            
            # Determine search type
            if ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA256]:
                payload = {"query": "search_hash", "hash": ioc}
            else:
                payload = {"query": "search_ioc", "search_term": ioc}
                
            response = self._make_request(url, method="POST", json=payload)
            response.raise_for_status()
            data = response.json()
            
            if data.get("query_status") != "ok" or not data.get("data"):
                return LookupResult(
                    source=self.name,
                    found=False,
                    threat_level=ThreatLevel.CLEAN,
                    data={"message": "Tehdit veritabanında bulunamadı"},
                    response_time=time.time() - start
                )
                
            # Found in ThreatFox = definitely malicious
            ioc_data = data["data"][0] if isinstance(data["data"], list) else data["data"]
            
            return LookupResult(
                source=self.name,
                found=True,
                threat_level=ThreatLevel.CRITICAL,
                data={
                    "malware": ioc_data.get("malware", "N/A"),
                    "malware_alias": ioc_data.get("malware_alias", "N/A"),
                    "threat_type": ioc_data.get("threat_type", "N/A"),
                    "confidence": ioc_data.get("confidence_level", "N/A"),
                    "first_seen": ioc_data.get("first_seen", "N/A"),
                    "last_seen": ioc_data.get("last_seen", "N/A"),
                    "reporter": ioc_data.get("reporter", "N/A"),
                    "tags": ioc_data.get("tags", [])
                },
                response_time=time.time() - start
            )
            
        except requests.exceptions.RequestException as e:
            return LookupResult(
                source=self.name,
                found=False,
                error=str(e),
                response_time=time.time() - start
            )


class URLHausProvider(BaseLookupProvider):
    """URLHaus (abuse.ch) lookup provider - FREE"""
    
    name = "URLHaus"
    supported_types = [IOCType.URL, IOCType.DOMAIN]
    requires_api_key = False
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        import time
        start = time.time()
        
        try:
            if ioc_type == IOCType.URL:
                url = "https://urlhaus-api.abuse.ch/v1/url/"
                payload = {"url": ioc}
            else:  # Domain
                url = "https://urlhaus-api.abuse.ch/v1/host/"
                payload = {"host": ioc}
                
            response = self._make_request(url, method="POST", data=payload)
            response.raise_for_status()
            data = response.json()
            
            if data.get("query_status") != "ok":
                return LookupResult(
                    source=self.name,
                    found=False,
                    threat_level=ThreatLevel.CLEAN,
                    data={"message": "URLHaus'ta bulunamadı"},
                    response_time=time.time() - start
                )
                
            # Determine threat level based on status
            threat_type = data.get("threat", "N/A")
            url_status = data.get("url_status", "unknown")
            
            if url_status == "online":
                threat_level = ThreatLevel.CRITICAL
            elif url_status == "offline":
                threat_level = ThreatLevel.HIGH
            else:
                threat_level = ThreatLevel.MEDIUM
                
            return LookupResult(
                source=self.name,
                found=True,
                threat_level=threat_level,
                data={
                    "threat_type": threat_type,
                    "status": url_status,
                    "date_added": data.get("date_added", "N/A"),
                    "url_count": data.get("url_count", 0),
                    "blacklists": data.get("blacklists", {}),
                    "tags": data.get("tags", [])
                },
                response_time=time.time() - start
            )
            
        except requests.exceptions.RequestException as e:
            return LookupResult(
                source=self.name,
                found=False,
                error=str(e),
                response_time=time.time() - start
            )


class MalwareBazaarProvider(BaseLookupProvider):
    """MalwareBazaar (abuse.ch) lookup provider - FREE"""
    
    name = "MalwareBazaar"
    supported_types = [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    requires_api_key = False
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        import time
        start = time.time()
        
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            
            # Determine hash type
            if ioc_type == IOCType.HASH_SHA256:
                payload = {"query": "get_info", "hash": ioc}
            else:
                payload = {"query": "get_info", "hash": ioc}
                
            response = self._make_request(url, method="POST", data=payload)
            response.raise_for_status()
            data = response.json()
            
            if data.get("query_status") != "ok" or not data.get("data"):
                return LookupResult(
                    source=self.name,
                    found=False,
                    threat_level=ThreatLevel.CLEAN,
                    data={"message": "MalwareBazaar'da bulunamadı"},
                    response_time=time.time() - start
                )
                
            sample = data["data"][0] if isinstance(data["data"], list) else data["data"]
            
            return LookupResult(
                source=self.name,
                found=True,
                threat_level=ThreatLevel.CRITICAL,
                data={
                    "file_name": sample.get("file_name", "N/A"),
                    "file_type": sample.get("file_type", "N/A"),
                    "file_size": sample.get("file_size", "N/A"),
                    "signature": sample.get("signature", "N/A"),
                    "first_seen": sample.get("first_seen", "N/A"),
                    "intelligence": sample.get("intelligence", {}),
                    "tags": sample.get("tags", []),
                    "delivery_method": sample.get("delivery_method", "N/A")
                },
                response_time=time.time() - start
            )
            
        except requests.exceptions.RequestException as e:
            return LookupResult(
                source=self.name,
                found=False,
                error=str(e),
                response_time=time.time() - start
            )


class IPAPIProvider(BaseLookupProvider):
    """IP-API.com geolocation provider - FREE"""
    
    name = "IP-API"
    supported_types = [IOCType.IP]
    requires_api_key = False
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        import time
        start = time.time()
        
        try:
            url = f"http://ip-api.com/json/{ioc}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"
            
            response = self._make_request(url)
            response.raise_for_status()
            data = response.json()
            
            if data.get("status") != "success":
                return LookupResult(
                    source=self.name,
                    found=False,
                    error=data.get("message", "Lookup failed"),
                    response_time=time.time() - start
                )
                
            # Check for suspicious indicators
            is_proxy = data.get("proxy", False)
            is_hosting = data.get("hosting", False)
            
            if is_proxy:
                threat_level = ThreatLevel.MEDIUM
            elif is_hosting:
                threat_level = ThreatLevel.LOW
            else:
                threat_level = ThreatLevel.CLEAN
                
            return LookupResult(
                source=self.name,
                found=True,
                threat_level=threat_level,
                data={
                    "country": f"{data.get('country', 'N/A')} ({data.get('countryCode', '')})",
                    "city": data.get("city", "N/A"),
                    "region": data.get("regionName", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "org": data.get("org", "N/A"),
                    "asn": data.get("as", "N/A"),
                    "reverse_dns": data.get("reverse", "N/A"),
                    "is_proxy": is_proxy,
                    "is_hosting": is_hosting,
                    "is_mobile": data.get("mobile", False),
                    "coordinates": f"{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}"
                },
                response_time=time.time() - start
            )
            
        except requests.exceptions.RequestException as e:
            return LookupResult(
                source=self.name,
                found=False,
                error=str(e),
                response_time=time.time() - start
            )


class ShodanInternetDBProvider(BaseLookupProvider):
    """Shodan InternetDB - FREE, no API key needed"""
    
    name = "Shodan"
    supported_types = [IOCType.IP]
    requires_api_key = False
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        import time
        start = time.time()
        
        try:
            url = f"https://internetdb.shodan.io/{ioc}"
            
            response = self._make_request(url)
            
            if response.status_code == 404:
                return LookupResult(
                    source=self.name,
                    found=False,
                    threat_level=ThreatLevel.CLEAN,
                    data={"message": "Shodan'da bulunamadı"},
                    response_time=time.time() - start
                )
                
            response.raise_for_status()
            data = response.json()
            
            vulns = data.get("vulns", [])
            ports = data.get("ports", [])
            
            # Determine threat level based on vulnerabilities
            if len(vulns) > 5:
                threat_level = ThreatLevel.CRITICAL
            elif len(vulns) > 0:
                threat_level = ThreatLevel.HIGH
            elif len(ports) > 10:
                threat_level = ThreatLevel.MEDIUM
            elif len(ports) > 0:
                threat_level = ThreatLevel.LOW
            else:
                threat_level = ThreatLevel.CLEAN
                
            return LookupResult(
                source=self.name,
                found=True,
                threat_level=threat_level,
                data={
                    "hostnames": data.get("hostnames", []),
                    "ports": ports,
                    "cpes": data.get("cpes", [])[:5],
                    "vulns": vulns[:10],
                    "tags": data.get("tags", []),
                    "vuln_count": len(vulns),
                    "port_count": len(ports)
                },
                response_time=time.time() - start
            )
            
        except requests.exceptions.RequestException as e:
            return LookupResult(
                source=self.name,
                found=False,
                error=str(e),
                response_time=time.time() - start
            )


class AlienVaultOTXProvider(BaseLookupProvider):
    """AlienVault OTX lookup - FREE"""
    
    name = "AlienVault OTX"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL,
                       IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    requires_api_key = False
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        import time
        start = time.time()
        
        try:
            base_url = "https://otx.alienvault.com/api/v1/indicators"
            
            # Build URL based on IOC type
            if ioc_type == IOCType.IP:
                url = f"{base_url}/IPv4/{ioc}/general"
            elif ioc_type == IOCType.DOMAIN:
                url = f"{base_url}/domain/{ioc}/general"
            elif ioc_type == IOCType.URL:
                url = f"{base_url}/url/{ioc}/general"
            elif ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
                url = f"{base_url}/file/{ioc}/general"
            else:
                return LookupResult(
                    source=self.name,
                    found=False,
                    error="Desteklenmeyen IOC tipi"
                )
                
            response = self._make_request(url)
            
            if response.status_code == 404:
                return LookupResult(
                    source=self.name,
                    found=False,
                    threat_level=ThreatLevel.CLEAN,
                    data={"message": "OTX'te bulunamadı"},
                    response_time=time.time() - start
                )
                
            response.raise_for_status()
            data = response.json()
            
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            
            # Determine threat level
            if pulse_count == 0:
                threat_level = ThreatLevel.CLEAN
            elif pulse_count < 5:
                threat_level = ThreatLevel.LOW
            elif pulse_count < 20:
                threat_level = ThreatLevel.MEDIUM
            elif pulse_count < 50:
                threat_level = ThreatLevel.HIGH
            else:
                threat_level = ThreatLevel.CRITICAL
                
            # Get pulse names
            pulses = data.get("pulse_info", {}).get("pulses", [])
            pulse_names = [p.get("name", "N/A") for p in pulses[:5]]
            
            return LookupResult(
                source=self.name,
                found=True,
                threat_level=threat_level,
                data={
                    "pulse_count": pulse_count,
                    "pulses": pulse_names,
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country_name", "N/A"),
                    "asn": data.get("asn", "N/A"),
                    "validation": data.get("validation", [])
                },
                response_time=time.time() - start
            )
            
        except requests.exceptions.RequestException as e:
            return LookupResult(
                source=self.name,
                found=False,
                error=str(e),
                response_time=time.time() - start
            )


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN LOOKUP ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class SOCToolkit:
    """Main SOC Toolkit engine"""
    
    def __init__(self):
        self.providers = [
            ThreatFoxProvider(),
            URLHausProvider(),
            MalwareBazaarProvider(),
            IPAPIProvider(),
            ShodanInternetDBProvider(),
            AlienVaultOTXProvider(),
            AbuseIPDBProvider(),
            VirusTotalProvider(),
        ]
        
        if RICH_AVAILABLE:
            self.console = Console()
        
    def lookup(self, ioc: str, ioc_type: Optional[IOCType] = None) -> IOCReport:
        """Perform comprehensive IOC lookup"""
        
        # Auto-detect IOC type if not provided
        if ioc_type is None:
            ioc_type = IOCDetector.detect(ioc)
            
        if ioc_type == IOCType.UNKNOWN:
            return IOCReport(
                ioc=ioc,
                ioc_type=ioc_type,
                timestamp=datetime.now().isoformat(),
                summary="❌ IOC tipi tespit edilemedi"
            )
            
        # Filter providers that support this IOC type
        applicable_providers = [
            p for p in self.providers 
            if ioc_type in p.supported_types
        ]
        
        results = []
        
        # Parallel lookup with threading
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_provider = {
                executor.submit(p.lookup, ioc, ioc_type): p 
                for p in applicable_providers
            }
            
            for future in concurrent.futures.as_completed(future_to_provider):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    provider = future_to_provider[future]
                    results.append(LookupResult(
                        source=provider.name,
                        found=False,
                        error=str(e)
                    ))
        
        # Calculate overall threat level
        overall_threat = self._calculate_overall_threat(results)
        
        # Generate summary
        summary = self._generate_summary(ioc, ioc_type, results, overall_threat)
        
        return IOCReport(
            ioc=ioc,
            ioc_type=ioc_type,
            timestamp=datetime.now().isoformat(),
            results=results,
            overall_threat_level=overall_threat,
            summary=summary
        )
        
    def _calculate_overall_threat(self, results: List[LookupResult]) -> ThreatLevel:
        """Calculate overall threat level from all results"""
        threat_scores = {
            ThreatLevel.CLEAN: 0,
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4,
            ThreatLevel.UNKNOWN: -1
        }
        
        max_score = -1
        for result in results:
            if result.found and result.threat_level != ThreatLevel.UNKNOWN:
                score = threat_scores.get(result.threat_level, -1)
                max_score = max(max_score, score)
                
        # Reverse lookup
        for level, score in threat_scores.items():
            if score == max_score:
                return level
                
        return ThreatLevel.UNKNOWN
        
    def _generate_summary(self, ioc: str, ioc_type: IOCType, 
                          results: List[LookupResult], 
                          overall_threat: ThreatLevel) -> str:
        """Generate human-readable summary"""
        
        threat_descriptions = {
            ThreatLevel.CLEAN: "✅ TEMİZ - Bu IOC güvenli görünüyor",
            ThreatLevel.LOW: "🟢 DÜŞÜK RİSK - Minimal tehdit göstergesi",
            ThreatLevel.MEDIUM: "🟡 ORTA RİSK - Dikkatli olunmalı",
            ThreatLevel.HIGH: "🟠 YÜKSEK RİSK - Şüpheli aktivite tespit edildi",
            ThreatLevel.CRITICAL: "🔴 KRİTİK - Bilinen kötü amaçlı gösterge!",
            ThreatLevel.UNKNOWN: "⚪ BİLİNMİYOR - Yeterli veri yok"
        }
        
        found_count = sum(1 for r in results if r.found)
        malicious_count = sum(1 for r in results if r.found and 
                            r.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL])
        
        summary = f"{threat_descriptions.get(overall_threat, 'Bilinmiyor')}\n"
        summary += f"📊 {found_count}/{len(results)} kaynakta bulundu"
        
        if malicious_count > 0:
            summary += f" | ⚠️ {malicious_count} kaynak kötü amaçlı olarak işaretledi"
            
        return summary


# ═══════════════════════════════════════════════════════════════════════════════
# CLI OUTPUT FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════

class OutputFormatter:
    """Format and display results"""
    
    def __init__(self):
        if RICH_AVAILABLE:
            self.console = Console()
            
    def print_banner(self):
        """Print tool banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ███████╗ ██████╗  ██████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗ ║
║   ██╔════╝██╔═══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝ ║
║   ███████╗██║   ██║██║            ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║    ║
║   ╚════██║██║   ██║██║            ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║    ║
║   ███████║╚██████╔╝╚██████╗       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║    ║
║   ╚══════╝ ╚═════╝  ╚═════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝    ║
║                                                                               ║
║   SOC Analyst Workbench v1.0 - All-in-One IOC Lookup Tool                    ║
║   Free & Open Source | github.com/soc-toolkit                                ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """
        if RICH_AVAILABLE:
            self.console.print(banner, style="bold cyan")
        else:
            print(banner)
            
    def print_report(self, report: IOCReport):
        """Print formatted report"""
        if RICH_AVAILABLE:
            self._print_rich_report(report)
        else:
            self._print_simple_report(report)
            
    def _print_rich_report(self, report: IOCReport):
        """Print report using Rich library"""
        
        # Threat level colors
        threat_colors = {
            ThreatLevel.CLEAN: "green",
            ThreatLevel.LOW: "blue",
            ThreatLevel.MEDIUM: "yellow",
            ThreatLevel.HIGH: "orange1",
            ThreatLevel.CRITICAL: "red bold",
            ThreatLevel.UNKNOWN: "white"
        }
        
        # Header panel
        header_text = Text()
        header_text.append(f"🔍 IOC: ", style="bold")
        header_text.append(f"{report.ioc}\n", style="cyan bold")
        header_text.append(f"📋 Tip: ", style="bold")
        header_text.append(f"{report.ioc_type.value.upper()}\n", style="magenta")
        header_text.append(f"🕐 Zaman: ", style="bold")
        header_text.append(f"{report.timestamp}\n", style="dim")
        header_text.append(f"\n{report.summary}", 
                         style=threat_colors.get(report.overall_threat_level, "white"))
        
        self.console.print(Panel(header_text, title="[bold white]📊 IOC Analiz Raporu[/]", 
                                 border_style="cyan", box=box.DOUBLE))
        
        # Results table
        table = Table(title="🔎 Kaynak Sonuçları", box=box.ROUNDED, 
                     show_header=True, header_style="bold magenta")
        table.add_column("Kaynak", style="cyan", width=15)
        table.add_column("Durum", width=10)
        table.add_column("Tehdit", width=12)
        table.add_column("Detaylar", style="dim")
        table.add_column("Süre", width=8, justify="right")
        
        for result in report.results:
            # Status
            if result.error:
                status = "❌ Hata"
                status_style = "red"
            elif result.found:
                status = "✅ Bulundu"
                status_style = "green"
            else:
                status = "⚪ Yok"
                status_style = "dim"
                
            # Threat level
            threat_icons = {
                ThreatLevel.CLEAN: "🟢 Temiz",
                ThreatLevel.LOW: "🔵 Düşük",
                ThreatLevel.MEDIUM: "🟡 Orta",
                ThreatLevel.HIGH: "🟠 Yüksek",
                ThreatLevel.CRITICAL: "🔴 Kritik",
                ThreatLevel.UNKNOWN: "⚪ ?"
            }
            threat_str = threat_icons.get(result.threat_level, "?")
            threat_style = threat_colors.get(result.threat_level, "white")
            
            # Details - first 3 important fields
            details = []
            if result.error:
                details.append(f"Hata: {result.error[:40]}")
            elif result.data:
                for key, value in list(result.data.items())[:3]:
                    if value and value != "N/A" and value != []:
                        if isinstance(value, list):
                            value = ", ".join(str(v) for v in value[:3])
                        details.append(f"{key}: {str(value)[:30]}")
                        
            details_str = " | ".join(details) if details else "-"
            
            # Response time
            time_str = f"{result.response_time:.2f}s" if result.response_time else "-"
            
            table.add_row(
                result.source,
                f"[{status_style}]{status}[/]",
                f"[{threat_style}]{threat_str}[/]",
                details_str[:60],
                time_str
            )
            
        self.console.print(table)
        
        # Detailed findings for malicious results
        malicious_results = [r for r in report.results 
                           if r.found and r.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]]
        
        if malicious_results:
            self.console.print("\n[bold red]⚠️  DETAYLI TEHDİT BİLGİSİ[/]\n")
            
            for result in malicious_results:
                detail_table = Table(title=f"[bold]{result.source}[/]", 
                                    box=box.SIMPLE, show_header=False)
                detail_table.add_column("Alan", style="cyan", width=20)
                detail_table.add_column("Değer", style="white")
                
                for key, value in result.data.items():
                    if value and value != "N/A":
                        if isinstance(value, list):
                            value = ", ".join(str(v) for v in value)
                        elif isinstance(value, dict):
                            value = json.dumps(value, indent=2)
                        detail_table.add_row(key, str(value))
                        
                self.console.print(detail_table)
                self.console.print()
                
    def _print_simple_report(self, report: IOCReport):
        """Print simple text report (no Rich)"""
        print("\n" + "="*70)
        print(f"IOC: {report.ioc}")
        print(f"Tip: {report.ioc_type.value}")
        print(f"Zaman: {report.timestamp}")
        print(f"Genel Tehdit: {report.overall_threat_level.value}")
        print(report.summary)
        print("="*70)
        
        for result in report.results:
            print(f"\n[{result.source}]")
            print(f"  Durum: {'Bulundu' if result.found else 'Bulunamadı'}")
            print(f"  Tehdit: {result.threat_level.value}")
            if result.error:
                print(f"  Hata: {result.error}")
            if result.data:
                for key, value in result.data.items():
                    print(f"  {key}: {value}")
                    
    def export_json(self, report: IOCReport, filepath: str):
        """Export report to JSON"""
        def serialize(obj):
            if isinstance(obj, Enum):
                return obj.value
            if hasattr(obj, '__dict__'):
                return {k: serialize(v) for k, v in obj.__dict__.items()}
            if isinstance(obj, list):
                return [serialize(i) for i in obj]
            if isinstance(obj, dict):
                return {k: serialize(v) for k, v in obj.items()}
            return obj
            
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(serialize(report), f, indent=2, ensure_ascii=False)
            
        if RICH_AVAILABLE:
            self.console.print(f"[green]✅ Rapor kaydedildi: {filepath}[/]")
        else:
            print(f"✅ Rapor kaydedildi: {filepath}")
            
    def export_markdown(self, report: IOCReport, filepath: str):
        """Export report to Markdown"""
        
        threat_emoji = {
            ThreatLevel.CLEAN: "🟢",
            ThreatLevel.LOW: "🔵", 
            ThreatLevel.MEDIUM: "🟡",
            ThreatLevel.HIGH: "🟠",
            ThreatLevel.CRITICAL: "🔴",
            ThreatLevel.UNKNOWN: "⚪"
        }
        
        md = f"""# 🔍 IOC Analiz Raporu

## Özet

| Alan | Değer |
|------|-------|
| **IOC** | `{report.ioc}` |
| **Tip** | {report.ioc_type.value.upper()} |
| **Zaman** | {report.timestamp} |
| **Genel Tehdit** | {threat_emoji.get(report.overall_threat_level, '')} {report.overall_threat_level.value.upper()} |

{report.summary}

---

## 📊 Kaynak Sonuçları

| Kaynak | Durum | Tehdit | Süre |
|--------|-------|--------|------|
"""
        
        for result in report.results:
            status = "✅" if result.found else ("❌" if result.error else "⚪")
            threat = f"{threat_emoji.get(result.threat_level, '')} {result.threat_level.value}"
            time_str = f"{result.response_time:.2f}s" if result.response_time else "-"
            md += f"| {result.source} | {status} | {threat} | {time_str} |\n"
            
        md += "\n---\n\n## 📋 Detaylı Bulgular\n\n"
        
        for result in report.results:
            if result.found and result.data:
                md += f"### {result.source}\n\n"
                md += "| Alan | Değer |\n|------|-------|\n"
                for key, value in result.data.items():
                    if value and value != "N/A":
                        if isinstance(value, list):
                            value = ", ".join(str(v) for v in value[:5])
                        md += f"| {key} | {value} |\n"
                md += "\n"
                
        md += f"""
---

*Rapor SOC Toolkit v{Config.VERSION} ile oluşturuldu*
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md)
            
        if RICH_AVAILABLE:
            self.console.print(f"[green]✅ Markdown raporu kaydedildi: {filepath}[/]")
        else:
            print(f"✅ Markdown raporu kaydedildi: {filepath}")


# ═══════════════════════════════════════════════════════════════════════════════
# BATCH PROCESSING
# ═══════════════════════════════════════════════════════════════════════════════

def process_batch(toolkit: SOCToolkit, formatter: OutputFormatter, 
                  filepath: str, output_dir: str = None):
    """Process multiple IOCs from file"""
    
    if not Path(filepath).exists():
        print(f"❌ Dosya bulunamadı: {filepath}")
        return
        
    with open(filepath, 'r') as f:
        iocs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
    if not iocs:
        print("❌ Dosyada IOC bulunamadı")
        return
        
    print(f"📋 {len(iocs)} IOC işlenecek...\n")
    
    results = []
    
    if RICH_AVAILABLE:
        console = Console()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("İşleniyor...", total=len(iocs))
            
            for ioc in iocs:
                progress.update(task, description=f"[cyan]Analiz: {ioc[:40]}...[/]")
                report = toolkit.lookup(ioc)
                results.append(report)
                progress.advance(task)
    else:
        for i, ioc in enumerate(iocs, 1):
            print(f"[{i}/{len(iocs)}] Analiz: {ioc}")
            report = toolkit.lookup(ioc)
            results.append(report)
            
    # Summary
    print("\n" + "="*70)
    print("📊 TOPLU ANALİZ SONUÇLARI")
    print("="*70)
    
    threat_counts = {}
    for report in results:
        level = report.overall_threat_level.value
        threat_counts[level] = threat_counts.get(level, 0) + 1
        
    for level, count in sorted(threat_counts.items()):
        print(f"  {level.upper()}: {count}")
        
    # Export if output directory specified
    if output_dir:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Export summary JSON
        summary_file = output_path / f"batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        all_data = []
        for report in results:
            all_data.append({
                "ioc": report.ioc,
                "type": report.ioc_type.value,
                "threat_level": report.overall_threat_level.value,
                "summary": report.summary
            })
            
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(all_data, f, indent=2, ensure_ascii=False)
            
        print(f"\n✅ Toplu rapor kaydedildi: {summary_file}")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Main entry point"""
    import os
    
    # Load API keys from environment
    Config.VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    Config.ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
    Config.SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
    
    parser = argparse.ArgumentParser(
        description="SOC Toolkit - All-in-One IOC Lookup Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  %(prog)s 185.220.101.45                    # IP lookup
  %(prog)s evil.com                           # Domain lookup
  %(prog)s 44d88612fea8a8f36de82e1278abb02f  # Hash lookup
  %(prog)s https://malware.site/payload      # URL lookup
  %(prog)s -f iocs.txt                        # Batch lookup
  %(prog)s 1.2.3.4 --json output.json        # JSON export
  %(prog)s 1.2.3.4 --md output.md            # Markdown export

Environment Variables:
  VIRUSTOTAL_API_KEY    - VirusTotal API key
  ABUSEIPDB_API_KEY     - AbuseIPDB API key
        """
    )
    
    parser.add_argument("ioc", nargs="?", help="IOC to lookup (IP, domain, hash, URL)")
    parser.add_argument("-f", "--file", help="File containing IOCs (one per line)")
    parser.add_argument("-t", "--type", choices=["ip", "domain", "url", "md5", "sha1", "sha256"],
                       help="Force IOC type")
    parser.add_argument("--json", metavar="FILE", help="Export to JSON file")
    parser.add_argument("--md", "--markdown", metavar="FILE", help="Export to Markdown file")
    parser.add_argument("-o", "--output-dir", help="Output directory for batch processing")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress banner")
    parser.add_argument("-v", "--version", action="version", version=f"SOC Toolkit v{Config.VERSION}")
    
    args = parser.parse_args()
    
    toolkit = SOCToolkit()
    formatter = OutputFormatter()
    
    # Print banner
    if not args.quiet:
        formatter.print_banner()
        
    # Batch mode
    if args.file:
        process_batch(toolkit, formatter, args.file, args.output_dir)
        return
        
    # Single IOC mode
    if not args.ioc:
        parser.print_help()
        return
        
    # Force IOC type if specified
    ioc_type = None
    if args.type:
        type_map = {
            "ip": IOCType.IP,
            "domain": IOCType.DOMAIN,
            "url": IOCType.URL,
            "md5": IOCType.HASH_MD5,
            "sha1": IOCType.HASH_SHA1,
            "sha256": IOCType.HASH_SHA256
        }
        ioc_type = type_map.get(args.type)
        
    # Perform lookup
    if RICH_AVAILABLE:
        console = Console()
        with console.status("[bold cyan]🔍 IOC analiz ediliyor...[/]"):
            report = toolkit.lookup(args.ioc, ioc_type)
    else:
        print("🔍 IOC analiz ediliyor...")
        report = toolkit.lookup(args.ioc, ioc_type)
        
    # Print report
    formatter.print_report(report)
    
    # Export if requested
    if args.json:
        formatter.export_json(report, args.json)
    if args.md:
        formatter.export_markdown(report, args.md)


if __name__ == "__main__":
    main()
