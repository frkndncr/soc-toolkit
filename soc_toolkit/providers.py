"""
Threat Intelligence Providers for SOC Toolkit v2.1
30+ FREE sources - NO API KEY REQUIRED for most!

Author: Furkan Dinçer
"""

import time
import base64
import socket
import re
from typing import List, Set, Dict, Optional
from urllib.parse import quote
import requests

from .enums import IOCType, ThreatLevel, LookupResult
from .config import Config
from .logger import get_logger

logger = get_logger(__name__)


class BlocklistCache:
    """Global cache for blocklists to avoid repeated downloads"""
    _cache: Dict[str, Set[str]] = {}
    _cache_times: Dict[str, float] = {}
    _cache_duration = 3600  # 1 hour
    
    @classmethod
    def get(cls, url: str, timeout: int = 10) -> Set[str]:
        """Download and cache a blocklist"""
        now = time.time()
        if url in cls._cache and (now - cls._cache_times.get(url, 0)) < cls._cache_duration:
            return cls._cache[url]
        
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": Config.USER_AGENT})
            r.raise_for_status()
            
            items = set()
            for line in r.text.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith(";"):
                    # Extract IP addresses
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        items.add(ip_match.group(1))
                    elif not any(c in line for c in ['#', ';', '/', ' ']):
                        items.add(line)
            
            cls._cache[url] = items
            cls._cache_times[url] = now
            return items
        except:
            return cls._cache.get(url, set())


class BaseLookupProvider:
    """Base class with rate limiting"""
    name: str = "Base"
    supported_types: List[IOCType] = []
    requires_api_key: bool = False
    rate_limit: float = 0.5
    _last_request: float = 0
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.USER_AGENT, "Accept": "application/json"})
        
    def _rate_limit_wait(self):
        elapsed = time.time() - self._last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request = time.time()
        
    def _make_request(self, url: str, method: str = "GET", **kwargs) -> requests.Response:
        self._rate_limit_wait()
        kwargs.setdefault("timeout", Config.TIMEOUT)
        return self.session.request(method, url, **kwargs)
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        raise NotImplementedError


# ═══════════════════════════════════════════════════════════════════════════════
# FREE PROVIDERS - API-based (No key required)
# ═══════════════════════════════════════════════════════════════════════════════

class ShodanInternetDBProvider(BaseLookupProvider):
    """Shodan InternetDB - Free IP intelligence"""
    name = "Shodan"
    supported_types = [IOCType.IP]
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            r = self._make_request(f"https://internetdb.shodan.io/{ioc}")
            if r.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            r.raise_for_status()
            d = r.json()
            vulns, ports = d.get("vulns", []), d.get("ports", [])
            if len(vulns) > 5: threat = ThreatLevel.CRITICAL
            elif len(vulns) > 0: threat = ThreatLevel.HIGH
            elif len(ports) > 10: threat = ThreatLevel.MEDIUM
            elif len(ports) > 0: threat = ThreatLevel.LOW
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"ports": ports[:10], "vulns": vulns[:5], "hostnames": d.get("hostnames", [])[:3]},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class IPAPIProvider(BaseLookupProvider):
    """IP-API - GeoIP information"""
    name = "IP-API"
    supported_types = [IOCType.IP]
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            r = self._make_request(f"http://ip-api.com/json/{ioc}?fields=status,country,countryCode,city,isp,org,as,proxy,hosting")
            r.raise_for_status()
            d = r.json()
            if d.get("status") != "success":
                return LookupResult(source=self.name, found=False, error="Lookup failed", response_time=time.time() - start)
            is_proxy, is_hosting = d.get("proxy", False), d.get("hosting", False)
            threat = ThreatLevel.MEDIUM if is_proxy else ThreatLevel.LOW if is_hosting else ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"country": f"{d.get('country', 'N/A')} ({d.get('countryCode', '')})", "city": d.get("city", "N/A"),
                    "isp": d.get("isp", "N/A"), "org": d.get("org", "N/A"), "asn": d.get("as", "N/A"),
                    "is_proxy": is_proxy, "is_hosting": is_hosting}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class GreyNoiseProvider(BaseLookupProvider):
    """GreyNoise Community - Scanner detection"""
    name = "GreyNoise"
    supported_types = [IOCType.IP]
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            headers = {"key": Config.GREYNOISE_API_KEY} if Config.GREYNOISE_API_KEY else {}
            r = self._make_request(f"https://api.greynoise.io/v3/community/{ioc}", headers=headers)
            if r.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not observed"}, response_time=time.time() - start)
            r.raise_for_status()
            d = r.json()
            classification = d.get("classification", "unknown")
            if d.get("riot"): threat = ThreatLevel.CLEAN
            elif classification == "malicious": threat = ThreatLevel.CRITICAL
            elif classification == "benign": threat = ThreatLevel.CLEAN
            elif d.get("noise"): threat = ThreatLevel.LOW
            else: threat = ThreatLevel.UNKNOWN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"classification": classification, "noise": d.get("noise", False), "name": d.get("name", "N/A")},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class StopForumSpamProvider(BaseLookupProvider):
    """StopForumSpam - Spam database"""
    name = "StopForumSpam"
    supported_types = [IOCType.IP, IOCType.EMAIL]
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            param = "ip" if ioc_type == IOCType.IP else "email"
            r = self._make_request(f"https://api.stopforumspam.org/api?{param}={quote(ioc)}&json")
            r.raise_for_status()
            result = r.json().get(param, {})
            appears = result.get("appears", 0)
            if appears == 0: threat = ThreatLevel.CLEAN
            elif appears < 5: threat = ThreatLevel.LOW
            elif appears < 20: threat = ThreatLevel.MEDIUM
            else: threat = ThreatLevel.HIGH
            return LookupResult(source=self.name, found=appears > 0, threat_level=threat,
                data={"appears": appears, "frequency": result.get("frequency", 0), "confidence": result.get("confidence", 0)},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class URLScanProvider(BaseLookupProvider):
    """URLScan.io - URL analysis"""
    name = "URLScan"
    supported_types = [IOCType.URL, IOCType.DOMAIN]
    rate_limit = 2.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            q = f"domain:{ioc}" if ioc_type == IOCType.DOMAIN else f"page.url:{quote(ioc)}"
            headers = {"API-Key": Config.URLSCAN_API_KEY} if Config.URLSCAN_API_KEY else {}
            r = self._make_request(f"https://urlscan.io/api/v1/search/?q={q}&size=1", headers=headers)
            r.raise_for_status()
            results = r.json().get("results", [])
            if not results:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.UNKNOWN,
                    data={"message": "No scans found"}, response_time=time.time() - start)
            result = results[0]
            is_malicious = result.get("verdicts", {}).get("overall", {}).get("malicious", False)
            threat = ThreatLevel.CRITICAL if is_malicious else ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"malicious": is_malicious, "country": result.get("page", {}).get("country", "N/A")},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class IPInfoProvider(BaseLookupProvider):
    """IPInfo.io - IP information"""
    name = "IPInfo"
    supported_types = [IOCType.IP]
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            url = f"https://ipinfo.io/{ioc}/json"
            if Config.IPINFO_API_KEY: url += f"?token={Config.IPINFO_API_KEY}"
            r = self._make_request(url)
            r.raise_for_status()
            d = r.json()
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.CLEAN,
                data={"country": d.get("country", "N/A"), "city": d.get("city", "N/A"), "org": d.get("org", "N/A")},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class CIRCLHashlookupProvider(BaseLookupProvider):
    """CIRCL Hashlookup - Known file hashes"""
    name = "CIRCL"
    supported_types = [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            if ioc_type == IOCType.HASH_SHA256: endpoint = f"sha256/{ioc}"
            elif ioc_type == IOCType.HASH_MD5: endpoint = f"md5/{ioc}"
            else: endpoint = f"sha1/{ioc}"
            r = self._make_request(f"https://hashlookup.circl.lu/lookup/{endpoint}")
            if r.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.UNKNOWN,
                    data={"message": "Unknown hash"}, response_time=time.time() - start)
            r.raise_for_status()
            d = r.json()
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.CLEAN,
                data={"filename": d.get("FileName", "N/A"), "product": d.get("ProductName", "N/A")},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


# ═══════════════════════════════════════════════════════════════════════════════
# FREE PROVIDERS - DNS Blacklist Check (No API key)
# ═══════════════════════════════════════════════════════════════════════════════

class DNSBLProvider(BaseLookupProvider):
    """DNSBL - Check IP against DNS blacklists"""
    name = "DNSBL"
    supported_types = [IOCType.IP]
    
    DNSBL_SERVERS = [
        "zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net",
        "b.barracudacentral.org", "cbl.abuseat.org", "dnsbl-1.uceprotect.net",
    ]
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            reversed_ip = ".".join(reversed(ioc.split(".")))
            listed_on = []
            for server in self.DNSBL_SERVERS:
                try:
                    socket.gethostbyname(f"{reversed_ip}.{server}")
                    listed_on.append(server)
                except socket.gaierror:
                    pass
            
            if len(listed_on) >= 3: threat = ThreatLevel.CRITICAL
            elif len(listed_on) >= 2: threat = ThreatLevel.HIGH
            elif len(listed_on) >= 1: threat = ThreatLevel.MEDIUM
            else: threat = ThreatLevel.CLEAN
            
            return LookupResult(source=self.name, found=len(listed_on) > 0, threat_level=threat,
                data={"blacklists_checked": len(self.DNSBL_SERVERS), "listed_on": listed_on, "listed_count": len(listed_on)},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


# ═══════════════════════════════════════════════════════════════════════════════
# FREE PROVIDERS - Blocklist Downloads (No API key, cached)
# ═══════════════════════════════════════════════════════════════════════════════

class EmergingThreatsProvider(BaseLookupProvider):
    """Emerging Threats - Compromised IPs"""
    name = "EmergingThreats"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = ioc in blocklist
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.CRITICAL if found else ThreatLevel.CLEAN,
                data={"status": "BLOCKED - Emerging Threats" if found else "Not listed", "list_size": len(blocklist)},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class CINSArmyProvider(BaseLookupProvider):
    """CINS Army - Bad reputation IPs"""
    name = "CINSArmy"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://cinsscore.com/list/ci-badguys.txt"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = ioc in blocklist
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.HIGH if found else ThreatLevel.CLEAN,
                data={"status": "BLOCKED - CINS Army" if found else "Not listed", "list_size": len(blocklist)},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class BlocklistDEProvider(BaseLookupProvider):
    """Blocklist.de - Attack IPs"""
    name = "BlocklistDE"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://lists.blocklist.de/lists/all.txt"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = ioc in blocklist
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.HIGH if found else ThreatLevel.CLEAN,
                data={"status": "BLOCKED - Blocklist.de" if found else "Not listed", "list_size": len(blocklist)},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class FeodoTrackerProvider(BaseLookupProvider):
    """Feodo Tracker - Botnet C2 IPs"""
    name = "FeodoTracker"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = ioc in blocklist
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.CRITICAL if found else ThreatLevel.CLEAN,
                data={"status": "BOTNET C2" if found else "Not listed", "type": "Dridex/Emotet/TrickBot" if found else "N/A"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class SSLBLProvider(BaseLookupProvider):
    """SSL Blacklist - Malicious SSL IPs"""
    name = "SSLBL"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = ioc in blocklist
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.CRITICAL if found else ThreatLevel.CLEAN,
                data={"status": "MALICIOUS SSL" if found else "Not listed"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class TorExitProvider(BaseLookupProvider):
    """Tor Exit Nodes"""
    name = "TorExit"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://check.torproject.org/torbulkexitlist"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = ioc in blocklist
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.MEDIUM if found else ThreatLevel.CLEAN,
                data={"status": "TOR EXIT NODE" if found else "Not a Tor exit"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class SpamhausDropProvider(BaseLookupProvider):
    """Spamhaus DROP - Hijacked networks"""
    name = "SpamhausDROP"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://www.spamhaus.org/drop/drop.txt"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            # Check if IP is in any CIDR range
            from ipaddress import ip_address, ip_network
            ip = ip_address(ioc)
            found = False
            for entry in blocklist:
                try:
                    if '/' in entry and ip in ip_network(entry, strict=False):
                        found = True
                        break
                except:
                    pass
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.CRITICAL if found else ThreatLevel.CLEAN,
                data={"status": "SPAMHAUS DROP" if found else "Not listed"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class BinaryDefenseProvider(BaseLookupProvider):
    """Binary Defense - Threat IPs"""
    name = "BinaryDefense"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://www.binarydefense.com/banlist.txt"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = ioc in blocklist
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.HIGH if found else ThreatLevel.CLEAN,
                data={"status": "BINARY DEFENSE BAN" if found else "Not listed"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class GreenSnowProvider(BaseLookupProvider):
    """GreenSnow - Attack IPs"""
    name = "GreenSnow"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://blocklist.greensnow.co/greensnow.txt"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = ioc in blocklist
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.HIGH if found else ThreatLevel.CLEAN,
                data={"status": "GREENSNOW BLOCKED" if found else "Not listed"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class IPSUMProvider(BaseLookupProvider):
    """IPsum - Aggregated threat IPs (Level 3+)"""
    name = "IPsum"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = ioc in blocklist
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.CRITICAL if found else ThreatLevel.CLEAN,
                data={"status": "IPSUM L3+ (3+ blacklists)" if found else "Not listed"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class DShieldProvider(BaseLookupProvider):
    """DShield - SANS Internet Storm Center"""
    name = "DShield"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://feeds.dshield.org/block.txt"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            # DShield uses network ranges
            ip_prefix = ".".join(ioc.split(".")[:3])
            found = any(ip_prefix in entry for entry in blocklist)
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.HIGH if found else ThreatLevel.CLEAN,
                data={"status": "DSHIELD BLOCKED" if found else "Not listed"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class BruteForceBlockerProvider(BaseLookupProvider):
    """Brute Force Blocker - SSH/FTP attackers"""
    name = "BruteForce"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://danger.rulez.sk/projects/bruteforceblocker/blist.php"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = ioc in blocklist
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.HIGH if found else ThreatLevel.CLEAN,
                data={"status": "BRUTE FORCE ATTACKER" if found else "Not listed"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class URLHausHostsProvider(BaseLookupProvider):
    """URLhaus - Malware hosting IPs (Free download, no API)"""
    name = "URLhaus"
    supported_types = [IOCType.IP, IOCType.DOMAIN]
    BLOCKLIST_URL = "https://urlhaus.abuse.ch/downloads/text_online/"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = any(ioc in entry for entry in blocklist)
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.CRITICAL if found else ThreatLevel.CLEAN,
                data={"status": "MALWARE HOST" if found else "Not listed"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class ThreatFoxExportProvider(BaseLookupProvider):
    """ThreatFox - Recent IOCs (Free CSV export, no API)"""
    name = "ThreatFox"
    supported_types = [IOCType.IP]
    BLOCKLIST_URL = "https://threatfox.abuse.ch/export/csv/ip-port/recent/"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = any(ioc in entry for entry in blocklist)
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.CRITICAL if found else ThreatLevel.CLEAN,
                data={"status": "THREATFOX IOC" if found else "Not listed"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class MalwareBazaarHashProvider(BaseLookupProvider):
    """MalwareBazaar - Recent malware hashes (Free export)"""
    name = "MalwareBazaar"
    supported_types = [IOCType.HASH_SHA256, IOCType.HASH_MD5]
    BLOCKLIST_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = ioc.lower() in (h.lower() for h in blocklist)
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.CRITICAL if found else ThreatLevel.UNKNOWN,
                data={"status": "KNOWN MALWARE" if found else "Not in recent samples"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class PhishingDatabaseProvider(BaseLookupProvider):
    """Phishing Database - Phishing domains"""
    name = "PhishingDB"
    supported_types = [IOCType.DOMAIN, IOCType.URL]
    BLOCKLIST_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            domain = ioc.replace("https://", "").replace("http://", "").split("/")[0]
            found = domain in blocklist
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.CRITICAL if found else ThreatLevel.CLEAN,
                data={"status": "PHISHING SITE" if found else "Not listed"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class OpenPhishProvider(BaseLookupProvider):
    """OpenPhish - Phishing URLs"""
    name = "OpenPhish"
    supported_types = [IOCType.URL, IOCType.DOMAIN]
    BLOCKLIST_URL = "https://openphish.com/feed.txt"
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            blocklist = BlocklistCache.get(self.BLOCKLIST_URL)
            found = any(ioc in entry for entry in blocklist)
            return LookupResult(source=self.name, found=found,
                threat_level=ThreatLevel.CRITICAL if found else ThreatLevel.CLEAN,
                data={"status": "PHISHING URL" if found else "Not listed"},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


# ═══════════════════════════════════════════════════════════════════════════════
# PREMIUM PROVIDERS - API Key Required
# ═══════════════════════════════════════════════════════════════════════════════

class VirusTotalProvider(BaseLookupProvider):
    """VirusTotal - Multi-AV scan (500/day free)"""
    name = "VirusTotal"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    requires_api_key = True
    rate_limit = 15.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.VIRUSTOTAL_API_KEY:
            return LookupResult(source=self.name, found=False, error="API key required", response_time=time.time() - start)
        try:
            headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
            if ioc_type == IOCType.IP: url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            elif ioc_type == IOCType.DOMAIN: url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
            elif ioc_type == IOCType.URL:
                url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            else: url = f"https://www.virustotal.com/api/v3/files/{ioc}"
            r = self._make_request(url, headers=headers)
            if r.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.UNKNOWN, response_time=time.time() - start)
            r.raise_for_status()
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            if malicious >= 10: threat = ThreatLevel.CRITICAL
            elif malicious >= 5: threat = ThreatLevel.HIGH
            elif malicious >= 1: threat = ThreatLevel.MEDIUM
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"detection": f"{malicious}/{total}"}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class AbuseIPDBProvider(BaseLookupProvider):
    """AbuseIPDB - IP abuse reports"""
    name = "AbuseIPDB"
    supported_types = [IOCType.IP]
    requires_api_key = True
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.ABUSEIPDB_API_KEY:
            return LookupResult(source=self.name, found=False, error="API key required", response_time=time.time() - start)
        try:
            headers = {"Key": Config.ABUSEIPDB_API_KEY}
            r = self._make_request("https://api.abuseipdb.com/api/v2/check", headers=headers,
                params={"ipAddress": ioc, "maxAgeInDays": 90})
            r.raise_for_status()
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            if score >= 75: threat = ThreatLevel.CRITICAL
            elif score >= 50: threat = ThreatLevel.HIGH
            elif score >= 25: threat = ThreatLevel.MEDIUM
            elif score > 0: threat = ThreatLevel.LOW
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"abuse_score": score, "reports": d.get("totalReports", 0)}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class AlienVaultOTXProvider(BaseLookupProvider):
    """AlienVault OTX"""
    name = "AlienVault"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.HASH_MD5, IOCType.HASH_SHA256]
    requires_api_key = True
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.OTX_API_KEY:
            return LookupResult(source=self.name, found=False, error="API key required", response_time=time.time() - start)
        try:
            base = "https://otx.alienvault.com/api/v1/indicators"
            if ioc_type == IOCType.IP: url = f"{base}/IPv4/{ioc}/general"
            elif ioc_type == IOCType.DOMAIN: url = f"{base}/domain/{ioc}/general"
            else: url = f"{base}/file/{ioc}/general"
            r = self._make_request(url, headers={"X-OTX-API-KEY": Config.OTX_API_KEY})
            r.raise_for_status()
            pulses = r.json().get("pulse_info", {}).get("count", 0)
            if pulses >= 10: threat = ThreatLevel.CRITICAL
            elif pulses >= 5: threat = ThreatLevel.HIGH
            elif pulses >= 1: threat = ThreatLevel.MEDIUM
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"pulse_count": pulses}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


# ═══════════════════════════════════════════════════════════════════════════════
# PROVIDER REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

ALL_PROVIDERS = [
    # FREE - API Based (7)
    ShodanInternetDBProvider,
    IPAPIProvider,
    GreyNoiseProvider,
    StopForumSpamProvider,
    URLScanProvider,
    IPInfoProvider,
    CIRCLHashlookupProvider,
    
    # FREE - DNS Blacklist (1)
    DNSBLProvider,
    
    # FREE - Blocklist Downloads (17)
    EmergingThreatsProvider,
    CINSArmyProvider,
    BlocklistDEProvider,
    FeodoTrackerProvider,
    SSLBLProvider,
    TorExitProvider,
    SpamhausDropProvider,
    BinaryDefenseProvider,
    GreenSnowProvider,
    IPSUMProvider,
    DShieldProvider,
    BruteForceBlockerProvider,
    URLHausHostsProvider,
    ThreatFoxExportProvider,
    MalwareBazaarHashProvider,
    PhishingDatabaseProvider,
    OpenPhishProvider,
    
    # PREMIUM - API Key Required (3)
    VirusTotalProvider,
    AbuseIPDBProvider,
    AlienVaultOTXProvider,
]

PROVIDER_COUNT = len(ALL_PROVIDERS)
FREE_PROVIDERS = [p for p in ALL_PROVIDERS if not p.requires_api_key]
PREMIUM_PROVIDERS = [p for p in ALL_PROVIDERS if p.requires_api_key]
