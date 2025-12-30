"""
Threat Intelligence Providers for SOC Toolkit v2.0
22 verified and working sources - December 2025

Author: Furkan Dinçer
GitHub: https://github.com/frkndncr/soc-toolkit
"""

import time
import base64
from typing import List
from urllib.parse import quote
import requests

from .enums import IOCType, ThreatLevel, LookupResult
from .config import Config
from .logger import get_logger

logger = get_logger(__name__)


class BaseLookupProvider:
    """Base class with rate limiting"""
    name: str = "Base"
    supported_types: List[IOCType] = []
    requires_api_key: bool = False
    rate_limit: float = 1.0
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
# FREE PROVIDERS - No API Key Required (10)
# ═══════════════════════════════════════════════════════════════════════════════

class ShodanInternetDBProvider(BaseLookupProvider):
    """Shodan InternetDB - Free IP intelligence"""
    name = "Shodan"
    supported_types = [IOCType.IP]
    rate_limit = 1.0
    
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
                data={"ports": ports[:10], "vulns": vulns[:5], "vuln_count": len(vulns),
                    "hostnames": d.get("hostnames", [])[:3]}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class IPAPIProvider(BaseLookupProvider):
    """IP-API - GeoIP information"""
    name = "IP-API"
    supported_types = [IOCType.IP]
    rate_limit = 0.7
    
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
                    data={"message": "Not observed (likely clean)"}, response_time=time.time() - start)
            r.raise_for_status()
            d = r.json()
            classification = d.get("classification", "unknown")
            if d.get("riot"): threat = ThreatLevel.CLEAN
            elif classification == "malicious": threat = ThreatLevel.CRITICAL
            elif classification == "benign": threat = ThreatLevel.CLEAN
            elif d.get("noise"): threat = ThreatLevel.LOW
            else: threat = ThreatLevel.UNKNOWN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"classification": classification, "noise": d.get("noise", False), 
                    "riot": d.get("riot", False), "name": d.get("name", "N/A")}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class PulsediveProvider(BaseLookupProvider):
    """Pulsedive - Threat intelligence"""
    name = "Pulsedive"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL]
    rate_limit = 1.5
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            url = f"https://pulsedive.com/api/info.php?indicator={quote(ioc)}"
            if Config.PULSEDIVE_API_KEY: url += f"&key={Config.PULSEDIVE_API_KEY}"
            r = self._make_request(url)
            if r.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            r.raise_for_status()
            d = r.json()
            if "error" in d:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": d.get("error")}, response_time=time.time() - start)
            risk = d.get("risk", "unknown").lower()
            risk_map = {"none": ThreatLevel.CLEAN, "low": ThreatLevel.LOW, "medium": ThreatLevel.MEDIUM,
                "high": ThreatLevel.HIGH, "critical": ThreatLevel.CRITICAL}
            threats = [t.get("name") for t in d.get("threats", [])[:5]]
            return LookupResult(source=self.name, found=True, threat_level=risk_map.get(risk, ThreatLevel.UNKNOWN),
                data={"risk": risk, "threats": threats}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class MaltiverseProvider(BaseLookupProvider):
    """Maltiverse - IOC intelligence"""
    name = "Maltiverse"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH_MD5, IOCType.HASH_SHA256]
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            if ioc_type == IOCType.IP: url = f"https://api.maltiverse.com/ip/{ioc}"
            elif ioc_type == IOCType.DOMAIN: url = f"https://api.maltiverse.com/hostname/{ioc}"
            elif ioc_type == IOCType.URL: url = f"https://api.maltiverse.com/url/{quote(ioc, safe='')}"
            else: url = f"https://api.maltiverse.com/sample/{ioc}"
            headers = {"Authorization": f"Bearer {Config.MALTIVERSE_API_KEY}"} if Config.MALTIVERSE_API_KEY else {}
            r = self._make_request(url, headers=headers)
            if r.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            r.raise_for_status()
            d = r.json()
            classification = d.get("classification", "unknown")
            threat_map = {"malicious": ThreatLevel.CRITICAL, "suspicious": ThreatLevel.HIGH,
                "neutral": ThreatLevel.CLEAN, "whitelist": ThreatLevel.CLEAN}
            return LookupResult(source=self.name, found=True, threat_level=threat_map.get(classification, ThreatLevel.UNKNOWN),
                data={"classification": classification, "tags": d.get("tag", [])[:5],
                    "blacklist": d.get("blacklist", [])[:3]}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class StopForumSpamProvider(BaseLookupProvider):
    """StopForumSpam - Spam database"""
    name = "StopForumSpam"
    supported_types = [IOCType.IP, IOCType.EMAIL]
    rate_limit = 0.5
    
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
                data={"appears": appears, "frequency": result.get("frequency", 0),
                    "confidence": result.get("confidence", 0)}, response_time=time.time() - start)
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
            score = result.get("verdicts", {}).get("overall", {}).get("score", 0)
            if is_malicious or score > 50: threat = ThreatLevel.CRITICAL
            elif score > 20: threat = ThreatLevel.HIGH
            elif score > 0: threat = ThreatLevel.MEDIUM
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"malicious": is_malicious, "score": score, 
                    "country": result.get("page", {}).get("country", "N/A")}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class IPInfoProvider(BaseLookupProvider):
    """IPInfo.io - IP information"""
    name = "IPInfo"
    supported_types = [IOCType.IP]
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            url = f"https://ipinfo.io/{ioc}/json"
            if Config.IPINFO_API_KEY: url += f"?token={Config.IPINFO_API_KEY}"
            r = self._make_request(url)
            if r.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.UNKNOWN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            r.raise_for_status()
            d = r.json()
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.CLEAN,
                data={"country": d.get("country", "N/A"), "city": d.get("city", "N/A"),
                    "org": d.get("org", "N/A"), "hostname": d.get("hostname", "N/A")}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class ThreatCrowdProvider(BaseLookupProvider):
    """ThreatCrowd - Open threat intel"""
    name = "ThreatCrowd"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.EMAIL]
    rate_limit = 10.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            if ioc_type == IOCType.IP: url = f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ioc}"
            elif ioc_type == IOCType.DOMAIN: url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={ioc}"
            else: url = f"https://www.threatcrowd.org/searchApi/v2/email/report/?email={quote(ioc)}"
            r = self._make_request(url)
            r.raise_for_status()
            d = r.json()
            if d.get("response_code") == "0":
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            votes = d.get("votes", 0)
            if votes < -1: threat = ThreatLevel.CRITICAL
            elif votes < 0: threat = ThreatLevel.HIGH
            elif votes == 0: threat = ThreatLevel.MEDIUM
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"votes": votes, "resolutions": len(d.get("resolutions", []))}, response_time=time.time() - start)
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
                data={"filename": d.get("FileName", "N/A"), "product": d.get("ProductName", "N/A"),
                    "known_source": d.get("source", "N/A")}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


# ═══════════════════════════════════════════════════════════════════════════════
# PREMIUM PROVIDERS - API Key Required (12)
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
            return LookupResult(source=self.name, found=False, error="API key required. Set VIRUSTOTAL_API_KEY", response_time=time.time() - start)
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
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.UNKNOWN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            r.raise_for_status()
            d = r.json().get("data", {}).get("attributes", {})
            stats = d.get("last_analysis_stats", {})
            malicious, total = stats.get("malicious", 0), sum(stats.values()) if stats else 0
            if total == 0: threat = ThreatLevel.UNKNOWN
            elif malicious == 0: threat = ThreatLevel.CLEAN
            elif malicious < 3: threat = ThreatLevel.LOW
            elif malicious < 10: threat = ThreatLevel.MEDIUM
            elif malicious < 20: threat = ThreatLevel.HIGH
            else: threat = ThreatLevel.CRITICAL
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"malicious": malicious, "total": total, "detection": f"{malicious}/{total}",
                    "reputation": d.get("reputation", "N/A")}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class AbuseIPDBProvider(BaseLookupProvider):
    """AbuseIPDB - IP abuse reports (1000/day free)"""
    name = "AbuseIPDB"
    supported_types = [IOCType.IP]
    requires_api_key = True
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.ABUSEIPDB_API_KEY:
            return LookupResult(source=self.name, found=False, error="API key required. Set ABUSEIPDB_API_KEY", response_time=time.time() - start)
        try:
            headers = {"Key": Config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
            r = self._make_request("https://api.abuseipdb.com/api/v2/check", headers=headers,
                params={"ipAddress": ioc, "maxAgeInDays": 90})
            r.raise_for_status()
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            if score == 0: threat = ThreatLevel.CLEAN
            elif score < 25: threat = ThreatLevel.LOW
            elif score < 50: threat = ThreatLevel.MEDIUM
            elif score < 75: threat = ThreatLevel.HIGH
            else: threat = ThreatLevel.CRITICAL
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"abuse_score": score, "country": d.get("countryCode", "N/A"), "isp": d.get("isp", "N/A"),
                    "total_reports": d.get("totalReports", 0), "is_tor": d.get("isTor", False)}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class HybridAnalysisProvider(BaseLookupProvider):
    """Hybrid Analysis - Malware sandbox (200/day free)"""
    name = "HybridAnalysis"
    supported_types = [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    requires_api_key = True
    rate_limit = 1.5
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.HYBRID_ANALYSIS_API_KEY:
            return LookupResult(source=self.name, found=False, error="API key required. Set HYBRID_ANALYSIS_API_KEY", response_time=time.time() - start)
        try:
            headers = {"api-key": Config.HYBRID_ANALYSIS_API_KEY, "User-Agent": "Falcon Sandbox",
                "Content-Type": "application/x-www-form-urlencoded"}
            r = self._make_request("https://www.hybrid-analysis.com/api/v2/search/hash", method="POST",
                headers=headers, data={"hash": ioc})
            r.raise_for_status()
            d = r.json()
            if not d:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            sample = d[0] if isinstance(d, list) else d
            verdict, score = sample.get("verdict", "unknown"), sample.get("threat_score", 0) or 0
            if verdict == "malicious" or score > 70: threat = ThreatLevel.CRITICAL
            elif verdict == "suspicious" or score > 30: threat = ThreatLevel.HIGH
            elif score > 0: threat = ThreatLevel.MEDIUM
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"verdict": verdict, "threat_score": score, "file_type": sample.get("type", "N/A"),
                    "vx_family": sample.get("vx_family", "N/A")}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class CensysProvider(BaseLookupProvider):
    """Censys - Internet scan data (250/day free)"""
    name = "Censys"
    supported_types = [IOCType.IP, IOCType.DOMAIN]
    requires_api_key = True
    rate_limit = 2.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.CENSYS_API_ID or not Config.CENSYS_API_SECRET:
            return LookupResult(source=self.name, found=False, error="Set CENSYS_API_ID and CENSYS_API_SECRET", response_time=time.time() - start)
        try:
            r = self._make_request(f"https://search.censys.io/api/v2/hosts/{ioc}",
                auth=(Config.CENSYS_API_ID, Config.CENSYS_API_SECRET))
            if r.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            r.raise_for_status()
            d = r.json().get("result", {})
            services = d.get("services", [])
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.LOW if services else ThreatLevel.CLEAN,
                data={"services_count": len(services), "services": [s.get("service_name", "?") for s in services[:5]],
                    "location": d.get("location", {}).get("country", "N/A")}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class AlienVaultOTXProvider(BaseLookupProvider):
    """AlienVault OTX - Threat intel (free with registration)"""
    name = "AlienVault"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    requires_api_key = True
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.OTX_API_KEY:
            return LookupResult(source=self.name, found=False, error="API key required. Set OTX_API_KEY", response_time=time.time() - start)
        try:
            base = "https://otx.alienvault.com/api/v1/indicators"
            if ioc_type == IOCType.IP: url = f"{base}/IPv4/{ioc}/general"
            elif ioc_type == IOCType.DOMAIN: url = f"{base}/domain/{ioc}/general"
            elif ioc_type == IOCType.URL: url = f"{base}/url/{ioc}/general"
            else: url = f"{base}/file/{ioc}/general"
            headers = {"X-OTX-API-KEY": Config.OTX_API_KEY}
            r = self._make_request(url, headers=headers)
            if r.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            r.raise_for_status()
            d = r.json()
            pulse_count = d.get("pulse_info", {}).get("count", 0)
            if pulse_count == 0: threat = ThreatLevel.CLEAN
            elif pulse_count < 5: threat = ThreatLevel.LOW
            elif pulse_count < 20: threat = ThreatLevel.MEDIUM
            elif pulse_count < 50: threat = ThreatLevel.HIGH
            else: threat = ThreatLevel.CRITICAL
            pulses = [p.get("name", "N/A") for p in d.get("pulse_info", {}).get("pulses", [])[:5]]
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"pulse_count": pulse_count, "pulses": pulses}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class ThreatFoxProvider(BaseLookupProvider):
    """ThreatFox - Malware IOCs (requires free key since May 2025)"""
    name = "ThreatFox"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH_MD5, IOCType.HASH_SHA256]
    requires_api_key = True
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.THREATFOX_API_KEY:
            return LookupResult(source=self.name, found=False, 
                error="API key required since May 2025. Get free key at auth.abuse.ch", response_time=time.time() - start)
        try:
            headers = {"Auth-Key": Config.THREATFOX_API_KEY}
            payload = {"query": "search_hash", "hash": ioc} if ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA256] else {"query": "search_ioc", "search_term": ioc}
            r = self._make_request("https://threatfox-api.abuse.ch/api/v1/", method="POST", headers=headers, json=payload)
            r.raise_for_status()
            d = r.json()
            if d.get("query_status") != "ok" or not d.get("data"):
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            ioc_data = d["data"][0] if isinstance(d["data"], list) else d["data"]
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.CRITICAL,
                data={"malware": ioc_data.get("malware", "N/A"), "threat_type": ioc_data.get("threat_type", "N/A"),
                    "confidence": ioc_data.get("confidence_level", "N/A"), "tags": ioc_data.get("tags", [])},
                response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class URLHausProvider(BaseLookupProvider):
    """URLHaus - Malicious URLs (requires free key since 2025)"""
    name = "URLHaus"
    supported_types = [IOCType.URL, IOCType.DOMAIN, IOCType.IP]
    requires_api_key = True
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.URLHAUS_API_KEY:
            return LookupResult(source=self.name, found=False,
                error="API key required. Get free key at auth.abuse.ch", response_time=time.time() - start)
        try:
            headers = {"Auth-Key": Config.URLHAUS_API_KEY}
            if ioc_type == IOCType.URL:
                r = self._make_request("https://urlhaus-api.abuse.ch/v1/url/", method="POST", headers=headers, data={"url": ioc})
            else:
                r = self._make_request("https://urlhaus-api.abuse.ch/v1/host/", method="POST", headers=headers, data={"host": ioc})
            r.raise_for_status()
            d = r.json()
            if d.get("query_status") != "ok":
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.CRITICAL,
                data={"threat": d.get("threat", "N/A"), "url_count": d.get("url_count", 0)}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class MalwareBazaarProvider(BaseLookupProvider):
    """MalwareBazaar - Malware samples (requires free key since 2025)"""
    name = "MalwareBazaar"
    supported_types = [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    requires_api_key = True
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.MALWAREBAZAAR_API_KEY:
            return LookupResult(source=self.name, found=False,
                error="API key required. Get free key at auth.abuse.ch", response_time=time.time() - start)
        try:
            headers = {"Auth-Key": Config.MALWAREBAZAAR_API_KEY}
            r = self._make_request("https://mb-api.abuse.ch/api/v1/", method="POST", headers=headers, data={"query": "get_info", "hash": ioc})
            r.raise_for_status()
            d = r.json()
            if d.get("query_status") != "ok" or not d.get("data"):
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            sample = d["data"][0] if isinstance(d["data"], list) else d["data"]
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.CRITICAL,
                data={"file_type": sample.get("file_type", "N/A"), "signature": sample.get("signature", "N/A"),
                    "tags": sample.get("tags", [])[:5]}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class BinaryEdgeProvider(BaseLookupProvider):
    """BinaryEdge - Internet scan data"""
    name = "BinaryEdge"
    supported_types = [IOCType.IP, IOCType.DOMAIN]
    requires_api_key = True
    rate_limit = 2.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.BINARYEDGE_API_KEY:
            return LookupResult(source=self.name, found=False, error="Set BINARYEDGE_API_KEY", response_time=time.time() - start)
        try:
            headers = {"X-Key": Config.BINARYEDGE_API_KEY}
            url = f"https://api.binaryedge.io/v2/query/ip/{ioc}" if ioc_type == IOCType.IP else f"https://api.binaryedge.io/v2/query/domains/subdomain/{ioc}"
            r = self._make_request(url, headers=headers)
            if r.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            r.raise_for_status()
            d = r.json()
            events = d.get("events", [])
            ports = list(set(e.get("port") for e in events if e.get("port")))
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.LOW,
                data={"total_events": len(events), "ports": ports[:10]}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class CriminalIPProvider(BaseLookupProvider):
    """CriminalIP - Threat intelligence"""
    name = "CriminalIP"
    supported_types = [IOCType.IP, IOCType.DOMAIN]
    requires_api_key = True
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.CRIMINALIP_API_KEY:
            return LookupResult(source=self.name, found=False, error="Set CRIMINALIP_API_KEY", response_time=time.time() - start)
        try:
            headers = {"x-api-key": Config.CRIMINALIP_API_KEY}
            url = f"https://api.criminalip.io/v1/asset/ip/report?ip={ioc}" if ioc_type == IOCType.IP else f"https://api.criminalip.io/v1/domain/reports?query={ioc}"
            r = self._make_request(url, headers=headers)
            r.raise_for_status()
            d = r.json()
            if d.get("status") != 200:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.UNKNOWN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            score = d.get("score", {})
            max_score = max(score.get("inbound", 0), score.get("outbound", 0))
            if max_score >= 80: threat = ThreatLevel.CRITICAL
            elif max_score >= 60: threat = ThreatLevel.HIGH
            elif max_score >= 40: threat = ThreatLevel.MEDIUM
            elif max_score > 0: threat = ThreatLevel.LOW
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"inbound_score": score.get("inbound", 0), "outbound_score": score.get("outbound", 0),
                    "is_vpn": d.get("is_vpn", False)}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class IPQualityScoreProvider(BaseLookupProvider):
    """IPQualityScore - Fraud scoring"""
    name = "IPQualityScore"
    supported_types = [IOCType.IP, IOCType.EMAIL]
    requires_api_key = True
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.IPQUALITYSCORE_API_KEY:
            return LookupResult(source=self.name, found=False, error="Set IPQUALITYSCORE_API_KEY", response_time=time.time() - start)
        try:
            url = f"https://ipqualityscore.com/api/json/ip/{Config.IPQUALITYSCORE_API_KEY}/{ioc}" if ioc_type == IOCType.IP else f"https://ipqualityscore.com/api/json/email/{Config.IPQUALITYSCORE_API_KEY}/{ioc}"
            r = self._make_request(url)
            r.raise_for_status()
            d = r.json()
            if not d.get("success", False):
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.UNKNOWN,
                    error=d.get("message", "Failed"), response_time=time.time() - start)
            fraud_score = d.get("fraud_score", 0)
            if fraud_score >= 85: threat = ThreatLevel.CRITICAL
            elif fraud_score >= 75: threat = ThreatLevel.HIGH
            elif fraud_score >= 50: threat = ThreatLevel.MEDIUM
            elif fraud_score > 0: threat = ThreatLevel.LOW
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"fraud_score": fraud_score, "vpn": d.get("vpn", False), "tor": d.get("tor", False),
                    "proxy": d.get("proxy", False)}, response_time=time.time() - start)
        except Exception as e:
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


# ═══════════════════════════════════════════════════════════════════════════════
# PROVIDER REGISTRY - 22 Total
# ═══════════════════════════════════════════════════════════════════════════════

ALL_PROVIDERS = [
    # FREE (10)
    ShodanInternetDBProvider, IPAPIProvider, GreyNoiseProvider, PulsediveProvider,
    MaltiverseProvider, StopForumSpamProvider, URLScanProvider, IPInfoProvider,
    ThreatCrowdProvider, CIRCLHashlookupProvider,
    # PREMIUM (12)
    VirusTotalProvider, AbuseIPDBProvider, HybridAnalysisProvider, CensysProvider,
    AlienVaultOTXProvider, ThreatFoxProvider, URLHausProvider, MalwareBazaarProvider,
    BinaryEdgeProvider, CriminalIPProvider, IPQualityScoreProvider,
]

PROVIDER_COUNT = len(ALL_PROVIDERS)
FREE_PROVIDERS = [p for p in ALL_PROVIDERS if not p.requires_api_key]
PREMIUM_PROVIDERS = [p for p in ALL_PROVIDERS if p.requires_api_key]
