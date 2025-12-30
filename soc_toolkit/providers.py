"""
Threat Intelligence Providers for SOC Toolkit
20 integrated sources for comprehensive IOC analysis
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
    """Base class for all lookup providers"""
    
    name: str = "Base"
    supported_types: List[IOCType] = []
    requires_api_key: bool = False
    rate_limit: float = 0.5
    _last_request: float = 0
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.USER_AGENT})
        
    def _rate_limit_wait(self):
        """Enforce rate limiting"""
        now = time.time()
        elapsed = now - self._last_request
        if elapsed < self.rate_limit:
            sleep_time = self.rate_limit - elapsed
            logger.debug(f"{self.name}: Rate limiting, sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        self._last_request = time.time()
        
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        raise NotImplementedError
        
    def _make_request(self, url: str, method: str = "GET", **kwargs) -> requests.Response:
        self._rate_limit_wait()
        kwargs.setdefault("timeout", Config.TIMEOUT)
        logger.debug(f"{self.name}: {method} {url}")
        return self.session.request(method, url, **kwargs)


# ═══════════════════════════════════════════════════════════════════════════════
# FREE PROVIDERS
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatFoxProvider(BaseLookupProvider):
    name = "ThreatFox"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH_MD5, IOCType.HASH_SHA256]
    requires_api_key = False
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            url = "https://threatfox-api.abuse.ch/api/v1/"
            if ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA256]:
                payload = {"query": "search_hash", "hash": ioc}
            else:
                payload = {"query": "search_ioc", "search_term": ioc}
            response = self._make_request(url, method="POST", json=payload)
            response.raise_for_status()
            data = response.json()
            if data.get("query_status") != "ok" or not data.get("data"):
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            ioc_data = data["data"][0] if isinstance(data["data"], list) else data["data"]
            logger.info(f"{self.name}: Found - {ioc_data.get('malware', 'Unknown')}")
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.CRITICAL,
                data={"malware": ioc_data.get("malware", "N/A"), "threat_type": ioc_data.get("threat_type", "N/A"),
                    "confidence": ioc_data.get("confidence_level", "N/A"), "first_seen": ioc_data.get("first_seen", "N/A"),
                    "tags": ioc_data.get("tags", [])}, response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class URLHausProvider(BaseLookupProvider):
    name = "URLHaus"
    supported_types = [IOCType.URL, IOCType.DOMAIN, IOCType.IP]
    requires_api_key = False
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            if ioc_type == IOCType.URL:
                url = "https://urlhaus-api.abuse.ch/v1/url/"
                payload = {"url": ioc}
            else:
                url = "https://urlhaus-api.abuse.ch/v1/host/"
                payload = {"host": ioc}
            response = self._make_request(url, method="POST", data=payload)
            response.raise_for_status()
            data = response.json()
            if data.get("query_status") == "no_results":
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            if data.get("query_status") == "ok":
                status = data.get("url_status", "unknown")
                return LookupResult(source=self.name, found=True,
                    threat_level=ThreatLevel.CRITICAL if status == "online" else ThreatLevel.HIGH,
                    data={"threat": data.get("threat", "N/A"), "status": status, "tags": data.get("tags", [])},
                    response_time=time.time() - start)
            if "urls" in data:
                return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.HIGH,
                    data={"url_count": len(data["urls"])}, response_time=time.time() - start)
            return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                data={"message": "Not found"}, response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class MalwareBazaarProvider(BaseLookupProvider):
    name = "MalwareBazaar"
    supported_types = [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    requires_api_key = False
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            response = self._make_request("https://mb-api.abuse.ch/api/v1/", method="POST",
                data={"query": "get_info", "hash": ioc})
            response.raise_for_status()
            data = response.json()
            if data.get("query_status") != "ok" or not data.get("data"):
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            sample = data["data"][0] if isinstance(data["data"], list) else data["data"]
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.CRITICAL,
                data={"file_name": sample.get("file_name", "N/A"), "file_type": sample.get("file_type", "N/A"),
                    "signature": sample.get("signature", "N/A"), "tags": sample.get("tags", [])},
                response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class FeodoTrackerProvider(BaseLookupProvider):
    name = "FeodoTracker"
    supported_types = [IOCType.IP]
    requires_api_key = False
    rate_limit = 2.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            response = self._make_request("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json")
            response.raise_for_status()
            for entry in response.json():
                if entry.get("ip_address") == ioc:
                    return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.CRITICAL,
                        data={"malware": entry.get("malware", "N/A"), "port": entry.get("port", "N/A"),
                            "status": entry.get("status", "N/A")}, response_time=time.time() - start)
            return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                data={"message": "Not found"}, response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class ShodanInternetDBProvider(BaseLookupProvider):
    name = "Shodan"
    supported_types = [IOCType.IP]
    requires_api_key = False
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            response = self._make_request(f"https://internetdb.shodan.io/{ioc}")
            if response.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            response.raise_for_status()
            data = response.json()
            vulns, ports = data.get("vulns", []), data.get("ports", [])
            if len(vulns) > 5: threat = ThreatLevel.CRITICAL
            elif len(vulns) > 0: threat = ThreatLevel.HIGH
            elif len(ports) > 10: threat = ThreatLevel.MEDIUM
            elif len(ports) > 0: threat = ThreatLevel.LOW
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"ports": ports, "vulns": vulns[:10], "vuln_count": len(vulns), "hostnames": data.get("hostnames", [])},
                response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class IPAPIProvider(BaseLookupProvider):
    name = "IP-API"
    supported_types = [IOCType.IP]
    requires_api_key = False
    rate_limit = 0.7
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            response = self._make_request(f"http://ip-api.com/json/{ioc}?fields=status,country,countryCode,city,isp,org,as,proxy,hosting")
            response.raise_for_status()
            data = response.json()
            if data.get("status") != "success":
                return LookupResult(source=self.name, found=False, error="Lookup failed", response_time=time.time() - start)
            is_proxy, is_hosting = data.get("proxy", False), data.get("hosting", False)
            if is_proxy: threat = ThreatLevel.MEDIUM
            elif is_hosting: threat = ThreatLevel.LOW
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"country": f"{data.get('country', 'N/A')} ({data.get('countryCode', '')})",
                    "city": data.get("city", "N/A"), "isp": data.get("isp", "N/A"), "org": data.get("org", "N/A"),
                    "asn": data.get("as", "N/A"), "is_proxy": is_proxy, "is_hosting": is_hosting},
                response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class AlienVaultOTXProvider(BaseLookupProvider):
    name = "AlienVault"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    requires_api_key = False
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            base = "https://otx.alienvault.com/api/v1/indicators"
            if ioc_type == IOCType.IP: url = f"{base}/IPv4/{ioc}/general"
            elif ioc_type == IOCType.DOMAIN: url = f"{base}/domain/{ioc}/general"
            elif ioc_type == IOCType.URL: url = f"{base}/url/{ioc}/general"
            else: url = f"{base}/file/{ioc}/general"
            headers = {"X-OTX-API-KEY": Config.OTX_API_KEY} if Config.OTX_API_KEY else {}
            response = self._make_request(url, headers=headers)
            if response.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            response.raise_for_status()
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            if pulse_count == 0: threat = ThreatLevel.CLEAN
            elif pulse_count < 5: threat = ThreatLevel.LOW
            elif pulse_count < 20: threat = ThreatLevel.MEDIUM
            elif pulse_count < 50: threat = ThreatLevel.HIGH
            else: threat = ThreatLevel.CRITICAL
            pulses = [p.get("name", "N/A") for p in data.get("pulse_info", {}).get("pulses", [])[:5]]
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"pulse_count": pulse_count, "pulses": pulses}, response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class PulsediveProvider(BaseLookupProvider):
    name = "Pulsedive"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL]
    requires_api_key = False
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            url = f"https://pulsedive.com/api/info.php?indicator={quote(ioc)}&pretty=1"
            if Config.PULSEDIVE_API_KEY: url += f"&key={Config.PULSEDIVE_API_KEY}"
            response = self._make_request(url)
            if response.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            response.raise_for_status()
            data = response.json()
            if "error" in data:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": data.get("error")}, response_time=time.time() - start)
            risk = data.get("risk", "unknown").lower()
            risk_map = {"none": ThreatLevel.CLEAN, "low": ThreatLevel.LOW, "medium": ThreatLevel.MEDIUM,
                "high": ThreatLevel.HIGH, "critical": ThreatLevel.CRITICAL}
            return LookupResult(source=self.name, found=True, threat_level=risk_map.get(risk, ThreatLevel.UNKNOWN),
                data={"risk": risk, "threats": [t.get("name") for t in data.get("threats", [])[:5]]},
                response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class GreyNoiseProvider(BaseLookupProvider):
    name = "GreyNoise"
    supported_types = [IOCType.IP]
    requires_api_key = False
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            headers = {"key": Config.GREYNOISE_API_KEY} if Config.GREYNOISE_API_KEY else {}
            response = self._make_request(f"https://api.greynoise.io/v3/community/{ioc}", headers=headers)
            if response.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not seen (likely clean)"}, response_time=time.time() - start)
            response.raise_for_status()
            data = response.json()
            noise, riot = data.get("noise", False), data.get("riot", False)
            classification = data.get("classification", "unknown")
            if riot: threat = ThreatLevel.CLEAN
            elif classification == "malicious": threat = ThreatLevel.CRITICAL
            elif classification == "benign": threat = ThreatLevel.CLEAN
            elif noise: threat = ThreatLevel.LOW
            else: threat = ThreatLevel.UNKNOWN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"classification": classification, "noise": noise, "riot": riot, "name": data.get("name", "N/A")},
                response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class BGPViewProvider(BaseLookupProvider):
    name = "BGPView"
    supported_types = [IOCType.IP]
    requires_api_key = False
    rate_limit = 0.5
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            response = self._make_request(f"https://api.bgpview.io/ip/{ioc}")
            response.raise_for_status()
            data = response.json()
            if data.get("status") != "ok":
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.UNKNOWN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            ip_data = data.get("data", {})
            prefixes = ip_data.get("prefixes", [])
            prefix_info = prefixes[0] if prefixes else {}
            asn_info = prefix_info.get("asn", {})
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.CLEAN,
                data={"asn": asn_info.get("asn", "N/A"), "asn_name": asn_info.get("name", "N/A"),
                    "country": asn_info.get("country_code", "N/A"), "prefix": prefix_info.get("prefix", "N/A")},
                response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class ThreatMinerProvider(BaseLookupProvider):
    name = "ThreatMiner"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.HASH_MD5, IOCType.HASH_SHA256]
    requires_api_key = False
    rate_limit = 6.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            if ioc_type == IOCType.IP: url = f"https://api.threatminer.org/v2/host.php?q={ioc}&rt=1"
            elif ioc_type == IOCType.DOMAIN: url = f"https://api.threatminer.org/v2/domain.php?q={ioc}&rt=1"
            else: url = f"https://api.threatminer.org/v2/sample.php?q={ioc}&rt=1"
            response = self._make_request(url)
            response.raise_for_status()
            data = response.json()
            if data.get("status_code") != "200" or not data.get("results"):
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            results = data.get("results", [])
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.MEDIUM,
                data={"results_count": len(results)}, response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class URLScanProvider(BaseLookupProvider):
    name = "URLScan"
    supported_types = [IOCType.URL, IOCType.DOMAIN]
    requires_api_key = False
    rate_limit = 2.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            q = f"domain:{ioc}" if ioc_type == IOCType.DOMAIN else f"url:{quote(ioc)}"
            headers = {"API-Key": Config.URLSCAN_API_KEY} if Config.URLSCAN_API_KEY else {}
            response = self._make_request(f"https://urlscan.io/api/v1/search/?q={q}&size=1", headers=headers)
            response.raise_for_status()
            results = response.json().get("results", [])
            if not results:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.UNKNOWN,
                    data={"message": "No scans found"}, response_time=time.time() - start)
            result = results[0]
            verdicts = result.get("verdicts", {})
            is_malicious = verdicts.get("overall", {}).get("malicious", False)
            score = verdicts.get("overall", {}).get("score", 0)
            if is_malicious or score > 50: threat = ThreatLevel.CRITICAL
            elif score > 20: threat = ThreatLevel.HIGH
            elif score > 0: threat = ThreatLevel.MEDIUM
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"malicious": is_malicious, "score": score, "scan_id": result.get("_id", "N/A")},
                response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class MaltiverseProvider(BaseLookupProvider):
    name = "Maltiverse"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH_MD5, IOCType.HASH_SHA256]
    requires_api_key = False
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            if ioc_type == IOCType.IP: url = f"https://api.maltiverse.com/ip/{ioc}"
            elif ioc_type == IOCType.DOMAIN: url = f"https://api.maltiverse.com/hostname/{ioc}"
            elif ioc_type == IOCType.URL: url = f"https://api.maltiverse.com/url/{quote(ioc, safe='')}"
            else: url = f"https://api.maltiverse.com/sample/{ioc}"
            headers = {"Authorization": f"Bearer {Config.MALTIVERSE_API_KEY}"} if Config.MALTIVERSE_API_KEY else {}
            response = self._make_request(url, headers=headers)
            if response.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            response.raise_for_status()
            data = response.json()
            classification = data.get("classification", "unknown")
            threat_map = {"malicious": ThreatLevel.CRITICAL, "suspicious": ThreatLevel.HIGH,
                "neutral": ThreatLevel.CLEAN, "whitelist": ThreatLevel.CLEAN}
            return LookupResult(source=self.name, found=True, threat_level=threat_map.get(classification, ThreatLevel.UNKNOWN),
                data={"classification": classification, "tags": data.get("tag", [])[:5]}, response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class PhishStatsProvider(BaseLookupProvider):
    name = "PhishStats"
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL]
    requires_api_key = False
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            response = self._make_request(f"https://phishstats.info/api/phishing?_where=(url,like,~{quote(ioc)}~)&_size=5")
            response.raise_for_status()
            data = response.json()
            if not data:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.CRITICAL,
                data={"phishing_count": len(data), "score": data[0].get("score", "N/A") if data else "N/A"},
                response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class StopForumSpamProvider(BaseLookupProvider):
    name = "StopForumSpam"
    supported_types = [IOCType.IP, IOCType.EMAIL]
    requires_api_key = False
    rate_limit = 0.5
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        try:
            param = "ip" if ioc_type == IOCType.IP else "email"
            response = self._make_request(f"https://api.stopforumspam.org/api?{param}={ioc}&json")
            response.raise_for_status()
            data = response.json()
            result = data.get(param, {})
            appears = result.get("appears", 0)
            if appears == 0: threat = ThreatLevel.CLEAN
            elif appears < 5: threat = ThreatLevel.LOW
            elif appears < 20: threat = ThreatLevel.MEDIUM
            else: threat = ThreatLevel.HIGH
            return LookupResult(source=self.name, found=appears > 0, threat_level=threat,
                data={"appears": appears, "frequency": result.get("frequency", 0), "confidence": result.get("confidence", 0)},
                response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


# ═══════════════════════════════════════════════════════════════════════════════
# PREMIUM PROVIDERS
# ═══════════════════════════════════════════════════════════════════════════════

class VirusTotalProvider(BaseLookupProvider):
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
            response = self._make_request(url, headers=headers)
            if response.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.UNKNOWN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            response.raise_for_status()
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious, total = stats.get("malicious", 0), sum(stats.values()) if stats else 0
            if total == 0: threat = ThreatLevel.UNKNOWN
            elif malicious == 0: threat = ThreatLevel.CLEAN
            elif malicious < 3: threat = ThreatLevel.LOW
            elif malicious < 10: threat = ThreatLevel.MEDIUM
            elif malicious < 20: threat = ThreatLevel.HIGH
            else: threat = ThreatLevel.CRITICAL
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"malicious": malicious, "total": total, "detection": f"{malicious}/{total}",
                    "reputation": data.get("reputation", "N/A")}, response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class AbuseIPDBProvider(BaseLookupProvider):
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
            response = self._make_request("https://api.abuseipdb.com/api/v2/check",
                headers=headers, params={"ipAddress": ioc, "maxAgeInDays": 90})
            response.raise_for_status()
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            if score == 0: threat = ThreatLevel.CLEAN
            elif score < 25: threat = ThreatLevel.LOW
            elif score < 50: threat = ThreatLevel.MEDIUM
            elif score < 75: threat = ThreatLevel.HIGH
            else: threat = ThreatLevel.CRITICAL
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"abuse_score": score, "country": data.get("countryCode", "N/A"), "isp": data.get("isp", "N/A"),
                    "total_reports": data.get("totalReports", 0), "is_tor": data.get("isTor", False)},
                response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class HybridAnalysisProvider(BaseLookupProvider):
    name = "HybridAnalysis"
    supported_types = [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    requires_api_key = True
    rate_limit = 1.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.HYBRID_ANALYSIS_API_KEY:
            return LookupResult(source=self.name, found=False, error="API key required. Set HYBRID_ANALYSIS_API_KEY", response_time=time.time() - start)
        try:
            headers = {"api-key": Config.HYBRID_ANALYSIS_API_KEY, "User-Agent": "Falcon Sandbox",
                "Content-Type": "application/x-www-form-urlencoded"}
            response = self._make_request("https://www.hybrid-analysis.com/api/v2/search/hash",
                method="POST", headers=headers, data={"hash": ioc})
            response.raise_for_status()
            data = response.json()
            if not data:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            sample = data[0] if isinstance(data, list) else data
            verdict, score = sample.get("verdict", "unknown"), sample.get("threat_score", 0)
            if verdict == "malicious" or score > 70: threat = ThreatLevel.CRITICAL
            elif verdict == "suspicious" or score > 30: threat = ThreatLevel.HIGH
            elif score > 0: threat = ThreatLevel.MEDIUM
            else: threat = ThreatLevel.CLEAN
            return LookupResult(source=self.name, found=True, threat_level=threat,
                data={"verdict": verdict, "threat_score": score, "file_type": sample.get("type", "N/A")},
                response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


class CensysProvider(BaseLookupProvider):
    name = "Censys"
    supported_types = [IOCType.IP, IOCType.DOMAIN]
    requires_api_key = True
    rate_limit = 2.0
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> LookupResult:
        start = time.time()
        if not Config.CENSYS_API_ID or not Config.CENSYS_API_SECRET:
            return LookupResult(source=self.name, found=False, error="API credentials required. Set CENSYS_API_ID and CENSYS_API_SECRET", response_time=time.time() - start)
        try:
            response = self._make_request(f"https://search.censys.io/api/v2/hosts/{ioc}",
                auth=(Config.CENSYS_API_ID, Config.CENSYS_API_SECRET))
            if response.status_code == 404:
                return LookupResult(source=self.name, found=False, threat_level=ThreatLevel.CLEAN,
                    data={"message": "Not found"}, response_time=time.time() - start)
            response.raise_for_status()
            data = response.json().get("result", {})
            services = data.get("services", [])
            return LookupResult(source=self.name, found=True, threat_level=ThreatLevel.LOW if services else ThreatLevel.CLEAN,
                data={"services_count": len(services), "services": [s.get("service_name", "?") for s in services[:5]],
                    "location": data.get("location", {}).get("country", "N/A")}, response_time=time.time() - start)
        except Exception as e:
            logger.error(f"{self.name}: {e}")
            return LookupResult(source=self.name, found=False, error=str(e), response_time=time.time() - start)


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

ALL_PROVIDERS = [
    ThreatFoxProvider, URLHausProvider, MalwareBazaarProvider, FeodoTrackerProvider,
    ShodanInternetDBProvider, IPAPIProvider, AlienVaultOTXProvider, PulsediveProvider,
    GreyNoiseProvider, BGPViewProvider, ThreatMinerProvider, URLScanProvider,
    MaltiverseProvider, PhishStatsProvider, StopForumSpamProvider,
    VirusTotalProvider, AbuseIPDBProvider, HybridAnalysisProvider, CensysProvider,
]

PROVIDER_COUNT = len(ALL_PROVIDERS)
FREE_PROVIDERS = [p for p in ALL_PROVIDERS if not p.requires_api_key]
PREMIUM_PROVIDERS = [p for p in ALL_PROVIDERS if p.requires_api_key]
