"""
OSINT Investigation Links Generator for SOC Toolkit
Generates direct URLs to major OSINT threat platforms (VirusTotal, Pulsedive, Censys, Shodan, Any.Run, URLScan, AbuseIPDB)
"""

from urllib.parse import quote
from typing import Dict, List
from .enums import IOCType


class OSINTLinksGenerator:
    """Generate OSINT links for 1-click manual analyst investigation"""

    @classmethod
    def get_links(cls, ioc: str, ioc_type: IOCType) -> Dict[str, str]:
        type_str = ioc_type.value if hasattr(ioc_type, 'value') else str(ioc_type)
        links = {}

        if type_str.lower() in ("ip", "ipv4", "ipv6"):
            links["VirusTotal"] = f"https://www.virustotal.com/gui/ip-address/{ioc}"
            links["AbuseIPDB"] = f"https://www.abuseipdb.com/check/{ioc}"
            links["Shodan"] = f"https://www.shodan.io/host/{ioc}"
            links["Censys"] = f"https://search.censys.io/hosts/{ioc}"
            links["Pulsedive"] = f"https://pulsedive.com/indicator/?ioc={quote(ioc)}"
            links["GreyNoise"] = f"https://viz.greynoise.io/ip/{ioc}"
            links["AlienVault OTX"] = f"https://otx.alienvault.com/indicator/ip/{ioc}"

        elif type_str.lower() in ("domain", "url"):
            domain = ioc.replace("https://", "").replace("http://", "").split("/")[0]
            links["VirusTotal"] = f"https://www.virustotal.com/gui/domain/{domain}"
            links["URLScan.io"] = f"https://urlscan.io/domain/{domain}"
            links["Pulsedive"] = f"https://pulsedive.com/indicator/?ioc={quote(domain)}"
            links["AlienVault OTX"] = f"https://otx.alienvault.com/indicator/domain/{domain}"
            links["Any.Run"] = f"https://app.any.run/submissions/#query={quote(domain)}"
            links["CRT.sh"] = f"https://crt.sh/?q={quote(domain)}"

        elif type_str.lower() in ("md5", "sha1", "sha256") or "hash" in type_str.lower():
            links["VirusTotal"] = f"https://www.virustotal.com/gui/file/{ioc}"
            links["MalwareBazaar"] = f"https://bazaar.abuse.ch/browse.php?search={ioc}"
            links["Hybrid-Analysis"] = f"https://www.hybrid-analysis.com/search?query={ioc}"
            links["Any.Run"] = f"https://app.any.run/submissions/#query={ioc}"
            links["Pulsedive"] = f"https://pulsedive.com/indicator/?ioc={ioc}"

        return links
