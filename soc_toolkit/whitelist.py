"""
False Positive & Known Benign / Cloud CDN Detector for SOC Toolkit
Helps SOC analysts eliminate noise and false positive triggers on legitimate infrastructure.
"""

import ipaddress
from typing import Dict, Any, Optional, Tuple


# Known Public DNS & Major CDN / Cloud Infrastructure Subnets
BENIGN_SUBNETS = [
    # Google Public DNS / Cloud
    ("8.8.8.0/24", "Google Public DNS", "Google"),
    ("8.8.4.0/24", "Google Public DNS", "Google"),
    ("2001:4860:4860::/48", "Google Public DNS IPv6", "Google"),
    # Cloudflare DNS & CDN
    ("1.1.1.0/24", "Cloudflare DNS", "Cloudflare"),
    ("1.0.0.0/24", "Cloudflare DNS", "Cloudflare"),
    ("104.16.0.0/12", "Cloudflare CDN", "Cloudflare"),
    ("172.64.0.0/13", "Cloudflare CDN", "Cloudflare"),
    # Quad9 DNS
    ("9.9.9.0/24", "Quad9 Public DNS", "Quad9"),
    ("149.112.112.0/24", "Quad9 Public DNS", "Quad9"),
    # OpenDNS / Cisco
    ("208.67.222.0/24", "Cisco OpenDNS", "Cisco"),
    ("208.67.220.0/24", "Cisco OpenDNS", "Cisco"),
    # Akamai CDN
    ("23.32.0.0/11", "Akamai Technologies CDN", "Akamai"),
    ("184.24.0.0/13", "Akamai Technologies CDN", "Akamai"),
    # Microsoft / Azure Office 365 Core
    ("13.107.6.0/24", "Microsoft 365 Core Service", "Microsoft"),
    ("52.96.0.0/12", "Microsoft Azure / Office 365", "Microsoft"),
    # Amazon AWS CloudFront / Core
    ("13.32.0.0/15", "Amazon CloudFront CDN", "Amazon"),
    ("54.239.0.0/16", "Amazon AWS Services", "Amazon"),
]

# Legitimate High-Ranked Benign Domains
BENIGN_DOMAINS = {
    "google.com", "www.google.com", "dns.google",
    "cloudflare.com", "one.one.one.one", "cloudflare-dns.com",
    "microsoft.com", "www.microsoft.com", "azure.com", "office.com",
    "github.com", "raw.githubusercontent.com", "githubusercontent.com",
    "amazon.com", "aws.amazon.com", "cloudfront.net",
    "wikipedia.org", "wikimedia.org",
    "apple.com", "icloud.com",
    "quad9.net", "opendns.com"
}


class WhitelistFilter:
    """Filter out known benign infrastructure to prevent false positive alert fatigue"""

    @staticmethod
    def check_ip(ip_str: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check if an IP address is a known benign public service/CDN.
        
        Returns:
            (is_benign, description, provider)
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private:
                return True, "RFC1918 Private Enterprise Internal IP", "Internal Network"
            if ip_obj.is_loopback:
                return True, "Localhost Loopback IP Address", "Localhost"
            if ip_obj.is_link_local:
                return True, "Link-Local IP Address", "Local Network"
            for cidr, name, provider in BENIGN_SUBNETS:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True, name, provider
        except ValueError:
            pass
        return False, None, None

    @staticmethod
    def check_domain(domain_str: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a domain is a known top-tier benign domain.
        
        Returns:
            (is_benign, description)
        """
        domain_clean = domain_str.lower().strip(".")
        if domain_clean in BENIGN_DOMAINS or any(domain_clean.endswith("." + b) for b in BENIGN_DOMAINS):
            return True, f"Top-Tier Trusted Benign Domain ({domain_clean})"
        return False, None

    @classmethod
    def evaluate(cls, ioc: str, ioc_type_str: str) -> Dict[str, Any]:
        """
        Evaluate an IOC against whitelist rules.
        """
        if ioc_type_str.lower() in ("ip", "ipv4", "ipv6"):
            is_benign, desc, provider = cls.check_ip(ioc)
            if is_benign:
                return {
                    "is_benign": True,
                    "reason": f"Known Benign Infrastructure: {desc} ({provider})",
                    "provider": provider,
                    "confidence": "HIGH"
                }
        elif ioc_type_str.lower() in ("domain", "url"):
            hostname = ioc.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            is_benign, desc = cls.check_domain(hostname)
            if is_benign:
                return {
                    "is_benign": True,
                    "reason": desc,
                    "confidence": "HIGH"
                }

        return {"is_benign": False, "reason": None, "confidence": "NONE"}
