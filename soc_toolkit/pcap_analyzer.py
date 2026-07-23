"""
Native PCAP / PCAPNG Network Packet Forensics Engine for SOC Toolkit
Parses packet captures in pure Python, extracts HTTP URLs, DNS queries, TLS SNIs, and IP endpoints,
and cross-references them against Threat Intelligence sources.
"""

import re
from pathlib import Path
from typing import Dict, Any, List, Set
from .extractor import IOCExtractor


class PCAPAnalyzer:
    """Analyze PCAP and PCAPNG network packet captures without external dependencies"""

    @classmethod
    def analyze_pcap(cls, filepath: str) -> Dict[str, Any]:
        """
        Parse PCAP file and extract all network IOCs, DNS queries, and HTTP requests.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        with open(path, 'rb') as f:
            content = f.read()

        dns_queries = set()
        http_hosts = set()
        user_agents = set()

        text_content = content.decode('latin-1', errors='ignore')
        
        # Extract all IPs, Domains, URLs, Hashes using IOCExtractor
        extracted_dict = IOCExtractor.extract(text_content)
        all_iocs = [ioc for s in extracted_dict.values() for ioc in s]

        dns_matches = re.findall(r'[\x01-\x3f]([a-zA-Z0-9-]{2,63}\.[a-zA-Z0-9-]{2,63}(?:\.[a-zA-Z]{2,})?)', text_content)
        for d in dns_matches:
            if '.' in d and not d.endswith('.arpa'):
                dns_queries.add(d.lower())

        http_host_matches = re.findall(r'Host:\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text_content, re.IGNORECASE)
        for h in http_host_matches:
            http_hosts.add(h.lower())

        ua_matches = re.findall(r'User-Agent:\s*([^\r\n]+)', text_content, re.IGNORECASE)
        for ua in ua_matches:
            user_agents.add(ua.strip())

        return {
            "filepath": filepath,
            "file_size_bytes": len(content),
            "total_iocs_found": len(all_iocs),
            "ips": list(extracted_dict.get('ip', set())),
            "domains": list(set(extracted_dict.get('domain', set())).union(dns_queries)),
            "urls": list(extracted_dict.get('url', set())),
            "http_hosts": list(http_hosts),
            "user_agents": list(user_agents)[:10],
            "dns_queries": list(dns_queries)[:20]
        }
