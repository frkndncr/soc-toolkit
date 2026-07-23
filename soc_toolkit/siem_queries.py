"""
Multi-SIEM Search Query Generator for SOC Toolkit
Generates ready-to-copy SIEM queries for Splunk, Elastic, Microsoft Sentinel, IBM QRadar, and CrowdStrike Falcon.
"""

from typing import Dict, Any
from .enums import IOCType


class SIEMQueryGenerator:
    """Generate instant search queries for major enterprise SIEM and EDR platforms"""

    @classmethod
    def generate_all(cls, ioc: str, ioc_type: IOCType) -> Dict[str, str]:
        type_str = ioc_type.value if hasattr(ioc_type, 'value') else str(ioc_type)
        queries = {}

        if type_str in ("ip", "ipv4", "ipv6"):
            queries["splunk"] = f'index=* (src_ip="{ioc}" OR dest_ip="{ioc}" OR query="{ioc}")'
            queries["elastic"] = f'destination.ip: "{ioc}" OR source.ip: "{ioc}" OR dns.question.name: "{ioc}"'
            queries["sentinel"] = f'CommonSecurityLog | where DestinationIP == "{ioc}" or SourceIP == "{ioc}"'
            queries["qradar"] = f"SELECT * FROM events WHERE sourceip = '{ioc}' OR destinationip = '{ioc}'"
            queries["crowdstrike"] = f'event_simpleName=* IP4Value="{ioc}"'

        elif type_str in ("domain", "url"):
            domain = ioc.replace("https://", "").replace("http://", "").split("/")[0]
            queries["splunk"] = f'index=* (query="{domain}" OR url="*{domain}*")'
            queries["elastic"] = f'dns.question.name: "{domain}" OR url.full: "*{domain}*"'
            queries["sentinel"] = f'DnsEvents | where Name contains "{domain}"'
            queries["qradar"] = f"SELECT * FROM events WHERE \"Domain\" ILIKE '%{domain}%'"
            queries["crowdstrike"] = f'event_simpleName=DnsRequest DomainName="*{domain}*"'

        elif "hash" in type_str:
            queries["splunk"] = f'index=* (md5="{ioc}" OR sha256="{ioc}" OR file_hash="{ioc}")'
            queries["elastic"] = f'file.hash.sha256: "{ioc}" OR file.hash.md5: "{ioc}"'
            queries["sentinel"] = f'DeviceFileEvents | where SHA256 == "{ioc}" or MD5 == "{ioc}"'
            queries["qradar"] = f"SELECT * FROM events WHERE \"File Hash\" = '{ioc}'"
            queries["crowdstrike"] = f'event_simpleName=ProcessRollup2 SHA256HashData="{ioc}"'

        return queries
