"""
Whois and DNS Lookup module for SOC Toolkit
Provides domain/IP enrichment with WHOIS and DNS data
"""

import socket
import time
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import requests

from .logger import get_logger

logger = get_logger(__name__)


@dataclass
class WhoisResult:
    """WHOIS lookup result"""
    query: str
    found: bool
    registrar: str = "N/A"
    registrant: str = "N/A"
    organization: str = "N/A"
    country: str = "N/A"
    creation_date: str = "N/A"
    expiration_date: str = "N/A"
    updated_date: str = "N/A"
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    dnssec: str = "N/A"
    emails: List[str] = field(default_factory=list)
    raw: str = ""
    error: str = ""


@dataclass
class DNSResult:
    """DNS lookup result"""
    query: str
    found: bool
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[Dict] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)
    soa_record: Dict = field(default_factory=dict)
    ptr_record: str = ""
    error: str = ""


class WhoisLookup:
    """WHOIS lookup using free APIs"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SOC-Toolkit/1.2 (https://github.com/frkndncr/soc-toolkit)"
        })
    
    def lookup(self, query: str) -> WhoisResult:
        """
        Perform WHOIS lookup for domain or IP
        
        Args:
            query: Domain name or IP address
            
        Returns:
            WhoisResult object
        """
        # Try multiple WHOIS APIs
        result = self._lookup_whoisjson(query)
        
        if not result.found:
            result = self._lookup_ip_api(query)
        
        return result
    
    def _lookup_whoisjson(self, query: str) -> WhoisResult:
        """Lookup using whoisjson.com API (free)"""
        try:
            url = f"https://whoisjson.com/api/v1/whois?domain={query}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code != 200:
                return WhoisResult(query=query, found=False, error="API error")
            
            data = response.json()
            
            if "error" in data:
                return WhoisResult(query=query, found=False, error=data.get("error", ""))
            
            return WhoisResult(
                query=query,
                found=True,
                registrar=data.get("registrar", {}).get("name", "N/A") if isinstance(data.get("registrar"), dict) else data.get("registrar", "N/A"),
                registrant=data.get("registrant", {}).get("name", "N/A") if isinstance(data.get("registrant"), dict) else "N/A",
                organization=data.get("registrant", {}).get("organization", "N/A") if isinstance(data.get("registrant"), dict) else "N/A",
                country=data.get("registrant", {}).get("country", "N/A") if isinstance(data.get("registrant"), dict) else "N/A",
                creation_date=data.get("created", "N/A"),
                expiration_date=data.get("expires", "N/A"),
                updated_date=data.get("updated", "N/A"),
                name_servers=data.get("nameservers", []) or [],
                status=data.get("status", []) if isinstance(data.get("status"), list) else [data.get("status", "N/A")],
                dnssec=data.get("dnssec", "N/A"),
                raw=str(data)
            )
            
        except Exception as e:
            logger.error(f"WHOIS lookup error: {e}")
            return WhoisResult(query=query, found=False, error=str(e))
    
    def _lookup_ip_api(self, query: str) -> WhoisResult:
        """Fallback lookup using ip-api.com for IPs"""
        try:
            # Check if it's an IP
            socket.inet_aton(query)
            
            url = f"http://ip-api.com/json/{query}?fields=status,country,countryCode,regionName,city,isp,org,as,query"
            response = self.session.get(url, timeout=10)
            
            if response.status_code != 200:
                return WhoisResult(query=query, found=False, error="API error")
            
            data = response.json()
            
            if data.get("status") != "success":
                return WhoisResult(query=query, found=False, error="Lookup failed")
            
            return WhoisResult(
                query=query,
                found=True,
                organization=data.get("org", "N/A"),
                country=data.get("country", "N/A"),
                registrar=data.get("isp", "N/A"),
                raw=str(data)
            )
            
        except socket.error:
            # Not an IP, try domain WHOIS via alternative
            return self._lookup_whois_alternative(query)
        except Exception as e:
            logger.error(f"IP WHOIS lookup error: {e}")
            return WhoisResult(query=query, found=False, error=str(e))
    
    def _lookup_whois_alternative(self, domain: str) -> WhoisResult:
        """Alternative WHOIS lookup"""
        try:
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=JSON"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                whois_record = data.get("WhoisRecord", {})
                
                if whois_record:
                    registrant = whois_record.get("registrant", {})
                    return WhoisResult(
                        query=domain,
                        found=True,
                        registrar=whois_record.get("registrarName", "N/A"),
                        organization=registrant.get("organization", "N/A"),
                        country=registrant.get("country", "N/A"),
                        creation_date=whois_record.get("createdDate", "N/A"),
                        expiration_date=whois_record.get("expiresDate", "N/A"),
                        name_servers=whois_record.get("nameServers", {}).get("hostNames", []),
                        raw=str(whois_record)
                    )
            
            return WhoisResult(query=domain, found=False, error="No data found")
            
        except Exception as e:
            logger.error(f"Alternative WHOIS error: {e}")
            return WhoisResult(query=domain, found=False, error=str(e))


class DNSLookup:
    """DNS lookup using system resolver and public APIs"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SOC-Toolkit/1.2"
        })
    
    def lookup(self, query: str) -> DNSResult:
        """
        Perform DNS lookup for domain
        
        Args:
            query: Domain name
            
        Returns:
            DNSResult object
        """
        result = DNSResult(query=query, found=False)
        
        # Try A records (basic)
        try:
            ips = socket.gethostbyname_ex(query)
            result.a_records = list(set(ips[2]))
            result.found = True
        except socket.gaierror:
            pass
        except Exception as e:
            result.error = str(e)
        
        # Try Google DNS API for more records
        try:
            dns_result = self._lookup_google_dns(query)
            if dns_result:
                result.a_records = dns_result.get("a", result.a_records)
                result.aaaa_records = dns_result.get("aaaa", [])
                result.mx_records = dns_result.get("mx", [])
                result.ns_records = dns_result.get("ns", [])
                result.txt_records = dns_result.get("txt", [])
                result.cname_records = dns_result.get("cname", [])
                result.found = True
        except Exception as e:
            logger.debug(f"Google DNS lookup error: {e}")
        
        # Reverse DNS for IPs
        try:
            socket.inet_aton(query)
            try:
                result.ptr_record = socket.gethostbyaddr(query)[0]
                result.found = True
            except socket.herror:
                pass
        except socket.error:
            pass
        
        return result
    
    def _lookup_google_dns(self, domain: str) -> Dict[str, List]:
        """Use Google DNS-over-HTTPS API"""
        records = {
            "a": [],
            "aaaa": [],
            "mx": [],
            "ns": [],
            "txt": [],
            "cname": []
        }
        
        record_types = {
            "A": "a",
            "AAAA": "aaaa",
            "MX": "mx",
            "NS": "ns",
            "TXT": "txt",
            "CNAME": "cname"
        }
        
        for rtype, key in record_types.items():
            try:
                url = f"https://dns.google/resolve?name={domain}&type={rtype}"
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("Status") == 0 and "Answer" in data:
                        for answer in data["Answer"]:
                            value = answer.get("data", "")
                            
                            if rtype == "MX":
                                # Parse MX priority
                                parts = value.split()
                                if len(parts) >= 2:
                                    records[key].append({
                                        "priority": int(parts[0]),
                                        "host": parts[1].rstrip(".")
                                    })
                            elif rtype == "TXT":
                                records[key].append(value.strip('"'))
                            else:
                                records[key].append(value.rstrip("."))
                                
            except Exception as e:
                logger.debug(f"DNS {rtype} lookup error: {e}")
                continue
        
        return records
    
    def reverse_lookup(self, ip: str) -> str:
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ""


class EnrichmentEngine:
    """Combined enrichment engine for WHOIS + DNS"""
    
    def __init__(self):
        self.whois = WhoisLookup()
        self.dns = DNSLookup()
    
    def enrich(self, query: str, query_type: str = "auto") -> Dict[str, Any]:
        """
        Enrich IOC with WHOIS and DNS data
        
        Args:
            query: Domain or IP
            query_type: 'domain', 'ip', or 'auto'
            
        Returns:
            Dictionary with enrichment data
        """
        result = {
            "query": query,
            "type": query_type,
            "whois": None,
            "dns": None,
            "enriched_at": datetime.now().isoformat()
        }
        
        # Auto-detect type
        if query_type == "auto":
            try:
                socket.inet_aton(query)
                query_type = "ip"
            except socket.error:
                query_type = "domain"
        
        result["type"] = query_type
        
        # WHOIS lookup
        whois_result = self.whois.lookup(query)
        if whois_result.found:
            result["whois"] = {
                "registrar": whois_result.registrar,
                "organization": whois_result.organization,
                "country": whois_result.country,
                "creation_date": whois_result.creation_date,
                "expiration_date": whois_result.expiration_date,
                "name_servers": whois_result.name_servers,
                "status": whois_result.status
            }
        
        # DNS lookup
        if query_type == "domain":
            dns_result = self.dns.lookup(query)
            if dns_result.found:
                result["dns"] = {
                    "a_records": dns_result.a_records,
                    "aaaa_records": dns_result.aaaa_records,
                    "mx_records": dns_result.mx_records,
                    "ns_records": dns_result.ns_records,
                    "txt_records": dns_result.txt_records[:3],  # Limit TXT records
                    "cname_records": dns_result.cname_records
                }
        elif query_type == "ip":
            ptr = self.dns.reverse_lookup(query)
            if ptr:
                result["dns"] = {"ptr_record": ptr}
        
        return result


def format_whois_output(whois: WhoisResult) -> str:
    """Format WHOIS result for CLI output"""
    if not whois.found:
        return f"  ❌ WHOIS lookup failed: {whois.error or 'No data'}"
    
    lines = [
        f"  📋 Registrar: {whois.registrar}",
        f"  🏢 Organization: {whois.organization}",
        f"  🌍 Country: {whois.country}",
        f"  📅 Created: {whois.creation_date}",
        f"  ⏰ Expires: {whois.expiration_date}",
    ]
    
    if whois.name_servers:
        lines.append(f"  🌐 Nameservers: {', '.join(whois.name_servers[:3])}")
    
    return "\n".join(lines)


def format_dns_output(dns: DNSResult) -> str:
    """Format DNS result for CLI output"""
    if not dns.found:
        return f"  ❌ DNS lookup failed: {dns.error or 'No records'}"
    
    lines = []
    
    if dns.a_records:
        lines.append(f"  📍 A Records: {', '.join(dns.a_records[:5])}")
    
    if dns.aaaa_records:
        lines.append(f"  📍 AAAA Records: {', '.join(dns.aaaa_records[:3])}")
    
    if dns.mx_records:
        mx_list = [f"{m['host']} ({m['priority']})" for m in dns.mx_records[:3]]
        lines.append(f"  📧 MX Records: {', '.join(mx_list)}")
    
    if dns.ns_records:
        lines.append(f"  🌐 NS Records: {', '.join(dns.ns_records[:3])}")
    
    if dns.txt_records:
        lines.append(f"  📝 TXT Records: {len(dns.txt_records)} found")
    
    if dns.cname_records:
        lines.append(f"  🔗 CNAME: {', '.join(dns.cname_records[:2])}")
    
    if dns.ptr_record:
        lines.append(f"  🔄 PTR: {dns.ptr_record}")
    
    return "\n".join(lines) if lines else "  No DNS records found"
