"""
IOC Extractor - Extract IOCs from log files, text, and various formats
"""

import re
import sys
from pathlib import Path
from typing import List, Set, Dict, Tuple
from collections import Counter
from dataclasses import dataclass, field

from .enums import IOCType


@dataclass
class ExtractionResult:
    """Result of IOC extraction"""
    source: str
    total_iocs: int
    unique_iocs: int
    iocs_by_type: Dict[str, List[str]] = field(default_factory=dict)
    top_iocs: Dict[str, List[Tuple[str, int]]] = field(default_factory=dict)


class IOCExtractor:
    """Extract IOCs from text, logs, and files"""
    
    # Regex patterns for IOC extraction
    PATTERNS = {
        'ip': re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        'ip_defanged': re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[\.\]){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        'domain': re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+' 
            r'(?:com|net|org|edu|gov|mil|io|co|info|biz|xyz|top|club|online|site|'
            r'ru|cn|de|uk|fr|jp|br|in|au|nl|ir|tr|it|es|pl|ca|kr|vn|ua|mx|id|'
            r'tk|ml|ga|cf|gq|pw|cc|ws|su|nu|mobi|pro|tel|asia|name|museum|coop|'
            r'aero|jobs|travel|xxx|onion|local)\b',
            re.IGNORECASE
        ),
        'domain_defanged': re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\[\.\])+' 
            r'(?:com|net|org|edu|gov|io|co|ru|cn|de|uk)\b',
            re.IGNORECASE
        ),
        'url': re.compile(
            r'https?://[^\s<>"\'}\]]+',
            re.IGNORECASE
        ),
        'url_defanged': re.compile(
            r'hxxps?://[^\s<>"\'}\]]+',
            re.IGNORECASE
        ),
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'email': re.compile(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        ),
        'email_defanged': re.compile(
            r'\b[a-zA-Z0-9._%+-]+\[@\][a-zA-Z0-9.-]+\[\.\][a-zA-Z]{2,}\b'
        ),
        'cve': re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE),
        'mac': re.compile(
            r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
        ),
        'btc': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
        'registry': re.compile(
            r'\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKU|HKCR|HKCC)'
            r'\\[^\s]+',
            re.IGNORECASE
        ),
        'filepath_windows': re.compile(
            r'\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
        ),
        'filepath_unix': re.compile(
            r'(?:/[a-zA-Z0-9._-]+)+/?'
        ),
    }
    
    # Known false positives to filter
    FALSE_POSITIVES = {
        'ip': {
            '0.0.0.0', '127.0.0.1', '255.255.255.255', '255.255.255.0',
            '192.168.0.1', '192.168.1.1', '10.0.0.1', '172.16.0.1',
            '224.0.0.1', '239.255.255.250', '8.8.8.8', '8.8.4.4',
            '1.1.1.1', '1.0.0.1'
        },
        'domain': {
            'example.com', 'example.org', 'example.net', 'localhost.local',
            'test.com', 'domain.com', 'google.com', 'microsoft.com',
            'windows.com', 'office.com', 'live.com', 'windowsupdate.com',
            'schema.org', 'w3.org', 'xmlns.com', 'purl.org'
        }
    }
    
    # Private IP ranges
    PRIVATE_IP_PATTERNS = [
        re.compile(r'^10\.'),
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),
        re.compile(r'^192\.168\.'),
        re.compile(r'^127\.'),
        re.compile(r'^169\.254\.'),
    ]
    
    @classmethod
    def is_private_ip(cls, ip: str) -> bool:
        """Check if IP is private/internal"""
        return any(pattern.match(ip) for pattern in cls.PRIVATE_IP_PATTERNS)
    
    @classmethod
    def refang(cls, ioc: str) -> str:
        """Convert defanged IOC to normal format"""
        return (ioc
            .replace('[.]', '.')
            .replace('[@]', '@')
            .replace('hxxp://', 'http://')
            .replace('hxxps://', 'https://')
            .replace('[://]', '://')
            .replace('[:]', ':')
        )
    
    @classmethod
    def defang(cls, ioc: str) -> str:
        """Convert IOC to defanged format for safe sharing"""
        return (ioc
            .replace('.', '[.]')
            .replace('http://', 'hxxp://')
            .replace('https://', 'hxxps://')
            .replace('@', '[@]')
        )
    
    @classmethod
    def extract_from_text(cls, text: str, 
                          include_private_ips: bool = False,
                          include_defanged: bool = True) -> Dict[str, Set[str]]:
        """
        Extract all IOCs from text
        
        Args:
            text: Input text to extract IOCs from
            include_private_ips: Include private/internal IPs
            include_defanged: Also match defanged IOCs
            
        Returns:
            Dictionary of IOC type -> set of IOCs
        """
        results: Dict[str, Set[str]] = {
            'ip': set(),
            'domain': set(),
            'url': set(),
            'md5': set(),
            'sha1': set(),
            'sha256': set(),
            'email': set(),
            'cve': set(),
            'mac': set(),
            'btc': set(),
            'registry': set(),
            'filepath': set(),
        }
        
        # Extract IPs
        for match in cls.PATTERNS['ip'].findall(text):
            if include_private_ips or not cls.is_private_ip(match):
                if match not in cls.FALSE_POSITIVES.get('ip', set()):
                    results['ip'].add(match)
                    
        # Extract defanged IPs
        if include_defanged:
            for match in cls.PATTERNS['ip_defanged'].findall(text):
                ip = cls.refang(match)
                if include_private_ips or not cls.is_private_ip(ip):
                    if ip not in cls.FALSE_POSITIVES.get('ip', set()):
                        results['ip'].add(ip)
        
        # Extract URLs first (to avoid domain false positives from URLs)
        urls_found = set()
        for match in cls.PATTERNS['url'].findall(text):
            # Clean URL
            url = match.rstrip('.,;:)\'"')
            results['url'].add(url)
            urls_found.add(url)
            
        if include_defanged:
            for match in cls.PATTERNS['url_defanged'].findall(text):
                url = cls.refang(match.rstrip('.,;:)\'"'))
                results['url'].add(url)
                urls_found.add(url)
        
        # Extract domains (filter out those already in URLs)
        for match in cls.PATTERNS['domain'].findall(text):
            domain = match.lower()
            # Check not part of URL
            is_in_url = any(domain in url for url in urls_found)
            if not is_in_url and domain not in cls.FALSE_POSITIVES.get('domain', set()):
                # Filter out version-like strings (1.0.0)
                if not re.match(r'^\d+\.\d+\.\d+$', domain):
                    results['domain'].add(domain)
                    
        if include_defanged:
            for match in cls.PATTERNS['domain_defanged'].findall(text):
                domain = cls.refang(match).lower()
                if domain not in cls.FALSE_POSITIVES.get('domain', set()):
                    results['domain'].add(domain)
        
        # Extract hashes
        for match in cls.PATTERNS['sha256'].findall(text):
            results['sha256'].add(match.lower())
            
        for match in cls.PATTERNS['sha1'].findall(text):
            # Make sure it's not part of a sha256
            if match.lower() not in [h[:40] for h in results['sha256']]:
                results['sha1'].add(match.lower())
                
        for match in cls.PATTERNS['md5'].findall(text):
            # Make sure it's not part of sha1 or sha256
            if (match.lower() not in [h[:32] for h in results['sha1']] and
                match.lower() not in [h[:32] for h in results['sha256']]):
                results['md5'].add(match.lower())
        
        # Extract emails
        for match in cls.PATTERNS['email'].findall(text):
            email = match.lower()
            # Filter out common false positives
            if not any(fp in email for fp in ['example.', 'test.', '@localhost']):
                results['email'].add(email)
                
        if include_defanged:
            for match in cls.PATTERNS['email_defanged'].findall(text):
                results['email'].add(cls.refang(match).lower())
        
        # Extract CVEs
        for match in cls.PATTERNS['cve'].findall(text):
            results['cve'].add(match.upper())
        
        # Extract MAC addresses
        for match in cls.PATTERNS['mac'].findall(text):
            results['mac'].add(match.upper())
        
        # Extract Bitcoin addresses
        for match in cls.PATTERNS['btc'].findall(text):
            results['btc'].add(match)
        
        # Extract Registry keys
        for match in cls.PATTERNS['registry'].findall(text):
            results['registry'].add(match)
        
        # Extract file paths
        for match in cls.PATTERNS['filepath_windows'].findall(text):
            if len(match) > 5:  # Filter out short false positives
                results['filepath'].add(match)
                
        for match in cls.PATTERNS['filepath_unix'].findall(text):
            # Filter out common false positives
            if (len(match) > 5 and 
                not match.startswith('/usr/') and 
                not match.startswith('/etc/') and
                not match.startswith('/var/log')):
                results['filepath'].add(match)
        
        return results
    
    @classmethod
    def extract_from_file(cls, filepath: str, **kwargs) -> ExtractionResult:
        """
        Extract IOCs from a file
        
        Args:
            filepath: Path to file
            **kwargs: Arguments passed to extract_from_text
            
        Returns:
            ExtractionResult with all extracted IOCs
        """
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        # Read file
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        except Exception as e:
            raise IOError(f"Error reading file: {e}")
        
        # Extract IOCs
        iocs = cls.extract_from_text(text, **kwargs)
        
        # Count totals
        total = sum(len(v) for v in iocs.values())
        
        # Build result
        iocs_by_type = {k: sorted(list(v)) for k, v in iocs.items() if v}
        
        return ExtractionResult(
            source=str(path),
            total_iocs=total,
            unique_iocs=total,
            iocs_by_type=iocs_by_type
        )
    
    @classmethod
    def extract_with_frequency(cls, text: str, **kwargs) -> Dict[str, Counter]:
        """
        Extract IOCs with frequency count
        
        Returns:
            Dictionary of IOC type -> Counter of IOCs
        """
        results: Dict[str, Counter] = {
            'ip': Counter(),
            'domain': Counter(),
            'url': Counter(),
            'md5': Counter(),
            'sha1': Counter(),
            'sha256': Counter(),
            'email': Counter(),
        }
        
        include_private_ips = kwargs.get('include_private_ips', False)
        
        # Count IPs
        for match in cls.PATTERNS['ip'].findall(text):
            if include_private_ips or not cls.is_private_ip(match):
                if match not in cls.FALSE_POSITIVES.get('ip', set()):
                    results['ip'][match] += 1
        
        # Count domains
        for match in cls.PATTERNS['domain'].findall(text):
            domain = match.lower()
            if domain not in cls.FALSE_POSITIVES.get('domain', set()):
                if not re.match(r'^\d+\.\d+\.\d+$', domain):
                    results['domain'][domain] += 1
        
        # Count URLs
        for match in cls.PATTERNS['url'].findall(text):
            url = match.rstrip('.,;:)\'"')
            results['url'][url] += 1
        
        # Count hashes
        for match in cls.PATTERNS['sha256'].findall(text):
            results['sha256'][match.lower()] += 1
        for match in cls.PATTERNS['sha1'].findall(text):
            results['sha1'][match.lower()] += 1
        for match in cls.PATTERNS['md5'].findall(text):
            results['md5'][match.lower()] += 1
        
        # Count emails
        for match in cls.PATTERNS['email'].findall(text):
            results['email'][match.lower()] += 1
        
        return results


def extract_iocs_cli(filepath: str, include_private: bool = False) -> ExtractionResult:
    """CLI wrapper for IOC extraction"""
    return IOCExtractor.extract_from_file(filepath, include_private_ips=include_private)
