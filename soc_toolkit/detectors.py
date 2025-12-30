"""
IOC Type Detection Module
"""

import re
from .enums import IOCType


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
    
    @classmethod
    def defang(cls, ioc: str) -> str:
        """Defang an IOC for safe sharing"""
        # Replace dots in IPs and domains
        if cls.detect(ioc) in [IOCType.IP, IOCType.DOMAIN]:
            return ioc.replace(".", "[.]")
        # Replace protocol in URLs
        if cls.detect(ioc) == IOCType.URL:
            return ioc.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
        return ioc
    
    @classmethod
    def refang(cls, ioc: str) -> str:
        """Refang a defanged IOC"""
        return (ioc
            .replace("[.]", ".")
            .replace("hxxp://", "http://")
            .replace("hxxps://", "https://")
            .replace("[://]", "://")
        )
