"""
Enums and data classes for SOC Toolkit
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


class IOCType(Enum):
    """Indicator of Compromise types"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    """Threat severity levels"""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class LookupResult:
    """Single source lookup result"""
    source: str
    found: bool
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    response_time: float = 0.0


@dataclass 
class IOCReport:
    """Complete IOC analysis report"""
    ioc: str
    ioc_type: IOCType
    timestamp: str
    results: List[LookupResult] = field(default_factory=list)
    overall_threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    summary: str = ""
