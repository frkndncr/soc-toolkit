"""
Enterprise SOC Toolkit v4.0.0 NextGen - Threat Hunting, Forensics & Malware Analysis Platform
"""

__version__ = "4.0.0"
__author__ = "Furkan Dinçer"
__email__ = "frkndncr@github.com"
__url__ = "https://github.com/frkndncr/soc-toolkit"

from .core import SOCToolkit, IOCReport, LookupResult
from .detectors import IOCDetector, IOCType
from .enums import ThreatLevel
from .extractor import IOCExtractor, ExtractionResult
from .cache import Cache, get_cache
from .logger import get_logger, set_log_level
from .mitre import MITREMapper, MITREMapping
from .enrichment import WhoisLookup, DNSLookup, EnrichmentEngine
from .playbook import PlaybookGenerator, Playbook
from .whitelist import WhitelistFilter
from .decoder import PayloadDecoder
from .triage import LogTriageEngine
from .rules import DetectionRuleGenerator
from .sdk import SOCToolkitSDK
from .osint import OSINTLinksGenerator
from .pcap_analyzer import PCAPAnalyzer
from .pe_analyzer import PEAnalyzer
from .c2_extractor import C2ConfigExtractor
from .mitre_navigator import MITRENavigatorExporter
from .siem_queries import SIEMQueryGenerator
from .graph_visualizer import ThreatGraphVisualizer

__all__ = [
    "SOCToolkit",
    "SOCToolkitSDK",
    "IOCReport", 
    "LookupResult",
    "IOCDetector",
    "IOCType",
    "ThreatLevel",
    "IOCExtractor",
    "ExtractionResult",
    "Cache",
    "get_cache",
    "get_logger",
    "set_log_level",
    "MITREMapper",
    "MITREMapping",
    "WhoisLookup",
    "DNSLookup",
    "EnrichmentEngine",
    "PlaybookGenerator",
    "Playbook",
    "WhitelistFilter",
    "PayloadDecoder",
    "LogTriageEngine",
    "DetectionRuleGenerator",
    "OSINTLinksGenerator",
    "PCAPAnalyzer",
    "PEAnalyzer",
    "C2ConfigExtractor",
    "MITRENavigatorExporter",
    "SIEMQueryGenerator",
    "ThreatGraphVisualizer",
    "__version__"
]
