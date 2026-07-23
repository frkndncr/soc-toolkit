"""
Python SDK API Interface for SOC Toolkit
Enables easy integration into Python scripts, SOAR platforms (Shuffle, DFIR-IRIS), and Jupyter Notebooks.
"""

from typing import Union, Dict, Any, List
from .core import SOCToolkit
from .detectors import IOCDetector, IOCType
from .playbook import PlaybookGenerator, Playbook
from .whitelist import WhitelistFilter
from .decoder import PayloadDecoder
from .rules import DetectionRuleGenerator
from .osint import OSINTLinksGenerator


class SOCToolkitSDK:
    """High-level Python SDK wrapper for SOC Analysts and Developers"""

    def __init__(self):
        self.engine = SOCToolkit()

    def analyze(self, ioc: str) -> Dict[str, Any]:
        """
        Perform complete threat intel lookup, false positive evaluation,
        playbook generation, OSINT links, and detection rule creation.
        """
        report = self.engine.lookup(ioc)
        playbook = PlaybookGenerator.generate(report.ioc, report.ioc_type, report.overall_threat_level)
        whitelist_eval = WhitelistFilter.evaluate(report.ioc, report.ioc_type.value)
        osint_links = OSINTLinksGenerator.get_links(report.ioc, report.ioc_type)
        sigma_rule = DetectionRuleGenerator.generate_sigma(report.ioc, report.ioc_type)
        nids_rules = DetectionRuleGenerator.generate_nids(report.ioc, report.ioc_type)

        return {
            "ioc": report.ioc,
            "type": report.ioc_type.value,
            "threat_level": report.overall_threat_level.value,
            "summary": report.summary,
            "whitelist_evaluation": whitelist_eval,
            "playbook": playbook,
            "osint_links": osint_links,
            "sigma_rule": sigma_rule,
            "nids_rules": nids_rules,
            "raw_report": report
        }

    def decode_payload(self, text: str) -> Dict[str, Any]:
        """Decode Base64 / PowerShell obfuscated payload"""
        return PayloadDecoder.decode_powershell(text)

    def defang(self, ioc: str) -> str:
        """Defang an IOC"""
        return PayloadDecoder.defang(ioc)

    def refang(self, ioc: str) -> str:
        """Refang an IOC"""
        return PayloadDecoder.refang(ioc)
