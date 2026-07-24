"""
Automated Log & Forensics File Triage Engine for SOC Toolkit
Parses log dumps, CSVs, syslog, firewall logs, refangs IOCs, executes parallel lookups,
and generates an Executive Incident Triage Summary with Top Critical Threats and Playbooks.
"""

from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

from .extractor import IOCExtractor
from .core import SOCToolkit
from .enums import ThreatLevel
from .playbook import PlaybookGenerator


class LogTriageEngine:
    """Perform automated ad-hoc threat triage on log files"""

    def __init__(self, soc_engine: SOCToolkit = None):
        self.soc = soc_engine or SOCToolkit()

    def triage_file(self, filepath: str, max_iocs: int = 50) -> Dict[str, Any]:
        """
        Triage a log file and produce executive analysis results.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        extraction_dict = IOCExtractor.extract(content)
        all_iocs = [ioc for s in extraction_dict.values() for ioc in s]

        if not all_iocs:
            return {
                "filepath": filepath,
                "timestamp": datetime.now().isoformat(),
                "total_iocs_found": 0,
                "summary": "No IOCs found in log file.",
                "top_critical_threats": [],
                "reports": []
            }

        target_iocs = all_iocs[:max_iocs]
        reports = []
        critical_reports = []

        for ioc_str in target_iocs:
            report = self.soc.lookup(ioc_str)
            reports.append(report)
            if report.overall_threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                critical_reports.append(report)

        critical_reports.sort(
            key=lambda r: 0 if r.overall_threat_level == ThreatLevel.CRITICAL else 1
        )

        return {
            "filepath": filepath,
            "timestamp": datetime.now().isoformat(),
            "total_iocs_extracted": len(all_iocs),
            "iocs_analyzed": len(reports),
            "critical_threats_count": len(critical_reports),
            "top_critical_threats": [
                {
                    "ioc": r.ioc,
                    "type": r.ioc_type.value,
                    "threat_level": r.overall_threat_level.value,
                    "summary": r.summary,
                    "playbook": PlaybookGenerator.generate(r.ioc, r.ioc_type, r.overall_threat_level)
                }
                for r in critical_reports[:10]
            ],
            "reports": reports
        }

    def triage_text(self, text: str, name: str = "Raw Log Snippet", max_iocs: int = 50) -> Dict[str, Any]:
        """Triage raw log text snippet or email body"""
        extraction_dict = IOCExtractor.extract_from_text(text, include_private_ips=True)
        ips = list(extraction_dict.get("ip", set()))
        domains = list(extraction_dict.get("domain", set()))
        hashes = list(extraction_dict.get("md5", set()) | extraction_dict.get("sha1", set()) | extraction_dict.get("sha256", set()))
        urls = list(extraction_dict.get("url", set()))
        all_iocs = list(set(ips + domains + hashes + urls))

        if not all_iocs:
            return {
                "source": name,
                "timestamp": datetime.now().isoformat(),
                "total_iocs_found": 0,
                "summary": "No IOCs found in log snippet.",
                "top_critical_threats": []
            }

        target_iocs = all_iocs[:max_iocs]
        reports = []
        critical_reports = []

        for ioc_str in target_iocs:
            report = self.soc.lookup(ioc_str)
            reports.append({
                "ioc": report.ioc,
                "type": report.ioc_type.value,
                "threat_level": report.overall_threat_level.value
            })
            if report.overall_threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                critical_reports.append(report.ioc)

        return {
            "source": name,
            "timestamp": datetime.now().isoformat(),
            "total_iocs_extracted": len(all_iocs),
            "iocs_analyzed": len(reports),
            "critical_threats_count": len(critical_reports),
            "critical_iocs": critical_reports,
            "all_extracted_iocs": reports
        }
