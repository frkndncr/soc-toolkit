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

        extraction = IOCExtractor.extract(content)
        all_iocs = extraction.get_all_iocs()

        if not all_iocs:
            return {
                "filepath": filepath,
                "timestamp": datetime.now().isoformat(),
                "total_iocs_found": 0,
                "summary": "No IOCs found in log file.",
                "top_critical_threats": [],
                "reports": []
            }

        # Limit to max_iocs for fast triage
        target_iocs = all_iocs[:max_iocs]
        reports = []
        critical_reports = []

        for ioc_str in target_iocs:
            report = self.soc.lookup(ioc_str)
            reports.append(report)
            if report.overall_threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                critical_reports.append(report)

        # Sort critical reports by threat level (Critical first, then High)
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
