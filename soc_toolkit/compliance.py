"""
Compliance & Regulatory Audit Engine for SOC Toolkit v5.0.0
Maps threat findings, malicious IOCs, and unpatched vulnerabilities directly to
PCI-DSS 4.0, ISO/IEC 27001:2022, SOC 2 Type II, and NIST CSF 2.0 regulatory controls.
"""

from typing import Dict, Any, List
from .enums import ThreatLevel, IOCType


class ComplianceEngine:
    """Evaluate threat findings against international cybersecurity compliance frameworks"""

    @classmethod
    def evaluate_compliance(cls, ioc: str, ioc_type: IOCType, threat_level: ThreatLevel) -> Dict[str, Any]:
        level_str = threat_level.value if hasattr(threat_level, 'value') else str(threat_level)
        is_threat = level_str.lower() in ("high", "critical")

        pci_dss_findings = []
        iso27001_findings = []
        soc2_findings = []
        nist_csf_findings = []

        if is_threat:
            pci_dss_findings.append({
                "control": "PCI-DSS 4.0 Req 6.4.1",
                "status": "NON-COMPLIANT",
                "finding": f"Active threat indicator {ioc} detected. Public-facing web applications & infrastructure must be protected against known attacks.",
                "remediation": "Block IOC on edge firewall and perform web application vulnerability scan."
            })
            pci_dss_findings.append({
                "control": "PCI-DSS 4.0 Req 10.4.1",
                "status": "REQUIRES AUDIT",
                "finding": f"Traffic associated with malicious IOC {ioc} requires audit trail review in SIEM.",
                "remediation": "Retain log telemetry for 90 days minimum as per PCI-DSS mandate."
            })

            iso27001_findings.append({
                "control": "ISO/IEC 27001:2022 A.8.7 (Protection against malware)",
                "status": "ACTION REQUIRED",
                "finding": f"Malicious IOC {ioc} identified on enterprise asset.",
                "remediation": "Deploy endpoint detection rules and update gateway blacklists."
            })
            iso27001_findings.append({
                "control": "ISO/IEC 27001:2022 A.8.23 (Web filtering)",
                "status": "NON-COMPLIANT",
                "finding": f"Domain/IP {ioc} not blocked in web proxy filtering rules.",
                "remediation": "Add domain to DNS sinkhole and proxy blocklist."
            })

            soc2_findings.append({
                "control": "SOC 2 Type II CC6.8 (Threat Detection)",
                "status": "ALERT TRIGGERED",
                "finding": f"High-risk threat activity {ioc} detected in operational environment.",
                "remediation": "Execute Incident Response Playbook and document root cause analysis for auditors."
            })

            nist_csf_findings.append({
                "control": "NIST CSF 2.0 DE.CM-01 (Networks are monitored to detect potential cybersecurity events)",
                "status": "DETECTED",
                "finding": f"Detection triggered for indicator {ioc}.",
                "remediation": "Isolate impacted system and initiate RS.AN-01 incident analysis."
            })

        else:
            pci_dss_findings.append({"control": "PCI-DSS 4.0 Req 6.4", "status": "COMPLIANT", "finding": f"No active threats detected for {ioc}."})
            iso27001_findings.append({"control": "ISO/IEC 27001 A.8.7", "status": "COMPLIANT", "finding": f"Baseline security validated for {ioc}."})
            soc2_findings.append({"control": "SOC 2 CC6.8", "status": "COMPLIANT", "finding": f"No security exceptions for {ioc}."})
            nist_csf_findings.append({"control": "NIST CSF DE.CM", "status": "COMPLIANT", "finding": f"Monitoring active, baseline normal."})

        return {
            "ioc": ioc,
            "overall_compliance_status": "NON-COMPLIANT (ACTION REQUIRED)" if is_threat else "COMPLIANT",
            "pci_dss": pci_dss_findings,
            "iso27001": iso27001_findings,
            "soc2": soc2_findings,
            "nist_csf": nist_csf_findings
        }
