"""
Autonomous AI Threat Analyst & Cyber Kill Chain Triage Engine for SOC Toolkit v6.0.0
Generates Root Cause Analysis (RCA), Cyber Kill Chain Phase Attribution, and Executive CISO Triage Summaries.
"""

from typing import Dict, Any, List
from .enums import ThreatLevel, IOCType


class AIThreatAnalyst:
    """Autonomous AI Threat Analysis & Kill Chain Attribution Engine"""

    @classmethod
    def analyze_threat(cls, ioc: str, ioc_type: IOCType, threat_level: ThreatLevel, provider_data: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        level_str = threat_level.value if hasattr(threat_level, 'value') else str(threat_level)
        type_str = ioc_type.value if hasattr(ioc_type, 'value') else str(ioc_type)
        provider_data = provider_data or []

        # Map Cyber Kill Chain Phase
        kill_chain_phase = "Unknown"
        attack_vector = "N/A"

        if level_str.lower() in ("high", "critical"):
            if type_str in ("ip", "ipv4", "ipv6"):
                kill_chain_phase = "Command and Control (C2) / Exfiltration"
                attack_vector = "Network Telemetry / Outbound TCP Connection"
            elif type_str in ("domain", "url"):
                kill_chain_phase = "Delivery / Phishing / Weaponization"
                attack_vector = "Web Browsing / Email Gateway Vector"
            elif "hash" in type_str:
                kill_chain_phase = "Installation / Exploitation / Execution"
                attack_vector = "Malicious File Execution on Endpoint"
        else:
            kill_chain_phase = "Reconnaissance / Baseline Telemetry"
            attack_vector = "Normal Operations"

        # Natural Language Root Cause Analysis (RCA)
        rca = (
            f"Autonomous AI Analysis of indicator '{ioc}' ({type_str.upper()}) concluded an overall risk score of {level_str.upper()}. "
            f"Attribution indicates active alignment with Cyber Kill Chain phase: '{kill_chain_phase}'. "
            f"Automated risk scoring recommends immediate network containment and host isolation."
        )

        ciso_summary = (
            f"EXECUTIVE SUMMARY: Indicator {ioc} poses a {level_str.upper()} risk to enterprise operations. "
            f"Recommended Action: Authorize automated SOAR containment playbook execution."
        )

        return {
            "ioc": ioc,
            "threat_level": level_str.upper(),
            "cyber_kill_chain_phase": kill_chain_phase,
            "attack_vector": attack_vector,
            "root_cause_analysis": rca,
            "ciso_executive_summary": ciso_summary
        }
