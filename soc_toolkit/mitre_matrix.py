"""
Full MITRE ATT&CK Matrix Heatmap Visualizer for SOC Toolkit v7.0.0
Maps findings across all 14 MITRE ATT&CK Enterprise Tactics.
"""

from typing import Dict, Any, List
from .enums import ThreatLevel, IOCType


MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]


class MITREMatrixEngine:
    """Generate visual ATT&CK Matrix coverage heatmaps"""

    @classmethod
    def generate_matrix(cls, ioc: str, ioc_type: IOCType, threat_level: ThreatLevel) -> Dict[str, Any]:
        level_str = threat_level.value if hasattr(threat_level, 'value') else str(threat_level)
        type_str = ioc_type.value if hasattr(ioc_type, 'value') else str(ioc_type)

        matrix = {}
        for tactic in MITRE_TACTICS:
            matrix[tactic] = {"active": False, "technique_id": "N/A", "technique_name": "N/A"}

        if level_str.lower() in ("high", "critical"):
            if type_str in ("ip", "domain", "url"):
                matrix["Command and Control"] = {"active": True, "technique_id": "T1071", "technique_name": "Application Layer Protocol"}
                matrix["Initial Access"] = {"active": True, "technique_id": "T1566", "technique_name": "Phishing"}
                matrix["Exfiltration"] = {"active": True, "technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel"}
            elif "hash" in type_str:
                matrix["Execution"] = {"active": True, "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"}
                matrix["Defense Evasion"] = {"active": True, "technique_id": "T1027", "technique_name": "Obfuscated Files or Information"}

        active_count = sum(1 for t in matrix.values() if t["active"])

        return {
            "ioc": ioc,
            "threat_level": level_str.upper(),
            "active_tactics_count": active_count,
            "mitre_matrix": matrix
        }
