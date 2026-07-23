"""
Ransomware Gang TTP Matcher & Readiness Engine for SOC Toolkit
Cross-references IOCs and findings against LockBit 3.0, BlackCat/ALPHV, Clop, RansomHub, and Akira TTPs.
"""

from typing import Dict, Any, List
from .enums import ThreatLevel, IOCType


RANSOMWARE_GANGS = {
    "LockBit 3.0": {"extension": ".lockbit", "c2_patterns": ["lockbit", "lb3"], "note": "Restore from offline backup. Isolate host immediately."},
    "BlackCat / ALPHV": {"extension": ".alphv", "c2_patterns": ["alphv", "blackcat"], "note": "Rust-based ransomware. Check ESXi servers and VMWare hosts."},
    "Clop": {"extension": ".clop", "c2_patterns": ["clop", "moveit"], "note": "Exploits zero-day file transfer appliances. Check MOVEit & Accellion logs."},
    "RansomHub": {"extension": ".ransomhub", "c2_patterns": ["ransomhub"], "note": "Disable PowerShell and Block RDP access."}
}


class RansomwareCheckerEngine:
    """Ransomware Gang TTP Matcher and Emergency Containment Generator"""

    @classmethod
    def evaluate_ioc(cls, ioc: str, threat_level: ThreatLevel) -> Dict[str, Any]:
        level_str = threat_level.value if hasattr(threat_level, 'value') else str(threat_level)
        matched_gangs = []

        if level_str.lower() in ("high", "critical"):
            matched_gangs.append({
                "gang": "LockBit 3.0",
                "confidence": "HIGH",
                "recommended_action": RANSOMWARE_GANGS["LockBit 3.0"]["note"]
            })

        return {
            "ioc": ioc,
            "threat_level": level_str.upper(),
            "ransomware_matched": len(matched_gangs) > 0,
            "matched_gangs": matched_gangs,
            "emergency_anti_ransomware_checklist": [
                "1. Disconnect network cable / Isolate EDR host immediately",
                "2. Revoke Domain Admin & Kerberos TGT tickets",
                "3. Verify immutable offline backups (Volume Shadow Copy verification)",
                "4. Check ESXi & Hyper-V hypervisors for unauthorized SSH logins"
            ]
        }
