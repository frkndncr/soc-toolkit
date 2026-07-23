"""
Threat Intelligence Correlation Engine for SOC Toolkit
Matches IOC findings against known Malware Families, Ransomware strains, and Threat Actors (APTs).
"""

from typing import Dict, Any, List, Optional


KNOWN_THREAT_FAMILY_PATTERNS = {
    "cobalt strike": ("Cobalt Strike C2", "Malicious C2 Beacon infrastructure used by threat actors and ransomware affiliates."),
    "qakbot": ("Qakbot / Qbot", "Banking trojan and initial access malware loader frequently distributing ransomware."),
    "lockbit": ("LockBit Ransomware", "Prolific Ransomware-as-a-Service (RaaS) operation."),
    "blackcat": ("BlackCat / ALPHV", "Rust-based Ransomware-as-a-Service group."),
    "asyncrat": ("AsyncRAT", "Remote Access Trojan used for system monitoring and data exfiltration."),
    "emotet": ("Emotet Botnet", "High-volume botnet loader and malware distribution network."),
    "trickbot": ("TrickBot", "Modular banking trojan used for lateral movement and ransomware deployment."),
    "dridex": ("Dridex", "Financial malware and botnet loader."),
    "redline": ("RedLine Stealer", "Information stealer targeting browser credentials, crypto wallets, and system info."),
    "agenttesla": ("AgentTesla", "Advanced RAT and keylogger operating via SMTP/HTTP C2."),
    "darkgate": ("DarkGate Loader", "Commodity loader supporting stealthy execution, credential theft, and remote access."),
    "formbook": ("Formbook", "InfoStealer malware targeting keystrokes, clipboard, and browser passwords.")
}


class ThreatIntelMatcher:
    """Matches provider lookup data with threat families and ransomware strains"""

    @classmethod
    def match(cls, raw_data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze findings from provider results and extract matched threat families.
        """
        matched_families: List[Dict[str, str]] = []
        seen_names = set()

        for data in raw_data_list:
            if not isinstance(data, dict):
                continue

            # Convert all dict values to string for pattern searching
            content_str = " ".join(str(v).lower() for v in data.values())

            for key, (family_name, description) in KNOWN_THREAT_FAMILY_PATTERNS.items():
                if key in content_str and family_name not in seen_names:
                    seen_names.add(family_name)
                    matched_families.append({
                        "family": family_name,
                        "description": description
                    })

        return {
            "has_threat_match": len(matched_families) > 0,
            "threat_families": matched_families
        }
