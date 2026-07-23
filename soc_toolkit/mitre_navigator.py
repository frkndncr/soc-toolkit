"""
MITRE ATT&CK Navigator Layer Exporter for SOC Toolkit
Generates JSON layer files compatible with MITRE ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/).
"""

import json
from pathlib import Path
from typing import Dict, Any, List
from .enums import IOCType, ThreatLevel


class MITRENavigatorExporter:
    """Export threat findings as MITRE ATT&CK Navigator JSON Layers"""

    @classmethod
    def generate_layer(cls, ioc: str, threat_level: ThreatLevel, techniques: List[str] = None) -> Dict[str, Any]:
        """
        Generate valid MITRE ATT&CK Navigator Layer JSON.
        """
        techniques = techniques or ["T1071.001", "T1110", "T1190", "T1566"]
        level_str = threat_level.value if hasattr(threat_level, 'value') else str(threat_level)

        score_map = {
            "critical": 100,
            "high": 75,
            "medium": 50,
            "low": 25,
            "clean": 0
        }
        score = score_map.get(level_str.lower(), 10)

        technique_objects = []
        for tech in techniques:
            technique_objects.append({
                "techniqueID": tech,
                "score": score,
                "comment": f"SOC Toolkit Finding for {ioc} (Threat: {level_str.upper()})",
                "enabled": True
            })

        layer = {
            "name": f"SOC Toolkit - {ioc}",
            "versions": {
                "attack": "14",
                "navigator": "4.9.0",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": f"Automated MITRE ATT&CK Heatmap exported by SOC Toolkit v4.0.0 for indicator {ioc}",
            "gradient": {
                "colors": ["#00e676", "#ffea00", "#ff1744"],
                "minValue": 0,
                "maxValue": 100
            },
            "techniques": technique_objects
        }
        return layer

    @classmethod
    def export_to_file(cls, ioc: str, threat_level: ThreatLevel, filepath: str):
        """Save MITRE layer to file"""
        layer = cls.generate_layer(ioc, threat_level)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(layer, f, indent=2)
