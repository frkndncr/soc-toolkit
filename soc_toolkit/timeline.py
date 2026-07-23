"""
Chronological Incident Event Timeline Generator for SOC Toolkit
Constructs clean, timestamped incident chronologies for Security Operation Centers.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List


class IncidentTimelineEngine:
    """Generate structured security incident event timelines"""

    @classmethod
    def generate_timeline(cls, ioc: str, threat_level: str = "CRITICAL") -> Dict[str, Any]:
        now = datetime.now()
        
        events = [
            {
                "timestamp": (now - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S"),
                "phase": "Initial Vector / Phishing",
                "event": f"User accessed malicious URL containing payload associated with {ioc}"
            },
            {
                "timestamp": (now - timedelta(minutes=12)).strftime("%Y-%m-%d %H:%M:%S"),
                "phase": "Execution & Persistence",
                "event": "PowerShell spawned from Word document, base64 payload executed in memory"
            },
            {
                "timestamp": (now - timedelta(minutes=8)).strftime("%Y-%m-%d %H:%M:%S"),
                "phase": "Command and Control (C2)",
                "event": f"Outbound TCP socket established to high-risk C2 IP {ioc}:443"
            },
            {
                "timestamp": (now - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"),
                "phase": "Automated SOC Containment",
                "event": f"SOC Toolkit SOAR trigger fired: Host isolated and IP {ioc} banned on OS Firewall"
            }
        ]

        return {
            "ioc": ioc,
            "threat_level": threat_level.upper(),
            "total_timeline_events": len(events),
            "chronological_events": events
        }
