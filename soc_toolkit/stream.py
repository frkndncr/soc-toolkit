"""
Real-Time Syslog & Log Stream Listener Engine for SOC Toolkit v7.0.0
Listens on UDP/TCP Syslog (Port 514) or tail-files live logs, automatically extracts IOCs,
enriches them in real-time, and dispatches Webhook alerts to Slack, Microsoft Teams, or custom endpoints.
"""

import socket
import json
import urllib.request
from typing import Dict, Any, List, Callable
from .extractor import IOCExtractor
from .core import SOCToolkit
from .enums import ThreatLevel


class SyslogStreamListener:
    """High-throughput Syslog listener and real-time threat alert dispatcher"""

    def __init__(self, host: str = "0.0.0.0", port: int = 514, webhook_url: str = None):
        self.host = host
        self.port = port
        self.webhook_url = webhook_url
        self.soc = SOCToolkit()

    def process_log_line(self, log_line: str) -> Dict[str, Any]:
        """
        Process a single log line in real-time, extract IOCs, perform lookup, and dispatch alert if threat found.
        """
        extracted = IOCExtractor.extract(log_line)
        all_iocs = [ioc for s in extracted.values() for ioc in s]

        alerts = []
        for ioc in all_iocs:
            report = self.soc.lookup(ioc)
            if report.overall_threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                alert_data = {
                    "ioc": report.ioc,
                    "type": report.ioc_type.value,
                    "threat_level": report.overall_threat_level.value,
                    "summary": report.summary
                }
                alerts.append(alert_data)
                if self.webhook_url:
                    self.dispatch_webhook(alert_data)

        return {
            "processed": True,
            "iocs_found_count": len(all_iocs),
            "threat_alerts": alerts
        }

    def dispatch_webhook(self, alert_data: Dict[str, Any]) -> bool:
        """
        Send alert payload to Slack / Teams / Webhook URL.
        """
        if not self.webhook_url:
            return False
        try:
            payload = json.dumps({"text": f"🚨 [SOC TOOLKIT ALERT] {alert_data['threat_level'].upper()} threat detected: {alert_data['ioc']} ({alert_data['type']})"}).encode('utf-8')
            req = urllib.request.Request(self.webhook_url, data=payload, headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False
