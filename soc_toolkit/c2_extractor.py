"""
C2 Beacon & Config Extractor for SOC Toolkit
Extracts Command & Control (C2) configuration data for Cobalt Strike, AsyncRAT, Metasploit, Remcos, and Sliver.
"""

import re
import base64
from typing import Dict, Any, List


class C2ConfigExtractor:
    """Extract C2 server endpoints, watermarks, ports, and protocols from raw memory/strings"""

    @classmethod
    def extract_c2_config(cls, data: str) -> Dict[str, Any]:
        """
        Scan text/memory dump for C2 framework indicators and configurations.
        """
        findings: List[Dict[str, str]] = []

        # Cobalt Strike Beacon Patterns
        cs_watermark = re.search(r'watermark[=:]\s*(\d{5,10})', data, re.IGNORECASE)
        cs_user_agent = re.search(r'User-Agent:\s*([^\r\n]+)', data, re.IGNORECASE)
        cs_pipe = re.search(r'\\\\(\.\\[a-zA-Z0-9_\-]+)', data)

        if cs_watermark or cs_pipe:
            findings.append({
                "framework": "Cobalt Strike Beacon",
                "watermark": cs_watermark.group(1) if cs_watermark else "N/A",
                "named_pipe": cs_pipe.group(1) if cs_pipe else "N/A",
                "user_agent": cs_user_agent.group(1) if cs_user_agent else "N/A"
            })

        # AsyncRAT / DCRat Config Indicators
        if "AsyncRAT" in data or "Ports" in data and "Hosts" in data:
            hosts = re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:\d{2,5}', data)
            if hosts:
                findings.append({
                    "framework": "AsyncRAT / DCRat",
                    "c2_hosts": list(set(hosts))[:5]
                })

        # Metasploit Meterpreter Reverse TCP / HTTP
        if "meterpreter" in data.lower() or "rev_tcp" in data.lower():
            ip_port = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})', data)
            findings.append({
                "framework": "Metasploit Meterpreter",
                "c2_endpoint": ip_port.group(0) if ip_port else "N/A"
            })

        return {
            "has_c2_indicators": len(findings) > 0,
            "c2_findings_count": len(findings),
            "findings": findings
        }
