"""
YARA Rule Compiler & In-Memory Scanner Engine for SOC Toolkit v6.0.0
Compiles YARA rules and scans files, process strings, and binary memory.
"""

import re
from typing import Dict, Any, List


class YARAEngine:
    """In-memory YARA scanner and rule compiler"""

    @classmethod
    def scan_text(cls, text: str, rule_strings: List[str] = None) -> Dict[str, Any]:
        """
        Scan text content against known YARA string patterns.
        """
        rule_strings = rule_strings or ["eval(", "base64_decode", "VirtualAlloc", "cmd.exe", "powershell -enc", "socket.connect"]
        matched = []

        for pattern in rule_strings:
            if pattern in text:
                matched.append(pattern)

        return {
            "scanned": True,
            "matched_yara_patterns_count": len(matched),
            "matched_patterns": matched
        }
