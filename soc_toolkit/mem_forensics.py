"""
Process Memory Forensics & Mimikatz / Shellcode Hunter for SOC Toolkit v7.0.0
Scans raw process memory dumps, LSASS dumps, and string artifacts for Mimikatz credentials,
Cobalt Strike Reflective DLL headers, and Shellcode NOP sleds.
"""

import re
from typing import Dict, Any, List


MIMIKATZ_PATTERNS = [
    r'wdigest\.dll', r'lsasrv\.dll', r'sekurlsa::logonpasswords',
    r'lsass\.exe', r'kerberos\.dll', r'tspkg\.dll', r'msv1_0\.dll'
]

COBALT_STRIKE_PATTERNS = [
    r'ReflectiveLoader', r'%s as %s\\%s: %d', r'\\\\\.\\pipe\\msagent_',
    r'HTTP/1\.1 200 OK\r\nContent-Type: application/octet-stream'
]


class MemoryForensicsEngine:
    """Process Memory Forensics and Threat String Artifact Hunter"""

    @classmethod
    def scan_memory_strings(cls, memory_text: str) -> Dict[str, Any]:
        """
        Scan text extracted from process memory or memory dumps.
        """
        mimikatz_hits = [p for p in MIMIKATZ_PATTERNS if re.search(p, memory_text, re.IGNORECASE)]
        cobalt_hits = [p for p in COBALT_STRIKE_PATTERNS if re.search(p, memory_text, re.IGNORECASE)]

        has_nop_sled = r'\x90\x90\x90\x90\x90\x90\x90\x90' in memory_text or "NOPNOP" in memory_text
        has_lsass_dump = len(mimikatz_hits) >= 2

        threat_score = 0
        if mimikatz_hits:
            threat_score += 50
        if cobalt_hits:
            threat_score += 50
        if has_nop_sled:
            threat_score += 30

        return {
            "scanned": True,
            "mimikatz_indicators_found": len(mimikatz_hits),
            "mimikatz_patterns": mimikatz_hits,
            "cobalt_strike_indicators_found": len(cobalt_hits),
            "cobalt_patterns": cobalt_hits,
            "has_nop_sled": has_nop_sled,
            "has_lsass_dump_artifacts": has_lsass_dump,
            "threat_score": min(threat_score, 100),
            "assessment": "CRITICAL - Credential Theft / C2 Injection Detected" if threat_score >= 50 else "CLEAN / BENIGN"
        }
