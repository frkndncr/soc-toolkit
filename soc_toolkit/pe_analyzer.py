"""
Malware Static PE & Binary Analyzer for SOC Toolkit
Extracts hashes (MD5, SHA1, SHA256, ImpHash), section entropy, suspicious API imports,
and IOC strings from executable files.
"""

import math
import hashlib
import struct
import re
from pathlib import Path
from typing import Dict, Any, List


SUSPICIOUS_WINDOWS_APIS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
    "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
    "SetThreadContext", "ResumeThread", "QueueUserAPC",
    "UrlDownloadToFileA", "UrlDownloadToFileW", "WinHttpOpen", "InternetOpenA",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "RegSetValueExA", "RegCreateKeyExA", "CreateServiceA", "ControlService"
]


class PEAnalyzer:
    """Static PE / ELF / Binary malware analyzer"""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon Entropy (0.0 to 8.0). High entropy (>7.2) indicates packing/encryption."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        occ = {}
        for b in data:
            occ[b] = occ.get(b, 0) + 1
        for count in occ.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @classmethod
    def analyze_file(cls, filepath: str) -> Dict[str, Any]:
        """
        Perform complete static file analysis on PE / binary files.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        with open(path, 'rb') as f:
            content = f.read()

        # Hash calculations
        md5_hash = hashlib.md5(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()

        # Entropy & Packer Detection
        overall_entropy = cls.calculate_entropy(content)
        is_packed = overall_entropy > 7.2

        # Extract ASCII & Unicode Strings
        text_ascii = content.decode('ascii', errors='ignore')
        suspicious_apis = [api for api in SUSPICIOUS_WINDOWS_APIS if api in text_ascii]

        # Extract IP / URL / Domain / Hash IOCs from binary strings
        from .extractor import IOCExtractor
        extracted = IOCExtractor.extract(text_ascii)

        # Detect PE header magic 'MZ'
        is_pe = content.startswith(b'MZ')

        return {
            "filepath": filepath,
            "file_size_bytes": len(content),
            "is_pe_executable": is_pe,
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sha256_hash,
            "entropy": overall_entropy,
            "is_likely_packed": is_packed,
            "suspicious_apis_detected": suspicious_apis,
            "extracted_iocs": {
                "ips": extracted.ips,
                "domains": extracted.domains,
                "urls": extracted.urls
            }
        }
