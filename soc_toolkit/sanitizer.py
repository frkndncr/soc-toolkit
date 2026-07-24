"""
Smart IOC Sanitizer & Defang Unquoter for SOC Toolkit
Cleans brackets, unquotes URLs, refangs hxxp/hxxps, and extracts pure IOC targets.
"""

import re
from typing import Dict, Any, List


class IOCSanitizer:
    """Sanitize and refine dirty user IOC inputs"""

    @classmethod
    def sanitize(cls, raw_input: str) -> str:
        if not raw_input:
            return ""

        cleaned = raw_input.strip()

        # Remove surrounding quotes or brackets
        cleaned = cleaned.strip("\"'`()[]{}<>")

        # Refang hxxp / hxxps
        cleaned = re.sub(r'^hxxps', 'https', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'^hxxp', 'http', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'\[:\]', ':', cleaned)
        cleaned = re.sub(r'\[\:\/\]', ':/', cleaned)
        cleaned = re.sub(r'\[:\/\/\]', '://', cleaned)
        cleaned = re.sub(r'\[\.\]', '.', cleaned)

        # Remove defanged brackets in IP/Domain (e.g. 1.2.3[.]4 -> 1.2.3.4)
        cleaned = cleaned.replace("[.]", ".").replace("(.)", ".")

        # Extract pure IP if input is surrounded by noise (e.g. "IP: 185.220.101.45")
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', cleaned)
        if ip_match and not cleaned.startswith(("http://", "https://")):
            return ip_match.group(0)

        # Extract pure Hash if input has noise (MD5, SHA1, SHA256)
        hash_match = re.search(r'\b[a-fA-F0-9]{32,64}\b', cleaned)
        if hash_match:
            return hash_match.group(0)

        return cleaned
