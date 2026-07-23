"""
Defang/Refang & PowerShell Base64/XOR Payload Decoder for SOC Toolkit
Enables SOC analysts to quickly defang malicious IOCs or decode obfuscated PowerShell/Base64 strings.
"""

import re
import base64
from typing import Dict, Any, List


class PayloadDecoder:
    """Decode obfuscated commands, Base64 strings, and defang/refang IOCs"""

    @staticmethod
    def defang(ioc: str) -> str:
        """
        Defang an IOC so it cannot be accidentally clicked or executed.
        e.g., https://evil.com/payload -> hXXps://evil[.]com/payload
              1.2.3.4 -> 1[.]2[.]3[.]4
        """
        ioc = ioc.strip()
        has_https = ioc.lower().startswith("https://")
        has_http = ioc.lower().startswith("http://")
        
        url_path = ""
        if has_https:
            raw_target = ioc[8:]
            protocol = "hXXps://"
        elif has_http:
            raw_target = ioc[7:]
            protocol = "hXXp://"
        else:
            raw_target = ioc
            protocol = ""

        parts = raw_target.split('/', 1)
        host = parts[0].replace('.', '[.]')
        path = f"/{parts[1]}" if len(parts) > 1 else ""
        
        return f"{protocol}{host}{path}"

    @staticmethod
    def refang(ioc: str) -> str:
        """
        Refang an IOC back to standard format.
        e.g., hXXps://evil[.]com -> https://evil.com
        """
        ioc = ioc.strip()
        ioc = re.sub(r'^h[xX]{2}ps://', 'https://', ioc, flags=re.IGNORECASE)
        ioc = re.sub(r'^h[xX]{2}p://', 'http://', ioc, flags=re.IGNORECASE)
        ioc = re.sub(r'\[\.\]|\(dot\)|\{dot\}|\.dot\.', '.', ioc, flags=re.IGNORECASE)
        ioc = re.sub(r'\[:\]|\(colon\)', ':', ioc, flags=re.IGNORECASE)
        ioc = re.sub(r'\[at\]|\(at\)', '@', ioc, flags=re.IGNORECASE)
        return ioc

    @classmethod
    def decode_powershell(cls, text: str) -> Dict[str, Any]:
        """
        Extract and decode PowerShell Base64 encoded commands (-encodedcommand / -enc)
        """
        results: List[Dict[str, str]] = []
        
        pattern = r'(?:-e|-enc|-encodedcommand|-ec)\s+([A-Za-z0-9+/=]{10,})'
        matches = re.findall(pattern, text, re.IGNORECASE)
        
        if not matches and re.match(r'^[A-Za-z0-9+/=]{16,}$', text.strip()):
            matches = [text.strip()]
            
        for match in matches:
            try:
                decoded_bytes = base64.b64decode(match)
                try:
                    decoded_str = decoded_bytes.decode('utf-16le')
                except UnicodeDecodeError:
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                
                results.append({
                    "encoded": match,
                    "decoded": decoded_str.strip()
                })
            except Exception as e:
                results.append({
                    "encoded": match,
                    "error": str(e)
                })

        return {
            "found": len(results) > 0,
            "count": len(results),
            "payloads": results
        }
