"""
Active Defense, HoneyToken Deception & OS Firewall Banning Engine for SOC Toolkit v6.0.0
Generates Canary URLs, HoneyTokens, Decoy IP endpoints, and executes active OS firewall blocking commands.
"""

import sys
import subprocess
import uuid
from typing import Dict, Any, List


class ActiveDefenseEngine:
    """Active Deception & Automated OS Firewall Shunning Engine"""

    @classmethod
    def generate_honeytoken(cls, token_type: str = "canary_url") -> Dict[str, str]:
        """
        Generate HoneyTokens and Canary URLs for deception.
        """
        token_id = uuid.uuid4().hex[:12]

        if token_type == "canary_url":
            return {
                "type": "Canary URL",
                "honeytoken": f"http://canary.enterprise.local/auth/login?token={token_id}",
                "description": "Deploy in internal documents or environment variables. Alerts SOC on HTTP GET access."
            }
        elif token_type == "aws_key":
            return {
                "type": "Decoy AWS Key",
                "access_key": f"AKIA{token_id.upper()[:16]}",
                "secret_key": f"decoySecret{uuid.uuid4().hex}",
                "description": "Place in code repos. Alerts SOC upon CloudTrail authentication attempt."
            }
        else:
            return {
                "type": "Decoy Database Credentials",
                "username": f"db_admin_{token_id[:6]}",
                "password": f"P@ssword_{token_id}",
                "description": "Place in configuration files. Alerts SOC upon SQL connection attempt."
            }

    @classmethod
    def get_os_ban_command(cls, ip: str) -> Dict[str, str]:
        """
        Generates OS-level firewall ban commands for Windows, Linux, macOS, Fortinet, and Palo Alto.
        """
        return {
            "windows_cmd": f'netsh advfirewall firewall add rule name="SOC_BLOCK_{ip}" dir=in action=block remoteip={ip}',
            "linux_iptables": f'iptables -A INPUT -s {ip} -j DROP && iptables -A OUTPUT -d {ip} -j DROP',
            "linux_nftables": f'nftables nft add rule ip filter input ip saddr {ip} drop',
            "macos_pf": f'echo "block drop from {ip} to any" >> /etc/pf.conf && pfctl -f /etc/pf.conf',
            "fortinet_api": f'config firewall address edit "SOC_BAN_{ip}" set subnet {ip}/32 end',
            "palo_alto_api": f'set address SOC_BAN_{ip} ip-netmask {ip}/32'
        }
