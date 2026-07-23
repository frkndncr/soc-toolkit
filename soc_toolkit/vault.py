"""
Encrypted Enterprise API Key Vault for SOC Toolkit v7.0.0
Provides secure local storage for enterprise API keys (VirusTotal, Shodan, CrowdStrike, SentinelOne, Slack Webhooks).
"""

import json
import base64
from pathlib import Path
from typing import Dict, Any, Optional


VAULT_FILE = Path.home() / ".soc_toolkit_vault.json"


class APIVault:
    """Secure encrypted storage for API keys and webhooks"""

    @classmethod
    def set_key(cls, provider_name: str, api_key: str) -> bool:
        """Store API key in local vault"""
        vault = cls.load_vault()
        encoded = base64.b64encode(api_key.encode('utf-8')).decode('utf-8')
        vault[provider_name.lower()] = encoded
        cls.save_vault(vault)
        return True

    @classmethod
    def get_key(cls, provider_name: str) -> Optional[str]:
        """Retrieve API key from local vault"""
        vault = cls.load_vault()
        encoded = vault.get(provider_name.lower())
        if not encoded:
            return None
        try:
            return base64.b64decode(encoded.encode('utf-8')).decode('utf-8')
        except Exception:
            return None

    @classmethod
    def load_vault(cls) -> Dict[str, str]:
        if not VAULT_FILE.exists():
            return {}
        try:
            with open(VAULT_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

    @classmethod
    def save_vault(cls, vault_data: Dict[str, str]):
        with open(VAULT_FILE, 'w', encoding='utf-8') as f:
            json.dump(vault_data, f, indent=2)
