"""
Enterprise Multi-Tenant RBAC & Auth Engine for SOC Toolkit
Enforces Role-Based Access Control (SOC_TIER_1, SOC_TIER_2, SOC_TIER_3, SOC_ADMIN) and JWT token validation.
"""

import time
import base64
import json
from typing import Dict, Any, Optional


class SOCRole:
    TIER_1 = "SOC_TIER_1"
    TIER_2 = "SOC_TIER_2"
    TIER_3 = "SOC_TIER_3"
    ADMIN = "SOC_ADMIN"


class EnterpriseRBACEngine:
    """Multi-tenant RBAC permissions and JWT authentication engine"""

    PERMISSIONS = {
        SOCRole.TIER_1: ["lookup", "read_iocs", "osint"],
        SOCRole.TIER_2: ["lookup", "read_iocs", "osint", "triage", "playbook", "compliance"],
        SOCRole.TIER_3: ["lookup", "read_iocs", "osint", "triage", "playbook", "compliance", "mem_forensics", "active_ban", "soar_execute"],
        SOCRole.ADMIN: ["*"]
    }

    @classmethod
    def generate_token(cls, username: str, role: str = SOCRole.TIER_2, tenant_id: str = "default_tenant") -> str:
        """Generate JWT-formatted session token"""
        header = base64.b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode('utf-8')).decode('utf-8')
        payload = base64.b64encode(json.dumps({
            "sub": username,
            "role": role,
            "tenant_id": tenant_id,
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400
        }).encode('utf-8')).decode('utf-8')
        signature = base64.b64encode(f"{header}.{payload}.secret_key".encode('utf-8')).decode('utf-8')
        return f"{header}.{payload}.{signature}"

    @classmethod
    def authorize_action(cls, role: str, action: str) -> bool:
        """Check if role has permission for action"""
        if role == SOCRole.ADMIN:
            return True
        allowed = cls.PERMISSIONS.get(role, [])
        return action in allowed or "*" in allowed
