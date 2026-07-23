"""
Incident Response Playbook Generator for SOC Toolkit
Generates actionable step-by-step containment, eradication, and remediation playbooks for SOC analysts.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
from .enums import ThreatLevel, IOCType


@dataclass
class Playbook:
    """Incident Response Playbook for a specific threat finding"""
    ioc: str
    ioc_type: str
    threat_level: str
    summary: str
    containment_actions: List[str] = field(default_factory=list)
    eradication_actions: List[str] = field(default_factory=list)
    recovery_actions: List[str] = field(default_factory=list)
    firewall_block_cmd: str = ""
    sigma_recommendation: str = ""

    def to_markdown(self) -> str:
        """Convert playbook to formatted markdown"""
        md = f"### 🛡️ Incident Response Playbook for `{self.ioc}` ({self.ioc_type.upper()})\n\n"
        md += f"**Threat Level:** {self.threat_level}\n\n"
        md += f"**Summary:** {self.summary}\n\n"

        md += "#### 🚨 1. Immediate Containment Actions\n"
        for act in self.containment_actions:
            md += f"- [ ] {act}\n"
        
        if self.firewall_block_cmd:
            md += f"\n```bash\n# Instant Firewall Containment Command\n{self.firewall_block_cmd}\n```\n"

        md += "\n#### 🧹 2. Eradication & Remediation\n"
        for act in self.eradication_actions:
            md += f"- [ ] {act}\n"

        md += "\n#### 🔄 3. Recovery & Continuous Monitoring\n"
        for act in self.recovery_actions:
            md += f"- [ ] {act}\n"

        if self.sigma_recommendation:
            md += f"\n> 💡 **SIEM Detection Tip:** {self.sigma_recommendation}\n"

        return md


class PlaybookGenerator:
    """Generate SOC Playbooks based on IOC Threat Analysis"""

    @classmethod
    def generate(cls, ioc: str, ioc_type: IOCType, threat_level: ThreatLevel, details: Dict[str, Any] = None) -> Playbook:
        details = details or {}
        type_str = ioc_type.value if hasattr(ioc_type, 'value') else str(ioc_type)
        level_str = threat_level.value if hasattr(threat_level, 'value') else str(threat_level)

        containment = []
        eradication = []
        recovery = []
        fw_cmd = ""
        sigma_tip = ""

        if threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            if type_str in ("ip", "ipv4", "ipv6"):
                containment.append(f"Block outbound and inbound traffic to IP `{ioc}` on Edge Firewall / Gateway.")
                containment.append(f"Isolate any internal endpoint that initiated active TCP connections to `{ioc}`.")
                containment.append(f"Revoke active VPN / SSO user sessions originating from `{ioc}`.")
                fw_cmd = f"iptables -A INPUT -s {ioc} -j DROP && iptables -A OUTPUT -d {ioc} -j DROP"
                eradication.append(f"Perform full EDR / antivirus memory scan on endpoints talking to `{ioc}`.")
                eradication.append(f"Inspect host DNS cache (`ipconfig /displaydns`) for malicious domains associated with `{ioc}`.")
                recovery.append(f"Add `{ioc}` to SIEM watchlists and blocklists for 90 days.")
                sigma_tip = f"Deploy SIEM alert rule for process network connections to dest_ip == '{ioc}'"

            elif type_str in ("domain", "url"):
                domain_name = ioc.replace("https://", "").replace("http://", "").split("/")[0]
                containment.append(f"Add domain `{domain_name}` to DNS Sinkhole & Web Proxy Blocklist.")
                containment.append(f"Reset credentials for users who navigated to or authenticated on `{domain_name}`.")
                containment.append(f"Block incoming email messages containing domain `{domain_name}` on SEG (Email Gateway).")
                fw_cmd = f"echo '0.0.0.0 {domain_name}' >> /etc/hosts"
                eradication.append(f"Clear browser cache and cookies on impacted endpoint machines.")
                eradication.append(f"Scan endpoint for dropped payloads from `{domain_name}`.")
                recovery.append(f"Monitor DNS proxy logs for subdomains of `{domain_name}`.")
                sigma_tip = f"Create proxy alert rule filtering queries for query_domain == '{domain_name}'"

            elif "hash" in type_str:
                containment.append(f"Add file hash `{ioc}` to EDR / Endpoint Antivirus global blacklists.")
                containment.append(f"Isolate endpoints where file hash `{ioc}` was executed.")
                containment.append(f"Quarantine file `{ioc}` across all email gateway attachments.")
                eradication.append(f"Kill active processes associated with hash `{ioc}` across network.")
                eradication.append(f"Inspect Windows Registry persistence keys (Run, RunOnce, Scheduled Tasks) on host.")
                recovery.append(f"Perform full system image backup / restore if ransomware activity confirmed.")
                sigma_tip = f"Add file integrity monitoring rule for sha256/md5 hash '{ioc}'"

        elif threat_level in (ThreatLevel.LOW, ThreatLevel.MEDIUM):
            containment.append(f"Flag IOC `{ioc}` for enhanced logging and telemetry in SIEM.")
            containment.append(f"Verify if traffic to `{ioc}` aligns with legitimate business activity.")
            eradication.append(f"Review user context and parent process execution trees.")
            recovery.append(f"Keep in SOC watchlist for 14 days.")

        else:
            containment.append(f"No immediate containment required for clean/unknown IOC `{ioc}`.")
            recovery.append(f"Standard SOC baseline logging applies.")

        return Playbook(
            ioc=ioc,
            ioc_type=type_str,
            threat_level=level_str.upper(),
            summary=f"Automated Playbook generated for {level_str.upper()} risk indicator {ioc}",
            containment_actions=containment,
            eradication_actions=eradication,
            recovery_actions=recovery,
            firewall_block_cmd=fw_cmd,
            sigma_recommendation=sigma_tip
        )
