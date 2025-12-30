"""
MITRE ATT&CK Mapping for SOC Toolkit
Maps IOCs and threat indicators to ATT&CK techniques
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from .enums import IOCType, ThreatLevel


@dataclass
class MITREMapping:
    """MITRE ATT&CK technique mapping"""
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    url: str
    confidence: str  # high, medium, low


# MITRE ATT&CK Technique Database
MITRE_TECHNIQUES = {
    # Initial Access
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems",
        "indicators": ["phishing", "spam", "email", "attachment", "macro"]
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access", 
        "description": "Adversaries may send spearphishing emails with a malicious attachment",
        "indicators": ["doc", "docx", "xls", "xlsx", "pdf", "zip", "attachment"]
    },
    "T1566.002": {
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious link",
        "indicators": ["url", "link", "click", "redirect"]
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may exploit vulnerabilities in internet-facing systems",
        "indicators": ["cve", "exploit", "vulnerability", "rce", "injection"]
    },
    
    # Execution
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands",
        "indicators": ["powershell", "cmd", "bash", "python", "script", "wscript"]
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell for execution",
        "indicators": ["powershell", "ps1", "invoke-expression", "iex", "downloadstring"]
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "description": "Adversary relies on user interaction to execute malicious code",
        "indicators": ["exe", "dll", "msi", "macro", "enable content"]
    },
    "T1204.002": {
        "name": "Malicious File",
        "tactic": "Execution",
        "description": "Adversary relies on user opening a malicious file",
        "indicators": ["trojan", "dropper", "loader", "downloader"]
    },
    
    # Persistence
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "description": "Adversaries may configure system settings to automatically execute a program during boot",
        "indicators": ["autorun", "startup", "registry", "run key"]
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Adversaries may abuse task scheduling to execute malicious code",
        "indicators": ["schtasks", "cron", "at", "scheduled task"]
    },
    
    # Defense Evasion
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obfuscate payloads to evade detection",
        "indicators": ["obfuscated", "encoded", "base64", "packed", "crypter"]
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may disable security tools to avoid detection",
        "indicators": ["disable av", "kill process", "stop service", "firewall off"]
    },
    
    # Credential Access
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may dump credentials to obtain account login information",
        "indicators": ["mimikatz", "lsass", "credential", "password dump", "hashdump"]
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts",
        "indicators": ["brute force", "password spray", "credential stuffing", "failed login"]
    },
    
    # Discovery
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may scan for services running on remote hosts",
        "indicators": ["port scan", "nmap", "service scan", "network scan"]
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Adversary may attempt to get detailed information about the operating system",
        "indicators": ["systeminfo", "hostname", "os version", "enumeration"]
    },
    
    # Lateral Movement
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use remote services to move laterally",
        "indicators": ["rdp", "ssh", "smb", "winrm", "psexec", "lateral"]
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use RDP to move laterally",
        "indicators": ["rdp", "3389", "remote desktop", "mstsc"]
    },
    
    # Collection
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Adversaries may search local system sources for data",
        "indicators": ["exfil", "collect", "gather", "steal", "data theft"]
    },
    "T1114": {
        "name": "Email Collection",
        "tactic": "Collection",
        "description": "Adversaries may collect emails from local or remote systems",
        "indicators": ["email", "outlook", "pst", "mail", "inbox"]
    },
    
    # Command and Control
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols",
        "indicators": ["http", "https", "dns", "c2", "beacon", "callback"]
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may use HTTP/HTTPS for C2 communications",
        "indicators": ["http", "https", "web c2", "http beacon"]
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may use non-application layer protocols for communication",
        "indicators": ["icmp", "raw socket", "tcp", "udp"]
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools from an external system into a compromised environment",
        "indicators": ["download", "wget", "curl", "certutil", "bitsadmin"]
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactic": "Command and Control",
        "description": "Adversaries may employ encryption to conceal C2 communications",
        "indicators": ["encrypted", "ssl", "tls", "https c2"]
    },
    
    # Exfiltration
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over the C2 channel",
        "indicators": ["exfiltration", "data theft", "upload", "send data"]
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": "Adversaries may use web services to exfiltrate data",
        "indicators": ["pastebin", "dropbox", "google drive", "mega", "cloud upload"]
    },
    
    # Impact
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability",
        "indicators": ["ransomware", "encrypt", "ransom", "locked", "decrypt"]
    },
    "T1489": {
        "name": "Service Stop",
        "tactic": "Impact",
        "description": "Adversaries may stop services to render systems or data unavailable",
        "indicators": ["stop service", "kill process", "disable", "shutdown"]
    },
}

# Malware family to ATT&CK mapping
MALWARE_MAPPING = {
    "cobalt strike": ["T1071.001", "T1059.001", "T1055", "T1105"],
    "cobaltstrike": ["T1071.001", "T1059.001", "T1055", "T1105"],
    "emotet": ["T1566.001", "T1204.002", "T1059.001", "T1071.001"],
    "trickbot": ["T1566.001", "T1059.001", "T1003", "T1071"],
    "ryuk": ["T1486", "T1489", "T1021.001"],
    "conti": ["T1486", "T1489", "T1021"],
    "lockbit": ["T1486", "T1489", "T1082"],
    "qakbot": ["T1566.001", "T1204.002", "T1055", "T1071"],
    "qbot": ["T1566.001", "T1204.002", "T1055", "T1071"],
    "icedid": ["T1566.001", "T1204.002", "T1071.001"],
    "dridex": ["T1566.001", "T1204.002", "T1059.001"],
    "agent tesla": ["T1566.001", "T1555", "T1114"],
    "agenttesla": ["T1566.001", "T1555", "T1114"],
    "formbook": ["T1566.001", "T1555", "T1056"],
    "lokibot": ["T1566.001", "T1555", "T1071"],
    "raccoon": ["T1555", "T1539", "T1071"],
    "redline": ["T1555", "T1539", "T1071"],
    "vidar": ["T1555", "T1539", "T1082"],
    "asyncrat": ["T1059.001", "T1071.001", "T1547"],
    "remcos": ["T1059", "T1071.001", "T1547"],
    "njrat": ["T1059", "T1071", "T1547"],
    "nanocore": ["T1059", "T1071", "T1547"],
    "darkcomet": ["T1059", "T1071", "T1547"],
    "metasploit": ["T1059", "T1071", "T1055", "T1105"],
    "meterpreter": ["T1059", "T1071", "T1055"],
    "mimikatz": ["T1003", "T1555"],
    "lazarus": ["T1566", "T1059", "T1071", "T1486"],
    "apt28": ["T1566", "T1059.001", "T1071"],
    "apt29": ["T1566", "T1059.001", "T1071"],
    "fin7": ["T1566.001", "T1059.001", "T1071"],
    "wizard spider": ["T1566", "T1486", "T1071"],
}

# Threat type to ATT&CK mapping
THREAT_TYPE_MAPPING = {
    "botnet": ["T1071", "T1573", "T1105"],
    "c2": ["T1071", "T1573", "T1095"],
    "c&c": ["T1071", "T1573", "T1095"],
    "command and control": ["T1071", "T1573", "T1095"],
    "phishing": ["T1566", "T1204"],
    "spam": ["T1566", "T1204"],
    "malware": ["T1204.002", "T1059"],
    "trojan": ["T1204.002", "T1547"],
    "ransomware": ["T1486", "T1489"],
    "cryptominer": ["T1496"],
    "miner": ["T1496"],
    "rat": ["T1071", "T1059", "T1547"],
    "stealer": ["T1555", "T1539", "T1005"],
    "infostealer": ["T1555", "T1539", "T1005"],
    "keylogger": ["T1056.001"],
    "backdoor": ["T1547", "T1071"],
    "dropper": ["T1204.002", "T1105"],
    "downloader": ["T1105", "T1204.002"],
    "loader": ["T1105", "T1055"],
    "exploit": ["T1190", "T1203"],
    "scanner": ["T1046", "T1595"],
    "brute": ["T1110"],
    "bruteforce": ["T1110"],
}


class MITREMapper:
    """Maps IOC data to MITRE ATT&CK techniques"""
    
    def __init__(self):
        self.techniques = MITRE_TECHNIQUES
        self.malware_mapping = MALWARE_MAPPING
        self.threat_mapping = THREAT_TYPE_MAPPING
    
    def map_from_report(self, report: dict) -> List[MITREMapping]:
        """
        Map IOC report data to MITRE techniques
        
        Args:
            report: IOC report dictionary with provider results
            
        Returns:
            List of MITREMapping objects
        """
        mappings = []
        seen_techniques = set()
        
        # Extract all text data from report
        text_data = self._extract_text(report)
        
        # Check malware families
        for malware, techniques in self.malware_mapping.items():
            if malware in text_data:
                for tech_id in techniques:
                    if tech_id not in seen_techniques and tech_id in self.techniques:
                        seen_techniques.add(tech_id)
                        tech = self.techniques[tech_id]
                        mappings.append(MITREMapping(
                            technique_id=tech_id,
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            description=tech["description"],
                            url=f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}",
                            confidence="high"
                        ))
        
        # Check threat types
        for threat_type, techniques in self.threat_mapping.items():
            if threat_type in text_data:
                for tech_id in techniques:
                    if tech_id not in seen_techniques and tech_id in self.techniques:
                        seen_techniques.add(tech_id)
                        tech = self.techniques[tech_id]
                        mappings.append(MITREMapping(
                            technique_id=tech_id,
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            description=tech["description"],
                            url=f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}",
                            confidence="medium"
                        ))
        
        # Check technique indicators
        for tech_id, tech in self.techniques.items():
            if tech_id in seen_techniques:
                continue
            for indicator in tech.get("indicators", []):
                if indicator in text_data:
                    seen_techniques.add(tech_id)
                    mappings.append(MITREMapping(
                        technique_id=tech_id,
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        description=tech["description"],
                        url=f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}",
                        confidence="low"
                    ))
                    break
        
        # Sort by confidence and tactic
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        mappings.sort(key=lambda x: (confidence_order.get(x.confidence, 3), x.tactic))
        
        return mappings
    
    def map_from_ioc_type(self, ioc_type: IOCType, threat_level: ThreatLevel) -> List[MITREMapping]:
        """
        Get likely techniques based on IOC type and threat level
        """
        mappings = []
        
        # Base mappings by IOC type
        type_techniques = {
            IOCType.IP: ["T1071", "T1095"],  # C2 related
            IOCType.DOMAIN: ["T1071", "T1566.002"],  # C2, phishing
            IOCType.URL: ["T1566.002", "T1105"],  # Phishing link, tool transfer
            IOCType.HASH_MD5: ["T1204.002"],  # Malicious file
            IOCType.HASH_SHA1: ["T1204.002"],
            IOCType.HASH_SHA256: ["T1204.002"],
            IOCType.EMAIL: ["T1566"],  # Phishing
        }
        
        technique_ids = type_techniques.get(ioc_type, [])
        
        # Add more techniques for higher threat levels
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            if ioc_type == IOCType.IP:
                technique_ids.extend(["T1573", "T1105"])
            elif ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
                technique_ids.extend(["T1059", "T1547"])
        
        for tech_id in technique_ids:
            if tech_id in self.techniques:
                tech = self.techniques[tech_id]
                mappings.append(MITREMapping(
                    technique_id=tech_id,
                    technique_name=tech["name"],
                    tactic=tech["tactic"],
                    description=tech["description"],
                    url=f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}",
                    confidence="low"
                ))
        
        return mappings
    
    def _extract_text(self, data: dict, depth: int = 0) -> str:
        """Recursively extract all text from dict"""
        if depth > 10:
            return ""
            
        texts = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                texts.append(str(key).lower())
                texts.append(self._extract_text(value, depth + 1))
        elif isinstance(data, list):
            for item in data:
                texts.append(self._extract_text(item, depth + 1))
        else:
            texts.append(str(data).lower())
        
        return " ".join(texts)
    
    def get_technique_info(self, technique_id: str) -> Optional[Dict]:
        """Get detailed info about a specific technique"""
        if technique_id in self.techniques:
            tech = self.techniques[technique_id]
            return {
                "id": technique_id,
                "name": tech["name"],
                "tactic": tech["tactic"],
                "description": tech["description"],
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
                "indicators": tech.get("indicators", [])
            }
        return None
    
    def get_tactics(self) -> List[str]:
        """Get list of all MITRE ATT&CK tactics"""
        return [
            "Initial Access",
            "Execution", 
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact"
        ]


def format_mitre_output(mappings: List[MITREMapping]) -> str:
    """Format MITRE mappings for CLI output"""
    if not mappings:
        return "  No MITRE ATT&CK mappings found"
    
    lines = []
    current_tactic = None
    
    for m in mappings:
        if m.tactic != current_tactic:
            current_tactic = m.tactic
            lines.append(f"\n  📌 {current_tactic}")
        
        confidence_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(m.confidence, "⚪")
        lines.append(f"    {confidence_icon} {m.technique_id}: {m.technique_name}")
    
    return "\n".join(lines)
