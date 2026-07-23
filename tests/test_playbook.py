from soc_toolkit.playbook import PlaybookGenerator
from soc_toolkit.enums import ThreatLevel, IOCType

def test_critical_ip_playbook():
    pb = PlaybookGenerator.generate("185.220.101.45", IOCType.IP, ThreatLevel.CRITICAL)
    assert "Block outbound" in pb.containment_actions[0]
    assert "iptables" in pb.firewall_block_cmd
    assert pb.threat_level == "CRITICAL"

def test_clean_domain_playbook():
    pb = PlaybookGenerator.generate("google.com", IOCType.DOMAIN, ThreatLevel.CLEAN)
    assert "No immediate containment" in pb.containment_actions[0]
