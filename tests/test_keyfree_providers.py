from soc_toolkit.providers import (
    VirusTotalPublicProvider,
    AbuseIPDBPublicProvider,
    ShodanPublicProvider,
    TalosPublicProvider
)
from soc_toolkit.enums import IOCType, ThreatLevel


def test_vt_public_provider():
    p = VirusTotalPublicProvider()
    assert p.requires_api_key is False
    assert p.name == "VirusTotal Public"
    
    # Test IP lookup
    res_ip = p.lookup("185.220.101.45", IOCType.IP)
    assert res_ip.source == "VirusTotal Public"
    assert res_ip.threat_level is not None


def test_abuseipdb_public_provider():
    p = AbuseIPDBPublicProvider()
    assert p.requires_api_key is False
    assert p.name == "AbuseIPDB Public"
    
    res = p.lookup("185.220.101.45", IOCType.IP)
    assert res.source == "AbuseIPDB Public"
    assert res.threat_level is not None


def test_shodan_public_provider():
    p = ShodanPublicProvider()
    assert p.requires_api_key is False
    assert p.name == "Shodan Public"
    
    res = p.lookup("185.220.101.45", IOCType.IP)
    assert res.source == "Shodan Public"
    assert res.threat_level is not None


def test_talos_public_provider():
    p = TalosPublicProvider()
    assert p.requires_api_key is False
    assert p.name == "Cisco Talos Public"
    
    res = p.lookup("185.220.101.45", IOCType.IP)
    assert res.source == "Cisco Talos Public"
    assert res.threat_level is not None
