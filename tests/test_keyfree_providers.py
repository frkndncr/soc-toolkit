from soc_toolkit.providers import (
    VirusTotalPublicProvider,
    AbuseIPDBPublicProvider,
    ShodanPublicProvider,
    TalosPublicProvider
)
from soc_toolkit.enums import IOCType, ThreatLevel

def test_vt_public_provider():
    p = VirusTotalPublicProvider()
    assert p.requires_api_key == False
    res = p.lookup("1.2.3.4", IOCType.IP)
    assert res.source == "VirusTotal Public"

def test_abuseipdb_public_provider():
    p = AbuseIPDBPublicProvider()
    assert p.requires_api_key == False
    res = p.lookup("1.2.3.4", IOCType.IP)
    assert res.source == "AbuseIPDB Public"

def test_shodan_public_provider():
    p = ShodanPublicProvider()
    assert p.requires_api_key == False
    res = p.lookup("1.2.3.4", IOCType.IP)
    assert res.source == "Shodan Public"

def test_talos_public_provider():
    p = TalosPublicProvider()
    assert p.requires_api_key == False
    res = p.lookup("1.2.3.4", IOCType.IP)
    assert res.source == "Cisco Talos Public"
