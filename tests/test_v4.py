from soc_toolkit.pcap_analyzer import PCAPAnalyzer
from soc_toolkit.pe_analyzer import PEAnalyzer
from soc_toolkit.c2_extractor import C2ConfigExtractor
from soc_toolkit.siem_queries import SIEMQueryGenerator
from soc_toolkit.mitre_navigator import MITRENavigatorExporter
from soc_toolkit.enums import IOCType, ThreatLevel

def test_pe_entropy():
    entropy = PEAnalyzer.calculate_entropy(b"AAAAAABBBBBBCCCCCC123456")
    assert entropy > 0.0

def test_c2_extraction():
    res = C2ConfigExtractor.extract_c2_config("watermark=1234567 User-Agent: Mozilla/5.0")
    assert res["has_c2_indicators"] is True

def test_siem_queries():
    q = SIEMQueryGenerator.generate_all("185.220.101.45", IOCType.IP)
    assert "splunk" in q
    assert "185.220.101.45" in q["splunk"]
    assert "sentinel" in q

def test_mitre_navigator():
    layer = MITRENavigatorExporter.generate_layer("185.220.101.45", ThreatLevel.CRITICAL)
    assert layer["name"] == "SOC Toolkit - 185.220.101.45"
    assert len(layer["techniques"]) > 0
