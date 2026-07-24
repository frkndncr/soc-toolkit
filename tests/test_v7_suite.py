from soc_toolkit.whitelist import WhitelistFilter
from soc_toolkit.batch import BatchScanner
from soc_toolkit.mitre_matrix import MITREMatrixEngine
from soc_toolkit.enums import ThreatLevel, IOCType

def test_whitelist_private_ip():
    res = WhitelistFilter.evaluate("192.168.1.1", "ip")
    assert res["is_benign"] is True
    assert "RFC1918" in res["reason"]

def test_batch_scanner_empty():
    res = BatchScanner.scan_file("non_existent_file.txt")
    assert "error" in res

def test_mitre_visual_heatmap():
    res = MITREMatrixEngine.generate_matrix("185.220.101.45", IOCType.IP, ThreatLevel.CRITICAL)
    assert res["active_tactics_count"] >= 3
    assert "Command and Control" in res["mitre_matrix"]
