import tempfile
import os
from soc_toolkit.whitelist import WhitelistFilter
from soc_toolkit.batch import BatchScanner
from soc_toolkit.mitre_matrix import MITREMatrixEngine
from soc_toolkit.sanitizer import IOCSanitizer
from soc_toolkit.enums import ThreatLevel, IOCType


def test_whitelist_comprehensive():
    """Test private IPs, loopbacks, DNS infrastructure, and malicious targets"""
    # Private IP RFC1918
    r1 = WhitelistFilter.evaluate("10.0.0.1", "ip")
    assert r1["is_benign"] is True
    assert "RFC1918" in r1["reason"]

    r2 = WhitelistFilter.evaluate("172.16.50.1", "ip")
    assert r2["is_benign"] is True
    assert "RFC1918" in r2["reason"]

    r3 = WhitelistFilter.evaluate("192.168.1.254", "ip")
    assert r3["is_benign"] is True
    assert "RFC1918" in r3["reason"]

    # Loopback & Link Local
    r4 = WhitelistFilter.evaluate("127.0.0.1", "ip")
    assert r4["is_benign"] is True

    # Public Trusted Infrastructure
    r5 = WhitelistFilter.evaluate("8.8.8.8", "ip")
    assert r5["is_benign"] is True
    assert "Google" in r5["reason"]

    r6 = WhitelistFilter.evaluate("1.1.1.1", "ip")
    assert r6["is_benign"] is True
    assert "Cloudflare" in r6["reason"]

    # Trusted Domain
    r7 = WhitelistFilter.evaluate("google.com", "domain")
    assert r7["is_benign"] is True

    # Malicious Non-Whitelisted Target
    r8 = WhitelistFilter.evaluate("185.220.101.45", "ip")
    assert r8["is_benign"] is False


def test_batch_scanner_real_file():
    """Test batch file IOC extraction and multithreaded scanning on a real file"""
    sample_log = """
    2026-07-24 10:00:00 [ALERT] Suspicious connection from IP: 185.220.101.45 to internal server 10.0.0.5
    2026-07-24 10:01:00 [INFO] DNS lookup for (8.8.8.8) and hxxps[://]malicious-c2[.]com/payload.exe
    2026-07-24 10:02:00 [WARN] File hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
        tmp.write(sample_log)
        tmp_path = tmp.name

    try:
        res = BatchScanner.scan_file(tmp_path, max_workers=4)
        assert res["total_extracted"] >= 3
        assert "clean_count" in res
        assert "critical_count" in res
        assert res["file_size_bytes"] > 0
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_mitre_matrix_engine_deep():
    """Test full 14-tactic MITRE ATT&CK coverage and visual rendering"""
    res = MITREMatrixEngine.generate_matrix("185.220.101.45", IOCType.IP, ThreatLevel.CRITICAL)
    assert res["ioc"] == "185.220.101.45"
    assert res["threat_level"] == "CRITICAL"
    assert res["active_tactics_count"] >= 3
    assert len(res["mitre_matrix"]) == 14
    assert res["mitre_matrix"]["Command and Control"]["technique_id"] == "T1071"
    assert res["mitre_matrix"]["Initial Access"]["technique_id"] == "T1566"
    assert res["mitre_matrix"]["Exfiltration"]["technique_id"] == "T1041"

    # Verify visual heatmap renderer executes without errors
    MITREMatrixEngine.print_visual_matrix("185.220.101.45", IOCType.IP, ThreatLevel.CRITICAL)


def test_ioc_sanitizer_extensive():
    """Test comprehensive edge case sanitization"""
    assert IOCSanitizer.sanitize("(185.220.101.45)") == "185.220.101.45"
    assert IOCSanitizer.sanitize("[1.2.3.4]") == "1.2.3.4"
    assert IOCSanitizer.sanitize("hxxps[://]bad[.]com") == "https://bad.com"
    assert IOCSanitizer.sanitize("hxxp[://]1.2.3.4/test") == "http://1.2.3.4/test"
    assert IOCSanitizer.sanitize("IP: 185.220.101.45") == "185.220.101.45"
    assert IOCSanitizer.sanitize("  '185.220.101.45'  ") == "185.220.101.45"
    assert IOCSanitizer.sanitize("Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
