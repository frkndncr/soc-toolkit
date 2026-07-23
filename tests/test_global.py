from soc_toolkit.asm import AttackSurfaceScanner
from soc_toolkit.ransomware_checker import RansomwareCheckerEngine
from soc_toolkit.beaconing import BeaconingCalculator
from soc_toolkit.i18n import GlobalI18nEngine
from soc_toolkit.converter import SIEMConverterEngine
from soc_toolkit.enums import IOCType, ThreatLevel

def test_asm_scanner():
    res = AttackSurfaceScanner.scan_domain("example.com")
    assert res["target_domain"] == "example.com"

def test_ransomware_checker():
    res = RansomwareCheckerEngine.evaluate_ioc("1.2.3.4", ThreatLevel.CRITICAL)
    assert res["ransomware_matched"] == True
    assert len(res["emergency_anti_ransomware_checklist"]) >= 1

def test_beaconing_calculator():
    res = BeaconingCalculator.calculate_beaconing([100.0, 160.0, 220.0, 280.0, 340.0])
    assert res["is_beaconing"] == True

def test_global_i18n():
    de_res = GlobalI18nEngine.format_report("1.2.3.4", "CRITICAL", "de")
    assert "SICHERHEITSBERICHT" in de_res["title"]

def test_siem_converter():
    conv = SIEMConverterEngine.convert_log_to_rules("Failed login from 185.220.101.45")
    assert "title:" in conv["sigma"]
    assert "rule " in conv["yara"]
