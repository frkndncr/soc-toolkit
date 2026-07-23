from soc_toolkit.stream import SyslogStreamListener
from soc_toolkit.mem_forensics import MemoryForensicsEngine
from soc_toolkit.report_gen import ExecutiveReportGenerator
from soc_toolkit.mitre_matrix import MITREMatrixEngine
from soc_toolkit.vault import APIVault
from soc_toolkit.enums import IOCType, ThreatLevel, IOCReport

def test_v7_syslog_stream():
    listener = SyslogStreamListener()
    res = listener.process_log_line("Log event from 185.220.101.45")
    assert res["processed"] == True

def test_v7_mem_forensics():
    res = MemoryForensicsEngine.scan_memory_strings("sekurlsa::logonpasswords wdigest.dll")
    assert res["mimikatz_indicators_found"] >= 2
    assert res["has_lsass_dump_artifacts"] == True

def test_v7_report_gen():
    report = IOCReport(ioc="1.2.3.4", ioc_type=IOCType.IP, timestamp="2026-07-23", overall_threat_level=ThreatLevel.HIGH, summary="High Threat")
    ticket = ExecutiveReportGenerator.generate_incident_ticket(report)
    assert "SECURITY INCIDENT TICKET" in ticket["markdown"]

def test_v7_mitre_matrix():
    matrix = MITREMatrixEngine.generate_matrix("1.2.3.4", IOCType.IP, ThreatLevel.CRITICAL)
    assert matrix["active_tactics_count"] >= 1

def test_v7_api_vault():
    APIVault.set_key("test_provider", "secret_key_123")
    val = APIVault.get_key("test_provider")
    assert val == "secret_key_123"
