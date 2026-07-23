from soc_toolkit.ai_analyst import AIThreatAnalyst
from soc_toolkit.active_defense import ActiveDefenseEngine
from soc_toolkit.siem_correlator import SIEMCorrelatorEngine
from soc_toolkit.soar import SOAREngine
from soc_toolkit.yara_engine import YARAEngine
from soc_toolkit.enums import IOCType, ThreatLevel

def test_ai_analyst():
    res = AIThreatAnalyst.analyze_threat("185.220.101.45", IOCType.IP, ThreatLevel.CRITICAL)
    assert "Command and Control" in res["cyber_kill_chain_phase"]
    assert "EXECUTIVE SUMMARY" in res["ciso_executive_summary"]

def test_active_defense_ban():
    cmds = ActiveDefenseEngine.get_os_ban_command("1.2.3.4")
    assert "netsh" in cmds["windows_cmd"]
    assert "iptables" in cmds["linux_iptables"]
    assert "nftables" in cmds["linux_nftables"]

def test_soar_workflow():
    workflow = SOAREngine.execute_workflow("1.2.3.4", "CRITICAL")
    assert workflow["workflow_status"] == "EXECUTED"
    assert len(workflow["actions_taken"]) > 0

def test_siem_correlator():
    log_sample = "EventID 4625 failed login\npowershell.exe -enc VwBy...\nHTTP/1.1 connect"
    corr = SIEMCorrelatorEngine.parse_and_correlate(log_sample)
    assert corr["total_log_lines"] > 0
