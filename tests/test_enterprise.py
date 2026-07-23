from soc_toolkit.enterprise_auth import EnterpriseRBACEngine, SOCRole
from soc_toolkit.edr_collector import EDRCollectorEngine
from soc_toolkit.timeline import IncidentTimelineEngine
from soc_toolkit.cluster import HAClusterEngine

def test_rbac_token_and_permissions():
    token = EnterpriseRBACEngine.generate_token("test_user", SOCRole.TIER_2)
    assert "JWT" in token or "." in token
    assert EnterpriseRBACEngine.authorize_action(SOCRole.TIER_2, "playbook") == True
    assert EnterpriseRBACEngine.authorize_action(SOCRole.TIER_1, "active_ban") == False

def test_edr_telemetry():
    res = EDRCollectorEngine.get_host_telemetry("HOST-01")
    assert "active_process_tree" in res
    assert len(res["active_process_tree"]) >= 1

def test_incident_timeline():
    t = IncidentTimelineEngine.generate_timeline("1.2.3.4")
    assert t["total_timeline_events"] >= 1

def test_ha_cluster():
    cluster = HAClusterEngine.get_cluster_status()
    assert cluster["cluster_health"] == "HEALTHY"
    assert cluster["total_nodes"] >= 1
