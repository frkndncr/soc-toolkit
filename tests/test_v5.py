from soc_toolkit.compliance import ComplianceEngine
from soc_toolkit.taxii_server import TAXIIServerEngine
from soc_toolkit.siem_integrations import SIEMIntegrations
from soc_toolkit.enums import IOCType, ThreatLevel

def test_compliance_evaluation():
    comp = ComplianceEngine.evaluate_compliance("185.220.101.45", IOCType.IP, ThreatLevel.CRITICAL)
    assert comp["overall_compliance_status"] == "NON-COMPLIANT (ACTION REQUIRED)"
    assert len(comp["pci_dss"]) > 0
    assert len(comp["iso27001"]) > 0

def test_taxii_discovery():
    disc = TAXIIServerEngine.get_discovery()
    assert "SOC Toolkit" in disc["title"]
    colls = TAXIIServerEngine.get_collections()
    assert len(colls["collections"]) > 0

def test_siem_splunk_script():
    script = SIEMIntegrations.get_splunk_command_script()
    assert "soclookup.py" in script
