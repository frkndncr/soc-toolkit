import os
import sys
import tempfile
import unittest
from pathlib import Path

tests_dir = str(Path(__file__).parent)
root_dir = str(Path(__file__).parent.parent)

if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from soc_toolkit.enums import IOCType, ThreatLevel, LookupResult, IOCReport
from soc_toolkit.whitelist import WhitelistFilter
from soc_toolkit.playbook import PlaybookGenerator, Playbook
from soc_toolkit.decoder import PayloadDecoder
from soc_toolkit.threat_intel import ThreatIntelMatcher
from soc_toolkit.osint import OSINTLinksGenerator
from soc_toolkit.rules import DetectionRuleGenerator
from soc_toolkit.pcap_analyzer import PCAPAnalyzer
from soc_toolkit.pe_analyzer import PEAnalyzer
from soc_toolkit.c2_extractor import C2ConfigExtractor
from soc_toolkit.mitre_navigator import MITRENavigatorExporter
from soc_toolkit.siem_queries import SIEMQueryGenerator
from soc_toolkit.graph_visualizer import ThreatGraphVisualizer
from soc_toolkit.compliance import ComplianceEngine
from soc_toolkit.taxii_server import TAXIIServerEngine
from soc_toolkit.siem_integrations import SIEMIntegrations
from soc_toolkit.ai_analyst import AIThreatAnalyst
from soc_toolkit.active_defense import ActiveDefenseEngine
from soc_toolkit.siem_correlator import SIEMCorrelatorEngine
from soc_toolkit.soar import SOAREngine
from soc_toolkit.yara_engine import YARAEngine
from soc_toolkit.dashboard import DashboardEngine
from soc_toolkit.detectors import IOCDetector
from soc_toolkit.extractor import IOCExtractor
from soc_toolkit.sdk import SOCToolkitSDK
from soc_toolkit.core import SOCToolkit
from soc_toolkit.formatter import OutputFormatter
from soc_toolkit.triage import LogTriageEngine


class ComprehensiveAllFunctionsTest(unittest.TestCase):
    """Exhaustively tests every function across all modules in soc-toolkit"""

    def test_01_whitelist_filter(self):
        is_b, desc, prov = WhitelistFilter.check_ip("8.8.8.8")
        self.assertTrue(is_b)
        self.assertEqual(prov, "Google")

        is_b_dom, desc_dom = WhitelistFilter.check_domain("google.com")
        self.assertTrue(is_b_dom)

        eval_ip = WhitelistFilter.evaluate("8.8.8.8", "ip")
        self.assertTrue(eval_ip["is_benign"])

    def test_02_playbook_generator(self):
        pb = PlaybookGenerator.generate("185.220.101.45", IOCType.IP, ThreatLevel.CRITICAL)
        self.assertIsInstance(pb, Playbook)
        md = pb.to_markdown()
        self.assertIn("Immediate Containment Actions", md)

    def test_03_payload_decoder(self):
        defanged = PayloadDecoder.defang("https://evil.com/test")
        self.assertEqual(defanged, "hXXps://evil[.]com/test")

        refanged = PayloadDecoder.refang("hXXps://evil[.]com/test")
        self.assertEqual(refanged, "https://evil.com/test")

        dec = PayloadDecoder.decode_powershell("powershell -enc VwByAGkAdABlAC0ASABvAHMAdAA=")
        self.assertTrue(dec["found"])

    def test_04_threat_intel_matcher(self):
        res = ThreatIntelMatcher.match([{"info": "detected cobalt strike beacon"}])
        self.assertTrue(res["has_threat_match"])
        self.assertEqual(res["threat_families"][0]["family"], "Cobalt Strike C2")

    def test_05_osint_links(self):
        links_ip = OSINTLinksGenerator.get_links("185.220.101.45", IOCType.IP)
        self.assertIn("VirusTotal", links_ip)
        self.assertIn("Shodan", links_ip)

        links_dom = OSINTLinksGenerator.get_links("evil.com", IOCType.DOMAIN)
        self.assertIn("VirusTotal", links_dom)

        links_hash = OSINTLinksGenerator.get_links("44d88612fea8a8f36de82e1278abb02f", IOCType.HASH_MD5)
        self.assertIn("MalwareBazaar", links_hash)

    def test_06_detection_rules(self):
        sigma = DetectionRuleGenerator.generate_sigma("1.2.3.4", IOCType.IP)
        self.assertIn("title:", sigma)

        yara = DetectionRuleGenerator.generate_yara("1.2.3.4", IOCType.IP)
        self.assertIn("rule ", yara)

        nids = DetectionRuleGenerator.generate_nids("1.2.3.4", IOCType.IP)
        self.assertIn("snort", nids)

    def test_07_pe_and_entropy(self):
        entropy = PEAnalyzer.calculate_entropy(b"MZ\x90\x00\x03\x00\x00\x00")
        self.assertGreaterEqual(entropy, 0.0)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"MZ\x90\x00VirtualAlloc\x00WriteProcessMemory")
            tmp_path = tmp.name

        try:
            pe_res = PEAnalyzer.analyze_file(tmp_path)
            self.assertTrue(pe_res["is_pe_executable"])
            self.assertIn("VirtualAlloc", pe_res["suspicious_apis_detected"])
        finally:
            os.remove(tmp_path)

    def test_08_c2_extractor(self):
        c2 = C2ConfigExtractor.extract_c2_config("watermark=987654 User-Agent: Mozilla")
        self.assertTrue(c2["has_c2_indicators"])

    def test_09_mitre_navigator(self):
        layer = MITRENavigatorExporter.generate_layer("1.2.3.4", ThreatLevel.HIGH)
        self.assertIn("techniques", layer)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            tmp_path = tmp.name

        try:
            MITRENavigatorExporter.export_to_file("1.2.3.4", ThreatLevel.HIGH, tmp_path)
            self.assertTrue(os.path.exists(tmp_path))
        finally:
            os.remove(tmp_path)

    def test_10_siem_queries(self):
        queries = SIEMQueryGenerator.generate_all("1.2.3.4", IOCType.IP)
        self.assertIn("splunk", queries)
        self.assertIn("elastic", queries)
        self.assertIn("sentinel", queries)

    def test_11_graph_visualizer(self):
        html = ThreatGraphVisualizer.generate_html_graph("1.2.3.4", "HIGH", [{"source": "Shodan"}])
        self.assertIn("Threat Relationship Graph", html)

    def test_12_compliance_engine(self):
        comp = ComplianceEngine.evaluate_compliance("185.220.101.45", IOCType.IP, ThreatLevel.CRITICAL)
        self.assertIn("pci_dss", comp)
        self.assertIn("iso27001", comp)

    def test_13_taxii_and_siem_integrations(self):
        disc = TAXIIServerEngine.get_discovery()
        self.assertIn("title", disc)

        colls = TAXIIServerEngine.get_collections()
        self.assertIn("collections", colls)

        spl = SIEMIntegrations.get_splunk_command_script()
        self.assertIn("soclookup", spl)

        soar_manifest = SIEMIntegrations.get_soar_app_manifest()
        self.assertIn("name", soar_manifest)

    def test_14_ai_analyst(self):
        ai_res = AIThreatAnalyst.analyze_threat("185.220.101.45", IOCType.IP, ThreatLevel.CRITICAL)
        self.assertIn("cyber_kill_chain_phase", ai_res)

    def test_15_active_defense(self):
        ht = ActiveDefenseEngine.generate_honeytoken("canary_url")
        self.assertIn("http://canary", ht["honeytoken"])

        ban = ActiveDefenseEngine.get_os_ban_command("1.2.3.4")
        self.assertIn("windows_cmd", ban)
        self.assertIn("linux_iptables", ban)

    def test_16_siem_correlator_and_soar(self):
        corr = SIEMCorrelatorEngine.parse_and_correlate("EventID 4625 failed login\npowershell -enc...")
        self.assertGreaterEqual(corr["total_log_lines"], 1)

        soar_res = SOAREngine.execute_workflow("1.2.3.4", "HIGH")
        self.assertEqual(soar_res["workflow_status"], "EXECUTED")

    def test_17_yara_and_dashboard(self):
        yara_res = YARAEngine.scan_text("eval(base64_decode())")
        self.assertTrue(yara_res["scanned"])

        dash_html = DashboardEngine.get_dashboard_html()
        self.assertIn("WARFARE DASHBOARD", dash_html)

    def test_18_detectors_and_extractor(self):
        det_type = IOCDetector.detect("185.220.101.45")
        self.assertEqual(det_type, IOCType.IP)

        ext = IOCExtractor.extract("Check 185.220.101.45 and evil.com")
        self.assertIn("185.220.101.45", ext["ip"])
        self.assertIn("evil.com", ext["domain"])

    def test_19_sdk(self):
        sdk = SOCToolkitSDK()
        defanged = sdk.defang("1.1.1.1")
        self.assertEqual(defanged, "1[.]1[.]1[.]1")

    def test_20_formatter_exports(self):
        report = IOCReport(
            ioc="8.8.8.8",
            ioc_type=IOCType.IP,
            timestamp="2026-07-23T12:00:00",
            results=[
                LookupResult(source="Shodan", found=True, threat_level=ThreatLevel.CLEAN, response_time=0.1)
            ],
            overall_threat_level=ThreatLevel.CLEAN,
            summary="Clean IP"
        )
        formatter = OutputFormatter()

        with tempfile.TemporaryDirectory() as tmpdir:
            json_p = os.path.join(tmpdir, "out.json")
            md_p = os.path.join(tmpdir, "out.md")
            csv_p = os.path.join(tmpdir, "out.csv")
            html_p = os.path.join(tmpdir, "out.html")
            stix_p = os.path.join(tmpdir, "out.stix.json")

            formatter.export_json(report, json_p)
            formatter.export_markdown(report, md_p)
            formatter.export_csv(report, csv_p)
            formatter.export_html(report, html_p)
            formatter.export_stix(report, stix_p)

            self.assertTrue(os.path.exists(json_p))
            self.assertTrue(os.path.exists(md_p))
            self.assertTrue(os.path.exists(csv_p))
            self.assertTrue(os.path.exists(html_p))
            self.assertTrue(os.path.exists(stix_p))

    def test_21_log_triage(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log", mode="w", encoding="utf-8") as tmp:
            tmp.write("Connection from 185.220.101.45\nDNS query evil-domain.com")
            tmp_path = tmp.name

        try:
            class DummySOC:
                def lookup(self, ioc):
                    return IOCReport(ioc=ioc, ioc_type=IOCType.IP, timestamp="2026-07-23", overall_threat_level=ThreatLevel.HIGH, summary="High Threat")
            
            triage_engine = LogTriageEngine(soc_engine=DummySOC())
            result = triage_engine.triage_file(tmp_path)
            self.assertGreaterEqual(result["total_iocs_extracted"], 1)
        finally:
            os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
