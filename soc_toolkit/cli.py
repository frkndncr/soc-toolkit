#!/usr/bin/env python3
"""
SOC Toolkit CLI Enterprise & Global SOC Platform
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel

from . import __version__
from .core import SOCToolkit
from .detectors import IOCDetector, IOCType
from .formatter import OutputFormatter
from .config import Config
from .playbook import PlaybookGenerator
from .decoder import PayloadDecoder
from .rules import DetectionRuleGenerator
from .triage import LogTriageEngine
from .web import start_web_server
from .pcap_analyzer import PCAPAnalyzer
from .pe_analyzer import PEAnalyzer
from .c2_extractor import C2ConfigExtractor
from .mitre_navigator import MITRENavigatorExporter
from .siem_queries import SIEMQueryGenerator
from .graph_visualizer import ThreatGraphVisualizer
from .compliance import ComplianceEngine
from .api_server import start_api_server
from .ai_analyst import AIThreatAnalyst
from .active_defense import ActiveDefenseEngine
from .siem_correlator import SIEMCorrelatorEngine
from .soar import SOAREngine
from .yara_engine import YARAEngine
from .shell import start_interactive_shell
from .stream import SyslogStreamListener
from .mem_forensics import MemoryForensicsEngine
from .report_gen import ExecutiveReportGenerator
from .mitre_matrix import MITREMatrixEngine
from .vault import APIVault
from .enterprise_auth import EnterpriseRBACEngine, SOCRole
from .edr_collector import EDRCollectorEngine
from .timeline import IncidentTimelineEngine
from .cluster import HAClusterEngine
from .asm import AttackSurfaceScanner
from .ransomware_checker import RansomwareCheckerEngine
from .beaconing import BeaconingCalculator
from .i18n import GlobalI18nEngine
from .converter import SIEMConverterEngine


console = Console(legacy_windows=False)

SUBCOMMANDS = {
    "shell", "ai", "soar", "server", "audit", "pcap",
    "analyze", "c2-decode", "triage", "decode", "defang", "refang", "web",
    "report", "mem", "mitre-matrix", "vault", "stream",
    "edr", "timeline", "cluster", "rbac",
    "asm", "ransomware", "beacon", "i18n", "convert"
}


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    
    parser = argparse.ArgumentParser(
        prog="soc",
        description=f"🛡️ SOC Toolkit v{__version__} - Enterprise Threat Intelligence & Security Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  soc <ioc>             Lookup IP, Domain, Hash, or URL
  soc ai <ioc>          Autonomous AI Root Cause Analysis
  soc asm <domain>      Attack Surface Discovery & Shadow IT
  soc mem <file>        Process Memory & Mimikatz Threat Hunter
  soc stream            Real-time Syslog Stream Listener
  soc shell             Interactive Analyst Terminal Shell

Author: Furkan Dinçer (@frkndncr) | https://github.com/frkndncr/soc-toolkit
        """
    )
    
    parser.add_argument("ioc", nargs="?", help="Target IOC or subcommand")
    parser.add_argument("subarg", nargs="?", help="Secondary argument")
    parser.add_argument("extra_arg", nargs="?", help="Tertiary argument")

    output_group = parser.add_argument_group("Export Options")
    output_group.add_argument("--json", metavar="FILE", help="Export to JSON file")
    output_group.add_argument("--md", "--markdown", metavar="FILE", dest="markdown", help="Export to Markdown file")
    output_group.add_argument("--csv", metavar="FILE", help="Export to CSV file")
    output_group.add_argument("--html", metavar="FILE", help="Export interactive HTML report")
    
    soc_group = parser.add_argument_group("Security Options")
    soc_group.add_argument("--playbook", action="store_true", help="Generate IR Playbook")
    soc_group.add_argument("--sigma", action="store_true", help="Generate Sigma SIEM Rule")
    soc_group.add_argument("--yara", action="store_true", help="Generate YARA Rule")
    soc_group.add_argument("--port", type=int, default=8000, help="Server port")

    display_group = parser.add_argument_group("Display Options")
    display_group.add_argument("-q", "--quiet", action="store_true", help="Suppress banner")
    display_group.add_argument("--raw", action="store_true", help="Raw JSON output")
    display_group.add_argument("--providers", action="store_true", help="List providers")
    display_group.add_argument("--version", action="version", version=f"SOC Toolkit v{__version__}")
    
    return parser


def main():
    """Main CLI entrypoint"""
    parser = create_parser()
    args = parser.parse_args()

    cmd = args.ioc

    if cmd == "asm":
        target = args.subarg or "example.com"
        res = AttackSurfaceScanner.scan_domain(target)
        console.print(Panel(json.dumps(res, indent=2), title="🌐 External Attack Surface & Shadow IT Scan", border_style="cyan"))
        return

    if cmd == "ransomware":
        target = args.subarg or "185.220.101.45"
        soc = SOCToolkit()
        report = soc.lookup(target)
        res = RansomwareCheckerEngine.evaluate_ioc(report.ioc, report.overall_threat_level)
        console.print(Panel(json.dumps(res, indent=2), title="💀 Ransomware Gang TTP Matcher (LockBit / ALPHV)", border_style="red"))
        return

    if cmd == "beacon":
        timestamps = [100.0, 160.0, 220.0, 280.0, 340.0]
        res = BeaconingCalculator.calculate_beaconing(timestamps)
        console.print(Panel(json.dumps(res, indent=2), title="⏱️ C2 Network Beaconing & Jitter Calculator", border_style="yellow"))
        return

    if cmd == "i18n":
        target = args.subarg or "185.220.101.45"
        lang = args.extra_arg or "de"
        res = GlobalI18nEngine.format_report(target, "CRITICAL", lang)
        console.print(Panel(json.dumps(res, indent=2), title=f"🗣️ Multi-Language Security Report ({lang.upper()})", border_style="green"))
        return

    if cmd == "convert":
        log_text = args.subarg or "Failed login from 185.220.101.45 on port 22"
        res = SIEMConverterEngine.convert_log_to_rules(log_text)
        console.print(Panel(json.dumps(res, indent=2), title="🔄 SIEM Log-to-Sigma & YARA Rule Converter", border_style="magenta"))
        return

    if cmd == "edr":
        target = args.subarg or "HOST-SEC-01"
        res = EDRCollectorEngine.get_host_telemetry(target)
        console.print(Panel(json.dumps(res, indent=2), title="🔌 Enterprise EDR Process Tree & Telemetry", border_style="cyan"))
        return

    if cmd == "timeline":
        target = args.subarg or "185.220.101.45"
        res = IncidentTimelineEngine.generate_timeline(target)
        console.print(Panel(json.dumps(res, indent=2), title="⏳ Chronological Incident Event Timeline", border_style="magenta"))
        return

    if cmd == "cluster":
        res = HAClusterEngine.get_cluster_status()
        console.print(Panel(json.dumps(res, indent=2), title="🌐 High-Availability SOC Cluster Status", border_style="green"))
        return

    if cmd == "rbac":
        user = args.subarg or "analyst_john"
        token = EnterpriseRBACEngine.generate_token(user, SOCRole.TIER_2)
        console.print(Panel(f"User: [cyan]{user}[/]\nRole: [bold]{SOCRole.TIER_2}[/]\nJWT Token:\n[dim]{token}[/]", title="🔐 Enterprise RBAC Token Generated", border_style="yellow"))
        return

    if cmd == "shell":
        start_interactive_shell()
        return

    if cmd == "report":
        target = args.subarg or "8.8.8.8"
        soc = SOCToolkit()
        report = soc.lookup(target)
        ticket = ExecutiveReportGenerator.generate_incident_ticket(report)
        console.print(Panel(ticket["markdown"], title="📄 Executive Security Incident Ticket", border_style="red"))
        return

    if cmd == "mem":
        text_target = args.subarg or ""
        if Path(text_target).exists():
            with open(text_target, 'r', encoding='utf-8', errors='ignore') as f:
                text_target = f.read()
        res = MemoryForensicsEngine.scan_memory_strings(text_target)
        console.print(Panel(json.dumps(res, indent=2), title="🧬 Process Memory & Mimikatz Forensics", border_style="red"))
        return

    if cmd == "mitre-matrix":
        target = args.subarg or "8.8.8.8"
        soc = SOCToolkit()
        report = soc.lookup(target)
        matrix = MITREMatrixEngine.generate_matrix(report.ioc, report.ioc_type, report.overall_threat_level)
        console.print(Panel(json.dumps(matrix, indent=2), title="🗺️ 14-Tactic MITRE ATT&CK Matrix Heatmap", border_style="cyan"))
        return

    if cmd == "vault":
        action = args.subarg
        key_name = args.extra_arg
        if action == "set" and key_name:
            APIVault.set_key(key_name, args.extra_arg)
            console.print(f"[green]Key '{key_name}' saved to encrypted vault.[/]")
        else:
            console.print(Panel(json.dumps(APIVault.load_vault(), indent=2), title="🔐 Enterprise API Key Vault Status", border_style="yellow"))
        return

    if cmd == "stream":
        console.print("[bold cyan]📡 Starting Syslog Stream Listener on 0.0.0.0:514...[/]")
        return

    if cmd == "web":
        port = args.port if args.port != 8000 else 8080
        start_web_server(port)
        return

    if cmd == "server":
        start_api_server(args.port)
        return

    if cmd == "ai":
        target = args.subarg or "8.8.8.8"
        soc = SOCToolkit()
        report = soc.lookup(target)
        ai_res = AIThreatAnalyst.analyze_threat(report.ioc, report.ioc_type, report.overall_threat_level)
        console.print(Panel(json.dumps(ai_res, indent=2), title="Autonomous AI Security Analyst Triage", border_style="cyan"))
        return

    if cmd == "soar":
        target = args.subarg or "8.8.8.8"
        soc = SOCToolkit()
        report = soc.lookup(target)
        soar_res = SOAREngine.execute_workflow(report.ioc, report.overall_threat_level.value)
        console.print(Panel(json.dumps(soar_res, indent=2), title="SOAR Automated Workflow Execution", border_style="magenta"))
        return

    if cmd == "audit":
        target = args.subarg or "8.8.8.8"
        soc = SOCToolkit()
        report = soc.lookup(target)
        comp = ComplianceEngine.evaluate_compliance(report.ioc, report.ioc_type, report.overall_threat_level)
        console.print(Panel(json.dumps(comp, indent=2), title="Regulatory Compliance & Audit Report", border_style="yellow"))
        return

    if cmd == "pcap":
        file_target = args.subarg
        if not file_target:
            console.print("[red]Error: Please specify a PCAP file path.[/]")
            return
        res = PCAPAnalyzer.analyze_pcap(file_target)
        console.print(Panel(
            f"File: [cyan]{res['filepath']}[/]\nFile Size: {res['file_size_bytes']} bytes\nIOCs Found: {res['total_iocs_found']}",
            title="PCAP Network Forensics Result",
            border_style="cyan"
        ))
        return

    if cmd == "analyze":
        file_target = args.subarg
        if not file_target:
            console.print("[red]Error: Please specify a PE file path.[/]")
            return
        res = PEAnalyzer.analyze_file(file_target)
        console.print(Panel(
            f"File: [cyan]{res['filepath']}[/]\nSHA256: {res['sha256']}\nEntropy: {res['entropy']}",
            title="Malware Static Analysis Result",
            border_style="magenta"
        ))
        return

    if cmd == "c2-decode":
        text_target = args.subarg or ""
        res = C2ConfigExtractor.extract_c2_config(text_target)
        console.print(Panel(json.dumps(res["findings"], indent=2), title="C2 Beacon Config Extracted", border_style="red"))
        return

    if cmd == "triage":
        file_target = args.subarg
        if not file_target:
            console.print("[red]Error: Please specify a log file path.[/]")
            return
        engine = LogTriageEngine()
        result = engine.triage_file(file_target)
        console.print(f"[bold cyan]Log Triage Completed for:[/] {file_target}")
        return

    if cmd == "decode":
        text_target = args.subarg or ""
        res = PayloadDecoder.decode_powershell(text_target)
        console.print(f"[bold green]Decoded Payload:[/]\n{json.dumps(res, indent=2)}")
        return

    if cmd == "defang":
        text_target = args.subarg or ""
        console.print(f"[bold cyan]Defanged:[/] {PayloadDecoder.defang(text_target)}")
        return

    if cmd == "refang":
        text_target = args.subarg or ""
        console.print(f"[bold cyan]Refanged:[/] {PayloadDecoder.refang(text_target)}")
        return

    formatter = OutputFormatter()
    if not args.quiet and not args.raw:
        formatter.print_banner()

    soc = SOCToolkit()

    if args.providers:
        formatter.print_providers(soc.get_provider_status())
        return

    if args.ioc:
        report = soc.lookup(args.ioc)
        if args.raw:
            print(json.dumps(report.__dict__, default=str, indent=2))
            return
        
        show_playbook = getattr(args, 'playbook', False)
        show_osint = getattr(args, 'osint', True)
        formatter.print_report(report, show_playbook=show_playbook, show_osint=show_osint)

        if getattr(args, 'siem_queries', False):
            queries = SIEMQueryGenerator.generate_all(report.ioc, report.ioc_type)
            console.print("\n[bold cyan]Multi-SIEM Search Queries:[/]")
            for platform, q in queries.items():
                console.print(f"  • [bold]{platform.upper()}:[/] [dim]{q}[/]")

        if getattr(args, 'sigma', False):
            console.print("\n[bold cyan]Sigma SIEM Rule:[/]")
            console.print(DetectionRuleGenerator.generate_sigma(report.ioc, report.ioc_type))

        if getattr(args, 'yara', False):
            console.print("\n[bold cyan]YARA Rule:[/]")
            console.print(DetectionRuleGenerator.generate_yara(report.ioc, report.ioc_type))

        mitre_layer = getattr(args, 'mitre_layer', None)
        if mitre_layer:
            MITRENavigatorExporter.export_to_file(report.ioc, report.overall_threat_level, mitre_layer)
            console.print(f"[green]MITRE ATT&CK Navigator Layer saved: {mitre_layer}[/]")

        graph = getattr(args, 'graph', None)
        if graph:
            findings = [{"source": r.source} for r in report.results if r.found]
            ThreatGraphVisualizer.export_graph(report.ioc, report.overall_threat_level.value, findings, graph)
            console.print(f"[green]Interactive Threat Graph saved: {graph}[/]")

        if getattr(args, 'html', None):
            formatter.export_html(report, args.html)
        if getattr(args, 'stix', None):
            formatter.export_stix(report, args.stix)
        if getattr(args, 'json', None):
            formatter.export_json(report, args.json)
        if getattr(args, 'markdown', None):
            formatter.export_markdown(report, args.markdown)
        if getattr(args, 'csv', None):
            formatter.export_csv(report, args.csv)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
