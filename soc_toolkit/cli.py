#!/usr/bin/env python3
"""
SOC Toolkit CLI v6.0.0 Military & Enterprise Security Suite
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime

# Reconfigure stdout/stderr for Windows UTF-8 compatibility
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


console = Console(legacy_windows=False)

SUBCOMMANDS = {
    "shell", "ai", "soar", "server", "audit", "pcap",
    "analyze", "c2-decode", "triage", "decode", "defang", "refang", "web"
}


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    
    parser = argparse.ArgumentParser(
        prog="soc",
        description="SOC Toolkit v6.0.0 - Autonomous AI Threat Intelligence & Cyber Warfare Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  soc 185.220.101.45                    # IP lookup
  soc 185.220.101.45 --playbook         # Show Incident Response Playbook
  soc shell                             # Launch Interactive Threat Analyst Terminal Shell
  soc ai 185.220.101.45                 # Autonomous AI Triage & Cyber Kill Chain Attribution
  soc soar 185.220.101.45               # Trigger Automated SOAR Workflow Playbook
  soc audit 185.220.101.45               # PCI-DSS & ISO 27001 Compliance Audit
  soc server --port 8000                 # Start Enterprise Production REST API Server
  soc pcap network.pcap                 # Parse PCAP & extract Threat Intel IOCs
  soc analyze sample.exe                # Static PE Malware Analysis & ImpHash
  soc web                               # Start local 3D Cyber Web GUI Dashboard

Author: Furkan Dinçer (@frkndncr)
GitHub: https://github.com/frkndncr/soc-toolkit
        """
    )
    
    parser.add_argument("ioc", nargs="?", help="IOC to lookup (IP, domain, hash, URL) or subcommand")
    parser.add_argument("subarg", nargs="?", help="Secondary argument for subcommands (e.g., target IOC or file path)")

    # Output options
    output_group = parser.add_argument_group("Output & Export Options")
    output_group.add_argument("--json", metavar="FILE", help="Export report to JSON file")
    output_group.add_argument("--md", "--markdown", metavar="FILE", dest="markdown", help="Export report to Markdown file")
    output_group.add_argument("--csv", metavar="FILE", help="Export report to CSV file")
    output_group.add_argument("--html", metavar="FILE", help="Export interactive HTML report")
    output_group.add_argument("--stix", metavar="FILE", help="Export STIX 2.1 JSON Bundle")
    output_group.add_argument("--mitre-layer", metavar="FILE", help="Export MITRE ATT&CK Navigator Layer JSON")
    output_group.add_argument("--graph", metavar="FILE", help="Export Interactive Threat Graph HTML")
    
    # SOC Features
    soc_group = parser.add_argument_group("Enterprise & Threat Hunting Features")
    soc_group.add_argument("--playbook", action="store_true", help="Generate Incident Response Playbook")
    soc_group.add_argument("--sigma", action="store_true", help="Generate Sigma SIEM Rule")
    soc_group.add_argument("--yara", action="store_true", help="Generate YARA Rule")
    soc_group.add_argument("--siem-queries", action="store_true", help="Generate Splunk/Elastic/Sentinel queries")
    soc_group.add_argument("--osint", action="store_true", help="Display OSINT investigation links")
    soc_group.add_argument("--port", type=int, default=8000, help="Port for server/web")

    # Display options
    display_group = parser.add_argument_group("Display Options")
    display_group.add_argument("-q", "--quiet", action="store_true", help="Suppress banner")
    display_group.add_argument("--raw", action="store_true", help="Output raw JSON")
    display_group.add_argument("--brief", action="store_true", help="Show brief summary only")
    display_group.add_argument("--providers", action="store_true", help="List available providers")
    display_group.add_argument("--version", action="version", version=f"SOC Toolkit v{__version__}")
    
    return parser


def main():
    """Main CLI entrypoint"""
    parser = create_parser()
    args = parser.parse_args()

    cmd = args.ioc

    if cmd == "shell":
        start_interactive_shell()
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
        formatter.print_report(report, show_playbook=args.playbook, show_osint=args.osint)

        if args.siem_queries:
            queries = SIEMQueryGenerator.generate_all(report.ioc, report.ioc_type)
            console.print("\n[bold cyan]Multi-SIEM Search Queries:[/]")
            for platform, q in queries.items():
                console.print(f"  • [bold]{platform.upper()}:[/] [dim]{q}[/]")

        if args.sigma:
            console.print("\n[bold cyan]Sigma SIEM Rule:[/]")
            console.print(DetectionRuleGenerator.generate_sigma(report.ioc, report.ioc_type))

        if args.yara:
            console.print("\n[bold cyan]YARA Rule:[/]")
            console.print(DetectionRuleGenerator.generate_yara(report.ioc, report.ioc_type))

        if args.mitre_layer:
            MITRENavigatorExporter.export_to_file(report.ioc, report.overall_threat_level, args.mitre_layer)
            console.print(f"[green]MITRE ATT&CK Navigator Layer saved: {args.mitre_layer}[/]")

        if args.graph:
            findings = [{"source": r.source} for r in report.results if r.found]
            ThreatGraphVisualizer.export_graph(report.ioc, report.overall_threat_level.value, findings, args.graph)
            console.print(f"[green]Interactive Threat Graph saved: {args.graph}[/]")

        if args.html:
            formatter.export_html(report, args.html)
        if args.stix:
            formatter.export_stix(report, args.stix)
        if args.json:
            formatter.export_json(report, args.json)
        if args.markdown:
            formatter.export_markdown(report, args.markdown)
        if args.csv:
            formatter.export_csv(report, args.csv)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
