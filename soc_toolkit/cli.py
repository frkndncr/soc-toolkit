#!/usr/bin/env python3
"""
SOC Toolkit CLI v6.0.0 Military & Enterprise Security Suite
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime

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


console = Console()


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    
    parser = argparse.ArgumentParser(
        prog="soc",
        description="🛡️ SOC Toolkit v6.0.0 - Autonomous AI Threat Intelligence & Cyber Warfare Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  soc 185.220.101.45                    # IP lookup with AI Root Cause Analysis
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
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommands")

    # Shell subcommand
    subparsers.add_parser("shell", help="Launch Interactive Analyst Terminal Shell")

    # AI Triage subcommand
    ai_parser = subparsers.add_parser("ai", help="Autonomous AI Root Cause Analysis & Kill Chain Attribution")
    ai_parser.add_argument("ioc", help="IOC to analyze with AI")

    # SOAR subcommand
    soar_parser = subparsers.add_parser("soar", help="Execute Automated SOAR Workflow Playbook")
    soar_parser.add_argument("ioc", help="IOC to trigger SOAR actions")

    # REST API Server subcommand
    server_parser = subparsers.add_parser("server", help="Start Enterprise Production REST API Server")
    server_parser.add_argument("--port", type=int, default=8000, help="API server port (default: 8000)")

    # Audit subcommand
    audit_parser = subparsers.add_parser("audit", help="Generate PCI-DSS / ISO 27001 Compliance Report")
    audit_parser.add_argument("ioc", help="IOC to audit")

    # PCAP subcommand
    pcap_parser = subparsers.add_parser("pcap", help="Parse PCAP network capture file")
    pcap_parser.add_argument("file", help="PCAP / PCAPNG file path")

    # Analyze Malware PE subcommand
    analyze_parser = subparsers.add_parser("analyze", help="Static Malware & PE File Analyzer")
    analyze_parser.add_argument("file", help="Executable / PE binary file path")

    # C2 Decode subcommand
    c2_parser = subparsers.add_parser("c2-decode", help="Extract Cobalt Strike / AsyncRAT C2 config")
    c2_parser.add_argument("text", help="Raw memory dump / string text")

    # Triage subcommand
    triage_parser = subparsers.add_parser("triage", help="Ad-hoc automated log file triage")
    triage_parser.add_argument("file", help="Log file path to triage")

    # Decode subcommand
    decode_parser = subparsers.add_parser("decode", help="Decode Base64 / PowerShell command")
    decode_parser.add_argument("text", help="Encoded text to decode")

    # Defang / Refang subcommands
    defang_parser = subparsers.add_parser("defang", help="Defang IOC")
    defang_parser.add_argument("ioc_str", help="IOC to defang")

    refang_parser = subparsers.add_parser("refang", help="Refang IOC")
    refang_parser.add_argument("ioc_str", help="IOC to refang")

    # Web subcommand
    web_parser = subparsers.add_parser("web", help="Start local 3D Cyber Web GUI Dashboard")
    web_parser.add_argument("--port", type=int, default=8080, help="Web server port (default: 8080)")

    # Positional argument
    parser.add_argument("ioc", nargs="?", help="IOC to lookup (IP, domain, hash, URL)")
    
    # Input options
    input_group = parser.add_argument_group("Input Options")
    input_group.add_argument("-f", "--file", metavar="FILE", help="File containing IOCs (one per line)")
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--json", metavar="FILE", help="Export report to JSON file")
    output_group.add_argument("--html", metavar="FILE", help="Export interactive HTML report")
    output_group.add_argument("--stix", metavar="FILE", help="Export STIX 2.1 JSON Bundle")
    
    # Display options
    display_group = parser.add_argument_group("Display Options")
    display_group.add_argument("-q", "--quiet", action="store_true", help="Suppress banner")
    display_group.add_argument("--raw", action="store_true", help="Output raw JSON")
    display_group.add_argument("--providers", action="store_true", help="List available providers")
    display_group.add_argument("--version", action="version", version=f"SOC Toolkit v{__version__}")
    
    return parser


def main():
    """Main CLI entrypoint"""
    parser = create_parser()
    args = parser.parse_args()

    if args.subcommand == "shell":
        start_interactive_shell()
        return

    if args.subcommand == "ai":
        soc = SOCToolkit()
        report = soc.lookup(args.ioc)
        ai_res = AIThreatAnalyst.analyze_threat(report.ioc, report.ioc_type, report.overall_threat_level)
        console.print(Panel(json.dumps(ai_res, indent=2), title="🤖 Autonomous AI Security Analyst Triage", border_style="cyan"))
        return

    if args.subcommand == "soar":
        soc = SOCToolkit()
        report = soc.lookup(args.ioc)
        soar_res = SOAREngine.execute_workflow(report.ioc, report.overall_threat_level.value)
        console.print(Panel(json.dumps(soar_res, indent=2), title="🔄 SOAR Automated Workflow Execution", border_style="magenta"))
        return

    if args.subcommand == "server":
        port = getattr(args, "port", 8000)
        start_api_server(port)
        return

    if args.subcommand == "web" or hasattr(args, 'web') and args.web:
        port = getattr(args, "port", 8080)
        start_web_server(port)
        return

    if args.subcommand == "audit":
        soc = SOCToolkit()
        report = soc.lookup(args.ioc)
        comp = ComplianceEngine.evaluate_compliance(report.ioc, report.ioc_type, report.overall_threat_level)
        console.print(Panel(json.dumps(comp, indent=2), title="📜 Regulatory Compliance & Audit Report", border_style="yellow"))
        return

    if args.subcommand == "pcap":
        res = PCAPAnalyzer.analyze_pcap(args.file)
        console.print(Panel(
            f"File: [cyan]{res['filepath']}[/]\nFile Size: {res['file_size_bytes']} bytes\nIOCs Found: {res['total_iocs_found']}",
            title="📦 PCAP Network Forensics Result",
            border_style="cyan"
        ))
        return

    if args.subcommand == "analyze":
        res = PEAnalyzer.analyze_file(args.file)
        console.print(Panel(
            f"File: [cyan]{res['filepath']}[/]\nSHA256: {res['sha256']}\nEntropy: {res['entropy']}",
            title="🔬 Malware Static Analysis Result",
            border_style="magenta"
        ))
        return

    if args.subcommand == "c2-decode":
        res = C2ConfigExtractor.extract_c2_config(args.text)
        console.print(Panel(json.dumps(res["findings"], indent=2), title="🎯 C2 Beacon Config Extracted", border_style="red"))
        return

    if args.subcommand == "triage":
        engine = LogTriageEngine()
        result = engine.triage_file(args.file)
        console.print(f"[bold cyan]🪵 Log Triage Completed for:[/] {args.file}")
        return

    if args.subcommand == "decode":
        res = PayloadDecoder.decode_powershell(args.text)
        console.print(f"[bold green]🔓 Decoded Payload:[/]\n{res}")
        return

    if args.subcommand == "defang":
        console.print(f"[bold cyan]Defanged:[/] {PayloadDecoder.defang(args.ioc_str)}")
        return

    if args.subcommand == "refang":
        console.print(f"[bold cyan]Refanged:[/] {PayloadDecoder.refang(args.ioc_str)}")
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
        formatter.print_report(report)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
