#!/usr/bin/env python3
"""
SOC Toolkit CLI v5.0.0 Ultimate Enterprise - Mandatory Security Platform
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich import box

from . import __version__
from .core import SOCToolkit
from .detectors import IOCDetector, IOCType
from .formatter import OutputFormatter, THREAT_ICONS, THREAT_COLORS
from .config import Config
from .extractor import IOCExtractor, ExtractionResult
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


console = Console()


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    
    parser = argparse.ArgumentParser(
        prog="soc",
        description="🛡️ Enterprise SOC Toolkit v5.0.0 Ultimate - Mandatory Threat Intel & Incident Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  soc 185.220.101.45                    # IP lookup
  soc audit 185.220.101.45               # PCI-DSS & ISO 27001 Compliance Audit
  soc server --port 8000                 # Start Enterprise Production REST API Server
  soc pcap network.pcap                 # Parse PCAP & extract Threat Intel IOCs
  soc analyze sample.exe                # Static PE Malware Analysis & ImpHash
  soc triage firewall.log                # Perform automated log triage
  soc web                               # Start local Cyber Web GUI Dashboard

Author: Furkan Dinçer (@frkndncr)
GitHub: https://github.com/frkndncr/soc-toolkit
        """
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommands")

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
    web_parser = subparsers.add_parser("web", help="Start local Cyber Web GUI Dashboard")
    web_parser.add_argument("--port", type=int, default=8080, help="Web server port (default: 8080)")

    # Positional argument
    parser.add_argument("ioc", nargs="?", help="IOC to lookup (IP, domain, hash, URL)")
    
    # Input options
    input_group = parser.add_argument_group("Input Options")
    input_group.add_argument("-f", "--file", metavar="FILE", help="File containing IOCs (one per line)")
    input_group.add_argument("-t", "--type", choices=["ip", "domain", "url", "md5", "sha1", "sha256", "email"], help="Force IOC type")
    
    # Output options
    output_group = parser.add_argument_group("Output & Export Options")
    output_group.add_argument("--json", metavar="FILE", help="Export report to JSON file")
    output_group.add_argument("--md", "--markdown", metavar="FILE", dest="markdown", help="Export report to Markdown file")
    output_group.add_argument("--csv", metavar="FILE", help="Export report to CSV file")
    output_group.add_argument("--html", metavar="FILE", help="Export interactive HTML report")
    output_group.add_argument("--stix", metavar="FILE", help="Export STIX 2.1 JSON Bundle")
    
    # SOC Features
    soc_group = parser.add_argument_group("Enterprise Features")
    soc_group.add_argument("--compliance", action="action_true" if False else "store_true", help="Generate Compliance Audit Report")
    soc_group.add_argument("--playbook", action="store_true", help="Generate Incident Response Playbook")
    soc_group.add_argument("--sigma", action="store_true", help="Generate Sigma SIEM Rule")
    soc_group.add_argument("--yara", action="store_true", help="Generate YARA Rule")
    soc_group.add_argument("--siem-queries", action="store_true", help="Generate Splunk/Elastic/Sentinel queries")
    soc_group.add_argument("--osint", action="store_true", help="Display OSINT investigation links")
    soc_group.add_argument("--web", action="store_true", help="Start Web GUI Dashboard")

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

    # Subcommand routing
    if args.subcommand == "server":
        port = getattr(args, "port", 8000)
        start_api_server(port)
        return

    if args.subcommand == "web" or args.web:
        port = getattr(args, "port", 8080)
        start_web_server(port)
        return

    if args.subcommand == "audit" or args.compliance:
        target_ioc = args.ioc if hasattr(args, 'ioc') and args.ioc else getattr(args, 'target', '185.220.101.45')
        soc = SOCToolkit()
        report = soc.lookup(target_ioc)
        comp = ComplianceEngine.evaluate_compliance(report.ioc, report.ioc_type, report.overall_threat_level)
        console.print(Panel(json.dumps(comp, indent=2), title="📜 Regulatory Compliance & Audit Report", border_style="yellow"))
        return

    if args.subcommand == "pcap":
        res = PCAPAnalyzer.analyze_pcap(args.file)
        console.print(Panel(
            f"File: [cyan]{res['filepath']}[/]\nFile Size: {res['file_size_bytes']} bytes\nIOCs Found: {res['total_iocs_found']}\nIPs: {len(res['ips'])}\nDomains: {len(res['domains'])}",
            title="📦 PCAP Network Forensics Result",
            border_style="cyan"
        ))
        return

    if args.subcommand == "analyze":
        res = PEAnalyzer.analyze_file(args.file)
        console.print(Panel(
            f"File: [cyan]{res['filepath']}[/]\nPE Executable: {res['is_pe_executable']}\nSHA256: {res['sha256']}\nEntropy: {res['entropy']}\nSuspicious APIs: {', '.join(res['suspicious_apis_detected']) if res['suspicious_apis_detected'] else 'None'}",
            title="🔬 Malware Static Analysis Result",
            border_style="magenta"
        ))
        return

    if args.subcommand == "c2-decode":
        res = C2ConfigExtractor.extract_c2_config(args.text)
        if res["has_c2_indicators"]:
            console.print(Panel(json.dumps(res["findings"], indent=2), title="🎯 C2 Beacon Config Extracted", border_style="red"))
        else:
            console.print("[yellow]No known C2 beacon signatures matched.[/]")
        return

    if args.subcommand == "triage":
        engine = LogTriageEngine()
        result = engine.triage_file(args.file)
        console.print(f"[bold cyan]🪵 Log Triage Completed for:[/] {args.file}")
        console.print(f"📊 Total IOCs Extracted: [bold]{result['total_iocs_extracted']}[/]")
        console.print(f"🔴 Critical Threats Found: [bold red]{result['critical_threats_count']}[/]\n")
        return

    if args.subcommand == "decode":
        res = PayloadDecoder.decode_powershell(args.text)
        if res["found"]:
            for payload in res["payloads"]:
                console.print(f"[bold green]🔓 Decoded Payload:[/]\n{payload.get('decoded')}")
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
        if args.raw:
            print(json.dumps(report.__dict__, default=str, indent=2))
            return
        formatter.print_report(report, show_playbook=args.playbook, show_osint=args.osint)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
