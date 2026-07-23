#!/usr/bin/env python3
"""
SOC Toolkit CLI v4.0.0 NextGen - Deep Cyber Threat Hunting & Forensics Workbench
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
from rich.prompt import Prompt, Confirm
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


console = Console()


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    
    parser = argparse.ArgumentParser(
        prog="soc",
        description="🛡️ Enterprise SOC Toolkit v4.0.0 NextGen - Threat Hunting, Forensics & Malware Analysis Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  soc 185.220.101.45                    # IP lookup
  soc 185.220.101.45 --siem-queries    # Generate Splunk/Elastic/Sentinel queries
  soc 185.220.101.45 --mitre-layer L.json # Export MITRE ATT&CK Navigator Layer
  soc 185.220.101.45 --graph graph.html # Export Interactive Threat Relationship Graph
  soc pcap network.pcap                 # Parse PCAP & extract Threat Intel IOCs
  soc analyze sample.exe                # Static PE Malware Analysis & ImpHash
  soc c2-decode "watermark=12345"       # Decode Cobalt Strike / AsyncRAT C2 Config
  soc triage firewall.log                # Perform automated log triage
  soc web                               # Start local Cyber Web GUI Dashboard

Author: Furkan Dinçer (@frkndncr)
GitHub: https://github.com/frkndncr/soc-toolkit
        """
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommands")

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
    input_group.add_argument("-e", "--extract", metavar="FILE", help="Extract IOCs from log file")
    
    # Output options
    output_group = parser.add_argument_group("Output & Export Options")
    output_group.add_argument("--json", metavar="FILE", help="Export report to JSON file")
    output_group.add_argument("--md", "--markdown", metavar="FILE", dest="markdown", help="Export report to Markdown file")
    output_group.add_argument("--csv", metavar="FILE", help="Export report to CSV file")
    output_group.add_argument("--html", metavar="FILE", help="Export interactive HTML report")
    output_group.add_argument("--stix", metavar="FILE", help="Export STIX 2.1 JSON Bundle")
    output_group.add_argument("--mitre-layer", metavar="FILE", help="Export MITRE ATT&CK Navigator Layer JSON")
    output_group.add_argument("--graph", metavar="FILE", help="Export Interactive Threat Graph HTML")
    
    # Threat Hunting Features
    soc_group = parser.add_argument_group("Threat Hunting & Forensics Features")
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
    display_group.add_argument("--brief", action="store_true", help="Show brief summary only")
    display_group.add_argument("--providers", action="store_true", help="List available providers")
    display_group.add_argument("--version", action="version", version=f"SOC Toolkit v{__version__}")
    
    return parser


def main():
    """Main CLI entrypoint"""
    parser = create_parser()
    args = parser.parse_args()

    # Subcommand routing
    if args.subcommand == "web" or args.web:
        port = getattr(args, "port", 8080)
        start_web_server(port)
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
            f"File: [cyan]{res['filepath']}[/]\nPE Executable: {res['is_pe_executable']}\nSHA256: {res['sha256']}\nEntropy: {res['entropy']} ({'PACKED/ENCRYPTED' if res['is_likely_packed'] else 'Normal'})\nSuspicious APIs: {', '.join(res['suspicious_apis_detected']) if res['suspicious_apis_detected'] else 'None'}",
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
        
        for threat in result["top_critical_threats"]:
            console.print(Panel(
                f"IOC: [cyan]{threat['ioc']}[/]\nType: {threat['type']}\nThreat Level: [red]{threat['threat_level']}[/]\nSummary: {threat['summary']}",
                title="🔴 Critical Incident",
                border_style="red"
            ))
        return

    if args.subcommand == "decode":
        res = PayloadDecoder.decode_powershell(args.text)
        if res["found"]:
            for payload in res["payloads"]:
                console.print(f"[bold green]🔓 Decoded Payload:[/]\n{payload.get('decoded')}")
        else:
            console.print("[yellow]No encoded payload detected.[/]")
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

    # Single IOC Lookup
    if args.ioc:
        report = soc.lookup(args.ioc)
        
        if args.raw:
            print(json.dumps(report.__dict__, default=str, indent=2))
            return

        formatter.print_report(report, show_playbook=args.playbook, show_osint=args.osint)

        if args.siem_queries:
            queries = SIEMQueryGenerator.generate_all(report.ioc, report.ioc_type)
            console.print("\n[bold cyan]🔍 Multi-SIEM Search Queries:[/]")
            for platform, q in queries.items():
                console.print(f"  • [bold]{platform.upper()}:[/] [dim]{q}[/]")

        if args.sigma:
            console.print("\n[bold cyan]📜 Sigma SIEM Rule:[/]")
            console.print(DetectionRuleGenerator.generate_sigma(report.ioc, report.ioc_type))

        if args.yara:
            console.print("\n[bold cyan]📜 YARA Rule:[/]")
            console.print(DetectionRuleGenerator.generate_yara(report.ioc, report.ioc_type))

        if args.mitre_layer:
            MITRENavigatorExporter.export_to_file(report.ioc, report.overall_threat_level, args.mitre_layer)
            console.print(f"[green]✅ MITRE ATT&CK Navigator Layer saved: {args.mitre_layer}[/]")

        if args.graph:
            findings = [{"source": r.source} for r in report.results if r.found]
            ThreatGraphVisualizer.export_graph(report.ioc, report.overall_threat_level.value, findings, args.graph)
            console.print(f"[green]✅ Interactive Threat Graph saved: {args.graph}[/]")

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
