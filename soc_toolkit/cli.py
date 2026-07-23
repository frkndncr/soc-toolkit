#!/usr/bin/env python3
"""
SOC Toolkit CLI v3.0.0 - Main command line interface
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


console = Console()


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    
    parser = argparse.ArgumentParser(
        prog="soc",
        description="🛡️ Enterprise SOC Toolkit v3.0.0 - Threat Intelligence & Incident Response Workbench",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  soc 185.220.101.45                    # IP lookup
  soc evil.com                           # Domain lookup  
  soc 44d88612fea8a8f36de82e1278abb02f  # Hash lookup
  soc https://malware.site/payload      # URL lookup
  soc 185.220.101.45 --playbook         # Show Incident Response Playbook
  soc 185.220.101.45 --html report.html # Export interactive HTML report
  soc 185.220.101.45 --stix stix.json   # Export STIX 2.1 JSON Bundle
  soc 185.220.101.45 --sigma            # Generate Sigma SIEM Rule
  soc triage firewall.log                # Perform full automated log triage
  soc decode "powershell -enc aGVsbG8=" # Decode obfuscated command
  soc defang "https://evil.com"         # Defang URL
  soc web                               # Start local Cyber Web GUI Dashboard

Author: Furkan Dinçer (@frkndncr)
GitHub: https://github.com/frkndncr/soc-toolkit
        """
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommands")

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
    input_group.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    input_group.add_argument("--stdin", action="store_true", help="Read IOCs from stdin")
    
    # Output options
    output_group = parser.add_argument_group("Output & Export Options")
    output_group.add_argument("--json", metavar="FILE", help="Export report to JSON file")
    output_group.add_argument("--md", "--markdown", metavar="FILE", dest="markdown", help="Export report to Markdown file")
    output_group.add_argument("--csv", metavar="FILE", help="Export report to CSV file")
    output_group.add_argument("--html", metavar="FILE", help="Export interactive HTML report")
    output_group.add_argument("--stix", metavar="FILE", help="Export STIX 2.1 JSON Bundle")
    
    # SOC Features
    soc_group = parser.add_argument_group("SOC Incident Response Features")
    soc_group.add_argument("--playbook", action="store_true", help="Generate Incident Response Playbook")
    soc_group.add_argument("--sigma", action="store_true", help="Generate Sigma SIEM Rule")
    soc_group.add_argument("--yara", action="store_true", help="Generate YARA Rule")
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

        if args.sigma:
            console.print("\n[bold cyan]📜 Sigma SIEM Rule:[/]")
            console.print(DetectionRuleGenerator.generate_sigma(report.ioc, report.ioc_type))

        if args.yara:
            console.print("\n[bold cyan]📜 YARA Rule:[/]")
            console.print(DetectionRuleGenerator.generate_yara(report.ioc, report.ioc_type))

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
