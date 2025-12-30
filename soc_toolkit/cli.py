#!/usr/bin/env python3
"""
SOC Toolkit CLI - Main command line interface
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


console = Console()


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    
    parser = argparse.ArgumentParser(
        prog="soc",
        description="🛡️ SOC Toolkit - All-in-One IOC Lookup Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  soc 185.220.101.45                    # IP lookup
  soc evil.com                           # Domain lookup  
  soc 44d88612fea8a8f36de82e1278abb02f  # Hash lookup
  soc https://malware.site/payload      # URL lookup
  soc -f iocs.txt                        # Batch lookup from file
  soc -f iocs.txt -o ./reports/          # Batch with output directory
  soc 1.2.3.4 --json report.json        # Export to JSON
  soc 1.2.3.4 --md report.md            # Export to Markdown
  soc -e firewall.log                    # Extract IOCs from log
  soc -e access.log --analyze            # Extract and analyze IOCs
  soc -i                                 # Interactive mode
  cat urls.txt | soc --stdin             # Read from pipe
  soc --providers                        # List available providers
  soc --config                           # Show configuration

Uninstall:
  pip uninstall soc-toolkit              # Remove package
  rm -rf ~/.soc-toolkit                  # Remove config/cache (optional)

Environment Variables:
  VIRUSTOTAL_API_KEY    VirusTotal API key (free: virustotal.com)
  ABUSEIPDB_API_KEY     AbuseIPDB API key (free: abuseipdb.com)
  OTX_API_KEY           AlienVault OTX API key (free: otx.alienvault.com)

Author: Furkan Dinçer (@frkndncr)
GitHub: https://github.com/frkndncr/soc-toolkit
        """
    )
    
    # Positional argument
    parser.add_argument(
        "ioc", 
        nargs="?", 
        help="IOC to lookup (IP, domain, hash, URL)"
    )
    
    # Input options
    input_group = parser.add_argument_group("Input Options")
    input_group.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="File containing IOCs (one per line)"
    )
    input_group.add_argument(
        "-t", "--type",
        choices=["ip", "domain", "url", "md5", "sha1", "sha256", "email"],
        help="Force IOC type (auto-detected by default)"
    )
    input_group.add_argument(
        "-e", "--extract",
        metavar="FILE",
        help="Extract IOCs from log file (firewall, syslog, etc.)"
    )
    input_group.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactive mode - continuous IOC lookup"
    )
    input_group.add_argument(
        "--stdin",
        action="store_true", 
        help="Read IOCs from stdin (for piping)"
    )
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--json",
        metavar="FILE",
        help="Export report to JSON file"
    )
    output_group.add_argument(
        "--md", "--markdown",
        metavar="FILE",
        dest="markdown",
        help="Export report to Markdown file"
    )
    output_group.add_argument(
        "--csv",
        metavar="FILE",
        help="Export report to CSV file"
    )
    output_group.add_argument(
        "-o", "--output-dir",
        metavar="DIR",
        help="Output directory for batch processing"
    )
    
    # Display options
    display_group = parser.add_argument_group("Display Options")
    display_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner and verbose output"
    )
    display_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    display_group.add_argument(
        "--raw",
        action="store_true",
        help="Output raw JSON to stdout"
    )
    display_group.add_argument(
        "--brief",
        action="store_true",
        help="Show only threat level summary"
    )
    
    # Extract options
    extract_group = parser.add_argument_group("Extract Options")
    extract_group.add_argument(
        "--include-private",
        action="store_true",
        help="Include private/internal IPs in extraction"
    )
    extract_group.add_argument(
        "--analyze",
        action="store_true",
        help="Automatically analyze extracted IOCs"
    )
    extract_group.add_argument(
        "--top",
        type=int,
        default=20,
        metavar="N",
        help="Show top N IOCs per type (default: 20)"
    )
    
    # Enrichment options
    enrich_group = parser.add_argument_group("Enrichment Options")
    enrich_group.add_argument(
        "--whois",
        action="store_true",
        help="Include WHOIS lookup for domains/IPs"
    )
    enrich_group.add_argument(
        "--dns",
        action="store_true",
        help="Include DNS records lookup"
    )
    enrich_group.add_argument(
        "--enrich",
        action="store_true",
        help="Full enrichment (WHOIS + DNS)"
    )
    enrich_group.add_argument(
        "--mitre",
        action="store_true",
        help="Show MITRE ATT&CK technique mappings"
    )
    
    # Info options
    info_group = parser.add_argument_group("Information")
    info_group.add_argument(
        "--providers",
        action="store_true",
        help="List available threat intelligence providers"
    )
    info_group.add_argument(
        "--config",
        action="store_true",
        help="Show current configuration"
    )
    info_group.add_argument(
        "-v", "--version",
        action="version",
        version=f"SOC Toolkit v{__version__}"
    )
    
    return parser


def process_single(toolkit: SOCToolkit, formatter: OutputFormatter, 
                   ioc: str, ioc_type: IOCType = None, args=None) -> dict:
    """Process single IOC lookup"""
    
    if not args.quiet and not args.raw:
        with console.status(f"[bold cyan]🔍 Analyzing {ioc}...[/]"):
            report = toolkit.lookup(ioc, ioc_type)
    else:
        report = toolkit.lookup(ioc, ioc_type)
    
    # Raw JSON output
    if args.raw:
        from enum import Enum
        def serialize(obj):
            if isinstance(obj, Enum):
                return obj.value
            if hasattr(obj, '__dict__'):
                return {k: serialize(v) for k, v in obj.__dict__.items()}
            if isinstance(obj, list):
                return [serialize(i) for i in obj]
            if isinstance(obj, dict):
                return {k: serialize(v) for k, v in obj.items()}
            return obj
        print(json.dumps(serialize(report), indent=2))
        return report
        
    # Print report
    if not args.quiet:
        formatter.print_report(report)
    
    # MITRE ATT&CK Mapping
    if args.mitre:
        try:
            from .mitre import MITREMapper, format_mitre_output
            mapper = MITREMapper()
            
            # Convert report to dict for mapping
            report_data = {
                "ioc": report.ioc,
                "ioc_type": report.ioc_type.value if report.ioc_type else "unknown",
                "results": []
            }
            for r in report.results:
                if r.data:
                    report_data["results"].append(r.data)
            
            mappings = mapper.map_from_report(report_data)
            
            # Also add type-based mappings
            if not mappings and report.ioc_type:
                mappings = mapper.map_from_ioc_type(report.ioc_type, report.overall_threat_level)
            
            if mappings:
                console.print("\n[bold cyan]🎯 MITRE ATT&CK Mapping[/]")
                console.print(format_mitre_output(mappings))
            else:
                console.print("\n[dim]No MITRE ATT&CK techniques mapped[/]")
        except Exception as e:
            console.print(f"[yellow]MITRE mapping error: {e}[/]")
    
    # Enrichment (WHOIS + DNS)
    if args.enrich or args.whois or args.dns:
        try:
            from .enrichment import EnrichmentEngine, format_whois_output, format_dns_output
            engine = EnrichmentEngine()
            
            if args.enrich or args.whois:
                console.print("\n[bold cyan]📋 WHOIS Information[/]")
                whois_result = engine.whois.lookup(report.ioc)
                console.print(format_whois_output(whois_result))
            
            if args.enrich or args.dns:
                if report.ioc_type in [IOCType.DOMAIN, IOCType.IP]:
                    console.print("\n[bold cyan]🌐 DNS Records[/]")
                    dns_result = engine.dns.lookup(report.ioc)
                    console.print(format_dns_output(dns_result))
        except Exception as e:
            console.print(f"[yellow]Enrichment error: {e}[/]")
    
    # Export options
    if args.json:
        formatter.export_json(report, args.json)
    if args.markdown:
        formatter.export_markdown(report, args.markdown)
    if args.csv:
        formatter.export_csv(report, args.csv)
        
    return report


def process_batch(toolkit: SOCToolkit, formatter: OutputFormatter,
                  filepath: str, output_dir: str = None, args=None):
    """Process multiple IOCs from file"""
    
    path = Path(filepath)
    if not path.exists():
        console.print(f"[red]❌ File not found: {filepath}[/]")
        sys.exit(1)
        
    with open(path, 'r', encoding='utf-8') as f:
        iocs = [
            line.strip() for line in f 
            if line.strip() and not line.strip().startswith('#')
        ]
        
    if not iocs:
        console.print("[red]❌ No IOCs found in file[/]")
        sys.exit(1)
        
    console.print(f"[cyan]📋 Processing {len(iocs)} IOCs...[/]\n")
    
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Processing...", total=len(iocs))
        
        for ioc in iocs:
            progress.update(task, description=f"[cyan]Analyzing: {ioc[:40]}...[/]")
            report = toolkit.lookup(ioc)
            results.append(report)
            progress.advance(task)
            
    # Summary
    console.print("\n" + "="*60)
    console.print("[bold]📊 BATCH ANALYSIS SUMMARY[/]")
    console.print("="*60)
    
    threat_counts = {}
    for report in results:
        level = report.overall_threat_level.value
        threat_counts[level] = threat_counts.get(level, 0) + 1
        
    for level, count in sorted(threat_counts.items()):
        console.print(f"  {level.upper()}: {count}")
        
    # Print critical/high threats
    critical = [r for r in results if r.overall_threat_level.value in ['critical', 'high']]
    if critical:
        console.print(f"\n[bold red]⚠️  HIGH/CRITICAL THREATS ({len(critical)}):[/]")
        for r in critical:
            console.print(f"  • {r.ioc} - {r.overall_threat_level.value.upper()}")
    
    # Export if output directory specified
    if output_dir:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Summary JSON
        summary_file = output_path / f"batch_report_{timestamp}.json"
        
        all_data = []
        for report in results:
            all_data.append({
                "ioc": report.ioc,
                "type": report.ioc_type.value,
                "threat_level": report.overall_threat_level.value,
                "summary": report.summary,
                "timestamp": report.timestamp
            })
            
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(all_data, f, indent=2, ensure_ascii=False)
            
        console.print(f"\n[green]✅ Batch report saved: {summary_file}[/]")
        
        # CSV summary
        csv_file = output_path / f"batch_report_{timestamp}.csv"
        import csv
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IOC', 'Type', 'Threat Level', 'Timestamp'])
            for report in results:
                writer.writerow([
                    report.ioc,
                    report.ioc_type.value,
                    report.overall_threat_level.value,
                    report.timestamp
                ])
        console.print(f"[green]✅ CSV summary saved: {csv_file}[/]")


def show_providers(toolkit: SOCToolkit, formatter: OutputFormatter):
    """Show available providers"""
    providers = toolkit.get_provider_status()
    formatter.print_providers(providers)


def show_config():
    """Show current configuration"""
    console.print("\n[bold]⚙️  Configuration[/]\n")
    
    console.print(f"Version: {Config.VERSION}")
    console.print(f"Config file: {Config.CONFIG_FILE}")
    console.print(f"Cache directory: {Config.CACHE_DIR}")
    console.print(f"Request timeout: {Config.TIMEOUT}s")
    console.print(f"Max workers: {Config.MAX_WORKERS}")
    
    console.print("\n[bold]API Keys:[/]")
    keys = [
        ("VIRUSTOTAL_API_KEY", Config.VIRUSTOTAL_API_KEY),
        ("ABUSEIPDB_API_KEY", Config.ABUSEIPDB_API_KEY),
        ("OTX_API_KEY", Config.OTX_API_KEY),
        ("SHODAN_API_KEY", Config.SHODAN_API_KEY),
    ]
    for name, value in keys:
        if value:
            masked = value[:4] + "..." + value[-4:] if len(value) > 8 else "***"
            console.print(f"  {name}: [green]✓ Set[/] ({masked})")
        else:
            console.print(f"  {name}: [yellow]⚠ Not set[/]")


def process_extract(filepath: str, args) -> ExtractionResult:
    """Extract IOCs from log file"""
    
    console.print(f"\n[bold cyan]📂 Extracting IOCs from:[/] {filepath}\n")
    
    try:
        result = IOCExtractor.extract_from_file(
            filepath, 
            include_private_ips=args.include_private
        )
    except FileNotFoundError:
        console.print(f"[red]❌ File not found: {filepath}[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/]")
        sys.exit(1)
    
    # Summary panel
    summary_text = f"""[bold]📊 Extraction Summary[/]
    
📁 Source: {result.source}
🔢 Total IOCs: [cyan]{result.total_iocs}[/]
📋 Unique IOCs: [cyan]{result.unique_iocs}[/]
"""
    console.print(Panel(summary_text, border_style="cyan"))
    
    # Show IOCs by type
    if result.iocs_by_type:
        for ioc_type, iocs in result.iocs_by_type.items():
            if iocs:
                # Create table for this IOC type
                table = Table(
                    title=f"[bold]{ioc_type.upper()}[/] ({len(iocs)} found)",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold magenta"
                )
                table.add_column("#", style="dim", width=4)
                table.add_column("IOC", style="cyan")
                
                # Show top N
                for i, ioc in enumerate(iocs[:args.top], 1):
                    table.add_row(str(i), ioc)
                    
                if len(iocs) > args.top:
                    table.add_row("...", f"[dim]and {len(iocs) - args.top} more[/]")
                    
                console.print(table)
                console.print()
    else:
        console.print("[yellow]⚠ No IOCs found in file[/]")
        
    return result


def interactive_mode(toolkit: SOCToolkit, formatter: OutputFormatter):
    """Run interactive mode"""
    
    console.print("\n[bold green]🔄 Interactive Mode[/]")
    console.print("[dim]Enter IOCs to analyze. Commands: 'exit', 'clear', 'help'[/]\n")
    
    history = []
    
    while True:
        try:
            # Prompt
            user_input = Prompt.ask("[bold cyan]soc>[/]").strip()
            
            if not user_input:
                continue
                
            # Commands
            if user_input.lower() in ['exit', 'quit', 'q']:
                console.print("[dim]Goodbye! 👋[/]")
                break
                
            if user_input.lower() == 'clear':
                console.clear()
                formatter.print_banner()
                console.print("[bold green]🔄 Interactive Mode[/]\n")
                continue
                
            if user_input.lower() == 'help':
                console.print("""
[bold]Commands:[/]
  [cyan]<ioc>[/]        Analyze an IOC (IP, domain, hash, URL)
  [cyan]history[/]     Show analysis history
  [cyan]clear[/]       Clear screen
  [cyan]exit[/]        Exit interactive mode
  
[bold]Examples:[/]
  185.220.101.45
  evil-domain.com
  44d88612fea8a8f36de82e1278abb02f
""")
                continue
                
            if user_input.lower() == 'history':
                if history:
                    table = Table(title="Analysis History", box=box.ROUNDED)
                    table.add_column("#", style="dim", width=4)
                    table.add_column("IOC", style="cyan")
                    table.add_column("Type", style="magenta")
                    table.add_column("Threat", width=12)
                    
                    for i, (ioc, ioc_type, threat) in enumerate(history[-20:], 1):
                        icon = THREAT_ICONS.get(threat, "⚪")
                        color = THREAT_COLORS.get(threat, "white")
                        table.add_row(
                            str(i), 
                            ioc[:40], 
                            ioc_type,
                            f"[{color}]{icon} {threat.value}[/]"
                        )
                    console.print(table)
                else:
                    console.print("[dim]No history yet[/]")
                continue
            
            # Analyze IOC
            with console.status(f"[bold cyan]🔍 Analyzing {user_input}...[/]"):
                report = toolkit.lookup(user_input)
            
            # Add to history
            history.append((
                report.ioc, 
                report.ioc_type.value, 
                report.overall_threat_level
            ))
            
            # Show brief result
            icon = THREAT_ICONS.get(report.overall_threat_level, "⚪")
            color = THREAT_COLORS.get(report.overall_threat_level, "white")
            
            console.print(f"\n[{color}]{icon} {report.overall_threat_level.value.upper()}[/] - {report.ioc}")
            
            # Show key findings
            for result in report.results:
                if result.found and result.threat_level.value in ['high', 'critical']:
                    console.print(f"  └─ [red]{result.source}[/]: {list(result.data.items())[0] if result.data else 'Malicious'}")
            
            console.print()
            
        except KeyboardInterrupt:
            console.print("\n[dim]Use 'exit' to quit[/]")
            continue
        except Exception as e:
            console.print(f"[red]Error: {e}[/]")
            continue


def process_stdin(toolkit: SOCToolkit, formatter: OutputFormatter, args):
    """Process IOCs from stdin"""
    
    console.print("[dim]Reading IOCs from stdin...[/]\n")
    
    iocs = []
    for line in sys.stdin:
        line = line.strip()
        if line and not line.startswith('#'):
            iocs.append(line)
            
    if not iocs:
        console.print("[red]❌ No IOCs received from stdin[/]")
        sys.exit(1)
        
    console.print(f"[cyan]📋 Processing {len(iocs)} IOCs...[/]\n")
    
    for ioc in iocs:
        report = toolkit.lookup(ioc)
        icon = THREAT_ICONS.get(report.overall_threat_level, "⚪")
        color = THREAT_COLORS.get(report.overall_threat_level, "white")
        console.print(f"[{color}]{icon}[/] {ioc} - [{color}]{report.overall_threat_level.value.upper()}[/]")


def main():
    """Main entry point"""
    
    parser = create_parser()
    args = parser.parse_args()
    
    # Initialize
    toolkit = SOCToolkit()
    formatter = OutputFormatter()
    
    # Show banner
    if not args.quiet and not args.raw:
        formatter.print_banner()
    
    # Handle info commands
    if args.providers:
        show_providers(toolkit, formatter)
        return
        
    if args.config:
        show_config()
        return
    
    # Handle extract mode
    if args.extract:
        result = process_extract(args.extract, args)
        
        # Auto-analyze if requested
        if args.analyze and result.iocs_by_type:
            console.print("\n[bold cyan]🔍 Analyzing extracted IOCs...[/]\n")
            
            # Collect analyzable IOCs
            to_analyze = []
            for ioc_type in ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256']:
                if ioc_type in result.iocs_by_type:
                    to_analyze.extend(result.iocs_by_type[ioc_type][:10])  # Top 10 each
            
            if to_analyze:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    task = progress.add_task("Analyzing...", total=len(to_analyze))
                    
                    threats_found = []
                    for ioc in to_analyze:
                        progress.update(task, description=f"[cyan]{ioc[:30]}...[/]")
                        report = toolkit.lookup(ioc)
                        if report.overall_threat_level.value in ['high', 'critical']:
                            threats_found.append(report)
                        progress.advance(task)
                
                # Show threats
                if threats_found:
                    console.print(f"\n[bold red]⚠️  THREATS FOUND ({len(threats_found)})[/]\n")
                    for report in threats_found:
                        icon = THREAT_ICONS.get(report.overall_threat_level, "⚪")
                        console.print(f"  {icon} [bold]{report.ioc}[/] - {report.overall_threat_level.value.upper()}")
                else:
                    console.print("\n[green]✅ No high-risk IOCs detected[/]")
        return
    
    # Handle interactive mode
    if args.interactive:
        interactive_mode(toolkit, formatter)
        return
    
    # Handle stdin
    if args.stdin:
        process_stdin(toolkit, formatter, args)
        return
    
    # Handle batch mode
    if args.file:
        process_batch(toolkit, formatter, args.file, args.output_dir, args)
        return
        
    # Handle single IOC
    if not args.ioc:
        parser.print_help()
        return
        
    # Parse IOC type if specified
    ioc_type = None
    if args.type:
        type_map = {
            "ip": IOCType.IP,
            "domain": IOCType.DOMAIN,
            "url": IOCType.URL,
            "md5": IOCType.HASH_MD5,
            "sha1": IOCType.HASH_SHA1,
            "sha256": IOCType.HASH_SHA256,
            "email": IOCType.EMAIL
        }
        ioc_type = type_map.get(args.type)
    
    # Process
    report = process_single(toolkit, formatter, args.ioc, ioc_type, args)
    
    # Brief mode
    if args.brief:
        icon = THREAT_ICONS.get(report.overall_threat_level, "⚪")
        color = THREAT_COLORS.get(report.overall_threat_level, "white")
        print(f"{icon} {report.ioc} - {report.overall_threat_level.value.upper()}")


if __name__ == "__main__":
    main()
