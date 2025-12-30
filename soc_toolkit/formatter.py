"""
Output formatting and export for SOC Toolkit
"""

import json
from enum import Enum
from pathlib import Path
from typing import Union

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .enums import ThreatLevel, IOCReport, LookupResult
from .config import Config


# Threat level styling
THREAT_COLORS = {
    ThreatLevel.CLEAN: "green",
    ThreatLevel.LOW: "blue",
    ThreatLevel.MEDIUM: "yellow",
    ThreatLevel.HIGH: "orange1",
    ThreatLevel.CRITICAL: "red bold",
    ThreatLevel.UNKNOWN: "white"
}

THREAT_ICONS = {
    ThreatLevel.CLEAN: "🟢",
    ThreatLevel.LOW: "🔵",
    ThreatLevel.MEDIUM: "🟡",
    ThreatLevel.HIGH: "🟠",
    ThreatLevel.CRITICAL: "🔴",
    ThreatLevel.UNKNOWN: "⚪"
}


class OutputFormatter:
    """Format and display results"""
    
    def __init__(self):
        self.console = Console()
        
    def print_banner(self):
        """Print tool banner"""
        banner = """
[bold cyan]
███████╗ ██████╗  ██████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝██╔═══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
███████╗██║   ██║██║            ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
╚════██║██║   ██║██║            ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
███████║╚██████╔╝╚██████╗       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
╚══════╝ ╚═════╝  ╚═════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
[/]
[dim]SOC Analyst Workbench v{version} | github.com/frkndncr/soc-toolkit[/]
        """.format(version=Config.VERSION)
        self.console.print(banner)
        
    def print_report(self, report: IOCReport):
        """Print formatted report to console"""
        
        # Header panel
        header_text = Text()
        header_text.append("🔍 IOC: ", style="bold")
        header_text.append(f"{report.ioc}\n", style="cyan bold")
        header_text.append("📋 Type: ", style="bold")
        header_text.append(f"{report.ioc_type.value.upper()}\n", style="magenta")
        header_text.append("🕐 Time: ", style="bold")
        header_text.append(f"{report.timestamp}\n", style="dim")
        header_text.append(f"\n{report.summary}", 
                         style=THREAT_COLORS.get(report.overall_threat_level, "white"))
        
        self.console.print(Panel(
            header_text, 
            title="[bold white]📊 IOC Analysis Report[/]", 
            border_style="cyan", 
            box=box.DOUBLE
        ))
        
        # Results table
        table = Table(
            title="🔎 Source Results", 
            box=box.ROUNDED, 
            show_header=True, 
            header_style="bold magenta"
        )
        table.add_column("Source", style="cyan", width=15)
        table.add_column("Status", width=12)
        table.add_column("Threat", width=12)
        table.add_column("Details", style="dim", max_width=45)
        table.add_column("Time", width=8, justify="right")
        
        for result in report.results:
            # Status
            if result.error:
                status = "[red]❌ Error[/]"
            elif result.found:
                status = "[green]✅ Found[/]"
            else:
                status = "[dim]⚪ None[/]"
                
            # Threat level
            icon = THREAT_ICONS.get(result.threat_level, "⚪")
            color = THREAT_COLORS.get(result.threat_level, "white")
            threat_str = f"[{color}]{icon} {result.threat_level.value.title()}[/]"
            
            # Details
            details = []
            if result.error:
                details.append(result.error[:40])
            elif result.data:
                for key, value in list(result.data.items())[:3]:
                    if value and value != "N/A" and value != []:
                        if isinstance(value, list):
                            value = ", ".join(str(v) for v in value[:3])
                        details.append(f"{key}: {str(value)[:25]}")
                        
            details_str = " | ".join(details) if details else "-"
            
            # Response time
            time_str = f"{result.response_time:.2f}s" if result.response_time else "-"
            
            table.add_row(result.source, status, threat_str, details_str, time_str)
            
        self.console.print(table)
        
        # Detailed findings for malicious
        malicious_results = [
            r for r in report.results 
            if r.found and r.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        ]
        
        if malicious_results:
            self.console.print("\n[bold red]⚠️  THREAT DETAILS[/]\n")
            
            for result in malicious_results:
                detail_table = Table(
                    title=f"[bold]{result.source}[/]", 
                    box=box.SIMPLE, 
                    show_header=False
                )
                detail_table.add_column("Field", style="cyan", width=20)
                detail_table.add_column("Value", style="white")
                
                for key, value in result.data.items():
                    if value and value != "N/A":
                        if isinstance(value, list):
                            value = ", ".join(str(v) for v in value)
                        detail_table.add_row(key, str(value))
                        
                self.console.print(detail_table)
                self.console.print()

    def print_providers(self, providers: dict):
        """Print provider status table"""
        table = Table(
            title="🔌 Available Providers", 
            box=box.ROUNDED,
            show_header=True
        )
        table.add_column("Provider", style="cyan")
        table.add_column("API Key", width=12)
        table.add_column("Status", width=10)
        table.add_column("Supported Types", style="dim")
        
        for name, info in providers.items():
            if info["requires_api_key"]:
                if info["has_api_key"]:
                    api_status = "[green]✓ Set[/]"
                else:
                    api_status = "[yellow]⚠ Required[/]"
            else:
                api_status = "[dim]Free[/]"
                
            status = "[green]✓ Ready[/]" if info["enabled"] else "[red]✗ Disabled[/]"
            types = ", ".join(info["supported_types"])
            
            table.add_row(name, api_status, status, types)
            
        self.console.print(table)
                
    def export_json(self, report: IOCReport, filepath: Union[str, Path]):
        """Export report to JSON file"""
        
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
            
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(serialize(report), f, indent=2, ensure_ascii=False)
            
        self.console.print(f"[green]✅ Report saved: {filepath}[/]")
        
    def export_markdown(self, report: IOCReport, filepath: Union[str, Path]):
        """Export report to Markdown file"""
        
        md = f"""# 🔍 IOC Analysis Report

## Summary

| Field | Value |
|-------|-------|
| **IOC** | `{report.ioc}` |
| **Type** | {report.ioc_type.value.upper()} |
| **Time** | {report.timestamp} |
| **Threat Level** | {THREAT_ICONS.get(report.overall_threat_level, '')} {report.overall_threat_level.value.upper()} |

{report.summary}

---

## 📊 Source Results

| Source | Status | Threat | Time |
|--------|--------|--------|------|
"""
        
        for result in report.results:
            status = "✅" if result.found else ("❌" if result.error else "⚪")
            icon = THREAT_ICONS.get(result.threat_level, "⚪")
            threat = f"{icon} {result.threat_level.value}"
            time_str = f"{result.response_time:.2f}s" if result.response_time else "-"
            md += f"| {result.source} | {status} | {threat} | {time_str} |\n"
            
        md += "\n---\n\n## 📋 Detailed Findings\n\n"
        
        for result in report.results:
            if result.found and result.data:
                md += f"### {result.source}\n\n"
                md += "| Field | Value |\n|-------|-------|\n"
                for key, value in result.data.items():
                    if value and value != "N/A":
                        if isinstance(value, list):
                            value = ", ".join(str(v) for v in value[:5])
                        md += f"| {key} | {value} |\n"
                md += "\n"
                
        md += f"""
---

*Report generated by SOC Toolkit v{Config.VERSION}*  
*https://github.com/frkndncr/soc-toolkit*
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md)
            
        self.console.print(f"[green]✅ Markdown report saved: {filepath}[/]")

    def export_csv(self, report: IOCReport, filepath: Union[str, Path]):
        """Export report to CSV file"""
        import csv
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IOC', 'Type', 'Source', 'Found', 'Threat Level', 'Response Time', 'Details'])
            
            for result in report.results:
                details = json.dumps(result.data) if result.data else ""
                writer.writerow([
                    report.ioc,
                    report.ioc_type.value,
                    result.source,
                    result.found,
                    result.threat_level.value,
                    f"{result.response_time:.2f}",
                    details
                ])
                
        self.console.print(f"[green]✅ CSV report saved: {filepath}[/]")
