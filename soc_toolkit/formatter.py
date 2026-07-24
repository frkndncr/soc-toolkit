"""
Output formatting and export for SOC Toolkit v6.0.0
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
from .playbook import PlaybookGenerator
from .osint import OSINTLinksGenerator


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
        self.console = Console(legacy_windows=False)
        
    def _safe_print(self, msg: str):
        try:
            self.console.print(msg)
        except Exception:
            try:
                print(msg.encode('ascii', 'ignore').decode('ascii'))
            except Exception:
                pass

    def print_banner(self):
        """Print minimalist tool banner"""
        self._safe_print(f"\n[bold cyan]🛡️ SOC Toolkit v{Config.VERSION}[/] [dim]| Global Enterprise Security Platform[/]\n")
        
    def print_report(self, report: IOCReport, show_playbook: bool = False, show_osint: bool = True, clean_mode: bool = False):
        """Print formatted report to console"""
        
        header_text = Text()
        header_text.append("🔍 IOC: ", style="bold")
        header_text.append(f"{report.ioc}\n", style="cyan bold")
        header_text.append("📋 Type: ", style="bold")
        header_text.append(f"{report.ioc_type.value.upper()}\n", style="magenta")
        header_text.append("🕐 Time: ", style="bold")
        header_text.append(f"{report.timestamp}\n", style="dim")
        
        icon = THREAT_ICONS.get(report.overall_threat_level, "⚪")
        color = THREAT_COLORS.get(report.overall_threat_level, "white")
        header_text.append(f"\n{icon} ", style="bold")
        header_text.append(f"{report.overall_threat_level.value} - ", style=f"{color}")
        
        found_sources = [r for r in report.results if r.found]
        if report.overall_threat_level == ThreatLevel.CLEAN:
            header_text.append("No threats detected\n", style="green")
        else:
            header_text.append(f"Threat detected across {len(found_sources)} sources\n", style="bold red")
            
        header_text.append(f"📊 Found in {len(found_sources)}/{len(report.results)} sources", style="dim")

        self._safe_print(Panel(header_text, title="📊 IOC Analysis Report", border_style=color.split()[0]))
        
        table = Table(
            title="🔎 Source Results", 
            box=box.ROUNDED, 
            show_header=True, 
            header_style="bold magenta"
        )
        table.add_column("Source", style="cyan", width=16)
        table.add_column("Status", width=10)
        table.add_column("Threat", width=12)
        table.add_column("Details", style="dim", max_width=45)
        table.add_column("Time", width=8, justify="right")
        
        for result in report.results:
            if clean_mode and result.error and "API key required" in result.error:
                continue

            if result.error:
                status = "[red]❌ Error[/]"
            elif result.found:
                status = "[green]✅ Found[/]"
            else:
                status = "[dim]⚪ None[/]"
                
            icon = THREAT_ICONS.get(result.threat_level, "⚪")
            color = THREAT_COLORS.get(result.threat_level, "white")
            threat_str = f"[{color}]{icon} {result.threat_level.value.title()}[/]"
            
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
            time_str = f"{result.response_time:.2f}s" if result.response_time else "-"
            table.add_row(result.source, status, threat_str, details_str, time_str)
            
        self._safe_print(table)
        
        if show_osint:
            links = OSINTLinksGenerator.get_links(report.ioc, report.ioc_type)
            if links:
                self._safe_print("\n[bold cyan]🔗 OSINT INVESTIGATION LINKS[/]")
                for name, url in links.items():
                    self._safe_print(f"  • [bold]{name}:[/] [dim underline]{url}[/]")

        if show_playbook or report.overall_threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            playbook = PlaybookGenerator.generate(report.ioc, report.ioc_type, report.overall_threat_level)
            self._safe_print("\n" + str(Panel(
                playbook.to_markdown(),
                title="[bold red]🛡️ Incident Response Playbook[/]",
                border_style="red"
            )))

    def export_html(self, report: IOCReport, filepath: Union[str, Path]):
        """Export report to single-file interactive HTML report"""
        links = OSINTLinksGenerator.get_links(report.ioc, report.ioc_type)
        playbook = PlaybookGenerator.generate(report.ioc, report.ioc_type, report.overall_threat_level)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SOC Report - {report.ioc}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 30px; line-height: 1.5; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        h1, h2, h3 {{ color: #58a6ff; }}
        .badge {{ padding: 4px 10px; border-radius: 12px; font-weight: bold; font-size: 14px; display: inline-block; }}
        .badge-CRITICAL {{ background: #da3633; color: white; }}
        .badge-HIGH {{ background: #d96f00; color: white; }}
        .badge-CLEAN {{ background: #238636; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ border: 1px solid #30363d; padding: 10px; text-align: left; }}
        th {{ background: #21262d; color: #8b949e; }}
        a {{ color: #58a6ff; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>🛡️ SOC Threat Intelligence Report</h1>
        <p><strong>IOC:</strong> <code>{report.ioc}</code> | <strong>Type:</strong> {report.ioc_type.value.upper()}</p>
        <p><strong>Threat Level:</strong> <span class="badge badge-{report.overall_threat_level.value.upper()}">{report.overall_threat_level.value.upper()}</span></p>
        <p>{report.summary}</p>
    </div>

    <div class="card">
        <h2>🔗 OSINT Investigation Links</h2>
        <ul>
"""
        for name, url in links.items():
            html += f'            <li><a href="{url}" target="_blank">{name}</a></li>\n'
        html += """        </ul>
    </div>

    <div class="card">
        <h2>🔎 Source Lookup Results</h2>
        <table>
            <tr><th>Provider</th><th>Found</th><th>Threat Level</th><th>Response Time</th></tr>
"""
        for r in report.results:
            found_str = "✅ Yes" if r.found else "⚪ No"
            html += f'            <tr><td>{r.source}</td><td>{found_str}</td><td>{r.threat_level.value}</td><td>{r.response_time:.2f}s</td></tr>\n'

        html += f"""        </table>
    </div>

    <div class="card">
        <h2>🛡️ Incident Response Containment Playbook</h2>
        <div>{playbook.to_markdown().replace('\n', '<br>')}</div>
    </div>
</body>
</html>"""

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        self._safe_print(f"[green]HTML Report saved: {filepath}[/]")

    def export_stix(self, report: IOCReport, filepath: Union[str, Path]):
        """Export report to STIX 2.1 JSON Bundle"""
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{hash(report.ioc) & 0xffffffff:08x}-1111-2222-3333-444444444444",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{hash(report.ioc) & 0xffffffff:08x}-1111-2222-3333-444444444444",
                    "created": report.timestamp,
                    "modified": report.timestamp,
                    "name": f"SOC Toolkit Finding - {report.ioc}",
                    "indicator_types": ["malicious-activity"],
                    "pattern": f"[{report.ioc_type.value}:value = '{report.ioc}']",
                    "pattern_type": "stix",
                    "valid_from": report.timestamp
                }
            ]
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(stix_bundle, f, indent=2)
        self._safe_print(f"[green]STIX 2.1 Bundle saved: {filepath}[/]")

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
            
        self._safe_print(f"[green]Report saved: {filepath}[/]")
        
    def export_markdown(self, report: IOCReport, filepath: Union[str, Path]):
        """Export report to Markdown file"""
        md = f"""# 🔍 IOC Analysis Report - {report.ioc}

| Field | Value |
|-------|-------|
| **IOC** | `{report.ioc}` |
| **Type** | {report.ioc_type.value.upper()} |
| **Time** | {report.timestamp} |
| **Threat Level** | {report.overall_threat_level.value.upper()} |

{report.summary}
"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md)
        self._safe_print(f"[green]Markdown report saved: {filepath}[/]")

    def export_csv(self, report: IOCReport, filepath: Union[str, Path]):
        """Export report to CSV file"""
        import csv
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IOC', 'Type', 'Source', 'Found', 'Threat Level', 'Response Time'])
            for result in report.results:
                writer.writerow([
                    report.ioc,
                    report.ioc_type.value,
                    result.source,
                    result.found,
                    result.threat_level.value,
                    f"{result.response_time:.2f}"
                ])
        self._safe_print(f"[green]CSV report saved: {filepath}[/]")
