"""
Next-Gen Interactive Analyst Shell Environment for SOC Toolkit v7.0.1
Provides full SOC analyst command center prompt, session tracking, side-by-side comparison,
direct SOAR firewall blocking, and AI Threat CTI Q&A.
"""

import json
import difflib
from pathlib import Path
from typing import List, Dict, Any

from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns

from .core import SOCToolkit
from .formatter import OutputFormatter
from .config import Config
from .sanitizer import IOCSanitizer
from .ai_analyst import AIThreatAnalyst
from .enums import ThreatLevel, IOCType
from .soar import SOAREngine
from .edr_collector import EDRCollectorEngine


class InteractiveShell:
    """Enterprise SOC Analyst Interactive Shell Console"""

    def __init__(self):
        self.console = Console(legacy_windows=False)
        self.formatter = OutputFormatter()
        self.soc = SOCToolkit()
        self.session_history: List[Dict[str, Any]] = []
        self.clean_mode: bool = True

    def _safe_print(self, msg: Any):
        try:
            self.console.print(msg)
        except Exception:
            try:
                print(str(msg).encode('ascii', 'ignore').decode('ascii'))
            except Exception:
                pass

    def print_help(self):
        table = Table(title="SOC Shell Command Guide", border_style="cyan", show_header=True)
        table.add_column("Command", style="bold yellow", width=25)
        table.add_column("Description", style="white")
        table.add_row("<ioc>", "Instant threat lookup on IP, Domain, Hash, or URL")
        table.add_row("compare <ioc1> <ioc2>", "Side-by-side threat comparison between 2 targets")
        table.add_row("block <ioc>", "Generate instant firewall ban rules (Palo Alto, Fortinet, IPTables)")
        table.add_row("isolate <host>", "Execute EDR host isolation workflow")
        table.add_row("ask <question>", "AI Threat Analyst CTI Q&A inside shell")
        table.add_row("export-session [file.html]", "Export all shift investigations into HTML/JSON report")
        table.add_row("session / history", "List all IOCs investigated in current session")
        table.add_row("toggle-clean", "Toggle hiding unconfigured API key error rows")
        table.add_row("clear", "Clear terminal screen")
        table.add_row("exit / quit", "Exit SOC Shell")
        self._safe_print(table)

    def run_compare(self, ioc1: str, ioc2: str):
        self._safe_print(f"[bold cyan]Comparing IOCs:[/] [bold]{ioc1}[/] vs [bold]{ioc2}[/]\n")
        r1 = self.soc.lookup(ioc1)
        r2 = self.soc.lookup(ioc2)

        panel1 = Panel(
            f"Type: {r1.ioc_type.value.upper()}\nThreat: [{r1.overall_threat_level.value}] {r1.overall_threat_level.value}[/]\nFound: {len([r for r in r1.results if r.found])}/{len(r1.results)} sources",
            title=f"IOC: {r1.ioc}",
            border_style="red" if r1.overall_threat_level == ThreatLevel.CRITICAL else "green"
        )
        panel2 = Panel(
            f"Type: {r2.ioc_type.value.upper()}\nThreat: [{r2.overall_threat_level.value}] {r2.overall_threat_level.value}[/]\nFound: {len([r for r in r2.results if r.found])}/{len(r2.results)} sources",
            title=f"IOC: {r2.ioc}",
            border_style="red" if r2.overall_threat_level == ThreatLevel.CRITICAL else "green"
        )
        self._safe_print(Columns([panel1, panel2]))

    def run_block(self, ioc: str):
        rules = {
            "Palo Alto CLI": f"set rulebase security rules BLOCK-{ioc} to any from any source {ioc} action drop",
            "Fortinet FortiOS": f"config firewall address\n edit BLOCK-{ioc}\n set subnet {ioc}/32\nend",
            "Windows Firewall": f"netsh advfirewall firewall add rule name=\"BLOCK-{ioc}\" dir=in action=block remoteip={ioc}",
            "Linux IPTables": f"iptables -A INPUT -s {ioc} -j DROP"
        }
        self._safe_print(Panel(json.dumps(rules, indent=2), title=f"Multi-Vendor Firewall Ban Rules ({ioc})", border_style="red"))

    def export_session(self, filepath: str = "soc_session_report.html"):
        if not self.session_history:
            self._safe_print("[yellow]No IOCs investigated in current session yet.[/]")
            return

        out_path = Path(filepath)
        data = {
            "session_total_iocs": len(self.session_history),
            "investigations": self.session_history
        }

        if out_path.suffix == ".json":
            out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        else:
            rows = ""
            for item in self.session_history:
                rows += f"<tr><td>{item['ioc']}</td><td>{item['type']}</td><td>{item['threat']}</td><td>{item['time']}</td></tr>"

            html = f"""<!DOCTYPE html>
<html>
<head><title>SOC Analyst Shift Session Report</title>
<style>body{{font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;}} table{{width:100%;border-collapse:collapse;}} th,td{{border:1px solid #30363d;padding:8px;text-align:left;}} th{{background:#161b22;color:#58a6ff;}}</style>
</head>
<body>
<h1>SOC Analyst Shift Session Report</h1>
<p>Total Indicators Investigated: {len(self.session_history)}</p>
<table><thead><tr><th>IOC</th><th>Type</th><th>Threat Level</th><th>Timestamp</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""
            out_path.write_text(html, encoding="utf-8")

        self._safe_print(f"[bold green]Session report exported successfully to: [cyan]{out_path.resolve()}[/][/]")

    def start(self):
        """Start interactive shell loop"""
        self.formatter.print_banner()
        self.console.print("[bold green]Welcome to Next-Gen SOC Analyst Command Center Shell v7.0.1[/]")
        self.console.print("Type an IOC to analyze, 'help' for command guide, or 'exit' to quit.\n")

        commands = ["help", "compare", "block", "isolate", "ask", "export-session", "session", "history", "clear", "toggle-clean", "exit", "quit"]

        while True:
            try:
                raw = Prompt.ask("[bold cyan]soc-shell>[/]").strip()
                if not raw:
                    continue

                parts = raw.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd in ("exit", "quit", "q"):
                    self.console.print("[yellow]Exiting SOC Analyst Shell. Stay vigilant![/]")
                    break

                if cmd == "clear":
                    self.console.clear()
                    continue

                if cmd == "help":
                    self.print_help()
                    continue

                if cmd == "toggle-clean":
                    self.clean_mode = not self.clean_mode
                    state = "ENABLED (Hiding unconfigured API key error rows)" if self.clean_mode else "DISABLED (Showing all raw rows)"
                    self.console.print(f"[yellow]Clean Display Mode: {state}[/]")
                    continue

                if cmd in ("session", "history"):
                    if not self.session_history:
                        self.console.print("[yellow]No IOCs investigated in current session.[/]")
                    else:
                        table = Table(title="📜 Current Session Investigation History", border_style="cyan")
                        table.add_column("IOC", style="bold cyan")
                        table.add_column("Type", style="magenta")
                        table.add_column("Threat", style="red")
                        table.add_column("Timestamp", style="dim")
                        for item in self.session_history:
                            table.add_row(item["ioc"], item["type"], item["threat"], item["time"])
                        self.console.print(table)
                    continue

                if cmd == "compare" and len(args) >= 2:
                    self.run_compare(args[0], args[1])
                    continue

                if cmd == "block" and len(args) >= 1:
                    self.run_block(args[0])
                    continue

                if cmd == "isolate" and len(args) >= 1:
                    res = EDRCollectorEngine.get_host_telemetry(args[0])
                    self.console.print(Panel(json.dumps(res, indent=2), title=f"🔌 EDR Host Containment Telemetry ({args[0]})", border_style="red"))
                    continue

                if cmd == "ask" and len(args) >= 1:
                    question = " ".join(args)
                    res = AIThreatAnalyst.analyze_threat(question, IOCType.IP, ThreatLevel.HIGH)
                    self.console.print(Panel(json.dumps(res, indent=2), title="🤖 AI Threat CTI Assistant Answer", border_style="cyan"))
                    continue

                if cmd == "export-session":
                    filepath = args[0] if args else "soc_session_report.html"
                    self.export_session(filepath)
                    continue

                # Fuzzy Command Correction
                if cmd not in commands:
                    fuzzy = difflib.get_close_matches(cmd, commands, n=1, cutoff=0.8)
                    if fuzzy and len(raw.split()) == 1:
                        cmd = fuzzy[0]
                        self.console.print(f"[yellow]💡 Auto-correcting to '{cmd}'...[/]\n")

                # Default IOC Lookup
                sanitized_target = IOCSanitizer.sanitize(raw)
                report = self.soc.lookup(sanitized_target)
                self.formatter.print_report(report, clean_mode=self.clean_mode)

                self.session_history.append({
                    "ioc": report.ioc,
                    "type": report.ioc_type.value.upper(),
                    "threat": report.overall_threat_level.value,
                    "time": report.timestamp
                })

            except (KeyboardInterrupt, EOFError):
                self.console.print("\n[yellow]Exiting SOC Analyst Shell.[/]")
                break


def start_interactive_shell():
    """Start interactive threat hunting shell console"""
    shell = InteractiveShell()
    shell.start()
