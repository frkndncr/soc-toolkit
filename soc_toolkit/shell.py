"""
Interactive Analyst Shell Environment for SOC Toolkit v6.0.0
Provides continuous threat hunting shell console (`soc shell`).
"""

from rich.console import Console
from rich.prompt import Prompt
from .core import SOCToolkit
from .formatter import OutputFormatter


def start_interactive_shell():
    """Start interactive threat hunting shell console"""
    console = Console()
    formatter = OutputFormatter()
    formatter.print_banner()
    soc = SOCToolkit()

    console.print("[bold green]Welcome to SOC Toolkit Interactive Shell v6.0.0[/]")
    console.print("Type an IOC (IP, domain, hash, URL) to analyze, or 'exit' / 'quit' to close.\n")

    while True:
        try:
            cmd = Prompt.ask("[bold cyan]soc-shell>[/]").strip()
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit", "q"):
                console.print("[yellow]Exiting SOC Shell. Stay safe![/]")
                break
            
            report = soc.lookup(cmd)
            formatter.print_report(report)
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Exiting SOC Shell.[/]")
            break
