"""
output/term.py — All terminal output for ADReaper v2.
"""

from rich.console import Console
from rich.rule    import Rule
from rich         import box
from rich.text    import Text


class Term:
    def __init__(self, no_color=False):
        self.console = Console(highlight=False, no_color=no_color)

    def banner(self, text: str):
        self.console.print(f"[bold red]{text}[/bold red]")

    def phase(self, title: str):
        self.console.print()
        self.console.print(Rule(f"[bold cyan]{title}[/bold cyan]", style="cyan"))

    def section(self, title: str):
        self.console.print()
        self.console.print(Rule(f"[bold white]{title}[/bold white]", style="dim white"))

    def rule(self, title: str = ""):
        self.console.print(Rule(f"[dim]{title}[/dim]", style="dim"))

    def spacer(self):
        self.console.print()

    # Status messages
    def info(self, msg: str):
        self.console.print(f"  [dim white][*][/dim white] {msg}")

    def success(self, msg: str):
        self.console.print(f"  [bold green][+][/bold green] {msg}")

    def warn(self, msg: str):
        self.console.print(f"  [yellow][!][/yellow] {msg}")

    def error(self, msg: str):
        self.console.print(f"  [bold red][-][/bold red] {msg}")

    def skip(self, msg: str):
        self.console.print(f"  [dim][~][/dim] [dim]{msg}[/dim]")

    def finding(self, msg: str):
        self.console.print(f"  [bold yellow][FIND][/bold yellow] {msg}")

    def highlight(self, msg: str):
        self.console.print(f"[bold green]{msg}[/bold green]")

    # Command display — shown before each shell command runs
    def cmd(self, command: str):
        self.console.print()
        self.console.print(f"  [dim cyan]$[/dim cyan] [cyan]{command}[/cyan]")

    # Raw tool output — streamed line by line
    def raw(self, line: str):
        self.console.print(f"    [dim]{line}[/dim]")

    # Interactive prompt
    def prompt(self, msg: str) -> str:
        self.console.print()
        return self.console.input(f"  [bold white][?][/bold white] {msg} ")
