"""
phantom/cli/ui.py

All terminal output lives here. Rich-powered.
Agents and commands import from here — never use raw print().
"""
from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ─────────────────────────────────────────────────────────────────────────────
# Theme
# ─────────────────────────────────────────────────────────────────────────────

PHANTOM_THEME = Theme({
    "phantom.red":      "bold red",
    "phantom.green":    "bold green",
    "phantom.yellow":   "bold yellow",
    "phantom.cyan":     "bold cyan",
    "phantom.dim":      "dim white",
    "phantom.label":    "bold bright_white",
    "severity.critical":"bold red",
    "severity.high":    "red",
    "severity.medium":  "yellow",
    "severity.low":     "cyan",
    "severity.info":    "dim white",
})

console = Console(theme=PHANTOM_THEME, highlight=False)

SEVERITY_COLORS = {
    "critical": "severity.critical",
    "high":     "severity.high",
    "medium":   "severity.medium",
    "low":      "severity.low",
    "info":     "severity.info",
}


# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
[bold red]
 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
[/bold red]
[dim]  AI-powered pentesting agent — thinks like a senior red teamer[/dim]
"""


def print_banner() -> None:
    console.print(BANNER)


# ─────────────────────────────────────────────────────────────────────────────
# Alerts
# ─────────────────────────────────────────────────────────────────────────────

def info(msg: str) -> None:
    console.print(f"[phantom.cyan]ℹ[/phantom.cyan]  {msg}")


def success(msg: str) -> None:
    console.print(f"[phantom.green]✔[/phantom.green]  {msg}")


def warn(msg: str) -> None:
    console.print(f"[phantom.yellow]⚠[/phantom.yellow]  {msg}")


def error(msg: str) -> None:
    console.print(f"[phantom.red]✖[/phantom.red]  {msg}")


def step(msg: str) -> None:
    console.print(f"[phantom.dim]→[/phantom.dim]  {msg}")


def finding(severity: str, description: str, proof: str = "") -> None:
    color = SEVERITY_COLORS.get(severity.lower(), "severity.info")
    badge = f"[{color}][{severity.upper()}][/{color}]"
    console.print(f"{badge}  {description}")
    if proof:
        console.print(f"[phantom.dim]  └─ {proof[:200]}[/phantom.dim]")


def section(title: str) -> None:
    console.rule(f"[phantom.label] {title} ", style="dim")


# ─────────────────────────────────────────────────────────────────────────────
# Tables
# ─────────────────────────────────────────────────────────────────────────────

def sessions_table(sessions: list) -> None:
    table = Table(
        title="Active Sessions",
        box=box.ROUNDED,
        border_style="dim",
        header_style="bold bright_white",
        show_lines=False,
    )
    table.add_column("ID", style="cyan", no_wrap=True, max_width=12)
    table.add_column("Target", style="white")
    table.add_column("Mode", style="yellow")
    table.add_column("Status", style="green")
    table.add_column("Started", style="dim")

    for s in sessions:
        sid_short = s.id[:8] + "…"
        status_style = {
            "active": "[bold green]active[/bold green]",
            "paused": "[yellow]paused[/yellow]",
            "complete": "[dim]complete[/dim]",
            "error": "[red]error[/red]",
        }.get(s.status, s.status)
        table.add_row(
            sid_short,
            s.target,
            s.mode,
            status_style,
            s.started_at[:16].replace("T", " "),
        )
    console.print(table)


def tools_table(statuses: list[dict]) -> None:
    table = Table(
        title="Tool Registry",
        box=box.ROUNDED,
        border_style="dim",
        header_style="bold bright_white",
    )
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Category", style="yellow")
    table.add_column("Version", style="white")
    table.add_column("Min", style="dim")
    table.add_column("Status")

    for t in statuses:
        status_str = {
            "ok":       "[bold green]✔ ok[/bold green]",
            "outdated": "[yellow]⚠ outdated[/yellow]",
            "missing":  "[red]✖ missing[/red]",
        }.get(t["status"], t["status"])
        table.add_row(
            t["id"],
            t["category"],
            t["version"],
            t["min_version"],
            status_str,
        )
    console.print(table)


def findings_table(findings: list) -> None:
    if not findings:
        info("No findings yet.")
        return
    table = Table(
        title="Findings",
        box=box.ROUNDED,
        border_style="dim",
        header_style="bold bright_white",
        show_lines=True,
    )
    table.add_column("Severity")
    table.add_column("Type", style="cyan")
    table.add_column("Description", style="white", max_width=60)
    table.add_column("Time", style="dim", no_wrap=True)

    for f in findings:
        color = SEVERITY_COLORS.get(f.severity.lower(), "severity.info")
        sev_str = f"[{color}]{f.severity.upper()}[/{color}]"
        table.add_row(
            sev_str,
            f.type,
            f.description,
            f.timestamp[:16].replace("T", " "),
        )
    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# Progress spinner
# ─────────────────────────────────────────────────────────────────────────────

def spinner(description: str = "Working…"):
    """Context manager — use with `with spinner('Running nmap...'):`"""
    return Progress(
        SpinnerColumn(spinner_name="dots", style="phantom.cyan"),
        TextColumn("[phantom.dim]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tool output panel
# ─────────────────────────────────────────────────────────────────────────────

def tool_output_panel(tool_id: str, output: str, exit_code: int, duration: float) -> None:
    status_color = "green" if exit_code == 0 else "red"
    status_icon = "✔" if exit_code == 0 else "✖"
    title = (
        f"[bold]{tool_id}[/bold]  "
        f"[{status_color}]{status_icon} exit {exit_code}[/{status_color}]  "
        f"[dim]{duration:.1f}s[/dim]"
    )
    # Cap displayed output for readability
    display_output = output[:3000] + "\n[dim]… (truncated)[/dim]" if len(output) > 3000 else output
    panel = Panel(
        display_output or "[dim](no output)[/dim]",
        title=title,
        border_style="dim",
        expand=False,
    )
    console.print(panel)
