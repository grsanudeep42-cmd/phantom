"""phantom/cli/commands/monitor.py — `phantom monitor` subcommand group"""
from __future__ import annotations

import asyncio
import click
from cli.ui import error, info, section, success, warn


@click.group("monitor")
def monitor_cmd() -> None:
    """Continuous change-detection — diff subdomains, endpoints, tech stack, ports."""


@monitor_cmd.command("add")
@click.argument("target")
def monitor_add_cmd(target: str) -> None:
    """Register a target for continuous monitoring."""
    from agents.monitor_agent import monitor_add
    monitor_add(target)
    success(f"Target added for monitoring: {target}")
    info("Run `phantom monitor run` to start a diff scan.")


@monitor_cmd.command("run")
@click.argument("target", required=False)
@click.option("--session", "-s", default="", help="Session ID to record findings into")
def monitor_run_cmd(target: str | None, session: str) -> None:
    """Run a change-detection scan and print the diff."""
    from agents.monitor_agent import monitor_list
    targets = [target] if target else [row["target"] for row in monitor_list()]
    if not targets:
        warn("No monitored targets. Use `phantom monitor add <target>` first.")
        return

    async def _run():
        from agents.monitor_agent import phantom_monitor_run
        for t in targets:
            section(f"Monitor scan: {t}")
            diff = await phantom_monitor_run(t, session)
            if diff.has_changes():
                success(diff.summary())
                if diff.new_subdomains:
                    info(f"New subdomains ({len(diff.new_subdomains)}): " + ", ".join(diff.new_subdomains[:5]))
                if diff.new_endpoints:
                    info(f"New endpoints ({len(diff.new_endpoints)}): " + ", ".join(diff.new_endpoints[:5]))
                if diff.stack_changes:
                    info(f"Stack changes: " + ", ".join(diff.stack_changes[:5]))
                if diff.new_ports:
                    info(f"New ports: " + ", ".join(diff.new_ports[:10]))
                if diff.takeover_candidates:
                    from cli.ui import console
                    console.print(f"  [bold red]⚠ Takeover candidates:[/bold red] " + ", ".join(diff.takeover_candidates))
            else:
                info(f"No changes detected since last scan.")

    asyncio.run(_run())


@monitor_cmd.command("list")
def monitor_list_cmd() -> None:
    """List all registered monitoring targets."""
    from agents.monitor_agent import monitor_list
    targets = monitor_list()
    if not targets:
        info("No monitored targets registered.")
        info("Use `phantom monitor add <target>` to add one.")
        return
    section(f"Monitored Targets ({len(targets)})")
    for row in targets:
        info(f"  {row['target']}  [dim]last run: {row.get('last_run', 'never')}[/dim]")


@monitor_cmd.command("diff")
@click.argument("target")
def monitor_diff_cmd(target: str) -> None:
    """Run a diff for a single target and display detailed output."""
    async def _run():
        from agents.monitor_agent import phantom_monitor_run
        section(f"Diff: {target}")
        diff = await phantom_monitor_run(target)
        from cli.ui import console
        console.print_json(diff.to_json())

    asyncio.run(_run())
