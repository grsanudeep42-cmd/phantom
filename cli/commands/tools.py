"""
phantom/cli/commands/tools.py

Tool registry commands.
phantom tools list
phantom tools status
phantom tools update [tool_id]
"""
from __future__ import annotations

import asyncio

import click

from cli.ui import error, info, success, tools_table, warn


@click.group("tools")
def tools_cmd() -> None:
    """Manage the tool registry."""
    pass


@tools_cmd.command("list")
def list_cmd() -> None:
    """List all tools in the manifest."""
    from registry.loader import list_tools
    tools = list_tools()
    info(f"[bold]{len(tools)} tools[/bold] registered in manifest\n")
    for t in tools:
        tags = "  ".join(f"[dim]{tag}[/dim]" for tag in t.get("tags", []))
        from cli.ui import console
        console.print(f"  [cyan]{t['id']:<20}[/cyan] [yellow]{t['category']:<15}[/yellow]  {t['description'][:60]}")


@tools_cmd.command("status")
def status_cmd() -> None:
    """Check which tools are installed and at what version."""
    info("Checking tool statuses (this may take a few seconds)…\n")
    from registry.loader import get_all_tool_statuses
    statuses = get_all_tool_statuses()
    tools_table(statuses)

    missing = [t for t in statuses if t["status"] == "missing"]
    outdated = [t for t in statuses if t["status"] == "outdated"]
    ok_count = len(statuses) - len(missing) - len(outdated)
    info(f"\n✔ {ok_count} ok  ⚠ {len(outdated)} outdated  ✖ {len(missing)} missing")

    if missing or outdated:
        info("Run [bold]phantom tools update[/bold] to install/update all tools on demand.")


@tools_cmd.command("update")
@click.argument("tool_id", required=False, default=None)
def update_cmd(tool_id: str) -> None:
    """Update all cached tools (or a specific one)."""

    async def _do_update() -> None:
        from registry.updater import check_and_update
        if tool_id:
            info(f"Updating {tool_id}…")
        else:
            info("Checking all cached tools for updates…")

        results = await check_and_update(tool_id)

        if not results:
            warn("No cached tools to update. Install tools first by running phantom scan or phantom red.")
            return

        for r in results:
            if r.updated:
                success(f"{r.tool_id}: {r.old_version} → {r.new_version}")
            elif r.error:
                error(f"{r.tool_id}: {r.error}")
            else:
                from cli.ui import step
                step(f"{r.tool_id}: already up to date ({r.new_version})")

    asyncio.run(_do_update())
