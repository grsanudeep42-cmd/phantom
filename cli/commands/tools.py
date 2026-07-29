"""
phantom/cli/commands/tools.py

Tool registry commands.
phantom tools list [--category]
phantom tools status
phantom tools update [tool_id] [--force] [--all]
phantom tools search <query>
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
@click.option("--category", "-c", default="", help="Filter by category")
def list_cmd(category: str) -> None:
    """List all tools in the manifest."""
    from registry.loader import list_tools
    from cli.ui import console

    tools = list_tools()
    if category:
        tools = [t for t in tools if t.get("category") == category]
    info(f"[bold]{len(tools)} tools[/bold] registered in manifest\n")
    for t in tools:
        console.print(
            f"  [cyan]{t['id']:<22}[/cyan] "
            f"[yellow]{t['category']:<14}[/yellow]  "
            f"{t['description'][:65]}"
        )


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
@click.option("--force", "-f", is_flag=True, default=False,
              help="Force reinstall even if already up to date.")
@click.option("--all", "update_all", is_flag=True, default=False,
              help="Ensure every tool in the manifest is installed and current.")
def update_cmd(tool_id: str, force: bool, update_all: bool) -> None:
    """Update cached tools. Use --force to reinstall, --all to cover full manifest."""

    async def _do_update() -> None:
        from registry.updater import check_and_update

        if tool_id:
            info(f"{'Reinstalling' if force else 'Updating'} {tool_id}…")
        elif update_all:
            info(f"{'Reinstalling' if force else 'Updating'} ALL tools in manifest…")
        else:
            info("Checking cached tools for updates…")

        results = await check_and_update(tool_id, force_reinstall=force)

        if not results and update_all:
            # Nothing cached yet — ensure every manifest tool is installed
            from registry.loader import list_tools, ensure_tool

            all_tools = list_tools()
            info(f"Installing all {len(all_tools)} manifest tools…")
            for spec in all_tools:
                r = await ensure_tool(spec["id"])
                if r.available:
                    success(f"{r.tool_id}: {r.version} ({r.install_method})")
                else:
                    error(f"{r.tool_id}: {r.error}")
            return

        if not results:
            warn(
                "No cached tools to update. "
                "Install tools first by running phantom scan or phantom red, "
                "or use --all to force-install everything."
            )
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


@tools_cmd.command("search")
@click.argument("query")
def search_cmd(query: str) -> None:
    """Search tools by name, description, tag, or category."""
    from registry.loader import list_tools
    from cli.ui import console

    q = query.lower()
    tools = list_tools()
    matched = [
        t for t in tools
        if q in t["id"].lower()
        or q in t.get("description", "").lower()
        or any(q in tag for tag in t.get("tags", []))
        or q in t.get("category", "").lower()
    ]

    if not matched:
        warn(f"No tools matched '{query}'")
        return

    info(f"[bold]{len(matched)} result(s)[/bold] for '[cyan]{query}[/cyan]'\n")
    for t in matched:
        tags = "  ".join(f"[dim]{tag}[/dim]" for tag in t.get("tags", []))
        console.print(
            f"  [cyan]{t['id']:<22}[/cyan] "
            f"[yellow]{t['category']:<14}[/yellow]  "
            f"{t['description'][:65]}"
        )
        if tags:
            console.print(f"  {'':22}  {tags}")
        console.print()
