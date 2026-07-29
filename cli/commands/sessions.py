"""
phantom/cli/commands/sessions.py

Session management commands.
phantom sessions list
phantom sessions resume <id>
phantom sessions clear <id>
"""
from __future__ import annotations

import click

from cli.ui import console, error, info, sessions_table, success, warn
from core import session as db


@click.group("sessions")
def sessions_cmd() -> None:
    """Manage engagement sessions."""
    pass


@sessions_cmd.command("list")
def list_cmd() -> None:
    """List all sessions."""
    sessions = db.list_sessions()
    if not sessions:
        info("No sessions found. Run [bold]phantom scan <target>[/bold] to start one.")
        return
    sessions_table(sessions)
    info(f"Total: {len(sessions)} session(s)")


@sessions_cmd.command("resume")
@click.argument("session_prefix")
def resume_cmd(session_prefix: str) -> None:
    """Resume a paused or active session (by ID prefix)."""
    all_sessions = db.list_sessions()
    matched = [s for s in all_sessions if s.id.startswith(session_prefix)]
    if not matched:
        error(f"No session found matching: {session_prefix}")
        raise SystemExit(1)
    s = matched[0]
    info(f"Session: {s.id}")
    info(f"Target:  {s.target}")
    info(f"Mode:    {s.mode}")
    info(f"Status:  {s.status}")
    info(f"Started: {s.started_at[:16].replace('T', ' ')} UTC")

    findings = db.get_findings(s.id)
    tried = db.get_tried(s.id)
    hypotheses = db.get_hypotheses(s.id, status="pending")
    info(f"Findings: {len(findings)} | Tried: {len(tried)} | Pending hypotheses: {len(hypotheses)}")

    if findings:
        from cli.ui import findings_table
        findings_table(findings)

    if hypotheses:
        console.rule("[dim] Pending Hypotheses", style="dim")
        for h in hypotheses:
            console.print(
                f"  [cyan]{h.confidence:.0%}[/cyan]  {h.hypothesis}  "
                f"[dim]→ {h.suggested_tool}[/dim]"
            )

    info(f"\nTo continue this session run [bold]phantom red {s.target} --resume {s.id[:8]}[/bold]")


@sessions_cmd.command("clear")
@click.argument("session_prefix")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def clear_cmd(session_prefix: str, yes: bool) -> None:
    """Delete a session and all its data."""
    all_sessions = db.list_sessions()
    matched = [s for s in all_sessions if s.id.startswith(session_prefix)]
    if not matched:
        error(f"No session found matching: {session_prefix}")
        raise SystemExit(1)
    s = matched[0]

    if not yes:
        confirm = click.confirm(
            f"Delete session {s.id[:8]}… ({s.target}, {s.mode})? This cannot be undone."
        )
        if not confirm:
            info("Cancelled.")
            return

    db.delete_session(s.id)
    success(f"Session {s.id[:8]}… deleted.")
