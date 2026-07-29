"""phantom/cli/commands/blue.py — `phantom blue <target_or_log>`"""
from __future__ import annotations
import asyncio
from typing import Optional
import click
from cli.ui import error, info, section
from core import session as db


@click.command("blue")
@click.argument("target")
@click.option("--log", "-l", default=None, help="Path to a log file to analyse")
@click.option("--siem", default="splunk",
              type=click.Choice(["splunk", "elastic"]),
              help="SIEM format for generated queries")
@click.option("--resume", "-r", default=None, help="Resume session by ID prefix")
def blue_cmd(target: str, log: Optional[str], siem: str, resume: Optional[str]) -> None:
    """Blue team mode — log analysis, hardening checklist, IR playbook, SIEM queries."""
    from dotenv import load_dotenv
    load_dotenv()

    if resume:
        all_sessions = db.list_sessions()
        matched = [s for s in all_sessions if s.id.startswith(resume)]
        if not matched:
            error(f"No session found: {resume}")
            raise SystemExit(1)
        sess = matched[0]
        info(f"Resuming: {sess.id[:8]}… ({sess.target})")
    else:
        sess = db.create_session(target=target, mode="blue", scope=[])
        info(f"New session: {sess.id[:8]}…  Target: {target}")

    from agents.blue_agent import run_full
    asyncio.run(run_full(sess, log_path=log))
