"""phantom/cli/commands/red.py — `phantom red <target>`"""
from __future__ import annotations
import asyncio
from typing import Optional
import click
from cli.ui import error, info, warn, section
from core import session as db


@click.command("red")
@click.argument("target")
@click.option("--scope", "-s", multiple=True, help="In-scope patterns (e.g. *.example.com)")
@click.option("--resume", "-r", default=None, help="Resume session by ID prefix")
@click.option("--phase", "-p", default="all",
              type=click.Choice(["all", "recon", "vulnscan", "fuzz"]),
              help="Run specific phase only")
def red_cmd(target: str, scope: tuple, resume: Optional[str], phase: str) -> None:
    """Full red team engagement — OSINT → Footprint → Vuln Scan → Fuzz → AI Analysis."""
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
        scope_list = list(scope) if scope else [target, f"*.{target}"]
        sess = db.create_session(target=target, mode="red", scope=scope_list)
        info(f"New session: {sess.id[:8]}…  Target: {target}")

    from agents.red_agent import run_full, run_recon_phase, run_vuln_scan_phase, run_fuzzing_phase
    import json

    async def _run():
        if phase == "all":
            await run_full(sess)
        elif phase == "recon":
            section("Recon Phase")
            r = await run_recon_phase(sess.target, sess.id)
            info(f"Done: {json.loads(r)['findings_added']} findings")
        elif phase == "vulnscan":
            section("Vuln Scan Phase")
            r = await run_vuln_scan_phase(sess.target, sess.id)
            info(f"Done: {json.loads(r)['findings_added']} findings")
        elif phase == "fuzz":
            section("Fuzzing Phase")
            r = await run_fuzzing_phase(sess.target, sess.id)
            info(f"Done: {json.loads(r)['findings_added']} endpoints")

    asyncio.run(_run())
