"""
phantom/cli/main.py

Entry point: the `phantom` CLI command.
Registers all sub-commands. Handles `phantom init`.
"""
from __future__ import annotations

import sys
from pathlib import Path

import click
from dotenv import load_dotenv

from cli.ui import console, error, info, print_banner, section, step, success, warn

load_dotenv()


@click.group()
@click.version_option(version="0.1.0", prog_name="phantom")
def cli() -> None:
    """PHANTOM — AI-powered penetration testing agent."""
    pass


# ── Sub-commands ──────────────────────────────────────────────────────────────

from cli.commands.scan import scan_cmd
from cli.commands.red import red_cmd
from cli.commands.blue import blue_cmd
from cli.commands.report import report_cmd
from cli.commands.sessions import sessions_cmd
from cli.commands.tools import tools_cmd
from cli.commands.identity import identity_cmd

cli.add_command(scan_cmd)
cli.add_command(red_cmd)
cli.add_command(blue_cmd)
cli.add_command(report_cmd)
cli.add_command(sessions_cmd)
cli.add_command(tools_cmd)
cli.add_command(identity_cmd)


# ── phantom init ──────────────────────────────────────────────────────────────

@cli.command("init")
def init_cmd() -> None:
    """First-run setup — create dirs, check Docker, validate API keys."""
    print_banner()
    section("PHANTOM Init")
    from config.settings import settings

    # 1. Create data directories
    step("Creating data directories…")
    settings.ensure_dirs()
    success(f"Data dir: {settings.data_dir}")

    # 2. Init SQLite DB
    step("Initialising database…")
    from core.session import init_db
    init_db()
    success(f"Database: {settings.db_path}")

    # 3. Validate API keys
    step("Checking API keys…")
    errors = settings.validate()
    if errors:
        for e in errors:
            warn(f"  Missing: {e}")
        warn("Set keys in .env or environment variables. See config/.env.example")
    else:
        success("ANTHROPIC_API_KEY found")

    # 4. Check Docker
    step("Checking Docker availability…")
    import shutil
    if shutil.which("docker"):
        success("Docker found — tool isolation enabled")
    else:
        warn("Docker not found — tools will run as subprocesses (less isolated)")
        info("Install Docker for better isolation: https://docs.docker.com/get-docker/")

    # 5. Check Go (needed for some tools)
    step("Checking Go…")
    if shutil.which("go"):
        success("Go found — nuclei, subfinder, httpx, ffuf can be installed")
    else:
        warn("Go not found — some tools (nuclei, subfinder, httpx, ffuf) won't auto-install")
        info("Install Go: https://go.dev/doc/install")

    # 6. Check .env.example
    env_example = Path(__file__).parent.parent / "config" / ".env.example"
    if not (Path.cwd() / ".env").exists():
        info(f"No .env found. Copy from: {env_example}")
        info("  cp config/.env.example .env && nano .env")

    section("Init Complete")
    success("PHANTOM is ready. Run [bold]phantom scan <target>[/bold] to start.")
    info("Docs: https://github.com/grsanudeep42-cmd/phantom")


# ── Grey team command ─────────────────────────────────────────────────────────

@cli.command("grey")
@click.argument("target")
@click.option("--scope", "-s", multiple=True)
@click.option("--resume", "-r", default=None)
def grey_cmd(target: str, scope: tuple, resume) -> None:
    """Bug bounty / OSCP-style engagement — no blind exploitation."""
    import asyncio
    from core import session as db

    if resume:
        all_sessions = db.list_sessions()
        matched = [s for s in all_sessions if s.id.startswith(resume)]
        if not matched:
            error(f"No session found: {resume}")
            raise SystemExit(1)
        sess = matched[0]
    else:
        scope_list = list(scope) if scope else [target, f"*.{target}"]
        sess = db.create_session(target=target, mode="grey", scope=scope_list)
        info(f"New session: {sess.id[:8]}…  Target: {target}")

    from agents.grey_agent import run_full
    asyncio.run(run_full(sess))


# ── Beginner mode ─────────────────────────────────────────────────────────────

@cli.command("learn")
@click.argument("target")
@click.option("--scope", "-s", multiple=True)
def learn_cmd(target: str, scope: tuple) -> None:
    """Beginner mode — every step is explained as it runs."""
    import asyncio
    from core import session as db

    scope_list = list(scope) if scope else [target, f"*.{target}"]
    sess = db.create_session(target=target, mode="beginner", scope=scope_list)
    info(f"New beginner session: {sess.id[:8]}…  Target: {target}")

    from agents.beginner_agent import run_full
    asyncio.run(run_full(sess))


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    """Adds project root to sys.path so imports work, then runs CLI."""
    project_root = Path(__file__).parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    cli()


if __name__ == "__main__":
    main()
