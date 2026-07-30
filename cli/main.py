"""
phantom/cli/main.py

Entry point: the `phantom` CLI command.
Supports any LLM via --provider, --model, --base-url, --api-key flags.
"""
from __future__ import annotations

import sys
from pathlib import Path

import click
from dotenv import load_dotenv

load_dotenv()


# ─────────────────────────────────────────────────────────────────────────────
# Global LLM option group (available on every command)
# ─────────────────────────────────────────────────────────────────────────────

_LLM_OPTIONS = [
    click.option("--provider", "-P", default=None,
                 type=click.Choice(["anthropic", "openai", "ollama", "openrouter", "custom"]),
                 help="LLM provider (auto-detected if not set)"),
    click.option("--model", "-M", default=None,
                 help="Model name (e.g. gpt-4o, llama3.1, claude-sonnet-4-6)"),
    click.option("--base-url", "-U", "base_url", default=None,
                 help="Custom API base URL (for Ollama or any OpenAI-compat endpoint)"),
    click.option("--api-key", "-K", "api_key", default=None,
                 help="API key override"),
]


def llm_options(func):
    """Decorator that adds --provider/--model/--base-url/--api-key to a command."""
    for option in reversed(_LLM_OPTIONS):
        func = option(func)
    return func


def _apply_llm_config(provider, model, base_url, api_key):
    """Apply CLI LLM overrides to the global LLM config singleton."""
    if any([provider, model, base_url, api_key]):
        from core.llm import LLMConfig, set_config
        cfg = LLMConfig.from_cli(
            provider=provider, model=model,
            base_url=base_url, api_key=api_key,
        )
        set_config(cfg)


# ─────────────────────────────────────────────────────────────────────────────
# Root CLI group
# ─────────────────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(version="0.3.0", prog_name="phantom")
def cli() -> None:
    """PHANTOM — General-purpose AI agent. Security-first, extensible to anything."""
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Sub-commands (imported from modules)
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# phantom grey
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("grey")
@click.argument("target")
@click.option("--scope", "-s", multiple=True)
@click.option("--resume", "-r", default=None)
@llm_options
def grey_cmd(target, scope, resume, provider, model, base_url, api_key) -> None:
    """Bug bounty / OSCP-style — no blind exploitation."""
    import asyncio
    from core import session as db
    from cli.ui import error, info
    _apply_llm_config(provider, model, base_url, api_key)

    if resume:
        matched = [s for s in db.list_sessions() if s.id.startswith(resume)]
        if not matched:
            error(f"No session: {resume}"); raise SystemExit(1)
        sess = matched[0]
    else:
        sess = db.create_session(target=target, mode="grey", scope=list(scope) or [target, f"*.{target}"])
        info(f"Session: {sess.id[:8]}…  Target: {target}")

    from agents.grey_agent import run_full
    asyncio.run(run_full(sess))


# ─────────────────────────────────────────────────────────────────────────────
# phantom learn (beginner mode)
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("learn")
@click.argument("target")
@click.option("--scope", "-s", multiple=True)
@llm_options
def learn_cmd(target, scope, provider, model, base_url, api_key) -> None:
    """Beginner mode — every step explained by AI as it runs."""
    import asyncio
    from core import session as db
    from cli.ui import info
    _apply_llm_config(provider, model, base_url, api_key)

    sess = db.create_session(target=target, mode="beginner", scope=list(scope) or [target])
    info(f"Beginner session: {sess.id[:8]}…  Target: {target}")

    from agents.beginner_agent import run_full
    asyncio.run(run_full(sess))


# ─────────────────────────────────────────────────────────────────────────────
# phantom chat — general-purpose AI chat (not just security)
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("chat")
@click.argument("message", nargs=-1, required=False)
@click.option("--session", "-s", "session_id", default=None,
              help="Session ID to give the AI context from your pentest")
@click.option("--system", default=None, help="Custom system prompt")
@llm_options
def chat_cmd(message, session_id, system, provider, model, base_url, api_key) -> None:
    """
    General-purpose AI chat — ask anything, optionally with session context.

    Examples:
      phantom chat "explain SQL injection"
      phantom chat --session abc123 "what should I test next?"
      phantom chat --provider ollama --model llama3.1 "write a Python script"
    """
    import asyncio
    from cli.ui import console, info, section
    from core.llm import chat_text, get_config

    _apply_llm_config(provider, model, base_url, api_key)

    cfg = get_config()
    info(f"Using: {cfg.summary()}")

    # Build the prompt
    user_input = " ".join(message) if message else None
    if not user_input:
        # Interactive mode
        section("PHANTOM Chat  (Ctrl+C to exit)")
        import asyncio

        async def _interactive():
            history = []
            while True:
                try:
                    user_input = console.input("[bold cyan]You:[/bold cyan] ").strip()
                    if not user_input:
                        continue
                    history.append({"role": "user", "content": user_input})
                    from core.llm import chat
                    response = await chat(
                        messages=history,
                        system=system or "You are PHANTOM, a general-purpose AI agent. Help with any task.",
                        max_tokens=2048,
                        cfg=cfg,
                    )
                    reply = response["text"]
                    console.print(f"\n[bold green]PHANTOM:[/bold green] {reply}\n")
                    history.append({"role": "assistant", "content": reply})
                except KeyboardInterrupt:
                    console.print("\n[dim]Exiting chat.[/dim]")
                    break

        asyncio.run(_interactive())
        return

    # Add session context if provided
    context = ""
    if session_id:
        from core import session as db
        all_sessions = db.list_sessions()
        matched = [s for s in all_sessions if s.id.startswith(session_id)]
        if matched:
            sess = matched[0]
            findings = db.get_findings(sess.id)
            context = (
                f"\nSession context — Target: {sess.target}, Mode: {sess.mode}\n"
                f"Findings:\n" +
                "\n".join(f"- [{f.severity}] {f.type}: {f.description[:100]}" for f in findings[:10])
            )

    full_prompt = (user_input + context) if context else user_input
    response = asyncio.run(chat_text(
        full_prompt,
        system=system or "You are PHANTOM, a general-purpose AI agent. Help with any task.",
        max_tokens=2048,
        cfg=cfg,
    ))
    console.print(f"\n{response}\n")


# ─────────────────────────────────────────────────────────────────────────────
# phantom init
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("init")
def init_cmd() -> None:
    """First-run setup — create dirs, check Docker, show config."""
    from cli.ui import console, info, section, step, success, warn, print_banner
    from config.settings import settings
    import shutil

    print_banner()
    section("PHANTOM Init")

    step("Creating data directories…")
    settings.ensure_dirs()
    success(f"Data dir: {settings.data_dir}")

    step("Initialising database…")
    from core.session import init_db
    init_db()
    success(f"Database: {settings.db_path}")

    step("Detecting LLM provider…")
    from core.llm import get_config
    cfg = get_config()
    success(f"LLM: {cfg.summary()}")

    # Soft warnings only
    warnings = settings.validate()
    for w in warnings:
        warn(w)

    step("Checking Docker…")
    if shutil.which("docker"):
        success("Docker found — tool isolation enabled")
    else:
        warn("Docker not found — tools run as subprocesses")

    step("Checking Go (needed for nuclei/subfinder/httpx/ffuf)…")
    if shutil.which("go"):
        success("Go found")
    else:
        warn("Go not found — install: https://go.dev/doc/install")

    env_example = Path(__file__).parent.parent / "config" / ".env.example"
    if not (Path.cwd() / ".env").exists():
        info(f"No .env found. Copy: cp config/.env.example .env")

    section("Ready")
    success("Run [bold]phantom scan <target>[/bold] or [bold]phantom chat[/bold] to start.")
    info("Docs: https://github.com/grsanudeep42-cmd/phantom")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    project_root = Path(__file__).parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    cli()


if __name__ == "__main__":
    main()
