"""
phantom/agents/beginner_agent.py

Learn-while-hacking mode. Every action explained before + after.
Uses core.llm — works with any configured LLM (including local Ollama).
"""
from __future__ import annotations

from cli.ui import console, info, section, step, success, warn
from core import session as db
from core.llm import chat_text
from core.session import Session
from registry.runner import ToolNotAvailableError, run_tool


async def _explain(topic: str, context: str = "") -> str:
    return await chat_text(
        prompt=(
            f"Explain to a cybersecurity beginner (under 150 words, plain English):\n"
            f"Topic: {topic}\nContext: {context or 'none'}"
        ),
        system="You are a patient cybersecurity teacher. Be concrete and encouraging.",
        max_tokens=400,
    )


async def _explain_finding(type: str, description: str, severity: str) -> str:
    return await chat_text(
        prompt=(
            f"Finding: [{severity.upper()}] {type}: {description}\n\n"
            "Explain to a beginner (under 200 words):\n"
            "1. What this means\n2. What vulnerability class it is\n"
            "3. Why attackers care\n4. What to learn next about this"
        ),
        system="You are a patient cybersecurity teacher.",
        max_tokens=400,
    )


async def _suggest_next_learning(findings: list) -> str:
    if not findings:
        return "Start with OWASP Top 10: https://owasp.org/Top10/"
    summary = "\n".join(f"- {f.type}: {f.description[:80]}" for f in findings[:10])
    return await chat_text(
        prompt=(
            f"A beginner just found:\n{summary}\n\n"
            "Suggest 3 specific things to learn next "
            "(with links: HackTheBox, TryHackMe, or PortSwigger). "
            "Keep it encouraging."
        ),
        system="You are an encouraging cybersecurity mentor.",
        max_tokens=300,
    )


async def run_tool_with_explanation(
    tool_id: str, args: list[str], session_id: str,
    explain_before: bool = True, timeout: int = 300,
):
    if explain_before:
        section(f"About to run: [bold]{tool_id}[/bold]")
        console.print(f"\n[dim]{await _explain(f'The security tool {tool_id}', f'Running: {tool_id} {chr(32).join(args[:3])}')}[/dim]\n")
        step(f"Running: [bold]{tool_id} {' '.join(args[:3])}[/bold]")
    try:
        result = await run_tool(tool_id, args, timeout=timeout)
        from cli.ui import tool_output_panel
        tool_output_panel(tool_id, result.stdout, result.exit_code, result.duration)
        if result.stdout.strip():
            section("What does this output mean?")
            console.print(f"\n[dim]{await _explain(f'Output from {tool_id}', result.stdout[:400])}[/dim]\n")
        return result
    except ToolNotAvailableError as e:
        warn(f"{tool_id} not available: {e}")
        console.print(f"\n[dim]{await _explain(f'How to install {tool_id}', 'Tool is missing')}[/dim]\n")
        return None


async def run_full(session: Session) -> None:
    from core.llm import get_config
    target = session.target
    section(f"BEGINNER MODE  →  {target}  [{get_config().summary()}]")
    console.print(
        "\n[bold cyan]Welcome to PHANTOM Beginner Mode![/bold cyan]\n"
        "Every step is explained before and after it runs.\n"
    )

    section("Step 1: Subdomain Enumeration")
    console.print(f"\n[dim]{await _explain('Subdomain enumeration', f'Starting scan on {target}')}[/dim]\n")
    result = await run_tool_with_explanation("subfinder", ["-d", target, "-silent"], session.id, explain_before=False)
    if result and result.stdout.strip():
        subs = [s.strip() for s in result.stdout.strip().splitlines() if s.strip()]
        for sub in subs:
            db.add_finding(session.id, "subdomain", sub, "info", "subfinder")
        success(f"Found {len(subs)} subdomains!")

    section("Step 2: Port Scanning")
    await run_tool_with_explanation("nmap", ["-sV", "--top-ports", "100", "-T3", target], session.id)

    section("Step 3: Web Technology Detection")
    url = target if target.startswith("http") else f"http://{target}"
    await run_tool_with_explanation("httpx", ["-u", url, "-title", "-tech-detect", "-silent"], session.id)

    all_findings = db.get_findings(session.id)
    if all_findings:
        section("Understanding Your Findings")
        for f in all_findings[:5]:
            console.print(f"\n[bold]Finding:[/bold] [{f.severity.upper()}] {f.description[:100]}")
            console.print(f"[dim]{await _explain_finding(f.type, f.description, f.severity)}[/dim]\n")

    section("What to Learn Next")
    console.print(await _suggest_next_learning(all_findings))

    section("Session Complete")
    success(f"Found {len(all_findings)} things!")
    info(f"Session: [bold]{session.id[:8]}[/bold]")
    info(f"Report: [bold]phantom report {session.id[:8]}[/bold]")
