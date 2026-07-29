"""
phantom/agents/beginner_agent.py

Learn-while-hacking mode. Every action explained before + after execution.
Never skips explanations, even if asked.
"""
from __future__ import annotations

import json
from typing import Optional

from cli.ui import console, info, section, step, success, warn
from core import session as db
from core.session import Session
from registry.runner import ToolNotAvailableError, run_tool


# ─────────────────────────────────────────────────────────────────────────────
# Claude-powered explanations
# ─────────────────────────────────────────────────────────────────────────────

async def _explain(topic: str, context: str = "") -> str:
    """Ask Claude to explain something in beginner-friendly terms."""
    from config.settings import settings
    import anthropic

    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    response = await client.messages.create(
        model=settings.claude_model,
        max_tokens=600,
        messages=[{
            "role": "user",
            "content": (
                f"Explain this to a beginner learning cybersecurity. "
                f"Keep it under 150 words. Use simple language. Be concrete.\n\n"
                f"Topic: {topic}\n"
                f"Context: {context or 'none'}"
            )
        }]
    )
    return response.content[0].text


async def _explain_finding(type: str, description: str, severity: str) -> str:
    """Explain what a finding means and what vulnerability class it belongs to."""
    from config.settings import settings
    import anthropic

    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    response = await client.messages.create(
        model=settings.claude_model,
        max_tokens=600,
        messages=[{
            "role": "user",
            "content": (
                f"A security scan found: [{severity.upper()}] {type}: {description}\n\n"
                f"Explain to a beginner:\n"
                f"1. What this finding means\n"
                f"2. What vulnerability class it belongs to (OWASP? CVE type?)\n"
                f"3. Why an attacker would care about it\n"
                f"4. What to learn next about this topic\n\n"
                f"Keep it under 200 words. Use plain English."
            )
        }]
    )
    return response.content[0].text


async def _suggest_next_learning(findings: list) -> str:
    """Suggest what concepts to study based on what was found."""
    from config.settings import settings
    import anthropic

    if not findings:
        return "Start by reading OWASP Top 10: https://owasp.org/Top10/"

    summary = "\n".join(f"- {f.type}: {f.description[:100]}" for f in findings[:10])
    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    response = await client.messages.create(
        model=settings.claude_model,
        max_tokens=400,
        messages=[{
            "role": "user",
            "content": (
                f"A beginner just completed a security scan and found:\n{summary}\n\n"
                f"Suggest 3 specific things they should learn next "
                f"(with resource links like HackTheBox, TryHackMe, or PortSwigger). "
                f"Keep it encouraging and concrete."
            )
        }]
    )
    return response.content[0].text


# ─────────────────────────────────────────────────────────────────────────────
# Beginner-wrapped tool runner
# ─────────────────────────────────────────────────────────────────────────────

async def run_tool_with_explanation(
    tool_id: str,
    args: list[str],
    session_id: str,
    explain_before: bool = True,
    timeout: int = 300,
):
    """Run a tool with before/after explanations for beginners."""
    if explain_before:
        section(f"About to run: [bold]{tool_id}[/bold]")
        explanation = await _explain(
            topic=f"The security tool '{tool_id}'",
            context=f"We are about to run: {tool_id} {' '.join(args)}",
        )
        console.print(f"\n[dim]{explanation}[/dim]\n")
        step(f"Running: [bold]{tool_id} {' '.join(args[:3])}[/bold]")

    try:
        result = await run_tool(tool_id, args, timeout=timeout)

        from cli.ui import tool_output_panel
        tool_output_panel(tool_id, result.stdout, result.exit_code, result.duration)

        if result.stdout.strip():
            section("What does this output mean?")
            output_explanation = await _explain(
                topic=f"Output from {tool_id}",
                context=f"Output snippet:\n{result.stdout[:400]}",
            )
            console.print(f"\n[dim]{output_explanation}[/dim]\n")

        return result
    except ToolNotAvailableError as e:
        warn(f"{tool_id} is not installed: {e}")
        explanation = await _explain(
            topic=f"How to install {tool_id}",
            context="The tool is missing from the system.",
        )
        console.print(f"\n[dim]{explanation}[/dim]\n")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Full beginner pipeline
# ─────────────────────────────────────────────────────────────────────────────

async def run_full(session: Session) -> None:
    target = session.target
    section(f"BEGINNER MODE  →  {target}")
    console.print(
        "\n[bold cyan]Welcome to PHANTOM Beginner Mode![/bold cyan]\n"
        "Every step will be explained before and after it runs.\n"
        "You can ask questions between steps.\n"
    )

    # Explain what recon is
    section("Step 1: Subdomain Enumeration")
    why = await _explain(
        "Subdomain enumeration",
        f"We are starting a security scan on {target}",
    )
    console.print(f"\n[dim]{why}[/dim]\n")

    result = await run_tool_with_explanation(
        "subfinder", ["-d", target, "-silent"], session.id, explain_before=False
    )
    if result and result.stdout.strip():
        subs = [s.strip() for s in result.stdout.strip().splitlines() if s.strip()]
        for sub in subs:
            db.add_finding(session.id, "subdomain", sub, "info", "subfinder")
        success(f"Found {len(subs)} subdomains!")

    # Port scanning
    section("Step 2: Port Scanning")
    result = await run_tool_with_explanation(
        "nmap",
        ["-sV", "--top-ports", "100", "-T3", target],
        session.id,
    )
    if result:
        open_ports = [l.strip() for l in result.stdout.splitlines() if "/open/" in l or ("open" in l and "/tcp" in l)]
        for p in open_ports:
            db.add_finding(session.id, "open_port", p, "info", "nmap")

    # HTTP probing
    section("Step 3: Web Technology Detection")
    url = target if target.startswith("http") else f"http://{target}"
    result = await run_tool_with_explanation(
        "httpx",
        ["-u", url, "-title", "-tech-detect", "-silent"],
        session.id,
    )

    # Explain findings
    all_findings = db.get_findings(session.id)
    if all_findings:
        section("Understanding Your Findings")
        for f in all_findings[:5]:  # Cap at 5 for readability
            console.print(f"\n[bold]Finding:[/bold] [{f.severity.upper()}] {f.description[:100]}")
            explanation = await _explain_finding(f.type, f.description, f.severity)
            console.print(f"[dim]{explanation}[/dim]\n")

    # What to learn next
    section("What to Learn Next")
    next_steps = await _suggest_next_learning(all_findings)
    console.print(next_steps)

    section("Session Complete")
    success(f"You found {len(all_findings)} things! Great first scan.")
    info(f"Your session ID is [bold]{session.id[:8]}[/bold] — save it to resume later.")
    info(f"Run [bold]phantom report {session.id[:8]}[/bold] to see a full report.")
