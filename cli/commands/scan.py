"""
phantom/cli/commands/scan.py

`phantom scan <target>` — quick recon. No Claude API needed.
Runs: subfinder → nmap → httpx → whatweb in sequence.
Findings stored in session. Report printed to terminal.
"""
from __future__ import annotations

import asyncio
from typing import Optional

import click

from cli.ui import (
    console,
    error,
    finding,
    info,
    section,
    step,
    success,
    tool_output_panel,
    warn,
)
from core import session as db
from registry.runner import ToolNotAvailableError, run_tool


async def _run_scan(target: str, session_id: str, scope: list[str]) -> None:
    section(f"PHANTOM SCAN  →  {target}")

    # ── Phase 1: Subdomain enumeration ───────────────────────────────────
    section("Phase 1 / Subdomain Enumeration")
    step(f"Running subfinder on {target}")
    try:
        result = await run_tool("subfinder", ["-d", target, "-silent"], timeout=120)
        tool_output_panel("subfinder", result.stdout, result.exit_code, result.duration)
        if result.stdout.strip():
            subdomains = [s.strip() for s in result.stdout.strip().splitlines() if s.strip()]
            for sub in subdomains:
                db.add_finding(
                    session_id,
                    type="subdomain",
                    description=sub,
                    severity="info",
                    proof=f"subfinder passive recon",
                )
            success(f"Found {len(subdomains)} subdomains")
            db.add_tried(
                session_id, "subfinder", ["-d", target, "-silent"],
                result_summary=f"{len(subdomains)} subdomains found",
                exit_code=result.exit_code,
            )
        else:
            warn("No subdomains found via subfinder")
    except ToolNotAvailableError as e:
        warn(f"subfinder unavailable: {e}")

    # ── Phase 2: Port scan ────────────────────────────────────────────────
    section("Phase 2 / Port Scan")
    step(f"Running nmap on {target} (top 1000 ports)")
    try:
        result = await run_tool(
            "nmap",
            ["-sV", "--top-ports", "1000", "-T4", "-oG", "-", target],
            timeout=300,
        )
        tool_output_panel("nmap", result.stdout, result.exit_code, result.duration)

        # Parse open ports from grepable output
        open_ports = []
        for line in result.stdout.splitlines():
            if "Ports:" in line:
                parts = line.split("Ports:")[1].strip().split(",")
                for part in parts:
                    part = part.strip()
                    if "/open/" in part:
                        open_ports.append(part)
                        db.add_finding(
                            session_id,
                            type="open_port",
                            description=part,
                            severity="info",
                            proof=f"nmap -sV",
                        )

        db.add_tried(
            session_id, "nmap",
            ["-sV", "--top-ports", "1000", "-T4", target],
            result_summary=f"{len(open_ports)} open ports",
            exit_code=result.exit_code,
        )
        if open_ports:
            success(f"Found {len(open_ports)} open ports")
        else:
            info("No open ports found in top 1000")
    except ToolNotAvailableError as e:
        warn(f"nmap unavailable: {e}")

    # ── Phase 3: HTTP probing ──────────────────────────────────────────────
    section("Phase 3 / HTTP Probing")
    step(f"Running httpx on {target}")
    try:
        result = await run_tool(
            "httpx",
            ["-u", target, "-title", "-tech-detect", "-status-code", "-silent"],
            timeout=60,
        )
        tool_output_panel("httpx", result.stdout, result.exit_code, result.duration)
        if result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                db.add_finding(
                    session_id,
                    type="http_probe",
                    description=line.strip(),
                    severity="info",
                    proof="httpx",
                )
            db.add_tried(
                session_id, "httpx",
                ["-u", target, "-title", "-tech-detect"],
                result_summary=result.stdout[:200],
                exit_code=result.exit_code,
            )
    except ToolNotAvailableError as e:
        warn(f"httpx unavailable: {e}")

    # ── Phase 4: Tech fingerprint ──────────────────────────────────────────
    section("Phase 4 / Tech Fingerprint")
    step(f"Running whatweb on {target}")
    try:
        url = target if target.startswith("http") else f"http://{target}"
        result = await run_tool("whatweb", [url, "--log-brief=-"], timeout=60)
        tool_output_panel("whatweb", result.stdout, result.exit_code, result.duration)
        if result.stdout.strip():
            db.add_finding(
                session_id,
                type="tech_fingerprint",
                description=result.stdout.strip()[:500],
                severity="info",
                proof="whatweb",
            )
            db.add_tried(
                session_id, "whatweb", [url],
                result_summary=result.stdout[:200],
                exit_code=result.exit_code,
            )
    except ToolNotAvailableError as e:
        warn(f"whatweb unavailable: {e}")

    # ── Summary ────────────────────────────────────────────────────────────
    section("Scan Complete")
    findings = db.get_findings(session_id)
    success(f"Session ID: {session_id}")
    info(f"Total findings: {len(findings)}")
    info(f"Run [bold]phantom report {session_id[:8]}[/bold] to generate a report")
    info(f"Run [bold]phantom sessions resume {session_id[:8]}[/bold] to continue this engagement")


@click.command("scan")
@click.argument("target")
@click.option("--scope", "-s", multiple=True, help="In-scope patterns (e.g. *.example.com)")
@click.option("--resume", "-r", default=None, help="Resume existing session by ID prefix")
def scan_cmd(target: str, scope: tuple, resume: Optional[str]) -> None:
    """Quick recon scan — subdomains, ports, HTTP, tech fingerprint."""
    from dotenv import load_dotenv
    load_dotenv()

    if resume:
        from core.session import list_sessions
        all_sessions = list_sessions()
        matched = [s for s in all_sessions if s.id.startswith(resume)]
        if not matched:
            error(f"No session found matching prefix: {resume}")
            raise SystemExit(1)
        sess = matched[0]
        info(f"Resuming session {sess.id[:8]}… (target: {sess.target})")
        session_id = sess.id
        scope_list = sess.scope
        target = sess.target
    else:
        scope_list = list(scope) if scope else [target, f"*.{target}"]
        sess = db.create_session(target=target, mode="scan", scope=scope_list)
        session_id = sess.id
        info(f"New session: {session_id[:8]}…")
        info(f"Target: {target}")
        info(f"Scope: {', '.join(scope_list)}")

    asyncio.run(_run_scan(target, session_id, scope_list))
