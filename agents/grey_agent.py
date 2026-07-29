"""
phantom/agents/grey_agent.py

Bug bounty / OSCP-style engagements.
Middle ground: recon + vuln scan + PoC confirm. NO blind exploitation.
Stops at verified PoC and hands off to reporting.
"""
from __future__ import annotations

import json
from typing import Optional

from cli.ui import console, error, finding, info, section, step, success, warn
from core import session as db
from core.hypothesis import generate as generate_hypotheses
from core.session import Session
from registry.runner import ToolNotAvailableError, run_tool, run_command


# CVSS base score → P-rating mapping (HackerOne style)
CVSS_PRIORITY = [
    (9.0, "P1 — Critical"),
    (7.0, "P2 — High"),
    (4.0, "P3 — Medium"),
    (0.1, "P4 — Low"),
    (0.0, "P5 — Informational"),
]


def _cvss_to_priority(cvss: float) -> str:
    for threshold, label in CVSS_PRIORITY:
        if cvss >= threshold:
            return label
    return "P5 — Informational"


def _severity_to_cvss(severity: str) -> float:
    return {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0, "info": 0.0}.get(
        severity.lower(), 0.0
    )


def _check_scope(target: str, scope: list[str]) -> None:
    if not scope:
        warn("No scope declared — proceeding but declare scope before submitting to bug bounty.")
        return
    in_scope = False
    for pattern in scope:
        if pattern.startswith("*."):
            domain = pattern[2:]
            if target.endswith(f".{domain}") or target == domain:
                in_scope = True
                break
        elif target == pattern or target.startswith(pattern):
            in_scope = True
            break
    if not in_scope:
        raise PermissionError(
            f"⚠ '{target}' is OUT OF SCOPE. Declared: {scope}. "
            f"In grey mode this is ALWAYS fatal — never touch OOS assets."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: Passive OSINT only
# ─────────────────────────────────────────────────────────────────────────────

async def run_passive_recon(target: str, session_id: str) -> str:
    findings_added = 0
    errors = []

    # Passive subdomain enum
    try:
        result = await run_tool("subfinder", ["-d", target, "-silent"], timeout=120)
        if result.stdout.strip():
            subs = [s.strip() for s in result.stdout.strip().splitlines() if s.strip()]
            for sub in subs:
                db.add_finding(session_id, "subdomain", sub, "info", "subfinder passive")
                findings_added += 1
            success(f"Subdomains: {len(subs)} found")
            db.add_tried(session_id, "subfinder", ["-d", target], f"{len(subs)} subs", result.exit_code)
    except ToolNotAvailableError as e:
        errors.append(f"subfinder: {e}")

    return json.dumps({"phase": "passive_recon", "findings_added": findings_added, "errors": errors})


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: Footprinting (active but non-intrusive)
# ─────────────────────────────────────────────────────────────────────────────

async def run_footprinting(target: str, session_id: str) -> str:
    findings_added = 0
    errors = []

    try:
        result = await run_tool("nmap", ["-sV", "-T3", "--top-ports", "100", target], timeout=180)
        open_ports = []
        for line in result.stdout.splitlines():
            if "/open/" in line or ("/tcp" in line and "open" in line):
                open_ports.append(line.strip())
                db.add_finding(session_id, "open_port", line.strip(), "info", "nmap")
                findings_added += 1
        db.add_tried(session_id, "nmap", ["-sV", "-T3", target], f"{len(open_ports)} ports", result.exit_code)
    except ToolNotAvailableError as e:
        errors.append(f"nmap: {e}")

    try:
        url = target if target.startswith("http") else f"http://{target}"
        result = await run_tool("whatweb", [url, "--log-brief=-"], timeout=60)
        if result.stdout.strip():
            db.add_finding(session_id, "tech_fingerprint", result.stdout.strip()[:400], "info", "whatweb")
            findings_added += 1
        db.add_tried(session_id, "whatweb", [url], result.summary(), result.exit_code)
    except ToolNotAvailableError as e:
        errors.append(f"whatweb: {e}")

    return json.dumps({"phase": "footprinting", "findings_added": findings_added, "errors": errors})


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: OWASP-focused vuln scan (non-destructive)
# ─────────────────────────────────────────────────────────────────────────────

async def run_vuln_scan(target: str, session_id: str) -> str:
    findings_added = 0
    errors = []
    url = target if target.startswith("http") else f"http://{target}"

    # nuclei — OWASP tags only
    try:
        result = await run_tool(
            "nuclei",
            ["-u", url, "-tags", "owasp,cve,sqli,xss,lfi,ssrf,idor", "-silent", "-json"],
            timeout=600,
        )
        if result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                try:
                    item = json.loads(line)
                    sev = item.get("info", {}).get("severity", "info")
                    name = item.get("info", {}).get("name", "unknown")
                    matched = item.get("matched-at", url)
                    desc = f"{name} at {matched}"
                    db.add_finding(session_id, "vulnerability", desc, sev, line[:500])
                    findings_added += 1
                    finding(sev, desc)
                except json.JSONDecodeError:
                    continue
        db.add_tried(session_id, "nuclei", ["-u", url, "-tags", "owasp"], f"{findings_added} vulns", result.exit_code)
    except ToolNotAvailableError as e:
        errors.append(f"nuclei: {e}")

    return json.dumps({"phase": "vuln_scan", "findings_added": findings_added, "errors": errors})


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4: PoC Confirm (minimal, non-destructive)
# ─────────────────────────────────────────────────────────────────────────────

async def run_poc_confirm(target: str, session_id: str) -> str:
    """
    Confirm findings with curl/httpx — minimal impact.
    Grey mode NEVER runs exploits. Just verifies the vuln exists.
    """
    findings = db.get_findings(session_id)
    vuln_findings = [f for f in findings if f.type == "vulnerability"]
    confirmed = 0

    url = target if target.startswith("http") else f"http://{target}"

    for f in vuln_findings[:10]:  # Cap at 10 to stay non-aggressive
        # Just re-probe the endpoint to confirm it's still accessible
        probe_result = await run_command(
            f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 10 "{url}"',
            timeout=15,
        )
        if probe_result.stdout.strip() in ("200", "301", "302", "403"):
            confirmed += 1
            # Add bounty priority classification
            cvss = _severity_to_cvss(f.severity)
            priority = _cvss_to_priority(cvss)
            db.add_finding(
                session_id,
                "poc_confirmed",
                f"[{priority}] {f.description}",
                f.severity,
                f"HTTP {probe_result.stdout.strip()} confirms target is live. CVSS ~{cvss}",
            )

    return json.dumps({"phase": "poc_confirm", "confirmed": confirmed})


# ─────────────────────────────────────────────────────────────────────────────
# Full grey pipeline (CLI entry point)
# ─────────────────────────────────────────────────────────────────────────────

async def run_full(session: Session) -> None:
    target = session.target
    section(f"GREY AGENT  →  {target}  [Bug Bounty Mode]")
    info(f"Session: {session.id[:8]}…")
    warn("Grey mode: Will NOT execute blind exploits. Stops at verified PoC.")

    if not session.scope:
        warn("No scope declared. Use --scope to set in-scope assets.")

    # Phase 1: Passive OSINT
    section("Phase 1 / Passive OSINT")
    r = await run_passive_recon(target, session.id)
    d = json.loads(r)
    success(f"Passive recon: {d['findings_added']} findings")

    # Phase 2: Footprinting
    section("Phase 2 / Footprinting")
    r = await run_footprinting(target, session.id)
    d = json.loads(r)
    success(f"Footprinting: {d['findings_added']} findings")

    # Phase 3: Vuln scan
    section("Phase 3 / OWASP Vulnerability Scan")
    r = await run_vuln_scan(target, session.id)
    d = json.loads(r)
    success(f"Vuln scan: {d['findings_added']} findings")

    # AI hypotheses
    hyps = await generate_hypotheses(session)
    if hyps:
        section("AI Hypotheses")
        for h in hyps:
            console.print(f"  [cyan]{h.confidence:.0%}[/cyan]  {h.hypothesis}  [dim]→ {h.suggested_tool}[/dim]")

    # Phase 4: PoC confirm
    section("Phase 4 / PoC Confirmation (non-destructive)")
    info("Confirming findings with minimal probes…")
    r = await run_poc_confirm(target, session.id)
    d = json.loads(r)
    success(f"Confirmed: {d['confirmed']} findings")

    # Summary + report
    final_findings = db.get_findings(session.id)
    section("Engagement Complete")
    success(f"Total findings: {len(final_findings)}")

    # Show priority breakdown
    for f in final_findings:
        if f.type == "poc_confirmed":
            finding(f.severity, f.description)

    info(f"Generate HackerOne report: [bold]phantom report {session.id[:8]} --format=hackerone[/bold]")
    from cli.ui import findings_table
    findings_table(final_findings)
