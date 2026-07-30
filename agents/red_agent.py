"""
phantom/agents/red_agent.py

Full offensive pipeline. Thinks like an attacker.
Phase flow: OSINT → Footprinting → Vuln Scan → Exploit → Post-Exploit → Report
"""
from __future__ import annotations

import json
from typing import Optional

from cli.ui import console, error, finding, info, section, step, success, warn, tool_output_panel
from core import session as db
from core.hypothesis import generate as generate_hypotheses
from core.session import Session, get_session
from registry.runner import ToolNotAvailableError, run_tool, run_command


# ─────────────────────────────────────────────────────────────────────────────
# Scope guard
# ─────────────────────────────────────────────────────────────────────────────

def _in_scope(target: str, scope: list[str]) -> bool:
    """Simple scope check — exact match or wildcard domain match."""
    if not scope:
        return True  # No scope declared = everything in scope (warn separately)
    for pattern in scope:
        if pattern.startswith("*."):
            domain = pattern[2:]
            if target.endswith(f".{domain}") or target == domain:
                return True
        elif target == pattern or target.startswith(pattern):
            return True
    return False


def _check_scope(target: str, scope: list[str]) -> None:
    """Raise if target is out of scope. This is enforced hard."""
    if not scope:
        warn("⚠ No scope declared. Proceeding but this is bad practice.")
        return
    if not _in_scope(target, scope):
        raise PermissionError(
            f"Target '{target}' is OUT OF SCOPE. Declared scope: {scope}. Aborting."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Phase implementations (also called by orchestrator via tool_use)
# ─────────────────────────────────────────────────────────────────────────────

async def run_recon_phase(target: str, session_id: str) -> str:
    """
    Phase 1 + 2: OSINT + Footprinting.
    Returns JSON summary string.
    """
    sess = get_session(session_id)
    if sess:
        _check_scope(target, sess.scope)

    findings_added = 0
    errors = []

    # 1a. Subdomain enum
    try:
        result = await run_tool("subfinder", ["-d", target, "-silent", "-all"], timeout=120)
        if result.stdout.strip():
            subs = [s.strip() for s in result.stdout.strip().splitlines() if s.strip()]
            for sub in subs:
                db.add_finding(session_id, "subdomain", sub, "info", "subfinder passive recon")
                findings_added += 1
            db.add_tried(session_id, "subfinder", ["-d", target], f"{len(subs)} subdomains", result.exit_code)
    except ToolNotAvailableError as e:
        errors.append(f"subfinder: {e}")

    # 1b. OSINT emails/hosts
    try:
        result = await run_tool("theHarvester", ["-d", target, "-b", "all", "-l", "50"], timeout=180)
        if result.stdout.strip() and result.exit_code == 0:
            db.add_finding(session_id, "osint", result.stdout[:500], "info", "theHarvester")
            db.add_tried(session_id, "theHarvester", ["-d", target], result.summary(), result.exit_code)
            findings_added += 1
    except ToolNotAvailableError as e:
        errors.append(f"theHarvester: {e}")

    # 2. Port scan
    try:
        result = await run_tool(
            "nmap",
            ["-sV", "--top-ports", "1000", "-T4", "-oG", "-", target],
            timeout=300,
        )
        open_ports = []
        for line in result.stdout.splitlines():
            if "Ports:" in line:
                parts = line.split("Ports:")[1].strip().split(",")
                for part in parts:
                    part = part.strip()
                    if "/open/" in part:
                        open_ports.append(part)
                        db.add_finding(session_id, "open_port", part, "info", "nmap -sV")
                        findings_added += 1
        db.add_tried(
            session_id, "nmap",
            ["-sV", "--top-ports", "1000", target],
            f"{len(open_ports)} open ports",
            result.exit_code,
        )
    except ToolNotAvailableError as e:
        errors.append(f"nmap: {e}")

    # 2b. Tech fingerprint
    try:
        url = target if target.startswith("http") else f"http://{target}"
        result = await run_tool("httpx", ["-u", url, "-title", "-tech-detect", "-status-code", "-silent"], timeout=60)
        if result.stdout.strip():
            db.add_finding(session_id, "http_probe", result.stdout.strip()[:300], "info", "httpx")
            db.add_tried(session_id, "httpx", ["-u", url], result.summary(), result.exit_code)
            findings_added += 1
    except ToolNotAvailableError as e:
        errors.append(f"httpx: {e}")

    return json.dumps({
        "phase": "recon",
        "target": target,
        "findings_added": findings_added,
        "errors": errors,
    })


async def run_vuln_scan_phase(target: str, session_id: str, severity: str = "medium") -> str:
    """Phase 3: Vulnerability scanning with nuclei and nikto."""
    sess = get_session(session_id)
    if sess:
        _check_scope(target, sess.scope)

    findings_added = 0
    errors = []
    url = target if target.startswith("http") else f"http://{target}"

    # nuclei
    try:
        nuclei_args = ["-u", url, "-severity", severity, "-silent", "-json"]
        result = await run_tool("nuclei", nuclei_args, timeout=600)
        if result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                try:
                    item = json.loads(line)
                    sev = item.get("info", {}).get("severity", "info")
                    name = item.get("info", {}).get("name", "unknown")
                    desc = f"{name} — {item.get('matched-at', url)}"
                    db.add_finding(session_id, "vulnerability", desc, sev, line[:500])
                    findings_added += 1
                    finding(sev, desc)
                except json.JSONDecodeError:
                    continue
        db.add_tried(session_id, "nuclei", nuclei_args, f"{findings_added} vulns", result.exit_code)
    except ToolNotAvailableError as e:
        errors.append(f"nuclei: {e}")

    # nikto
    try:
        result = await run_tool("nikto", ["-h", url, "-Format", "txt", "-nointeractive"], timeout=300)
        if result.stdout.strip() and result.exit_code == 0:
            # Parse OSVDB references as individual findings
            for line in result.stdout.splitlines():
                if line.strip().startswith("+"):
                    db.add_finding(session_id, "web_vuln", line.strip()[1:].strip()[:300], "low", "nikto")
                    findings_added += 1
        db.add_tried(session_id, "nikto", ["-h", url], result.summary(), result.exit_code)
    except ToolNotAvailableError as e:
        errors.append(f"nikto: {e}")

    return json.dumps({
        "phase": "vuln_scan",
        "target": target,
        "findings_added": findings_added,
        "errors": errors,
    })


async def run_fuzzing_phase(target: str, session_id: str, wordlist: Optional[str] = None) -> str:
    """Phase fuzzing: directory and endpoint discovery with ffuf."""
    sess = get_session(session_id)
    if sess:
        _check_scope(target, sess.scope)

    findings_added = 0
    errors = []
    url = target if target.startswith("http") else f"http://{target}"

    wl = wordlist or "/usr/share/wordlists/dirb/common.txt"

    try:
        ffuf_args = [
            "-u", f"{url}/FUZZ",
            "-w", wl,
            "-mc", "200,204,301,302,307,403",
            "-o", "-",
            "-of", "json",
            "-s",
        ]
        result = await run_tool("ffuf", ffuf_args, timeout=300)
        if result.stdout.strip():
            try:
                ffuf_json = json.loads(result.stdout)
                for r in ffuf_json.get("results", []):
                    desc = f"{r.get('status')} {r.get('url', '')}"
                    sev = "low" if r.get("status") in (200, 204) else "info"
                    db.add_finding(session_id, "endpoint", desc, sev, json.dumps(r)[:200])
                    findings_added += 1
            except json.JSONDecodeError:
                pass
        db.add_tried(session_id, "ffuf", ffuf_args, f"{findings_added} endpoints", result.exit_code)
    except ToolNotAvailableError as e:
        errors.append(f"ffuf: {e}")

    return json.dumps({
        "phase": "fuzzing",
        "target": target,
        "findings_added": findings_added,
        "errors": errors,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Phase 0: Target Intelligence (Phase 10)
# ─────────────────────────────────────────────────────────────────────────────

async def run_intel_phase(
    target: str, session_id: str, program_url: Optional[str] = None
) -> dict:
    """Run phantom_understand_target and store intel in session."""
    section("Phase 0 / Target Intelligence")
    try:
        from agents.intel_agent import phantom_understand_target
        intel = await phantom_understand_target(target, session_id, program_url=program_url)
        success(
            f"Stack: {', '.join((intel.tech_profile.stack + intel.tech_profile.frameworks)[:4]) or 'unknown'} | "
            f"API: {intel.tech_profile.api_type} | "
            f"Surface: {intel.attack_surface.total()} URLs"
        )
        if intel.threat_model.ranked:
            top = intel.threat_model.ranked[0]
            info(f"Top threat: {top['vuln_class']} — {top['reasoning'][:80]}")
        return {
            "status": "ok",
            "threat_model_items": len(intel.threat_model.ranked),
            "surface_total": intel.attack_surface.total(),
        }
    except Exception as exc:
        warn(f"Intel phase error (non-fatal): {exc}")
        return {"status": "error", "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Full red agent pipeline (CLI entry point)
# ─────────────────────────────────────────────────────────────────────────────

async def run_full(session: Session) -> None:
    """Run all phases. Uses orchestrator for reasoning between phases."""
    from core.orchestrator import run as orchestrate
    from cli.ui import findings_table

    target = session.target
    section(f"RED AGENT  →  {target}")
    info(f"Session: {session.id[:8]}…   Mode: red")

    if not session.scope:
        warn("No scope declared. Use --scope to limit the engagement.")

    # Phase 0: Target Intelligence
    await run_intel_phase(target, session.id)

    # Phase 1+2: Recon
    section("Phase 1+2 / OSINT + Footprinting")
    info("Running passive recon and port scan…")
    recon_result = await run_recon_phase(target, session.id)
    recon_data = json.loads(recon_result)
    success(f"Recon: {recon_data['findings_added']} findings")
    for e in recon_data.get("errors", []):
        warn(f"  Tool unavailable: {e}")

    # Generate hypotheses after recon
    hyps = await generate_hypotheses(session)
    if hyps:
        section("AI Hypotheses — next moves")
        for h in hyps:
            console.print(
                f"  [cyan]{h.confidence:.0%}[/cyan]  {h.hypothesis}  "
                f"[dim]→ {h.suggested_tool}[/dim]"
            )

    # Phase 3: Vuln Scan
    section("Phase 3 / Vulnerability Scan")
    info("Running nuclei + nikto…")
    vuln_result = await run_vuln_scan_phase(target, session.id)
    vuln_data = json.loads(vuln_result)
    success(f"Vuln scan: {vuln_data['findings_added']} findings")

    # Phase 4: Fuzzing
    section("Phase 4 / Directory Fuzzing")
    info("Running ffuf directory brute-force…")
    fuzz_result = await run_fuzzing_phase(target, session.id)
    fuzz_data = json.loads(fuzz_result)
    success(f"Fuzzing: {fuzz_data['findings_added']} endpoints found")

    # Phase 5: AI Analysis via orchestrator
    section("Phase 5 / AI Analysis")
    info("Running orchestrator reasoning pass…")
    findings = db.get_findings(session.id)
    task = (
        f"Analyse the {len(findings)} findings from the engagement on {target}. "
        f"Identify the highest-impact vulnerabilities, suggest next exploitation steps, "
        f"and classify each finding by CVSS severity. "
        f"Then call add_finding for any additional inferences you can make."
    )
    # OrchestratorResult — use .output (not bare string)
    result = await orchestrate(task, session, mode="red")
    if result.output:
        section("Orchestrator Analysis")
        console.print(result.output)
    if result.total_cost_usd > 0:
        info(f"LLM cost this session: ${result.total_cost_usd:.4f}")

    # Summary
    final_findings = db.get_findings(session.id)
    section("Engagement Complete")
    success(f"Total findings: {len(final_findings)}")
    info(f"Generate report: [bold]phantom report {session.id[:8]} --format=hackerone[/bold]")
    findings_table(final_findings)
