"""
phantom/agents/blue_agent.py

Defensive mode — log analysis, IOC extraction, hardening, IR playbooks.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from cli.ui import console, error, finding, info, section, step, success, warn
from core import session as db
from core.session import Session


# ─────────────────────────────────────────────────────────────────────────────
# IOC extraction
# ─────────────────────────────────────────────────────────────────────────────

IP_REGEX     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_REGEX = re.compile(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', re.IGNORECASE)
HASH_MD5     = re.compile(r'\b[a-fA-F0-9]{32}\b')
HASH_SHA1    = re.compile(r'\b[a-fA-F0-9]{40}\b')
HASH_SHA256  = re.compile(r'\b[a-fA-F0-9]{64}\b')
CVE_REGEX    = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)


def extract_iocs(text: str) -> dict:
    """Extract all IOCs from raw log text."""
    ips = list(set(IP_REGEX.findall(text)))
    # Filter private IPs
    public_ips = [
        ip for ip in ips
        if not (
            ip.startswith("10.") or
            ip.startswith("192.168.") or
            ip.startswith("127.") or
            ip.startswith("172.")
        )
    ]
    return {
        "ips": public_ips[:50],
        "domains": list(set(DOMAIN_REGEX.findall(text)))[:50],
        "md5": list(set(HASH_MD5.findall(text)))[:20],
        "sha1": list(set(HASH_SHA1.findall(text)))[:20],
        "sha256": list(set(HASH_SHA256.findall(text)))[:20],
        "cves": list(set(CVE_REGEX.findall(text)))[:20],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Log analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_log_file(log_path: str, session_id: str) -> dict:
    """Parse a log file, extract IOCs, detect attack patterns."""
    path = Path(log_path)
    if not path.exists():
        return {"error": f"File not found: {log_path}"}

    text = path.read_text(errors="replace")
    iocs = extract_iocs(text)
    findings_added = 0

    # Detect common attack patterns
    attack_patterns = [
        (r'(union\s+select|sleep\(\d+\)|benchmark\()', "SQL Injection attempt", "high"),
        (r'(<script[\s>]|javascript:|onerror\s*=)', "XSS attempt", "high"),
        (r'(\.\./){3,}', "Path traversal attempt", "medium"),
        (r'(cmd\.exe|/bin/sh|/bin/bash|powershell)', "Command injection attempt", "critical"),
        (r'(401|403)\s+\d+', "Auth failure / access denied", "low"),
        (r'(\d+\.\d+\.\d+\.\d+).*?(\d{3,4})\s+.*?(?:scan|probe|nikto|nmap)', "Scanner detected", "medium"),
    ]

    for pattern, label, severity in attack_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            db.add_finding(
                session_id,
                type="log_pattern",
                description=f"{label}: {len(matches)} occurrence(s)",
                severity=severity,
                proof=str(matches[:3]),
            )
            findings_added += 1
            finding(severity, f"{label} ({len(matches)} hits)")

    # Store IOC findings
    for ip in iocs["ips"][:10]:
        db.add_finding(session_id, "ioc_ip", f"Suspicious IP: {ip}", "low", f"extracted from {log_path}")
        findings_added += 1

    for cve in iocs["cves"]:
        db.add_finding(session_id, "cve_mention", f"CVE referenced: {cve}", "medium", f"found in log")
        findings_added += 1

    return {
        "log": log_path,
        "iocs": iocs,
        "findings_added": findings_added,
        "total_lines": text.count("\n"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Hardening checklist (Claude-powered)
# ─────────────────────────────────────────────────────────────────────────────

async def generate_hardening_checklist(target: str, session_id: str) -> str:
    """Use Claude to generate a hardening checklist based on current findings."""
    from config.settings import settings
    import anthropic

    findings = db.get_findings(session_id)
    if not findings:
        return "No findings to base hardening checklist on. Run a scan first."

    findings_text = "\n".join(
        f"- [{f.severity.upper()}] {f.type}: {f.description}" for f in findings
    )

    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    response = await client.messages.create(
        model=settings.claude_model,
        max_tokens=2048,
        messages=[{
            "role": "user",
            "content": (
                f"You are a security hardening expert.\n"
                f"Target: {target}\n"
                f"Findings:\n{findings_text}\n\n"
                f"Generate a prioritised hardening checklist in markdown. "
                f"Group by priority (Critical / High / Medium / Low). "
                f"Be specific — include actual config changes, not just 'update software'."
            )
        }]
    )
    return response.content[0].text


# ─────────────────────────────────────────────────────────────────────────────
# IR Playbook (Claude-powered)
# ─────────────────────────────────────────────────────────────────────────────

async def generate_ir_playbook(session_id: str) -> str:
    """Generate an incident response playbook from findings + IOCs."""
    from config.settings import settings
    import anthropic

    findings = db.get_findings(session_id)
    ioc_findings = [f for f in findings if f.type.startswith("ioc_")]
    log_findings = [f for f in findings if f.type == "log_pattern"]

    if not findings:
        return "No findings. Run blue team log analysis first."

    context = "\n".join(
        f"- [{f.severity.upper()}] {f.type}: {f.description}" for f in findings[:30]
    )

    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    response = await client.messages.create(
        model=settings.claude_model,
        max_tokens=2048,
        messages=[{
            "role": "user",
            "content": (
                f"You are a DFIR specialist.\n"
                f"Evidence from the environment:\n{context}\n\n"
                f"Generate a step-by-step incident response playbook covering:\n"
                f"1. Immediate containment steps\n"
                f"2. Evidence collection\n"
                f"3. Root cause investigation\n"
                f"4. Remediation steps\n"
                f"5. Post-incident review\n"
                f"Be specific and actionable. Include actual commands where relevant."
            )
        }]
    )
    return response.content[0].text


# ─────────────────────────────────────────────────────────────────────────────
# SIEM query generation
# ─────────────────────────────────────────────────────────────────────────────

async def generate_siem_queries(session_id: str, siem: str = "splunk") -> str:
    """Generate Splunk SPL or Elastic KQL queries from IOCs and patterns."""
    from config.settings import settings
    import anthropic

    findings = db.get_findings(session_id)
    if not findings:
        return "No findings to generate queries from."

    iocs = [f for f in findings if f.type.startswith("ioc_")]
    patterns = [f for f in findings if f.type == "log_pattern"]

    context = "\n".join(
        f"- {f.type}: {f.description}" for f in (iocs + patterns)[:20]
    )

    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    response = await client.messages.create(
        model=settings.claude_model,
        max_tokens=1024,
        messages=[{
            "role": "user",
            "content": (
                f"Generate {siem.upper()} search queries for the following IOCs and attack patterns.\n"
                f"IOCs and patterns:\n{context}\n\n"
                f"Return only valid {'SPL' if siem == 'splunk' else 'KQL'} queries, "
                f"one per finding, with a comment above each explaining what it detects."
            )
        }]
    )
    return response.content[0].text


# ─────────────────────────────────────────────────────────────────────────────
# Full blue agent pipeline (CLI entry point)
# ─────────────────────────────────────────────────────────────────────────────

async def run_full(session: Session, log_path: Optional[str] = None) -> None:
    target = session.target
    section(f"BLUE AGENT  →  {target}")
    info(f"Session: {session.id[:8]}…   Mode: blue")

    if log_path:
        section("Log Analysis")
        info(f"Analysing: {log_path}")
        result = analyze_log_file(log_path, session.id)
        if "error" in result:
            error(result["error"])
        else:
            success(f"Analysed {result['total_lines']:,} lines → {result['findings_added']} findings")
            iocs = result["iocs"]
            if iocs["ips"]:
                info(f"Suspicious IPs: {', '.join(iocs['ips'][:5])}")
            if iocs["cves"]:
                info(f"CVEs referenced: {', '.join(iocs['cves'])}")

    section("Hardening Checklist")
    info("Generating AI-powered hardening checklist…")
    checklist = await generate_hardening_checklist(target, session.id)
    console.print(checklist)

    section("IR Playbook")
    info("Generating incident response playbook…")
    playbook = await generate_ir_playbook(session.id)
    console.print(playbook)

    section("SIEM Queries")
    info("Generating Splunk SPL queries…")
    queries = await generate_siem_queries(session.id, siem="splunk")
    console.print(queries)

    section("Blue Team Complete")
    from cli.ui import findings_table
    findings_table(db.get_findings(session.id))
    info(f"Generate report: [bold]phantom report {session.id[:8]}[/bold]")
