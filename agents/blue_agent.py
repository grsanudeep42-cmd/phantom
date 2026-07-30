"""
phantom/agents/blue_agent.py

Defensive mode — log analysis, IOC extraction, hardening, IR playbooks.
Uses core.llm — works with any configured LLM provider.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from cli.ui import console, error, finding, info, section, step, success, warn
from core import session as db
from core.llm import chat_text
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

_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "172.")


def extract_iocs(text: str) -> dict:
    ips = list(set(IP_REGEX.findall(text)))
    public_ips = [ip for ip in ips if not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)]
    return {
        "ips":     public_ips[:50],
        "domains": list(set(DOMAIN_REGEX.findall(text)))[:50],
        "md5":     list(set(HASH_MD5.findall(text)))[:20],
        "sha1":    list(set(HASH_SHA1.findall(text)))[:20],
        "sha256":  list(set(HASH_SHA256.findall(text)))[:20],
        "cves":    list(set(CVE_REGEX.findall(text)))[:20],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Log analysis
# ─────────────────────────────────────────────────────────────────────────────

_ATTACK_PATTERNS = [
    (r'(union\s+select|sleep\(\d+\)|benchmark\()',    "SQL Injection attempt",    "high"),
    (r'(<script[\s>]|javascript:|onerror\s*=)',        "XSS attempt",             "high"),
    (r'(\.\./){3,}',                                   "Path traversal attempt",  "medium"),
    (r'(cmd\.exe|/bin/sh|/bin/bash|powershell)',        "Command injection",       "critical"),
    (r'(401|403)\s+\d+',                               "Auth failure",            "low"),
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*(nikto|nmap|sqlmap|masscan)', "Scanner detected", "medium"),
]


def analyze_log_file(log_path: str, session_id: str) -> dict:
    path = Path(log_path)
    if not path.exists():
        return {"error": f"File not found: {log_path}"}

    text = path.read_text(errors="replace")
    iocs = extract_iocs(text)
    findings_added = 0

    for pattern, label, severity in _ATTACK_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            db.add_finding(session_id, "log_pattern", f"{label}: {len(matches)} hit(s)", severity, str(matches[:3]))
            findings_added += 1
            finding(severity, f"{label} ({len(matches)} hits)")

    for ip in iocs["ips"][:10]:
        db.add_finding(session_id, "ioc_ip", f"Suspicious IP: {ip}", "low", f"from {log_path}")
        findings_added += 1

    for cve in iocs["cves"]:
        db.add_finding(session_id, "cve_mention", f"CVE referenced: {cve}", "medium", "found in log")
        findings_added += 1

    return {"log": log_path, "iocs": iocs, "findings_added": findings_added, "total_lines": text.count("\n")}


# ─────────────────────────────────────────────────────────────────────────────
# AI-powered analysis (provider-agnostic)
# ─────────────────────────────────────────────────────────────────────────────

async def generate_hardening_checklist(target: str, session_id: str) -> str:
    findings = db.get_findings(session_id)
    if not findings:
        return "No findings yet. Run a scan or provide a log file first."

    findings_text = "\n".join(
        f"- [{f.severity.upper()}] {f.type}: {f.description}" for f in findings
    )
    return await chat_text(
        prompt=(
            f"Target: {target}\nFindings:\n{findings_text}\n\n"
            "Generate a prioritised hardening checklist in markdown. "
            "Group by priority (Critical/High/Medium/Low). "
            "Be specific — include actual config changes, not just 'update software'."
        ),
        system="You are a security hardening expert. Be specific and actionable.",
        max_tokens=2048,
    )


async def generate_ir_playbook(session_id: str) -> str:
    findings = db.get_findings(session_id)
    if not findings:
        return "No findings. Run blue team log analysis first."

    context = "\n".join(
        f"- [{f.severity.upper()}] {f.type}: {f.description}" for f in findings[:30]
    )
    return await chat_text(
        prompt=(
            f"Evidence:\n{context}\n\n"
            "Generate a step-by-step incident response playbook covering:\n"
            "1. Immediate containment\n2. Evidence collection\n"
            "3. Root cause analysis\n4. Remediation\n5. Post-incident review\n"
            "Include actual commands where relevant."
        ),
        system="You are a DFIR specialist. Be specific and actionable.",
        max_tokens=2048,
    )


async def generate_siem_queries(session_id: str, siem: str = "splunk") -> str:
    findings = db.get_findings(session_id)
    if not findings:
        return "No findings to generate queries from."

    context = "\n".join(f"- {f.type}: {f.description}" for f in findings[:20])
    lang = "SPL" if siem == "splunk" else "KQL"
    return await chat_text(
        prompt=(
            f"Generate {siem.upper()} search queries for:\n{context}\n\n"
            f"Return valid {lang} queries, one per finding, "
            f"with a comment above each explaining what it detects."
        ),
        system="You are a SIEM expert. Return only query code with comments.",
        max_tokens=1024,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Delegation entry point — called by orchestrator.delegate_agent
# ─────────────────────────────────────────────────────────────────────────────

async def run_blue_phase(target: str, session_id: str, task: str) -> str:
    """
    Orchestrator-callable delegation handler.
    Routes to the correct blue capability based on task description.
    Returns a plain text or JSON result string.
    """
    task_lower = task.lower()
    if any(k in task_lower for k in ("harden", "checklist", "remediat")):
        result = await generate_hardening_checklist(target, session_id)
        return result[:800]
    elif any(k in task_lower for k in ("ir", "incident", "playbook", "respond")):
        result = await generate_ir_playbook(session_id)
        return result[:800]
    elif any(k in task_lower for k in ("siem", "query", "splunk", "kql")):
        siem = "splunk" if "splunk" in task_lower else "azure"
        result = await generate_siem_queries(session_id, siem)
        return result[:800]
    elif any(k in task_lower for k in ("log", "analyse", "ioc")):
        # Extract log path from task if present
        import re
        path_match = re.search(r'(/\S+|\w+\.\w+)', task)
        log_path = path_match.group(1) if path_match else "/var/log/syslog"
        result = analyze_log_file(log_path, session_id)
        return str(result)[:800]
    else:
        result = await generate_hardening_checklist(target, session_id)
        return result[:800]


# ─────────────────────────────────────────────────────────────────────────────
# Full pipeline
# ─────────────────────────────────────────────────────────────────────────────

async def run_full(session: Session, log_path: Optional[str] = None) -> None:
    from cli.ui import findings_table
    from core.llm import get_config
    target = session.target
    section(f"BLUE AGENT  →  {target}  [{get_config().summary()}]")

    if log_path:
        section("Log Analysis")
        result = analyze_log_file(log_path, session.id)
        if "error" in result:
            error(result["error"])
        else:
            success(f"Analysed {result['total_lines']:,} lines → {result['findings_added']} findings")
            iocs = result["iocs"]
            if iocs["ips"]:
                info(f"Suspicious IPs: {', '.join(iocs['ips'][:5])}")
            if iocs["cves"]:
                info(f"CVEs: {', '.join(iocs['cves'])}")

    section("Hardening Checklist")
    console.print(await generate_hardening_checklist(target, session.id))

    section("IR Playbook")
    console.print(await generate_ir_playbook(session.id))

    section("SIEM Queries")
    console.print(await generate_siem_queries(session.id))

    section("Blue Team Complete")
    findings_table(db.get_findings(session.id))
    info(f"Report: [bold]phantom report {session.id[:8]}[/bold]")
