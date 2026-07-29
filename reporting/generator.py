"""
phantom/reporting/generator.py

Fills Jinja2 templates from session findings.
Supports generic, hackerone, and bugcrowd formats.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader

from core.session import Finding, Session, get_findings, get_hypotheses, get_tried

TEMPLATES_DIR = Path(__file__).parent / "templates"

_env: Optional[Environment] = None


def _get_env() -> Environment:
    global _env
    if _env is None:
        _env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
    return _env


def _severity_order(f: Finding) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        f.severity.lower(), 5
    )


def _auto_vuln_title(findings: list[Finding]) -> str:
    """Pick the most severe finding as the report title."""
    if not findings:
        return "Security Assessment Report"
    top = sorted(findings, key=_severity_order)[0]
    return f"{top.type.replace('_', ' ').title()} — {top.description[:80]}"


def _auto_poc(findings: list[Finding]) -> str:
    """Use proof from the top finding as PoC."""
    for f in sorted(findings, key=_severity_order):
        if f.proof:
            return f.proof[:800]
    return "See supporting findings."


def _auto_impact(findings: list[Finding]) -> str:
    criticals = [f for f in findings if f.severity == "critical"]
    highs = [f for f in findings if f.severity == "high"]
    if criticals:
        return f"Critical severity findings could allow an attacker to fully compromise the target. {criticals[0].description}"
    if highs:
        return f"High severity findings could result in significant data exposure or system compromise. {highs[0].description}"
    return "The identified vulnerabilities could be chained or individually exploited to impact the confidentiality, integrity, or availability of the target."


def _auto_remediation(findings: list[Finding]) -> str:
    return (
        "1. Immediately patch all critical and high severity findings.\n"
        "2. Review and harden the affected components.\n"
        "3. Implement WAF rules to detect exploitation attempts.\n"
        "4. Conduct a follow-up scan after remediation to confirm fixes.\n"
        "5. Consider a full penetration test after hardening."
    )


def generate_report(
    session: Session,
    format: str = "generic",
    output_path: Optional[str] = None,
) -> str:
    """
    Generate a formatted report from session findings.
    format: generic | hackerone | bugcrowd
    Returns the rendered report as a string and optionally writes to file.
    """
    findings = sorted(get_findings(session.id), key=_severity_order)
    tried = get_tried(session.id)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    template_file = f"{format}.j2"
    env = _get_env()

    try:
        template = env.get_template(template_file)
    except Exception:
        template = env.get_template("generic.j2")

    # Build context
    ctx: dict = {
        "session": session,
        "findings": findings,
        "tried": tried,
        "generated_at": now,
        # Auto-generated fields for bug bounty templates
        "vuln_title": _auto_vuln_title(findings),
        "severity": findings[0].severity if findings else "info",
        "cvss_score": {
            "critical": "9.5", "high": "7.5", "medium": "5.0",
            "low": "2.0", "info": "0.0"
        }.get(findings[0].severity if findings else "info", "0.0"),
        "endpoint": session.target,
        "description": findings[0].description if findings else "No findings.",
        "poc": _auto_poc(findings),
        "impact": _auto_impact(findings),
        "remediation": _auto_remediation(findings),
        "expected": "The application should handle all inputs safely and not expose sensitive data or functionality.",
        "actual": f"{len(findings)} security issues were identified during testing.",
        "steps": list(enumerate([
            f"Navigate to {session.target}",
            "Run PHANTOM recon and vuln scan",
            "Observe the findings listed in this report",
        ], start=1)),
        # Bugcrowd-specific
        "vrt_category": "Server-Side Injection",
    }

    rendered = template.render(**ctx)

    if output_path:
        Path(output_path).write_text(rendered)

    return rendered
