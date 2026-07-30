"""
phantom/core/chainer.py

Module 2 — Vulnerability Chaining Engine (Phase 10).

chain_finding(finding, session_id)

  After every finding is added to session, auto-triggers Claude to:
  1. Look for chains combining the new finding with existing session findings
  2. Suggest common follow-up vulns for this finding type
  3. Cross-reference with the target's tech profile

  Persists chain hypotheses with confidence >= 0.85 (highest priority in queue).
  Non-fatal — all exceptions silently swallowed.
  Designed to run as asyncio.create_task (fire-and-forget).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Hardcoded chain templates (seeded into every LLM prompt as context)
# ─────────────────────────────────────────────────────────────────────────────

CHAIN_TEMPLATES: list[dict] = [
    {
        "chain": "open_redirect + xss",
        "result": "account_takeover",
        "description": "Open redirect lets attacker steal OAuth token via XSS payload in redirect URI",
    },
    {
        "chain": "idor + pii_access",
        "result": "data_breach",
        "description": "IDOR on user ID exposes PII of all users, enabling mass data exfiltration",
    },
    {
        "chain": "ssrf + internal_metadata",
        "result": "cloud_key_exfiltration",
        "description": "SSRF to 169.254.169.254 fetches AWS/GCP metadata including IAM keys",
    },
    {
        "chain": "info_disclosure + bruteforce",
        "result": "credential_stuffing",
        "description": "Error messages reveal valid usernames enabling targeted credential attacks",
    },
    {
        "chain": "self_xss + csrf",
        "result": "stored_xss",
        "description": "CSRF forces victim to submit attacker's XSS payload making it stored/persistent",
    },
    {
        "chain": "jwt_weak + idor",
        "result": "privilege_escalation",
        "description": "Weak JWT secret allows role field manipulation combined with IDOR to access admin APIs",
    },
    {
        "chain": "subdomain_takeover + cookie_scope",
        "result": "session_hijack",
        "description": "Takeover of subdomain allows reading session cookies scoped to parent domain",
    },
]

_CHAIN_TEMPLATES_TEXT = "\n".join(
    f"  • {t['chain']} → {t['result']}: {t['description']}"
    for t in CHAIN_TEMPLATES
)


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ChainResult:
    steps: list[str]            # e.g. ["Exploit IDOR on /api/user/{id}", "Access PII fields"]
    combined_severity: str      # critical | high | medium | low
    next_test: str              # what to do next to confirm the chain
    potential_impact: str
    confidence: float = 0.9
    component_types: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# LLM system prompt
# ─────────────────────────────────────────────────────────────────────────────

_CHAIN_SYSTEM = (
    "You are an elite bug bounty hunter specialising in vulnerability chaining — "
    "combining multiple low/medium findings into critical attack paths. "
    "Think about trust boundaries, data flows, and what a real attacker would chain together. "
    "Respond ONLY with valid JSON. No prose, no markdown fences."
)


# ─────────────────────────────────────────────────────────────────────────────
# Core function
# ─────────────────────────────────────────────────────────────────────────────

async def chain_finding(finding_id: str, session_id: str) -> list[ChainResult]:
    """
    Analyse a newly-added finding for attack chain opportunities.

    Pulls all existing session findings + tech_profile from session KV,
    sends to Claude, and persists discovered chains as high-priority hypotheses.

    Designed for fire-and-forget use via asyncio.create_task().
    Always returns — never raises.
    """
    try:
        from core import session as db

        # Get the new finding
        all_findings = db.get_findings(session_id)
        new_finding = next((f for f in all_findings if f.id == finding_id), None)
        if new_finding is None:
            return []

        # Get session context
        other_findings = [f for f in all_findings if f.id != finding_id]

        tech_profile_json = db.get_session_kv(session_id, "tech_profile") or "{}"
        try:
            tech = json.loads(tech_profile_json)
        except json.JSONDecodeError:
            tech = {}

        # Nothing to chain against yet — store new finding type for future runs
        if not other_findings:
            return []

        # Build prompt
        new_finding_text = (
            f"Type: {new_finding.type}\n"
            f"Severity: {new_finding.severity}\n"
            f"Description: {new_finding.description[:300]}"
        )
        other_text = "\n".join(
            f"  - [{f.severity.upper()}] {f.type}: {f.description[:150]}"
            for f in other_findings[:20]
        )
        stack_text = (
            f"Stack: {', '.join(tech.get('stack', []) + tech.get('frameworks', []))[:100]}, "
            f"API: {tech.get('api_type', 'unknown')}, "
            f"Auth: {tech.get('auth_method', 'unknown')}"
            if tech else "tech profile not available"
        )

        prompt = (
            f"NEW FINDING:\n{new_finding_text}\n\n"
            f"OTHER SESSION FINDINGS:\n{other_text or 'none yet'}\n\n"
            f"TARGET TECH PROFILE:\n{stack_text}\n\n"
            f"KNOWN CHAIN TEMPLATES (use as inspiration):\n{_CHAIN_TEMPLATES_TEXT}\n\n"
            f"Analyse attack chains possible by combining the NEW FINDING with:\n"
            f"1. Other findings already in this session\n"
            f"2. Common follow-up vulnerabilities for '{new_finding.type}'\n"
            f"3. The target's architecture and trust model\n\n"
            f"For each discovered chain, provide:\n"
            f'[{{'
            f'"steps": ["step1", "step2", "step3"], '
            f'"combined_severity": "critical|high|medium", '
            f'"next_test": "what to test next to confirm this chain", '
            f'"potential_impact": "what attacker achieves", '
            f'"confidence": 0.0-1.0, '
            f'"component_types": ["finding_type_a", "finding_type_b"]'
            f'}}]'
            f"\n\nReturn an empty array [] if no meaningful chains exist. "
            f"Focus only on chains with real impact. Quality over quantity."
        )

        from core.llm import chat_text
        raw = await chat_text(prompt, system=_CHAIN_SYSTEM, max_tokens=1500)

        # Strip markdown
        raw = raw.strip()
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1] if len(parts) > 1 else raw
            if raw.startswith("json"):
                raw = raw[4:]

        items = json.loads(raw)
        chains = [
            ChainResult(
                steps=item.get("steps", []),
                combined_severity=item.get("combined_severity", "medium"),
                next_test=item.get("next_test", ""),
                potential_impact=item.get("potential_impact", ""),
                confidence=float(item.get("confidence", 0.9)),
                component_types=item.get("component_types", [new_finding.type]),
            )
            for item in items
            if isinstance(item, dict) and item.get("steps")
        ]

        # Persist as high-priority hypotheses
        _persist_chains(session_id, chains, new_finding)

        return chains

    except Exception:
        return []  # Always non-fatal


def _persist_chains(session_id: str, chains: list[ChainResult], trigger_finding) -> None:
    """Save each chain as a hypothesis with elevated confidence."""
    if not chains:
        return
    try:
        from core import session as db
        for chain in chains:
            steps_text = " → ".join(chain.steps[:4])
            hypothesis_text = (
                f"[CHAIN] {steps_text}"
            )
            rationale = (
                f"Attack chain triggered by finding '{trigger_finding.type}'. "
                f"Impact: {chain.potential_impact}. "
                f"Next: {chain.next_test}"
            )
            # Chains always get elevated confidence (0.85 floor)
            confidence = max(chain.confidence, 0.85)
            db.add_hypothesis(
                session_id,
                hypothesis=hypothesis_text,
                rationale=rationale,
                suggested_tool=_suggest_tool_for_chain(chain),
                suggested_args={"chain_steps": chain.steps, "severity": chain.combined_severity},
                confidence=confidence,
            )
    except Exception:
        pass


def _suggest_tool_for_chain(chain: ChainResult) -> str:
    """Pick the most relevant tool for confirming the chain's next step."""
    next_test_lower = chain.next_test.lower()
    tool_map = [
        ("xss",        "dalfox"),
        ("sqli",       "sqlmap"),
        ("ssrf",       "curl"),
        ("idor",       "ffuf"),
        ("redirect",   "httpx"),
        ("jwt",        "phantom_jwt_analyze"),
        ("subdomain",  "subfinder"),
        ("upload",     "curl"),
        ("api",        "ffuf"),
        ("auth",       "hydra"),
    ]
    for kw, tool in tool_map:
        if kw in next_test_lower:
            return tool
    return "manual"


# ─────────────────────────────────────────────────────────────────────────────
# Sync-safe fire-and-forget wrapper
# ─────────────────────────────────────────────────────────────────────────────

def fire_chain_analysis(finding_id: str, session_id: str) -> None:
    """
    Schedule chain_finding as a background asyncio task if a loop is running.
    Called from the synchronous add_finding() — never blocks.
    """
    import asyncio
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(chain_finding(finding_id, session_id))
    except RuntimeError:
        pass  # No running loop (e.g. sync test context) — skip silently
