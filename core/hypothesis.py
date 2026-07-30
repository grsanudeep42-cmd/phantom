"""
phantom/core/hypothesis.py

AI-powered next-action suggestion engine.
Analyses current session findings and suggests what to do next.
Works with any LLM via core.llm.

Phase 8: CVE auto-trigger — when open service versions are found,
  automatically queries NVD and boosts confidence of CVE-targeting hypotheses.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

from core import session as db
from core.llm import chat_text
from core.session import Session


@dataclass
class Hypothesis:
    hypothesis: str
    suggested_tool: str
    confidence: float    # 0.0–1.0
    reasoning: str


_SYSTEM = (
    "You are an expert penetration tester with 15+ years of experience. "
    "Analyse security findings and suggest the highest-impact next action. "
    "Be specific — name the exact tool and flags to run. "
    "Respond ONLY with valid JSON, no prose."
)


async def generate(
    session: Session,
    max_suggestions: int = 3,
) -> list[Hypothesis]:
    """
    Generate AI-powered next-action hypotheses from session findings.
    Returns a list of Hypothesis objects sorted by confidence (highest first).

    Phase 8 addition: auto-queries NVD for any service version strings found
    in findings, injecting CVE context to sharpen the LLM's suggestions.
    """
    findings = db.get_findings(session.id)
    tried = db.get_tried(session.id)

    if not findings and not tried:
        return []

    # ── CVE auto-trigger ──────────────────────────────────────────────────────
    cve_context = await _collect_cve_context(findings)
    # ─────────────────────────────────────────────────────────────────────────

    findings_text = "\n".join(
        f"- [{f.severity.upper()}] {f.type}: {f.description[:200]}"
        for f in findings[:30]
    )
    tried_text = "\n".join(
        f"- {t.tool} {' '.join(t.args[:3])} → exit {t.exit_code}"
        for t in tried[:20]
    )

    prompt = (
        f"Target: {session.target}\n"
        f"Mode: {session.mode}\n"
        f"Scope: {', '.join(session.scope) if session.scope else 'not declared'}\n\n"
        f"Findings so far:\n{findings_text or 'none yet'}\n\n"
        f"Tools already tried:\n{tried_text or 'none yet'}\n\n"
        + (f"CVE intelligence:\n{cve_context}\n\n" if cve_context else "")
        + f"Generate {max_suggestions} next-action hypotheses. "
        f"Return JSON array:\n"
        f'[{{"hypothesis": "...", "suggested_tool": "...", '
        f'"confidence": 0.0-1.0, "reasoning": "..."}}]'
    )

    try:
        raw = await chat_text(prompt, system=_SYSTEM, max_tokens=1024)

        # Strip markdown code fences if present
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        items = json.loads(raw)
        hyps = [
            Hypothesis(
                hypothesis=item.get("hypothesis", ""),
                suggested_tool=item.get("suggested_tool", ""),
                confidence=float(item.get("confidence", 0.5)),
                reasoning=item.get("reasoning", ""),
            )
            for item in items
            if isinstance(item, dict)
        ]
        # Sort by confidence descending
        hyps.sort(key=lambda h: h.confidence, reverse=True)

        # Boost confidence if critical CVEs were found in auto-trigger
        if cve_context and "CRITICAL" in cve_context:
            for h in hyps:
                if any(kw in h.hypothesis.lower() for kw in ["cve", "exploit", "patch", "version"]):
                    h.confidence = min(1.0, h.confidence + 0.15)

        # Persist to DB
        for h in hyps:
            db.add_hypothesis(
                session.id,
                h.hypothesis,
                rationale=h.reasoning,
                suggested_tool=h.suggested_tool,
                confidence=h.confidence,
            )

        return hyps

    except Exception as e:
        # Non-fatal — hypothesis engine failure never blocks execution
        return []


# ─────────────────────────────────────────────────────────────────────────────
# CVE auto-trigger helper
# ─────────────────────────────────────────────────────────────────────────────

# Pattern to extract "product version" pairs from finding descriptions
_VERSION_RE = re.compile(
    r'(\w[\w\-\.]+)\s+v?(\d+\.\d+[\.\d]*)(?:\s|$)',
    re.IGNORECASE,
)


async def _collect_cve_context(findings) -> str:
    """
    Extract product+version strings from findings and query NVD.
    Returns a formatted CVE summary string for injection into the hypothesis prompt.
    Non-fatal — if NVD is unreachable, returns empty string.
    """
    seen: set[str] = set()
    cve_lines: list[str] = []

    for f in findings[:20]:  # cap scan scope
        matches = _VERSION_RE.findall(f.description)
        for product, version in matches:
            key = f"{product.lower()} {version}"
            if key in seen:
                continue
            seen.add(key)

            try:
                from core.cve import version_cves
                import asyncio
                results = await asyncio.wait_for(
                    version_cves(product, version, max_results=3),
                    timeout=8.0,
                )
                for r in results:
                    if r.cvss_score >= 7.0:  # only notable CVEs
                        exploit_flag = " [PUBLIC EXPLOIT]" if r.has_public_exploit else ""
                        cve_lines.append(
                            f"  {r.id} ({r.severity} CVSS {r.cvss_score}){exploit_flag}: "
                            f"{r.description[:120]}"
                        )
            except Exception:
                pass  # NVD down or timeout — non-fatal

    if not cve_lines:
        return ""

    return "Relevant CVEs found for discovered versions:\n" + "\n".join(cve_lines[:10])
