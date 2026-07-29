"""
phantom/core/hypothesis.py

AI-powered next-action suggestion engine.
Analyses current session findings and suggests what to do next.
Works with any LLM via core.llm.
"""
from __future__ import annotations

import json
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
    """
    findings = db.get_findings(session.id)
    tried = db.get_tried(session.id)

    if not findings and not tried:
        return []

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
        f"Generate {max_suggestions} next-action hypotheses. "
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
