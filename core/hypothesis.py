"""
phantom/core/hypothesis.py

Generates next-move hypotheses from session findings using Claude.
Called after every tool result is logged.
"""
from __future__ import annotations

import json
from typing import Optional

import anthropic

from config.settings import settings
from core.session import (
    Hypothesis,
    Session,
    add_hypothesis,
    get_findings,
    get_hypotheses,
    get_tried,
    update_hypothesis_status,
)

_client: Optional[anthropic.AsyncAnthropic] = None


def _get_client() -> anthropic.AsyncAnthropic:
    global _client
    if _client is None:
        if not settings.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY not set. Run phantom init to configure.")
        _client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    return _client


HYPOTHESIS_PROMPT = """You are a senior penetration tester reviewing the current state of an active security engagement.

Target: {target}
Mode: {mode}
Scope: {scope}

FINDINGS SO FAR:
{findings}

ALREADY TRIED:
{tried}

PENDING HYPOTHESES (don't re-suggest these):
{pending}

Based on the evidence above, generate up to 3 actionable next-move hypotheses.
For each hypothesis:
- State specifically what you suspect (not vague — be concrete)
- Explain why the evidence supports it
- Specify which tool to use
- Specify exact args to pass to that tool

IMPORTANT rules:
- Only suggest tools from this list: nmap, subfinder, nuclei, httpx, ffuf, gobuster, sqlmap, whatweb, nikto, theHarvester
- Don't re-suggest anything in "ALREADY TRIED"
- Rank by confidence (highest first)
- If there's nothing useful to try, return an empty array

Return ONLY a valid JSON array. No explanation outside the JSON. Schema:
[
  {{
    "hypothesis": "string — what you think is there",
    "rationale": "string — why the evidence suggests this",
    "suggested_tool": "string — tool id from the manifest",
    "suggested_args": {{"arg1": "val1"}},
    "confidence": 0.0
  }}
]"""


async def generate(session: Session) -> list[Hypothesis]:
    """
    Generate hypotheses from the current session state.
    Calls Claude. Results are persisted to SQLite.
    """
    findings = get_findings(session.id)
    tried = get_tried(session.id)
    pending = get_hypotheses(session.id, status="pending")

    if not findings and not tried:
        # Nothing to reason about yet
        return []

    findings_text = "\n".join(
        f"- [{f.severity.upper()}] {f.type}: {f.description}" for f in findings
    ) or "None yet"

    tried_text = "\n".join(
        f"- {t.tool} {t.args} → {t.result_summary[:100]}" for t in tried
    ) or "None yet"

    pending_text = "\n".join(
        f"- {h.hypothesis}" for h in pending
    ) or "None"

    prompt = HYPOTHESIS_PROMPT.format(
        target=session.target,
        mode=session.mode,
        scope=", ".join(session.scope) or "not declared",
        findings=findings_text,
        tried=tried_text,
        pending=pending_text,
    )

    client = _get_client()

    # Retry up to 3 times
    last_error = None
    for attempt in range(3):
        try:
            response = await client.messages.create(
                model=settings.claude_model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text.strip()

            # Strip markdown code fences if present
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            raw = raw.strip()

            hypotheses_data = json.loads(raw)
            break
        except json.JSONDecodeError:
            last_error = "Claude returned non-JSON"
            hypotheses_data = []
            break
        except anthropic.APIError as e:
            last_error = str(e)
            import asyncio
            await asyncio.sleep(4 ** attempt)
    else:
        # All retries failed
        return []

    results = []
    for item in hypotheses_data[:3]:  # Cap at 3
        h = add_hypothesis(
            session_id=session.id,
            hypothesis=item.get("hypothesis", ""),
            rationale=item.get("rationale", ""),
            suggested_tool=item.get("suggested_tool", ""),
            suggested_args=item.get("suggested_args", {}),
            confidence=float(item.get("confidence", 0.5)),
        )
        results.append(h)

    return results


async def confirm(hypothesis_id: str) -> None:
    """Mark a hypothesis as confirmed (tool ran and validated it)."""
    update_hypothesis_status(hypothesis_id, "confirmed")


async def reject(hypothesis_id: str) -> None:
    """Mark a hypothesis as rejected (tool ran and it was a dead end)."""
    update_hypothesis_status(hypothesis_id, "rejected")
