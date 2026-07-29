"""
phantom/core/orchestrator.py

The brain. Receives a task, reasons about it via Claude tool_use,
delegates to the right agent, manages session context.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Optional

import anthropic

from config.settings import settings
from core import hypothesis as hyp_engine
from core.session import (
    Session,
    get_findings,
    get_hypotheses,
    get_session,
    get_tried,
    update_session_status,
)

_client: Optional[anthropic.AsyncAnthropic] = None


def _get_client() -> anthropic.AsyncAnthropic:
    global _client
    if _client is None:
        if not settings.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set.")
        _client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    return _client


# ─────────────────────────────────────────────────────────────────────────────
# Response type
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AgentResponse:
    session_id: str
    agent: str
    output: str
    findings_count: int
    hypotheses: list
    status: str  # ok | error | paused

    def to_json(self) -> str:
        d = asdict(self)
        d["hypotheses"] = [asdict(h) for h in self.hypotheses]
        return json.dumps(d, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Mode detection
# ─────────────────────────────────────────────────────────────────────────────

MODE_KEYWORDS = {
    "red":      ["attack", "exploit", "red team", "offensive", "hack", "penetrate"],
    "blue":     ["defend", "hardening", "log", "incident", "siem", "blue team"],
    "grey":     ["bug bounty", "oscp", "responsible disclosure", "cvss", "grey"],
    "beginner": ["learn", "explain", "ctf", "what is", "beginner", "newbie"],
    "scan":     ["scan", "recon", "discover", "enumerate", "footprint"],
}


def detect_mode(task: str) -> str:
    task_lower = task.lower()
    scores = {mode: 0 for mode in MODE_KEYWORDS}
    for mode, keywords in MODE_KEYWORDS.items():
        for kw in keywords:
            if kw in task_lower:
                scores[mode] += 1
    best = max(scores, key=lambda m: scores[m])
    return best if scores[best] > 0 else "scan"


# ─────────────────────────────────────────────────────────────────────────────
# Tool definitions for Claude tool_use
# ─────────────────────────────────────────────────────────────────────────────

ORCHESTRATOR_TOOLS = [
    {
        "name": "run_recon",
        "description": "Run reconnaissance on a target. Includes subdomain enum, port scan, HTTP probing.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain or IP"},
                "session_id": {"type": "string", "description": "Active session ID"},
            },
            "required": ["target", "session_id"],
        },
    },
    {
        "name": "run_vuln_scan",
        "description": "Run vulnerability scan using nuclei templates against a target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "session_id": {"type": "string"},
                "severity": {
                    "type": "string",
                    "description": "Minimum severity: critical, high, medium, low, info",
                    "default": "medium",
                },
            },
            "required": ["target", "session_id"],
        },
    },
    {
        "name": "run_tool",
        "description": "Run a specific security tool with custom arguments.",
        "input_schema": {
            "type": "object",
            "properties": {
                "tool_id": {
                    "type": "string",
                    "description": "Tool ID from manifest (nmap, nuclei, ffuf, etc.)",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Command line arguments for the tool",
                },
                "session_id": {"type": "string"},
                "timeout": {"type": "integer", "default": 300},
            },
            "required": ["tool_id", "args", "session_id"],
        },
    },
    {
        "name": "get_session_state",
        "description": "Get the current session findings and tried actions for context.",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "add_finding",
        "description": "Record a new finding discovered during analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "type": {"type": "string", "description": "e.g. sqli, xss, open_port, subdomain"},
                "description": {"type": "string"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "proof": {"type": "string", "description": "Evidence or PoC snippet"},
            },
            "required": ["session_id", "type", "description", "severity"],
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Tool execution handler
# ─────────────────────────────────────────────────────────────────────────────

async def _handle_tool_call(tool_name: str, tool_input: dict) -> str:
    """Execute a tool_use call from Claude and return string result."""
    from core import session as db
    from registry.runner import run_tool, ToolNotAvailableError

    if tool_name == "get_session_state":
        session_id = tool_input["session_id"]
        findings = db.get_findings(session_id)
        tried = db.get_tried(session_id)
        return json.dumps({
            "findings": [asdict(f) for f in findings],
            "tried": [asdict(t) for t in tried],
        })

    elif tool_name == "add_finding":
        session_id = tool_input["session_id"]
        f = db.add_finding(
            session_id=session_id,
            type=tool_input["type"],
            description=tool_input["description"],
            severity=tool_input.get("severity", "info"),
            proof=tool_input.get("proof", ""),
        )
        return json.dumps({"status": "ok", "finding_id": f.id})

    elif tool_name == "run_tool":
        tool_id = tool_input["tool_id"]
        args = tool_input["args"]
        session_id = tool_input["session_id"]
        timeout = tool_input.get("timeout", 300)
        try:
            result = await run_tool(tool_id, args, timeout=timeout)
            db.add_tried(
                session_id, tool_id, args,
                result_summary=result.summary(),
                exit_code=result.exit_code,
            )
            return result.to_json()
        except ToolNotAvailableError as e:
            return json.dumps({"error": str(e)})

    elif tool_name == "run_recon":
        # Delegate to red agent recon phase
        from agents.red_agent import run_recon_phase
        target = tool_input["target"]
        session_id = tool_input["session_id"]
        output = await run_recon_phase(target, session_id)
        return output

    elif tool_name == "run_vuln_scan":
        from agents.red_agent import run_vuln_scan_phase
        target = tool_input["target"]
        session_id = tool_input["session_id"]
        severity = tool_input.get("severity", "medium")
        output = await run_vuln_scan_phase(target, session_id, severity)
        return output

    return json.dumps({"error": f"Unknown tool: {tool_name}"})


# ─────────────────────────────────────────────────────────────────────────────
# Main orchestrator
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are PHANTOM, an AI-powered penetration testing agent.
You think like a senior red teamer. You are methodical, precise, and strategic.

Current session:
- Target: {target}
- Mode: {mode}
- Scope: {scope}
- Findings so far: {findings_count}
- Actions tried: {tried_count}

RULES you must follow:
1. Never run tools outside the declared scope
2. Always think about what the most impactful next action is
3. Record every finding with add_finding — even informational ones
4. When you're done, summarize what was found clearly

You have tools available. Use them systematically."""


async def run(
    task: str,
    session: Session,
    mode: Optional[str] = None,
) -> AgentResponse:
    """
    Main entry point. Process a task for a given session.
    Uses Claude tool_use to reason and delegate.
    """
    if not mode:
        mode = detect_mode(task)

    findings = get_findings(session.id)
    tried = get_tried(session.id)

    system = SYSTEM_PROMPT.format(
        target=session.target,
        mode=mode,
        scope=", ".join(session.scope) or "not set",
        findings_count=len(findings),
        tried_count=len(tried),
    )

    messages = [{"role": "user", "content": task}]
    client = _get_client()

    full_output_parts = []
    last_error = None

    # Agentic loop — continue until Claude stops calling tools
    for _turn in range(20):  # Hard cap on turns
        for attempt in range(3):
            try:
                response = await client.messages.create(
                    model=settings.claude_model,
                    max_tokens=4096,
                    system=system,
                    tools=ORCHESTRATOR_TOOLS,
                    messages=messages,
                )
                last_error = None
                break
            except anthropic.APIError as e:
                last_error = str(e)
                import asyncio
                await asyncio.sleep(4 ** attempt)
        else:
            update_session_status(session.id, "error")
            return AgentResponse(
                session_id=session.id,
                agent=mode,
                output=f"API error after retries: {last_error}",
                findings_count=len(get_findings(session.id)),
                hypotheses=[],
                status="error",
            )

        # Collect text from this response
        for block in response.content:
            if hasattr(block, "text"):
                full_output_parts.append(block.text)

        # If Claude stopped → we're done
        if response.stop_reason == "end_turn":
            break

        # If Claude wants to call tools → process them
        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    tool_result = await _handle_tool_call(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": tool_result,
                    })

            # Add Claude's response + our tool results to message history
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
        else:
            break

    # Generate hypotheses from updated session state
    hypotheses = await hyp_engine.generate(session)
    final_findings = get_findings(session.id)

    return AgentResponse(
        session_id=session.id,
        agent=mode,
        output="\n".join(full_output_parts),
        findings_count=len(final_findings),
        hypotheses=hypotheses,
        status="ok",
    )


async def delegate(
    agent_name: str,
    subtask: str,
    session: Session,
) -> AgentResponse:
    """
    Delegate a subtask directly to a named agent,
    bypassing mode detection.
    """
    return await run(subtask, session, mode=agent_name)
