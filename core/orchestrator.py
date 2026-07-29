"""
phantom/core/orchestrator.py

The brain — an agentic tool-use loop that decides what to do next.
Uses core.llm for provider-agnostic AI calls.
Supports Anthropic tool_use AND OpenAI function calling transparently.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from core import session as db
from core.session import Session
from core.memory import add_message, get_context_window

_SYSTEM = """You are PHANTOM — an elite AI security agent that thinks like a senior red teamer.

You have access to tools for reconnaissance, vulnerability scanning, fuzzing, and analysis.
You decide which tools to run, in which order, and how to interpret results.

Rules:
- ALWAYS check scope before touching any asset
- NEVER run exploits unless mode is "red" and scope is confirmed
- Think step-by-step: reconnaissance → footprinting → vulnerability assessment → exploitation
- After each tool run, analyse the output and decide the next move
- When you have enough findings, generate a comprehensive assessment

Available agent modes: red, blue, grey, beginner
Current mode guides what actions are permitted."""

# Tool definitions (normalised — works for both Anthropic and OpenAI)
TOOL_DEFINITIONS = [
    {
        "name": "run_tool",
        "description": "Execute a security tool from the registry. Tool is installed on demand if not present.",
        "input_schema": {
            "type": "object",
            "properties": {
                "tool_id": {
                    "type": "string",
                    "description": "Tool ID from registry (e.g. nmap, subfinder, nuclei, ffuf, httpx)"
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Command-line arguments for the tool"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default 300)",
                    "default": 300
                }
            },
            "required": ["tool_id", "args"]
        }
    },
    {
        "name": "add_finding",
        "description": "Record a security finding to the session database.",
        "input_schema": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "description": "Finding type (e.g. sqli, xss, open_port, subdomain)"},
                "description": {"type": "string", "description": "Human-readable description"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "proof": {"type": "string", "description": "Evidence or PoC string"}
            },
            "required": ["type", "description", "severity"]
        }
    },
    {
        "name": "get_findings",
        "description": "Retrieve all findings recorded so far in this session.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity_filter": {
                    "type": "string",
                    "description": "Optional filter: critical | high | medium | low | info"
                }
            }
        }
    },
    {
        "name": "delegate_agent",
        "description": "Delegate to a specialised sub-agent (red/blue/grey/identity).",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent": {"type": "string", "enum": ["red", "blue", "grey", "identity", "beginner"]},
                "task": {"type": "string", "description": "Specific task for the agent"}
            },
            "required": ["agent", "task"]
        }
    },
    {
        "name": "generate_report",
        "description": "Generate a formatted vulnerability report from session findings.",
        "input_schema": {
            "type": "object",
            "properties": {
                "format": {"type": "string", "enum": ["generic", "hackerone", "bugcrowd"]}
            }
        }
    },
    {
        "name": "finish",
        "description": "Signal that the engagement is complete. Summarise what was found.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "Engagement summary"}
            },
            "required": ["summary"]
        }
    }
]


# ─────────────────────────────────────────────────────────────────────────────
# Tool dispatcher
# ─────────────────────────────────────────────────────────────────────────────

async def _dispatch(tool_name: str, tool_input: dict, session: Session) -> str:
    """Execute the tool requested by the AI and return a string result."""
    try:
        if tool_name == "run_tool":
            from registry.runner import run_tool as rt, ToolNotAvailableError
            try:
                result = await rt(
                    tool_input["tool_id"],
                    tool_input.get("args", []),
                    timeout=tool_input.get("timeout", 300),
                )
                db.add_tried(
                    session.id,
                    tool_input["tool_id"],
                    tool_input.get("args", []),
                    result.summary(),
                    result.exit_code,
                )
                return json.dumps({
                    "stdout": result.stdout[:3000],
                    "stderr": result.stderr[:500],
                    "exit_code": result.exit_code,
                    "duration": result.duration,
                    "truncated": result.truncated,
                })
            except ToolNotAvailableError as e:
                return json.dumps({"error": str(e)})

        elif tool_name == "add_finding":
            db.add_finding(
                session.id,
                tool_input["type"],
                tool_input["description"],
                tool_input.get("severity", "info"),
                tool_input.get("proof", ""),
            )
            return json.dumps({"status": "recorded"})

        elif tool_name == "get_findings":
            findings = db.get_findings(session.id)
            sev = tool_input.get("severity_filter")
            if sev:
                findings = [f for f in findings if f.severity == sev]
            return json.dumps([{
                "type": f.type,
                "description": f.description,
                "severity": f.severity,
                "proof": f.proof[:200] if f.proof else "",
            } for f in findings])

        elif tool_name == "delegate_agent":
            return json.dumps({
                "status": "delegated",
                "agent": tool_input["agent"],
                "note": "Delegation acknowledged — run the sub-agent pipeline"
            })

        elif tool_name == "generate_report":
            from reporting.generator import generate_report
            report = generate_report(session, format=tool_input.get("format", "generic"))
            return report[:2000]  # Truncated for context window

        elif tool_name == "finish":
            return json.dumps({"status": "finished", "summary": tool_input.get("summary", "")})

        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

    except Exception as e:
        return json.dumps({"error": str(e)})


# ─────────────────────────────────────────────────────────────────────────────
# Agentic loop
# ─────────────────────────────────────────────────────────────────────────────

async def run(
    session: Session,
    user_message: str,
    max_iterations: int = 20,
) -> str:
    """
    Run the agentic tool-use loop.
    Returns a final summary string when done.
    """
    from core.llm import chat, get_config
    from cli.ui import info, step, warn

    cfg = get_config()
    info(f"Orchestrator using: {cfg.summary()}")

    # Restore conversation context
    history = get_context_window(session.id)
    add_message(session.id, "user", user_message)

    messages = history + [{"role": "user", "content": user_message}]

    for iteration in range(max_iterations):
        response = await chat(
            messages=messages,
            system=_SYSTEM,
            max_tokens=4096,
            tools=TOOL_DEFINITIONS,
            cfg=cfg,
        )

        # No tool calls — final text answer
        if not response["tool_calls"]:
            final_text = response["text"]
            add_message(session.id, "assistant", final_text)
            return final_text

        # Handle "finish" tool
        finish_calls = [tc for tc in response["tool_calls"] if tc["name"] == "finish"]
        if finish_calls:
            summary = finish_calls[0]["input"].get("summary", "Engagement complete.")
            add_message(session.id, "assistant", summary)
            return summary

        # Log AI reasoning text
        if response["text"]:
            step(f"AI: {response['text'][:120]}…")

        # Execute all tool calls
        tool_results = []
        for tc in response["tool_calls"]:
            step(f"→ {tc['name']}({json.dumps(tc['input'])[:80]}…)")
            result_str = await _dispatch(tc["name"], tc["input"], session)
            tool_results.append({
                "tool_call_id": tc["id"],
                "name": tc["name"],
                "content": result_str,
            })

        # Build next message turn — provider-specific format
        if cfg.provider.value == "anthropic":
            # Anthropic: assistant message contains tool_use blocks, then tool_result turn
            messages.append({
                "role": "assistant",
                "content": [
                    {"type": "text", "text": response["text"]}
                ] + [
                    {"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["input"]}
                    for tc in response["tool_calls"]
                ]
            })
            messages.append({
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tr["tool_call_id"],
                        "content": tr["content"],
                    }
                    for tr in tool_results
                ]
            })
        else:
            # OpenAI format
            messages.append({
                "role": "assistant",
                "content": response["text"] or None,
                "tool_calls": [
                    {
                        "id": tc["id"],
                        "type": "function",
                        "function": {"name": tc["name"], "arguments": json.dumps(tc["input"])},
                    }
                    for tc in response["tool_calls"]
                ],
            })
            for tr in tool_results:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tr["tool_call_id"],
                    "content": tr["content"],
                })

    warn(f"Max iterations ({max_iterations}) reached.")
    return "Engagement reached iteration limit. Check findings with: phantom sessions findings <id>"
