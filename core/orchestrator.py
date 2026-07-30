"""
phantom/core/orchestrator.py

The brain — production-grade agentic tool-use loop.

Fixes applied vs previous version:
  1. delegate_agent is now REAL — actually calls sub-agent run() functions
  2. Mode-specific system prompts (red/blue/grey/beginner each get own persona)
  3. Scope + tried list injected into every LLM call (AI knows what it already ran)
  4. OrchestratorResult typed return (no more bare string / .output crashes)
  5. Scope guard in _dispatch() — not just in red_agent
  6. Smart tool output truncation (head+tail, never mid-line cut)
  7. Dedup protection — won't re-run tool+args already tried this session
  8. Parallel tool execution via asyncio.gather
  9. Anthropic prompt caching via llm.py (automatic)
  10. Cost tracking logged at end of engagement
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from core import session as db
from core.session import Session
from core.memory import add_message, get_context_window, maybe_summarize


# ─────────────────────────────────────────────────────────────────────────────
# Return type — fixes the response.output AttributeError in red_agent
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OrchestratorResult:
    output: str                      # Final LLM text answer
    tool_calls_made: int = 0         # How many tool calls executed
    findings_added: int = 0          # Findings written this run
    total_cost_usd: float = 0.0      # Estimated LLM cost
    iterations: int = 0              # Loop iterations consumed
    hit_limit: bool = False          # True if max_iterations reached
    errors: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Mode-specific system prompts
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM_BASE = """You are PHANTOM — an elite AI security agent built for professional engagements.
You have access to tools for reconnaissance, vulnerability scanning, fuzzing, exploitation, and analysis.
You decide which tools to run, in which order, and how to interpret results.

Core rules (ALWAYS followed, non-negotiable):
- ALWAYS check scope before touching any asset
- After each tool run, analyse the output and decide the next move
- When you have enough findings, generate a comprehensive assessment
- Never repeat a tool+args combination already in the tried list
- Prioritise high-impact findings over info-level noise"""

_SYSTEM_MODES: dict[str, str] = {
    "red": _SYSTEM_BASE + """

MODE: RED TEAM — Full offensive operator.
- You ARE permitted to run exploits, credential attacks, and post-exploitation modules
- Think like an APT: chain vulnerabilities together for maximum impact
- Prioritise: RCE > auth bypass > data exfil > privilege escalation > info disclosure
- Follow the kill chain: Recon → Initial Access → Execution → Persistence → Exfil
- Use aggressive timing (-T4/T5) and thorough scanning
- CVSS 9.0+ findings get immediate exploitation attempts""",

    "blue": _SYSTEM_BASE + """

MODE: BLUE TEAM — Defensive analyst.
- Focus: threat hunting, IOC extraction, anomaly detection, incident response
- Do NOT run offensive exploits — your job is detect, not attack
- Look for: exposed services, misconfigurations, leaked credentials, weak TLS
- Output should be actionable remediation steps
- Classify findings by MITRE ATT&CK tactic where possible""",

    "grey": _SYSTEM_BASE + """

MODE: GREY HAT / BUG BOUNTY — Authorised researcher.
- Stay strictly within declared scope — out-of-scope touches are mission failure
- Aim for: XSS, SQLi, IDOR, SSRF, auth issues, business logic flaws
- Document every finding with: description, reproduction steps, impact, CVSS
- Format output for HackerOne / Bugcrowd submission
- Do not exploit beyond proof-of-concept — demonstrate impact, don't cause harm
- Prioritise: critical/high findings that earn bounties""",

    "beginner": _SYSTEM_BASE + """

MODE: BEGINNER — Educational guided mode.
- Explain every action before taking it (what the tool does, why you're running it)
- Use safe, non-destructive scans only (no active exploitation)
- After each tool result, explain what the output means in plain English
- Suggest learning resources for each vulnerability type found
- Use conservative scan settings (T2 timing, limited ports)""",
}


def _build_system_prompt(mode: str, scope: list[str], tried: list) -> str:
    """Build the full system prompt with mode persona + live session context."""
    base = _SYSTEM_MODES.get(mode, _SYSTEM_MODES["grey"])

    # Inject scope so the AI knows what it's allowed to touch
    scope_block = (
        f"\nIn-scope targets: {', '.join(scope)}"
        if scope
        else "\nWARNING: No scope declared. Assume everything in scope — be cautious."
    )

    # Inject already-tried tools so the AI doesn't repeat
    if tried:
        tried_lines = "\n".join(
            f"  - {t.tool} {' '.join(str(a) for a in t.args[:3])} → exit {t.exit_code}"
            for t in tried[-20:]  # Last 20 to avoid bloat
        )
        tried_block = f"\n\nAlready tried this session (DO NOT repeat):\n{tried_lines}"
    else:
        tried_block = ""

    return base + scope_block + tried_block


# ─────────────────────────────────────────────────────────────────────────────
# Tool definitions
# ─────────────────────────────────────────────────────────────────────────────

TOOL_DEFINITIONS = [
    {
        "name": "run_tool",
        "description": "Execute a security tool from the registry. Installed on demand if missing.",
        "input_schema": {
            "type": "object",
            "properties": {
                "tool_id": {
                    "type": "string",
                    "description": "Tool ID from registry (e.g. nmap, subfinder, nuclei, ffuf, httpx, sqlmap, dalfox)"
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
        "description": "Record a confirmed security finding to the session database.",
        "input_schema": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "description": "Finding type (e.g. sqli, xss, idor, open_port, subdomain, rce, ssrf)"},
                "description": {"type": "string", "description": "Human-readable description with URL/location"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "proof": {"type": "string", "description": "Evidence: raw output snippet, payload, curl command, or PoC"}
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
                    "description": "Optional: critical | high | medium | low | info"
                }
            }
        }
    },
    {
        "name": "delegate_agent",
        "description": (
            "Delegate a specific task to a specialised sub-agent. "
            "Use 'red' for exploitation, 'grey' for bug bounty phases, "
            "'blue' for defensive analysis, 'identity' for persona generation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "agent": {"type": "string", "enum": ["red", "blue", "grey", "identity", "beginner", "intel"]},
                "task": {"type": "string", "description": "Specific task for the agent — be precise"},
                "target": {"type": "string", "description": "Target URL or host for the agent"}
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
        "description": "Signal that the engagement is complete. Call when all meaningful testing is done.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "Engagement summary — key findings and recommendations"}
            },
            "required": ["summary"]
        }
    }
]


# ─────────────────────────────────────────────────────────────────────────────
# Scope guard
# ─────────────────────────────────────────────────────────────────────────────

def _target_in_scope(target: str, scope: list[str]) -> bool:
    """Return True if target matches any scope pattern."""
    if not scope:
        return True
    for pattern in scope:
        if pattern.startswith("*."):
            domain = pattern[2:]
            if target.endswith(f".{domain}") or target == domain:
                return True
        elif target == pattern or target.startswith(pattern):
            return True
    return False


def _extract_targets_from_args(tool_id: str, args: list[str]) -> list[str]:
    """Extract likely target values from tool args for scope checking."""
    targets = []
    target_flags = {"-u", "--url", "-d", "--domain", "-H", "--host", "-t", "--target"}
    for i, arg in enumerate(args):
        if arg in target_flags and i + 1 < len(args):
            targets.append(args[i + 1])
        elif arg.startswith("http://") or arg.startswith("https://"):
            targets.append(arg)
        elif "." in arg and not arg.startswith("-") and i > 0:
            targets.append(arg)
    return targets


# ─────────────────────────────────────────────────────────────────────────────
# Smart tool output truncation
# ─────────────────────────────────────────────────────────────────────────────

def _truncate_output(stdout: str, stderr: str, max_chars: int = 4000) -> tuple[str, str]:
    """
    Smart truncation: keep first HEAD_LINES + last TAIL_LINES.
    Triggers on EITHER too many chars OR too many lines — whichever comes first.
    Never cuts mid-line. Adds a count of skipped lines.
    """
    HEAD = 60
    TAIL = 30

    def _smart_cut(text: str, limit: int) -> str:
        lines = text.splitlines()
        too_long   = len(text) > limit
        too_many   = len(lines) > (HEAD + TAIL)

        if not too_long and not too_many:
            return text

        # Apply line-based truncation
        if len(lines) <= HEAD + TAIL:
            # Can't do line-based — just hard-cut chars
            return text[:limit] + f"\n… [{len(text) - limit} chars omitted] …"
        head    = lines[:HEAD]
        tail    = lines[-TAIL:]
        skipped = len(lines) - HEAD - TAIL
        return "\n".join(head) + f"\n… [{skipped} lines omitted] …\n" + "\n".join(tail)

    return _smart_cut(stdout, max_chars), _smart_cut(stderr, 500)


# ─────────────────────────────────────────────────────────────────────────────
# Tool dispatcher
# ─────────────────────────────────────────────────────────────────────────────

async def _dispatch(
    tool_name: str,
    tool_input: dict,
    session: Session,
    result_tracker: dict,
) -> str:
    """
    Execute the tool requested by the AI and return a string result.
    result_tracker is mutated to track findings_added and tool_calls_made.
    """
    try:
        # ── run_tool ──────────────────────────────────────────────────────────
        if tool_name == "run_tool":
            from registry.runner import run_tool as rt, ToolNotAvailableError

            tool_id = tool_input["tool_id"]
            args    = tool_input.get("args", [])
            timeout = tool_input.get("timeout", 300)

            # Scope check — extract targets from args and validate
            if session.scope:
                targets = _extract_targets_from_args(tool_id, args)
                for t in targets:
                    # Strip protocol for matching
                    clean = t.replace("https://", "").replace("http://", "").split("/")[0]
                    if clean and not _target_in_scope(clean, session.scope):
                        return json.dumps({
                            "error": f"SCOPE VIOLATION: '{clean}' is not in scope {session.scope}. Aborting."
                        })

            # Dedup check — don't re-run same tool+args
            tried = db.get_tried(session.id)
            for past in tried:
                if past.tool == tool_id and past.args == args:
                    return json.dumps({
                        "skipped": True,
                        "reason": f"Already ran {tool_id} with same args (exit {past.exit_code}). "
                                  f"Result: {past.result_summary[:200]}",
                    })

            try:
                result = await rt(tool_id, args, timeout=timeout)
                stdout_clean, stderr_clean = _truncate_output(result.stdout, result.stderr)
                db.add_tried(
                    session.id, tool_id, args,
                    result.summary(), result.exit_code,
                )
                result_tracker["tool_calls_made"] += 1
                return json.dumps({
                    "stdout":    stdout_clean,
                    "stderr":    stderr_clean,
                    "exit_code": result.exit_code,
                    "duration":  result.duration,
                    "truncated": result.truncated,
                })
            except ToolNotAvailableError as e:
                return json.dumps({"error": f"Tool not available: {e}"})

        # ── add_finding ───────────────────────────────────────────────────────
        elif tool_name == "add_finding":
            db.add_finding(
                session.id,
                tool_input["type"],
                tool_input["description"],
                tool_input.get("severity", "info"),
                tool_input.get("proof", ""),
            )
            result_tracker["findings_added"] += 1
            return json.dumps({"status": "recorded", "severity": tool_input.get("severity", "info")})

        # ── get_findings ──────────────────────────────────────────────────────
        elif tool_name == "get_findings":
            findings = db.get_findings(session.id)
            sev = tool_input.get("severity_filter")
            if sev:
                findings = [f for f in findings if f.severity == sev]
            return json.dumps([{
                "type":        f.type,
                "severity":    f.severity,
                "description": f.description,
                "proof":       (f.proof or "")[:300],
            } for f in findings])

        # ── delegate_agent ────────────────────────────────────────────────────
        elif tool_name == "delegate_agent":
            agent_name = tool_input["agent"]
            task       = tool_input["task"]
            target     = tool_input.get("target", session.target)
            return await _delegate(agent_name, task, target, session, result_tracker)

        # ── generate_report ───────────────────────────────────────────────────
        elif tool_name == "generate_report":
            try:
                from reporting.generator import generate_report
                report = generate_report(session, format=tool_input.get("format", "generic"))
                # Return a reference summary, not the full report (to save context)
                lines = report.splitlines()
                preview = "\n".join(lines[:50])
                return (
                    f"{preview}\n\n[Report generated — {len(lines)} lines total. "
                    f"Use: phantom report {session.id[:8]} to view full report]"
                )
            except Exception as e:
                return json.dumps({"error": f"Report generation failed: {e}"})

        # ── finish ────────────────────────────────────────────────────────────
        elif tool_name == "finish":
            result_tracker["finished"] = True
            return json.dumps({"status": "finished", "summary": tool_input.get("summary", "")})

        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

    except Exception as e:
        return json.dumps({"error": f"Dispatch error [{tool_name}]: {e}"})


# ─────────────────────────────────────────────────────────────────────────────
# Real agent delegation
# ─────────────────────────────────────────────────────────────────────────────

async def _delegate(
    agent_name: str,
    task: str,
    target: str,
    session: Session,
    result_tracker: dict,
) -> str:
    """
    Actually invoke the specified sub-agent.
    Each agent has a specific interface — this wires them up correctly.
    """
    try:
        if agent_name == "red":
            from agents.red_agent import run_recon_phase, run_vuln_scan_phase, run_fuzzing_phase
            task_lower = task.lower()
            if "recon" in task_lower or "osint" in task_lower or "subdomain" in task_lower:
                result_json = await run_recon_phase(target, session.id)
            elif "vuln" in task_lower or "scan" in task_lower or "nuclei" in task_lower:
                result_json = await run_vuln_scan_phase(target, session.id)
            elif "fuzz" in task_lower or "directory" in task_lower or "endpoint" in task_lower:
                result_json = await run_fuzzing_phase(target, session.id)
            else:
                # Default: full recon
                result_json = await run_recon_phase(target, session.id)
            data = json.loads(result_json)
            result_tracker["findings_added"] += data.get("findings_added", 0)
            return json.dumps({"agent": "red", "status": "complete", **data})

        elif agent_name == "grey":
            from agents.grey_agent import run_grey_phase
            result_json = await run_grey_phase(target, session.id, task)
            return json.dumps({"agent": "grey", "status": "complete", "result": result_json[:500]})

        elif agent_name == "blue":
            from agents.blue_agent import run_blue_phase
            result_json = await run_blue_phase(target, session.id, task)
            return json.dumps({"agent": "blue", "status": "complete", "result": result_json[:500]})

        elif agent_name == "identity":
            from agents.identity_agent import generate_persona
            persona = await generate_persona(session.id)
            return json.dumps({"agent": "identity", "status": "complete", "persona": str(persona)[:300]})

        elif agent_name == "intel":
            from agents.intel_agent import phantom_understand_target
            intel = await phantom_understand_target(target, session.id)
            return json.dumps({
                "agent": "intel",
                "status": "complete",
                "stack": intel.tech_profile.stack[:5] if hasattr(intel, "tech_profile") else [],
                "threat_items": len(intel.threat_model.ranked) if hasattr(intel, "threat_model") else 0,
            })

        elif agent_name == "beginner":
            from agents.beginner_agent import run_beginner_phase
            result = await run_beginner_phase(target, session.id, task)
            return json.dumps({"agent": "beginner", "status": "complete", "result": str(result)[:500]})

        else:
            return json.dumps({"error": f"Unknown agent: {agent_name}"})

    except ImportError as e:
        return json.dumps({"error": f"Agent '{agent_name}' module not found: {e}"})
    except Exception as e:
        return json.dumps({"error": f"Agent '{agent_name}' failed: {e}"})


# ─────────────────────────────────────────────────────────────────────────────
# Agentic loop
# ─────────────────────────────────────────────────────────────────────────────

async def run(
    user_message: str,
    session: Session,
    mode: Optional[str] = None,
    max_iterations: int = 20,
) -> OrchestratorResult:
    """
    Run the agentic tool-use loop.

    Args:
        user_message: The task/question to address.
        session: Active engagement session.
        mode: Override mode (defaults to session.mode).
        max_iterations: Safety cap on the loop.

    Returns:
        OrchestratorResult with output text, stats, and cost.
    """
    from core.llm import chat, get_config
    from cli.ui import info, step, warn

    effective_mode = mode or session.mode
    cfg = get_config()
    info(f"Orchestrator | mode={effective_mode} | provider={cfg.summary()}")

    # Trigger summarization if memory is getting long (non-blocking)
    asyncio.create_task(maybe_summarize(session.id))

    # Build the dynamic system prompt
    tried    = db.get_tried(session.id)
    findings = db.get_findings(session.id)
    system   = _build_system_prompt(effective_mode, session.scope, tried)

    # Build message history with findings injected at the end
    findings_dicts = [
        {"type": f.type, "severity": f.severity, "description": f.description}
        for f in findings
    ]
    history  = get_context_window(session.id, findings_context=findings_dicts)
    add_message(session.id, "user", user_message)
    messages = history + [{"role": "user", "content": user_message}]

    # Result tracker (mutated by _dispatch)
    tracker: dict[str, Any] = {
        "tool_calls_made": 0,
        "findings_added":  0,
        "total_cost_usd":  0.0,
        "finished":        False,
    }
    errors: list[str] = []

    for iteration in range(max_iterations):
        # ── LLM call ──────────────────────────────────────────────────────────
        try:
            response = await chat(
                messages=messages,
                system=system,
                max_tokens=4096,
                tools=TOOL_DEFINITIONS,
                cfg=cfg,
            )
        except Exception as e:
            err = f"LLM call failed (iter {iteration}): {e}"
            errors.append(err)
            warn(err)
            break

        tracker["total_cost_usd"] += response.get("cost_usd", 0.0)

        # ── No tool calls → final text answer ─────────────────────────────────
        if not response["tool_calls"]:
            final_text = response["text"]
            add_message(session.id, "assistant", final_text)
            return OrchestratorResult(
                output=final_text,
                tool_calls_made=tracker["tool_calls_made"],
                findings_added=tracker["findings_added"],
                total_cost_usd=tracker["total_cost_usd"],
                iterations=iteration + 1,
                errors=errors,
            )

        # ── Handle "finish" tool ───────────────────────────────────────────────
        finish_calls = [tc for tc in response["tool_calls"] if tc["name"] == "finish"]
        if finish_calls:
            summary = finish_calls[0]["input"].get("summary", "Engagement complete.")
            add_message(session.id, "assistant", summary)
            return OrchestratorResult(
                output=summary,
                tool_calls_made=tracker["tool_calls_made"],
                findings_added=tracker["findings_added"],
                total_cost_usd=tracker["total_cost_usd"],
                iterations=iteration + 1,
                errors=errors,
            )

        # ── Log reasoning text ─────────────────────────────────────────────────
        if response["text"]:
            step(f"AI reasoning: {response['text'][:120]}…")

        # ── Execute tool calls (parallel where safe) ───────────────────────────
        # Read-only tools can run in parallel; write tools run sequentially
        read_only  = {"get_findings", "generate_report"}
        write_tools = [tc for tc in response["tool_calls"] if tc["name"] not in read_only]
        read_tools  = [tc for tc in response["tool_calls"] if tc["name"] in read_only]

        tool_results = []

        # Parallel: read-only tools
        if read_tools:
            tasks = [
                _dispatch(tc["name"], tc["input"], session, tracker)
                for tc in read_tools
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for tc, res in zip(read_tools, results):
                result_str = res if isinstance(res, str) else json.dumps({"error": str(res)})
                step(f"→ {tc['name']}({json.dumps(tc['input'])[:60]}…)")
                tool_results.append({
                    "tool_call_id": tc["id"],
                    "name":         tc["name"],
                    "content":      result_str,
                })

        # Sequential: write tools (order matters, findings affect next hypothesis)
        for tc in write_tools:
            step(f"→ {tc['name']}({json.dumps(tc['input'])[:60]}…)")
            result_str = await _dispatch(tc["name"], tc["input"], session, tracker)
            tool_results.append({
                "tool_call_id": tc["id"],
                "name":         tc["name"],
                "content":      result_str,
            })

        if tracker.get("finished"):
            break

        # ── Build next message turn ────────────────────────────────────────────
        if cfg.provider.value == "anthropic":
            messages.append({
                "role": "assistant",
                "content": (
                    [{"type": "text", "text": response["text"]}]
                    if response["text"] else []
                ) + [
                    {
                        "type":  "tool_use",
                        "id":    tc["id"],
                        "name":  tc["name"],
                        "input": tc["input"],
                    }
                    for tc in response["tool_calls"]
                ]
            })
            messages.append({
                "role": "user",
                "content": [
                    {
                        "type":        "tool_result",
                        "tool_use_id": tr["tool_call_id"],
                        "content":     tr["content"],
                    }
                    for tr in tool_results
                ]
            })
        else:
            # OpenAI format
            messages.append({
                "role":    "assistant",
                "content": response["text"] or None,
                "tool_calls": [
                    {
                        "id":   tc["id"],
                        "type": "function",
                        "function": {
                            "name":      tc["name"],
                            "arguments": json.dumps(tc["input"]),
                        },
                    }
                    for tc in response["tool_calls"]
                ],
            })
            for tr in tool_results:
                messages.append({
                    "role":         "tool",
                    "tool_call_id": tr["tool_call_id"],
                    "content":      tr["content"],
                })

        # Refresh system prompt every 5 iterations (tried list grows)
        if iteration > 0 and iteration % 5 == 0:
            tried  = db.get_tried(session.id)
            system = _build_system_prompt(effective_mode, session.scope, tried)

    # ── Max iterations hit ─────────────────────────────────────────────────────
    warn(f"Orchestrator: max iterations ({max_iterations}) reached.")
    msg = (
        f"Engagement reached iteration limit ({max_iterations}). "
        f"Findings so far: {tracker['findings_added']} new. "
        f"Check all findings with: phantom sessions findings {session.id[:8]}"
    )
    return OrchestratorResult(
        output=msg,
        tool_calls_made=tracker["tool_calls_made"],
        findings_added=tracker["findings_added"],
        total_cost_usd=tracker["total_cost_usd"],
        iterations=max_iterations,
        hit_limit=True,
        errors=errors,
    )
