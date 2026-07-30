"""
phantom/core/memory.py

Persistent conversation memory — production grade.

Architecture (Buffer + Summary hybrid, industry standard):
  - SHORT-TERM: Last N raw turns kept verbatim (precision for recent context)
  - MID-TERM: Older turns summarized into a compressed block via LLM
  - All storage backed by the shared SQLite DB (same WAL connection as session.py)

Key improvements over naive approach:
  - Uses session._db() context manager → no race conditions, WAL enforced
  - Sliding window with LLM summarization of evicted turns (not hard-drop)
  - Tool result compression: large tool outputs → 1-line summary
  - Findings injection: top N findings always appended as context (never evicted)
  - Token budget via approximate tiktoken-style char estimate (4 chars ≈ 1 token)
  - "Lost in the middle" mitigation: critical info placed at beginning/end of prompt

Memory layout injected into each LLM call:
  [SUMMARY_BLOCK]   (if summarization exists)
  [raw turns...]    (last RAW_WINDOW_SIZE turns)
  [FINDINGS_BLOCK]  (top 10 findings, always fresh)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional
import uuid

from core.session import _db, init_db


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Max raw turns to keep verbatim in context
RAW_WINDOW_SIZE = 12

# Approximate token budget for the full context window returned
CONTEXT_TOKEN_BUDGET = 12_000

# Tool result lines: keep first N + last N lines when compressing
TOOL_RESULT_HEAD_LINES = 30
TOOL_RESULT_TAIL_LINES = 15

# Chars per token estimate (conservative)
CHARS_PER_TOKEN = 3.5


# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

MEMORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    role        TEXT NOT NULL,   -- user | assistant | tool | system
    content     TEXT NOT NULL,
    turn_index  INTEGER NOT NULL DEFAULT 0,
    timestamp   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_session ON memory(session_id, turn_index);

CREATE TABLE IF NOT EXISTS memory_summaries (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL UNIQUE,
    summary     TEXT NOT NULL,
    covers_up_to_turn INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_summary_session ON memory_summaries(session_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_schema() -> None:
    """Create memory tables if they don't exist. Uses the shared DB connection."""
    init_db()
    with _db() as conn:
        conn.executescript(MEMORY_SCHEMA)


# ─────────────────────────────────────────────────────────────────────────────
# Core write operations
# ─────────────────────────────────────────────────────────────────────────────

def add_message(session_id: str, role: str, content: str) -> None:
    """Append a message to the session's memory."""
    _ensure_schema()
    # Compress large tool results before storing
    if role == "tool" or role == "assistant":
        content = _compress_tool_content(content)

    with _db() as conn:
        # Get next turn index
        row = conn.execute(
            "SELECT MAX(turn_index) FROM memory WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        next_idx = (row[0] or 0) + 1

        conn.execute(
            "INSERT INTO memory (id, session_id, role, content, turn_index, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), session_id, role, content, next_idx, _now()),
        )


def clear_memory(session_id: str) -> None:
    """Wipe all memory and summaries for a session."""
    _ensure_schema()
    with _db() as conn:
        conn.execute("DELETE FROM memory WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM memory_summaries WHERE session_id = ?", (session_id,))


# ─────────────────────────────────────────────────────────────────────────────
# Core read operations
# ─────────────────────────────────────────────────────────────────────────────

def get_messages(session_id: str, limit: int = 50) -> list[dict]:
    """Retrieve the last N messages (oldest first), excluding internal system turns."""
    _ensure_schema()
    with _db() as conn:
        rows = conn.execute(
            "SELECT role, content, turn_index FROM memory "
            "WHERE session_id = ? AND role != 'system' "
            "ORDER BY turn_index DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
    return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]


def get_summary(session_id: str) -> Optional[str]:
    """Retrieve the compressed summary of older turns, if any."""
    _ensure_schema()
    with _db() as conn:
        row = conn.execute(
            "SELECT summary FROM memory_summaries WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    return row["summary"] if row else None


def save_summary(session_id: str, summary: str, covers_up_to_turn: int) -> None:
    """Upsert a summary block for the session."""
    _ensure_schema()
    with _db() as conn:
        conn.execute(
            "INSERT INTO memory_summaries (id, session_id, summary, covers_up_to_turn, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(session_id) DO UPDATE SET "
            "summary=excluded.summary, covers_up_to_turn=excluded.covers_up_to_turn, updated_at=excluded.updated_at",
            (str(uuid.uuid4()), session_id, summary, covers_up_to_turn, _now()),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Context window builder — the main output consumed by the orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def get_context_window(
    session_id: str,
    token_budget: int = CONTEXT_TOKEN_BUDGET,
    findings_context: Optional[list[dict]] = None,
) -> list[dict]:
    """
    Build the message list to inject into the next LLM call.

    Layout (production "lost in the middle" mitigation):
      1. Summary block at the TOP (if exists) — always seen
      2. Raw recent turns (last RAW_WINDOW_SIZE)
      3. Findings block at the END — always seen, never evicted

    Args:
        session_id: Session to load memory for.
        token_budget: Approximate token budget (chars / CHARS_PER_TOKEN).
        findings_context: Optional pre-built findings list to append.
                          Format: [{"type": ..., "severity": ..., "description": ...}]

    Returns:
        List of {role, content} dicts ready for the LLM messages list.
    """
    _ensure_schema()
    messages: list[dict] = []
    char_budget = int(token_budget * CHARS_PER_TOKEN)

    # 1. Summary block (old turns compressed)
    summary = get_summary(session_id)
    if summary:
        summary_msg = {
            "role": "user",
            "content": (
                f"[CONTEXT SUMMARY — earlier engagement history]\n{summary}\n"
                f"[END SUMMARY — current session continues below]"
            ),
        }
        messages.append(summary_msg)
        char_budget -= len(summary_msg["content"])

    # 2. Recent raw turns (walk newest→oldest, keep within budget)
    raw_turns = get_messages(session_id, limit=RAW_WINDOW_SIZE)
    kept = []
    for msg in reversed(raw_turns):
        cost = len(msg["content"])
        if char_budget - cost < 0:
            break
        kept.insert(0, msg)
        char_budget -= cost
    messages.extend(kept)

    # 3. Findings block at the END (critical info placed last → model focuses on it)
    if findings_context:
        top = findings_context[:10]
        findings_lines = "\n".join(
            f"  [{f.get('severity', 'info').upper()}] {f.get('type', '?')}: "
            f"{str(f.get('description', ''))[:150]}"
            for f in top
        )
        findings_msg = {
            "role": "user",
            "content": (
                f"[SESSION FINDINGS — {len(findings_context)} total, top {len(top)} shown]\n"
                f"{findings_lines}"
            ),
        }
        messages.append(findings_msg)

    return messages


# ─────────────────────────────────────────────────────────────────────────────
# Summarization trigger — call when context is getting long
# ─────────────────────────────────────────────────────────────────────────────

async def maybe_summarize(session_id: str, force: bool = False) -> bool:
    """
    If more than RAW_WINDOW_SIZE * 2 turns exist, compress the oldest half via LLM.
    Returns True if a new summary was created.
    Set force=True to always summarize regardless of turn count.
    """
    _ensure_schema()
    with _db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM memory WHERE session_id = ?",
            (session_id,),
        ).fetchone()[0]

    threshold = RAW_WINDOW_SIZE * 2
    if not force and count < threshold:
        return False  # Not enough turns yet

    # Get the old turns to compress (everything outside the recent window)
    with _db() as conn:
        rows = conn.execute(
            "SELECT role, content, turn_index FROM memory "
            "WHERE session_id = ? ORDER BY turn_index ASC",
            (session_id,),
        ).fetchall()

    all_turns = list(rows)
    if len(all_turns) <= RAW_WINDOW_SIZE:
        return False

    # Summarize everything except the last RAW_WINDOW_SIZE turns
    to_summarize = all_turns[: -RAW_WINDOW_SIZE]
    max_turn = to_summarize[-1]["turn_index"]

    history_text = "\n".join(
        f"[{r['role'].upper()}]: {r['content'][:300]}"
        for r in to_summarize
    )

    prompt = (
        "Summarize the following security engagement conversation history into a "
        "concise, fact-dense block. Preserve: target name, discovered subdomains, "
        "open ports, vulnerabilities found, tools run and their outcomes, "
        "hypotheses made, and any scope decisions. "
        "Use bullet points. Max 400 words. No fluff.\n\n"
        f"HISTORY:\n{history_text}"
    )

    try:
        from core.llm import chat_text
        summary = await chat_text(
            prompt,
            system="You are a security engagement summarizer. Be concise and factual.",
            max_tokens=600,
        )
        save_summary(session_id, summary.strip(), max_turn)
        return True
    except Exception:
        return False  # Summarization is non-fatal


# ─────────────────────────────────────────────────────────────────────────────
# Tool result compression
# ─────────────────────────────────────────────────────────────────────────────

def _compress_tool_content(content: str) -> str:
    """
    Compress large tool results to avoid bloating the context window.
    Strategy:
      1. Under 1500 chars → keep verbatim
      2. Valid JSON dict → truncate long string values in-place
      3. Multi-line plain text → keep HEAD + TAIL lines
      4. Single long line → hard char-cut with ellipsis
    """
    if len(content) < 1500:
        return content  # Small enough — keep as-is

    # Try JSON — summarize numeric fields, keep structure
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            compressed = {}
            for k, v in data.items():
                if isinstance(v, str) and len(v) > 300:
                    compressed[k] = v[:200] + f"…[{len(v) - 200} chars truncated]"
                else:
                    compressed[k] = v
            return json.dumps(compressed)
    except (json.JSONDecodeError, TypeError):
        pass

    # Multi-line plain text: head + tail
    lines = content.splitlines()
    if len(lines) > TOOL_RESULT_HEAD_LINES + TOOL_RESULT_TAIL_LINES:
        head    = lines[:TOOL_RESULT_HEAD_LINES]
        tail    = lines[-TOOL_RESULT_TAIL_LINES:]
        skipped = len(lines) - TOOL_RESULT_HEAD_LINES - TOOL_RESULT_TAIL_LINES
        return "\n".join(head) + f"\n… [{skipped} lines omitted] …\n" + "\n".join(tail)

    # Single long line or few long lines — hard char-cut
    limit = 1200
    return content[:limit] + f"… [{len(content) - limit} chars omitted]"
