"""
phantom/core/memory.py

Persistent context across turns — stores and retrieves
conversation-style context for an ongoing session.
Backed by SQLite, just like everything else.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

from config.settings import settings
from core.session import init_db

MEMORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    role        TEXT NOT NULL,   -- user | assistant | system
    content     TEXT NOT NULL,
    timestamp   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_session ON memory(session_id);
"""


def _db():
    init_db()
    conn = sqlite3.connect(str(settings.db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(MEMORY_SCHEMA)
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_message(session_id: str, role: str, content: str) -> None:
    """Append a message to the session's memory."""
    conn = _db()
    try:
        conn.execute(
            "INSERT INTO memory (id, session_id, role, content, timestamp) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), session_id, role, content, _now()),
        )
        conn.commit()
    finally:
        conn.close()


def get_messages(session_id: str, limit: int = 50) -> list[dict]:
    """Retrieve the last N messages for a session (oldest first)."""
    conn = _db()
    try:
        rows = conn.execute(
            "SELECT role, content, timestamp FROM memory "
            "WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
    finally:
        conn.close()
    # Reverse so oldest is first
    return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]


def clear_memory(session_id: str) -> None:
    """Wipe all memory for a session."""
    conn = _db()
    try:
        conn.execute("DELETE FROM memory WHERE session_id = ?", (session_id,))
        conn.commit()
    finally:
        conn.close()


def get_context_window(session_id: str, max_tokens: int = 8000) -> list[dict]:
    """
    Return messages that fit within an approximate token budget.
    Crude estimate: 1 token ≈ 4 chars.
    """
    messages = get_messages(session_id, limit=100)
    result = []
    total_chars = 0
    # Walk newest → oldest, keep until budget exhausted
    for msg in reversed(messages):
        chars = len(msg["content"])
        if total_chars + chars > max_tokens * 4:
            break
        result.insert(0, msg)
        total_chars += chars
    return result
