"""
phantom/registry/cache.py

Tool cache management. Exposes cache inspection and cleanup utilities.
The write path is inside loader.py — this module is for reads + management.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional

from config.settings import settings
from core.session import init_db


@contextmanager
def _db():
    init_db()
    conn = sqlite3.connect(str(settings.db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


@dataclass
class CachedTool:
    tool_id: str
    version: str
    executable_path: str
    install_method: str
    cached_at: str
    last_checked_at: str


def get_cached_tool(tool_id: str) -> Optional[CachedTool]:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM tool_cache WHERE tool_id = ?", (tool_id,)
        ).fetchone()
    if not row:
        return None
    return CachedTool(
        tool_id=row["tool_id"],
        version=row["version"],
        executable_path=row["executable_path"],
        install_method=row["install_method"],
        cached_at=row["cached_at"],
        last_checked_at=row["last_checked_at"],
    )


def list_cached_tools() -> list[CachedTool]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM tool_cache ORDER BY tool_id"
        ).fetchall()
    return [
        CachedTool(
            tool_id=r["tool_id"],
            version=r["version"],
            executable_path=r["executable_path"],
            install_method=r["install_method"],
            cached_at=r["cached_at"],
            last_checked_at=r["last_checked_at"],
        )
        for r in rows
    ]


def clear_cache(tool_id: Optional[str] = None) -> int:
    """Clear tool cache. If tool_id given, only clear that entry. Returns rows deleted."""
    with _db() as conn:
        if tool_id:
            cursor = conn.execute("DELETE FROM tool_cache WHERE tool_id = ?", (tool_id,))
        else:
            cursor = conn.execute("DELETE FROM tool_cache")
    return cursor.rowcount
