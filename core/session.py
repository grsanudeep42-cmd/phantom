"""
phantom/core/session.py

Persistent session management backed by SQLite.
Sessions survive crashes. Everything tied to a session_id.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

from config.settings import settings


# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    mode        TEXT NOT NULL,
    scope       TEXT NOT NULL DEFAULT '[]',   -- JSON array of in-scope patterns
    started_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active' -- active | paused | complete | error
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id),
    type        TEXT NOT NULL,          -- e.g. open_port, subdomain, vuln, credential
    severity    TEXT NOT NULL DEFAULT 'info',  -- critical | high | medium | low | info
    description TEXT NOT NULL,
    proof       TEXT NOT NULL DEFAULT '',      -- raw evidence (command output snippet)
    timestamp   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tried (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(id),
    tool           TEXT NOT NULL,
    args           TEXT NOT NULL DEFAULT '[]', -- JSON array
    result_summary TEXT NOT NULL DEFAULT '',
    exit_code      INTEGER NOT NULL DEFAULT 0,
    timestamp      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hypotheses (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(id),
    hypothesis     TEXT NOT NULL,
    rationale      TEXT NOT NULL DEFAULT '',
    suggested_tool TEXT NOT NULL DEFAULT '',
    suggested_args TEXT NOT NULL DEFAULT '{}', -- JSON object
    confidence     REAL NOT NULL DEFAULT 0.5,
    status         TEXT NOT NULL DEFAULT 'pending', -- pending | confirmed | rejected
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_cache (
    tool_id         TEXT PRIMARY KEY,
    version         TEXT NOT NULL DEFAULT '',
    executable_path TEXT NOT NULL DEFAULT '',
    install_method  TEXT NOT NULL DEFAULT '',  -- apt | brew | pip | docker | manual
    cached_at       TEXT NOT NULL,
    last_checked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS personas (
    id                   TEXT PRIMARY KEY,
    session_id           TEXT NOT NULL REFERENCES sessions(id),
    name                 TEXT NOT NULL,
    dob                  TEXT NOT NULL,
    address              TEXT NOT NULL,
    city                 TEXT NOT NULL,
    country              TEXT NOT NULL,
    occupation           TEXT NOT NULL,
    email                TEXT NOT NULL,
    phone                TEXT NOT NULL DEFAULT '',
    browser_profile_json TEXT NOT NULL DEFAULT '{}',
    created_at           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_session   ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_tried_session      ON tried(session_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_session ON hypotheses(session_id);
CREATE INDEX IF NOT EXISTS idx_personas_session   ON personas(session_id);
"""


# ─────────────────────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Session:
    id: str
    target: str
    mode: str
    scope: list[str]
    started_at: str
    updated_at: str
    status: str

    def to_json(self) -> str:
        d = asdict(self)
        return json.dumps(d, indent=2)

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Session":
        return cls(
            id=row["id"],
            target=row["target"],
            mode=row["mode"],
            scope=json.loads(row["scope"]),
            started_at=row["started_at"],
            updated_at=row["updated_at"],
            status=row["status"],
        )


@dataclass
class Finding:
    id: str
    session_id: str
    type: str
    severity: str
    description: str
    proof: str
    timestamp: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Finding":
        return cls(
            id=row["id"],
            session_id=row["session_id"],
            type=row["type"],
            severity=row["severity"],
            description=row["description"],
            proof=row["proof"],
            timestamp=row["timestamp"],
        )


@dataclass
class TriedAction:
    id: str
    session_id: str
    tool: str
    args: list
    result_summary: str
    exit_code: int
    timestamp: str

    def to_json(self) -> str:
        d = asdict(self)
        return json.dumps(d, indent=2)

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "TriedAction":
        return cls(
            id=row["id"],
            session_id=row["session_id"],
            tool=row["tool"],
            args=json.loads(row["args"]),
            result_summary=row["result_summary"],
            exit_code=row["exit_code"],
            timestamp=row["timestamp"],
        )


@dataclass
class Hypothesis:
    id: str
    session_id: str
    hypothesis: str
    rationale: str
    suggested_tool: str
    suggested_args: dict
    confidence: float
    status: str
    created_at: str

    def to_json(self) -> str:
        d = asdict(self)
        return json.dumps(d, indent=2)

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Hypothesis":
        return cls(
            id=row["id"],
            session_id=row["session_id"],
            hypothesis=row["hypothesis"],
            rationale=row["rationale"],
            suggested_tool=row["suggested_tool"],
            suggested_args=json.loads(row["suggested_args"]),
            confidence=row["confidence"],
            status=row["status"],
            created_at=row["created_at"],
        )


# ─────────────────────────────────────────────────────────────────────────────
# Database connection
# ─────────────────────────────────────────────────────────────────────────────

def _get_db_path() -> Path:
    settings.ensure_dirs()
    return settings.db_path


@contextmanager
def _db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(str(_get_db_path()))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create all tables if they don't exist. Safe to call multiple times."""
    with _db() as conn:
        conn.executescript(SCHEMA)


# ─────────────────────────────────────────────────────────────────────────────
# Session CRUD
# ─────────────────────────────────────────────────────────────────────────────

def create_session(target: str, mode: str, scope: Optional[list[str]] = None) -> Session:
    """Create a new engagement session and persist it."""
    init_db()
    now = _now()
    session = Session(
        id=str(uuid.uuid4()),
        target=target,
        mode=mode,
        scope=scope or [],
        started_at=now,
        updated_at=now,
        status="active",
    )
    with _db() as conn:
        conn.execute(
            "INSERT INTO sessions (id, target, mode, scope, started_at, updated_at, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                session.id,
                session.target,
                session.mode,
                json.dumps(session.scope),
                session.started_at,
                session.updated_at,
                session.status,
            ),
        )
    return session


def get_session(session_id: str) -> Optional[Session]:
    """Fetch a session by ID. Returns None if not found."""
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
    return Session.from_row(row) if row else None


def list_sessions() -> list[Session]:
    """Return all sessions ordered by most recently updated."""
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY updated_at DESC"
        ).fetchall()
    return [Session.from_row(r) for r in rows]


def update_session_status(session_id: str, status: str) -> None:
    with _db() as conn:
        conn.execute(
            "UPDATE sessions SET status = ?, updated_at = ? WHERE id = ?",
            (status, _now(), session_id),
        )


def set_session_scope(session_id: str, scope: list[str]) -> None:
    with _db() as conn:
        conn.execute(
            "UPDATE sessions SET scope = ?, updated_at = ? WHERE id = ?",
            (json.dumps(scope), _now(), session_id),
        )


# Alias used by phantom-mcp session_tools
update_scope = set_session_scope


def delete_session(session_id: str) -> None:
    """Delete a session and all its associated data."""
    with _db() as conn:
        for table in ("findings", "tried", "hypotheses", "personas"):
            conn.execute(f"DELETE FROM {table} WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))


# ─────────────────────────────────────────────────────────────────────────────
# Findings CRUD
# ─────────────────────────────────────────────────────────────────────────────

def add_finding(
    session_id: str,
    type: str,
    description: str,
    severity: str = "info",
    proof: str = "",
) -> Finding:
    finding = Finding(
        id=str(uuid.uuid4()),
        session_id=session_id,
        type=type,
        severity=severity,
        description=description,
        proof=proof,
        timestamp=_now(),
    )
    with _db() as conn:
        conn.execute(
            "INSERT INTO findings (id, session_id, type, severity, description, proof, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                finding.id,
                finding.session_id,
                finding.type,
                finding.severity,
                finding.description,
                finding.proof,
                finding.timestamp,
            ),
        )
    return finding


def get_findings(session_id: str) -> list[Finding]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY timestamp",
            (session_id,),
        ).fetchall()
    return [Finding.from_row(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# Tried actions CRUD
# ─────────────────────────────────────────────────────────────────────────────

def add_tried(
    session_id: str,
    tool: str,
    args: list,
    result_summary: str = "",
    exit_code: int = 0,
) -> TriedAction:
    action = TriedAction(
        id=str(uuid.uuid4()),
        session_id=session_id,
        tool=tool,
        args=args,
        result_summary=result_summary,
        exit_code=exit_code,
        timestamp=_now(),
    )
    with _db() as conn:
        conn.execute(
            "INSERT INTO tried (id, session_id, tool, args, result_summary, exit_code, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                action.id,
                action.session_id,
                action.tool,
                json.dumps(action.args),
                action.result_summary,
                action.exit_code,
                action.timestamp,
            ),
        )
    return action


def get_tried(session_id: str) -> list[TriedAction]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM tried WHERE session_id = ? ORDER BY timestamp",
            (session_id,),
        ).fetchall()
    return [TriedAction.from_row(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# Hypotheses CRUD
# ─────────────────────────────────────────────────────────────────────────────

def add_hypothesis(
    session_id: str,
    hypothesis: str,
    rationale: str = "",
    suggested_tool: str = "",
    suggested_args: Optional[dict] = None,
    confidence: float = 0.5,
) -> Hypothesis:
    h = Hypothesis(
        id=str(uuid.uuid4()),
        session_id=session_id,
        hypothesis=hypothesis,
        rationale=rationale,
        suggested_tool=suggested_tool,
        suggested_args=suggested_args or {},
        confidence=confidence,
        status="pending",
        created_at=_now(),
    )
    with _db() as conn:
        conn.execute(
            "INSERT INTO hypotheses "
            "(id, session_id, hypothesis, rationale, suggested_tool, suggested_args, confidence, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                h.id,
                h.session_id,
                h.hypothesis,
                h.rationale,
                h.suggested_tool,
                json.dumps(h.suggested_args),
                h.confidence,
                h.status,
                h.created_at,
            ),
        )
    return h


def get_hypotheses(session_id: str, status: Optional[str] = None) -> list[Hypothesis]:
    with _db() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM hypotheses WHERE session_id = ? AND status = ? ORDER BY confidence DESC",
                (session_id, status),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM hypotheses WHERE session_id = ? ORDER BY confidence DESC",
                (session_id,),
            ).fetchall()
    return [Hypothesis.from_row(r) for r in rows]


def update_hypothesis_status(hypothesis_id: str, status: str) -> None:
    with _db() as conn:
        conn.execute(
            "UPDATE hypotheses SET status = ? WHERE id = ?",
            (status, hypothesis_id),
        )
