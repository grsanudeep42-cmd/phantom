"""
phantom/identity/email_server.py

Disposable email with two modes:
  Mode 1 — Self-hosted (aiosmtpd) when PHANTOM_EMAIL_DOMAIN is set
  Mode 2 — Guerrilla Mail API fallback (zero config, works everywhere)

All callers use the same interface:
    create_address(session_id) -> str
    get_inbox(email) -> list[EmailMessage]
"""
from __future__ import annotations

import asyncio
import email as email_lib
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# EmailMessage type
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EmailMessage:
    id: str
    to: str
    from_: str
    subject: str
    body: str
    received_at: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Mode detection
# ─────────────────────────────────────────────────────────────────────────────

def _is_selfhosted_mode() -> bool:
    from config.settings import settings
    return bool(settings.email_domain)


# ─────────────────────────────────────────────────────────────────────────────
# Mode 2: Guerrilla Mail API (default, zero config)
# ─────────────────────────────────────────────────────────────────────────────

GUERRILLA_BASE = "https://api.guerrillamail.com/ajax.php"

_guerrilla_sessions: dict[str, str] = {}  # email -> sid_token


async def _guerrilla_create() -> tuple[str, str]:
    """Create a new Guerrilla Mail address. Returns (email, sid_token)."""
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.get(
            GUERRILLA_BASE,
            params={"f": "get_email_address"},
            headers={"User-Agent": "phantom/1.0"},
        ) as resp:
            data = await resp.json(content_type=None)
            email = data.get("email_addr", "")
            sid = data.get("sid_token", "")
            return email, sid


async def _guerrilla_get_inbox(email: str) -> list[EmailMessage]:
    """Poll Guerrilla Mail for new messages."""
    import aiohttp
    sid = _guerrilla_sessions.get(email, "")
    if not sid:
        return []

    async with aiohttp.ClientSession() as session:
        async with session.get(
            GUERRILLA_BASE,
            params={"f": "get_email_list", "offset": "0", "sid_token": sid},
            headers={"User-Agent": "phantom/1.0"},
        ) as resp:
            data = await resp.json(content_type=None)

    messages = []
    for item in data.get("list", []):
        msg = EmailMessage(
            id=str(item.get("mail_id", uuid.uuid4())),
            to=email,
            from_=item.get("mail_from", ""),
            subject=item.get("mail_subject", ""),
            body=item.get("mail_excerpt", ""),
            received_at=item.get("mail_date", ""),
        )
        messages.append(msg)
    return messages


# ─────────────────────────────────────────────────────────────────────────────
# Mode 1: Self-hosted aiosmtpd
# ─────────────────────────────────────────────────────────────────────────────

# In-process inbox (maps email -> list[EmailMessage])
_selfhosted_inbox: dict[str, list[EmailMessage]] = {}
_smtp_server = None


class _PhantomSMTPHandler:
    async def handle_DATA(self, server, session, envelope):
        try:
            msg = email_lib.message_from_bytes(envelope.content)
            subject = msg.get("Subject", "")
            from_ = envelope.mail_from
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                        break
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="replace")

            for rcpt in envelope.rcpt_tos:
                rcpt_lower = rcpt.lower()
                if rcpt_lower not in _selfhosted_inbox:
                    _selfhosted_inbox[rcpt_lower] = []
                email_msg = EmailMessage(
                    id=str(uuid.uuid4()),
                    to=rcpt_lower,
                    from_=from_,
                    subject=subject,
                    body=body[:10_000],
                    received_at=datetime.now(timezone.utc).isoformat(),
                )
                _selfhosted_inbox[rcpt_lower].append(email_msg)
        except Exception:
            pass
        return "250 OK"


async def start_smtp_server() -> None:
    """Start the self-hosted SMTP server (call once at startup if configured)."""
    global _smtp_server
    from config.settings import settings

    if not settings.email_domain:
        return

    try:
        from aiosmtpd.controller import Controller
        handler = _PhantomSMTPHandler()
        _smtp_server = Controller(handler, hostname="0.0.0.0", port=settings.email_port)
        _smtp_server.start()
    except Exception as e:
        from cli.ui import warn as ui_warn
        ui_warn(f"Self-hosted SMTP failed to start: {e}. Falling back to Guerrilla Mail.")


def _selfhosted_create(session_id: str) -> str:
    from config.settings import settings
    local = uuid.uuid4().hex[:12]
    email = f"{local}@{settings.email_domain}"
    _selfhosted_inbox[email.lower()] = []
    return email


def _selfhosted_get_inbox(email: str) -> list[EmailMessage]:
    return _selfhosted_inbox.get(email.lower(), [])


# ─────────────────────────────────────────────────────────────────────────────
# Public API (unified interface)
# ─────────────────────────────────────────────────────────────────────────────

async def create_address(session_id: str) -> str:
    """
    Create a disposable email address for this session.
    Uses self-hosted if PHANTOM_EMAIL_DOMAIN is configured, else Guerrilla Mail.
    """
    if _is_selfhosted_mode():
        return _selfhosted_create(session_id)
    else:
        try:
            email, sid = await _guerrilla_create()
            _guerrilla_sessions[email] = sid
            return email
        except Exception as e:
            # If Guerrilla Mail fails, generate a placeholder
            return f"{uuid.uuid4().hex[:10]}@guerrillamail.com"


async def get_inbox(email: str) -> list[EmailMessage]:
    """
    Retrieve all messages for a given email address.
    Returns list of EmailMessage objects.
    """
    if _is_selfhosted_mode():
        return _selfhosted_get_inbox(email)
    else:
        try:
            return await _guerrilla_get_inbox(email)
        except Exception:
            return []


async def wait_for_email(
    email: str,
    timeout: int = 120,
    poll_interval: int = 5,
) -> Optional[EmailMessage]:
    """
    Poll until an email arrives or timeout. Useful for OTP flows.
    Returns the first new message or None on timeout.
    """
    seen_ids: set[str] = set()
    elapsed = 0
    while elapsed < timeout:
        messages = await get_inbox(email)
        for msg in messages:
            if msg.id not in seen_ids:
                return msg
        await asyncio.sleep(poll_interval)
        elapsed += poll_interval
    return None
