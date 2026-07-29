"""
phantom/agents/identity_agent.py

Orchestrates persona creation: generates identity, creates email, optionally gets phone.
Can be called manually (phantom identity gen) or by red/grey agents automatically.
"""
from __future__ import annotations

from typing import Optional

from cli.ui import console, info, section, step, success, warn
from core.session import get_session
from identity import email_server, persona as persona_mod, sms as sms_mod
from identity.persona import Persona


async def generate(
    session_id: str,
    locale: str = "US",
    with_phone: bool = False,
    phone_service: str = "google",
    phone_country: str = "US",
) -> Persona:
    """
    Generate a complete persona for the session.
    One persona per session — if one exists, return it.
    """
    # Check if persona already exists for this session
    existing = persona_mod.get_persona(session_id)
    if existing:
        info(f"Persona already exists for session {session_id[:8]}: {existing.name}")
        return existing

    section("Generating Persona")

    # 1. Create temp email
    step("Creating disposable email address…")
    email_addr = await email_server.create_address(session_id)
    success(f"Email: {email_addr}")

    # 2. Generate persona with that email
    step(f"Generating {locale} identity…")
    p = persona_mod.generate(session_id, locale=locale, email=email_addr)

    # 3. Optionally get a real phone number
    if with_phone:
        step(f"Getting {phone_country} phone number for {phone_service}…")
        try:
            phone_number, request_id = await sms_mod.get_number(phone_service, phone_country)
            persona_mod.update_persona_phone(p.id, phone_number)
            p.phone = phone_number
            success(f"Phone: {phone_number}  (request_id: {request_id})")
            info("To get OTP: run phantom identity otp <request_id>")
        except sms_mod.SMSError as e:
            warn(f"SMS failed: {e}")
        except Exception as e:
            warn(f"Phone number error: {e}")

    success(f"Persona created: {p.name}")
    console.print(f"\n[dim]{p.header_string()}[/dim]\n")
    return p


async def get_inbox(email: str) -> list:
    """Fetch inbox for an identity email address."""
    messages = await email_server.get_inbox(email)
    return messages


async def wait_for_otp(email: str, timeout: int = 120) -> Optional[str]:
    """Wait for an OTP email to arrive. Returns the first message body."""
    import re
    msg = await email_server.wait_for_email(email, timeout=timeout)
    if not msg:
        return None
    # Try to extract a numeric OTP from subject or body
    text = msg.subject + " " + msg.body
    digits = re.findall(r"\b\d{4,8}\b", text)
    return digits[0] if digits else msg.body[:100]


async def get_sms_otp(request_id: str, timeout: int = 120) -> str:
    """Poll for SMS OTP given a request_id from get_number."""
    return await sms_mod.get_otp(request_id, timeout=timeout)
