"""phantom/cli/commands/identity.py — `phantom identity gen|inbox|otp`"""
from __future__ import annotations
import asyncio
import click
from cli.ui import console, error, info, section, success, warn


@click.group("identity")
def identity_cmd() -> None:
    """Manage fake personas and disposable identities."""
    pass


@identity_cmd.command("gen")
@click.option("--locale", "-l", default="US",
              help="Locale (US, IN, UK, DE, FR, JP, CN, BR)")
@click.option("--session", "-s", "session_id", required=True,
              help="Session ID to attach the persona to")
@click.option("--phone", is_flag=True, default=False,
              help="Also get a real temporary phone number")
@click.option("--phone-service", default="google",
              help="Service to get phone for (google, facebook, etc.)")
@click.option("--phone-country", default="US", help="Country for phone number")
def gen_cmd(locale: str, session_id: str, phone: bool,
            phone_service: str, phone_country: str) -> None:
    """Generate a fake persona (email + identity, optionally phone)."""
    from dotenv import load_dotenv
    load_dotenv()

    from core.session import list_sessions
    all_sessions = list_sessions()
    matched = [s for s in all_sessions if s.id.startswith(session_id)]
    if not matched:
        error(f"No session found: {session_id}")
        raise SystemExit(1)
    sess = matched[0]

    from agents.identity_agent import generate
    persona = asyncio.run(generate(
        sess.id, locale=locale,
        with_phone=phone,
        phone_service=phone_service,
        phone_country=phone_country,
    ))
    section("Persona Generated")
    console.print(f"\n[bold green]{persona.header_string()}[/bold green]\n")
    info(f"Saved to session {sess.id[:8]}")


@identity_cmd.command("inbox")
@click.argument("email")
def inbox_cmd(email: str) -> None:
    """Check the temp email inbox for a given address."""
    from agents.identity_agent import get_inbox
    messages = asyncio.run(get_inbox(email))
    if not messages:
        info("Inbox is empty.")
        return
    section(f"Inbox: {email}")
    for msg in messages:
        console.print(
            f"\n[bold]{msg.subject or '(no subject)'}[/bold]"
            f"  [dim]from: {msg.from_}  at: {msg.received_at[:16]}[/dim]\n"
            f"{msg.body[:500]}\n"
            f"{'─' * 40}"
        )
    info(f"{len(messages)} message(s)")


@identity_cmd.command("otp")
@click.argument("request_id")
@click.option("--timeout", "-t", default=120, help="Wait up to N seconds for OTP")
def otp_cmd(request_id: str, timeout: int) -> None:
    """Poll for an SMS OTP given a request_id from identity gen --phone."""
    from agents.identity_agent import get_sms_otp
    from identity.sms import SMSError
    info(f"Waiting for OTP (up to {timeout}s)…")
    try:
        otp = asyncio.run(get_sms_otp(request_id, timeout=timeout))
        success(f"OTP received: [bold]{otp}[/bold]")
    except SMSError as e:
        error(f"SMS error: {e}")
