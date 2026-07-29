"""
phantom/identity/persona.py

Fake persona generation. Locale-aware. Consistent per session.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

from faker import Faker

from core.session import init_db
from config.settings import settings


# ─────────────────────────────────────────────────────────────────────────────
# Browser profile
# ─────────────────────────────────────────────────────────────────────────────

# Realistic UA pool per platform
_UA_POOL = {
    "windows": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    ],
    "macos": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    ],
    "linux": [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    ],
}

_TIMEZONE_MAP = {
    "en_IN": "Asia/Kolkata",
    "en_US": "America/New_York",
    "en_GB": "Europe/London",
    "de_DE": "Europe/Berlin",
    "fr_FR": "Europe/Paris",
    "ja_JP": "Asia/Tokyo",
    "zh_CN": "Asia/Shanghai",
    "pt_BR": "America/Sao_Paulo",
}

_PLATFORM_MAP = {
    "en_IN": "linux",
    "en_US": "windows",
    "en_GB": "windows",
    "de_DE": "windows",
    "fr_FR": "windows",
    "ja_JP": "windows",
    "zh_CN": "windows",
    "pt_BR": "windows",
}


@dataclass
class BrowserProfile:
    user_agent: str
    timezone: str
    locale: str
    platform: str
    screen_width: int = 1920
    screen_height: int = 1080
    color_depth: int = 24

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Persona
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Persona:
    id: str
    session_id: str
    name: str
    dob: str
    address: str
    city: str
    country: str
    occupation: str
    email: str
    phone: str
    browser_profile: BrowserProfile
    created_at: str
    locale: str

    def to_json(self) -> str:
        d = asdict(self)
        return json.dumps(d, indent=2)

    def to_dict(self) -> dict:
        return asdict(self)

    def header_string(self) -> str:
        """Human-readable summary for terminal display."""
        return (
            f"Name: {self.name}\n"
            f"DOB:  {self.dob}\n"
            f"Email: {self.email}\n"
            f"Phone: {self.phone or 'not assigned'}\n"
            f"Address: {self.address}, {self.city}, {self.country}\n"
            f"Job: {self.occupation}\n"
            f"UA: {self.browser_profile.user_agent[:60]}…"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Locale mapping
# ─────────────────────────────────────────────────────────────────────────────

LOCALE_ALIASES = {
    "IN": "en_IN",
    "US": "en_US",
    "UK": "en_GB",
    "GB": "en_GB",
    "DE": "de_DE",
    "FR": "fr_FR",
    "JP": "ja_JP",
    "CN": "zh_CN",
    "BR": "pt_BR",
}


def _resolve_locale(locale_str: str) -> str:
    return LOCALE_ALIASES.get(locale_str.upper(), locale_str)


# ─────────────────────────────────────────────────────────────────────────────
# Generation
# ─────────────────────────────────────────────────────────────────────────────

import random

def generate(
    session_id: str,
    locale: str = "US",
    email: Optional[str] = None,
    phone: Optional[str] = None,
) -> Persona:
    """
    Generate a realistic, consistent persona for the given locale.
    One persona per session — call this once, store it, reuse it.
    """
    faker_locale = _resolve_locale(locale)
    try:
        fake = Faker(faker_locale)
    except Exception:
        fake = Faker("en_US")
        faker_locale = "en_US"

    Faker.seed(hash(session_id) % (2**31))  # Deterministic per session

    platform = _PLATFORM_MAP.get(faker_locale, "windows")
    ua_list = _UA_POOL.get(platform, _UA_POOL["windows"])
    ua = random.choice(ua_list)
    tz = _TIMEZONE_MAP.get(faker_locale, "UTC")

    browser_profile = BrowserProfile(
        user_agent=ua,
        timezone=tz,
        locale=faker_locale,
        platform=platform,
    )

    # Generate consistent identity
    name = fake.name()
    dob = fake.date_of_birth(minimum_age=22, maximum_age=45).isoformat()
    address = fake.street_address()
    city = fake.city()
    country = fake.current_country()
    occupation = fake.job()

    persona_email = email or f"{fake.user_name()}@guerrillamailblock.com"

    persona = Persona(
        id=str(uuid.uuid4()),
        session_id=session_id,
        name=name,
        dob=dob,
        address=address,
        city=city,
        country=country,
        occupation=occupation,
        email=persona_email,
        phone=phone or "",
        browser_profile=browser_profile,
        created_at=datetime.now(timezone.utc).isoformat(),
        locale=faker_locale,
    )

    _save_persona(persona)
    return persona


def _save_persona(persona: Persona) -> None:
    """Persist persona to SQLite persona vault."""
    import sqlite3
    from contextlib import contextmanager

    init_db()

    conn = sqlite3.connect(str(settings.db_path))
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            """INSERT OR REPLACE INTO personas
               (id, session_id, name, dob, address, city, country, occupation,
                email, phone, browser_profile_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                persona.id,
                persona.session_id,
                persona.name,
                persona.dob,
                persona.address,
                persona.city,
                persona.country,
                persona.occupation,
                persona.email,
                persona.phone,
                json.dumps(persona.browser_profile.to_dict()),
                persona.created_at,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_persona(session_id: str) -> Optional[Persona]:
    """Retrieve the persona for a session, if one exists."""
    import sqlite3

    init_db()
    conn = sqlite3.connect(str(settings.db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM personas WHERE session_id = ? ORDER BY created_at DESC LIMIT 1",
            (session_id,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return None

    bp_data = json.loads(row["browser_profile_json"])
    return Persona(
        id=row["id"],
        session_id=row["session_id"],
        name=row["name"],
        dob=row["dob"],
        address=row["address"],
        city=row["city"],
        country=row["country"],
        occupation=row["occupation"],
        email=row["email"],
        phone=row["phone"],
        browser_profile=BrowserProfile(**bp_data),
        created_at=row["created_at"],
        locale=bp_data.get("locale", "en_US"),
    )


def update_persona_email(persona_id: str, email: str) -> None:
    import sqlite3
    conn = sqlite3.connect(str(settings.db_path))
    try:
        conn.execute("UPDATE personas SET email = ? WHERE id = ?", (email, persona_id))
        conn.commit()
    finally:
        conn.close()


def update_persona_phone(persona_id: str, phone: str) -> None:
    import sqlite3
    conn = sqlite3.connect(str(settings.db_path))
    try:
        conn.execute("UPDATE personas SET phone = ? WHERE id = ?", (phone, persona_id))
        conn.commit()
    finally:
        conn.close()
