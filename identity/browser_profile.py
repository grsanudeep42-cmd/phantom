"""
phantom/identity/browser_profile.py

Browser fingerprint management. Exposes profile as request headers.
"""
from __future__ import annotations

from identity.persona import BrowserProfile


def to_headers(profile: BrowserProfile) -> dict[str, str]:
    """Convert a BrowserProfile to HTTP request headers."""
    return {
        "User-Agent": profile.user_agent,
        "Accept-Language": _locale_to_accept(profile.locale),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }


def _locale_to_accept(locale: str) -> str:
    mapping = {
        "en_US": "en-US,en;q=0.9",
        "en_GB": "en-GB,en;q=0.9",
        "en_IN": "en-IN,en;q=0.9,hi;q=0.8",
        "de_DE": "de-DE,de;q=0.9,en;q=0.8",
        "fr_FR": "fr-FR,fr;q=0.9,en;q=0.8",
        "ja_JP": "ja-JP,ja;q=0.9,en;q=0.8",
        "zh_CN": "zh-CN,zh;q=0.9,en;q=0.8",
        "pt_BR": "pt-BR,pt;q=0.9,en;q=0.8",
    }
    return mapping.get(locale, "en-US,en;q=0.9")


def fingerprint_js(profile: BrowserProfile) -> str:
    """Return a JS snippet that spoofs navigator properties (for use with Playwright/Selenium)."""
    return f"""
Object.defineProperty(navigator, 'userAgent', {{ get: () => '{profile.user_agent}' }});
Object.defineProperty(navigator, 'language', {{ get: () => '{profile.locale.replace("_", "-")}' }});
Object.defineProperty(navigator, 'platform', {{ get: () => '{profile.platform}' }});
Object.defineProperty(screen, 'width', {{ get: () => {profile.screen_width} }});
Object.defineProperty(screen, 'height', {{ get: () => {profile.screen_height} }});
Object.defineProperty(screen, 'colorDepth', {{ get: () => {profile.color_depth} }});
"""
