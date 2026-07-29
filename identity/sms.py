"""
phantom/identity/sms.py

SMS OTP via SMSPool or TextVerified API.
Only external identity dependency.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Optional


class SMSError(Exception):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# SMSPool backend
# ─────────────────────────────────────────────────────────────────────────────

SMSPOOL_BASE = "https://api.smspool.net"


async def _smspool_get_number(api_key: str, service: str, country: str) -> tuple[str, str]:
    """Returns (phone_number, request_id)."""
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SMSPOOL_BASE}/purchase/sms",
            data={"key": api_key, "service": service, "country": country},
        ) as resp:
            data = await resp.json(content_type=None)
    if not data.get("success"):
        raise SMSError(f"SMSPool error: {data.get('message', 'unknown')}")
    return data["phonenumber"], data["request_id"]


async def _smspool_get_otp(api_key: str, request_id: str, timeout: int) -> str:
    import aiohttp
    elapsed = 0
    while elapsed < timeout:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{SMSPOOL_BASE}/sms/check",
                data={"key": api_key, "id": request_id},
            ) as resp:
                data = await resp.json(content_type=None)
        if data.get("status") == 3:  # Message received
            sms_text = data.get("sms", "")
            # Extract digits
            digits = re.findall(r"\d{4,8}", sms_text)
            if digits:
                return digits[0]
            return sms_text
        await asyncio.sleep(5)
        elapsed += 5
    raise SMSError(f"OTP not received within {timeout}s")


# ─────────────────────────────────────────────────────────────────────────────
# TextVerified backend
# ─────────────────────────────────────────────────────────────────────────────

TEXTVERIFIED_BASE = "https://www.textverified.com/api"


async def _textverified_get_number(api_key: str, service: str) -> tuple[str, str]:
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{TEXTVERIFIED_BASE}/Authentications",
            json={"serviceName": service},
            headers={"X-SIMPLE-API-ACCESS-TOKEN": api_key},
        ) as resp:
            data = await resp.json(content_type=None)
    if "id" not in data:
        raise SMSError(f"TextVerified error: {data}")
    return data.get("phonenumber", ""), str(data["id"])


async def _textverified_get_otp(api_key: str, auth_id: str, timeout: int) -> str:
    import aiohttp
    elapsed = 0
    while elapsed < timeout:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{TEXTVERIFIED_BASE}/Authentications/{auth_id}",
                headers={"X-SIMPLE-API-ACCESS-TOKEN": api_key},
            ) as resp:
                data = await resp.json(content_type=None)
        code = data.get("code", "")
        if code and code != "pending":
            return code
        await asyncio.sleep(5)
        elapsed += 5
    raise SMSError(f"OTP not received within {timeout}s")


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def _get_provider() -> tuple[str, str]:
    """Returns (provider_name, api_key). Raises if neither configured."""
    from config.settings import settings
    if settings.smspool_api_key:
        return "smspool", settings.smspool_api_key
    if settings.textverified_api_key:
        return "textverified", settings.textverified_api_key
    raise SMSError(
        "No SMS API key configured. Set SMSPOOL_API_KEY or TEXTVERIFIED_API_KEY in .env"
    )


async def get_number(service: str, country: str = "US") -> tuple[str, str]:
    """
    Get a temporary phone number for the given service.
    Returns (phone_number, request_id).
    The request_id is needed to poll for the OTP.
    """
    provider, api_key = _get_provider()
    if provider == "smspool":
        return await _smspool_get_number(api_key, service, country)
    else:
        return await _textverified_get_number(api_key, service)


async def get_otp(request_id: str, timeout: int = 120) -> str:
    """
    Poll for an OTP for the given request_id.
    Returns the OTP string when received, raises SMSError on timeout.
    """
    provider, api_key = _get_provider()
    if provider == "smspool":
        return await _smspool_get_otp(api_key, request_id, timeout)
    else:
        return await _textverified_get_otp(api_key, request_id, timeout)
