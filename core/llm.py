"""
phantom/core/llm.py

Unified LLM client abstraction.
Supports: Anthropic, OpenAI, Ollama (local), OpenRouter, any OpenAI-compatible endpoint.

Usage:
    from core.llm import chat, chat_stream, get_client

    response = await chat([{"role": "user", "content": "hello"}])
    print(response)

Provider selection priority:
  1. LLM_PROVIDER env var (explicit)
  2. Auto-detect from available keys:
     - ANTHROPIC_API_KEY → anthropic
     - OPENAI_API_KEY    → openai
     - OPENROUTER_API_KEY → openrouter
     - Nothing           → ollama (local, no key needed)
"""
from __future__ import annotations

import os
from enum import Enum
from typing import Any, AsyncIterator, Optional

from config.settings import settings


# ─────────────────────────────────────────────────────────────────────────────
# Provider enum
# ─────────────────────────────────────────────────────────────────────────────

class Provider(str, Enum):
    ANTHROPIC  = "anthropic"
    OPENAI     = "openai"
    OLLAMA     = "ollama"
    OPENROUTER = "openrouter"
    CUSTOM     = "custom"   # any OpenAI-compatible base URL


# ─────────────────────────────────────────────────────────────────────────────
# Auto-detect active provider
# ─────────────────────────────────────────────────────────────────────────────

def _detect_provider() -> Provider:
    explicit = os.getenv("LLM_PROVIDER", "").lower()
    if explicit:
        return Provider(explicit)
    if settings.anthropic_api_key:
        return Provider.ANTHROPIC
    if os.getenv("OPENAI_API_KEY"):
        return Provider.OPENAI
    if os.getenv("OPENROUTER_API_KEY"):
        return Provider.OPENROUTER
    # Default: Ollama (local, no key required)
    return Provider.OLLAMA


def _detect_model(provider: Provider) -> str:
    # Env override always wins
    env_model = os.getenv("LLM_MODEL", "")
    if env_model:
        return env_model

    defaults = {
        Provider.ANTHROPIC:  "claude-sonnet-4-6",
        Provider.OPENAI:     "gpt-4o",
        Provider.OLLAMA:     "llama3.1",
        Provider.OPENROUTER: "anthropic/claude-3.5-sonnet",
        Provider.CUSTOM:     "gpt-4o",
    }
    return defaults[provider]


def _detect_base_url(provider: Provider) -> Optional[str]:
    env_url = os.getenv("LLM_BASE_URL", "")
    if env_url:
        return env_url
    if provider == Provider.OLLAMA:
        return "http://localhost:11434/v1"
    if provider == Provider.OPENROUTER:
        return "https://openrouter.ai/api/v1"
    return None


def _detect_api_key(provider: Provider) -> str:
    if provider == Provider.ANTHROPIC:
        return settings.anthropic_api_key or ""
    if provider == Provider.OPENAI:
        return os.getenv("OPENAI_API_KEY", "")
    if provider == Provider.OPENROUTER:
        return os.getenv("OPENROUTER_API_KEY", "")
    if provider == Provider.OLLAMA:
        return "ollama"   # Ollama doesn't need a real key
    return os.getenv("LLM_API_KEY", "sk-placeholder")


# ─────────────────────────────────────────────────────────────────────────────
# LLM Config (resolved once per session)
# ─────────────────────────────────────────────────────────────────────────────

class LLMConfig:
    def __init__(self):
        self.provider  = _detect_provider()
        self.model     = _detect_model(self.provider)
        self.base_url  = _detect_base_url(self.provider)
        self.api_key   = _detect_api_key(self.provider)

    def summary(self) -> str:
        return f"{self.provider.value} / {self.model}"

    @classmethod
    def from_cli(
        cls,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> "LLMConfig":
        """Override config from CLI flags."""
        cfg = cls()
        if provider:
            cfg.provider = Provider(provider.lower())
            # Re-resolve defaults for the new provider
            if not model:
                cfg.model = _detect_model(cfg.provider)
            if not base_url:
                cfg.base_url = _detect_base_url(cfg.provider)
            if not api_key:
                cfg.api_key = _detect_api_key(cfg.provider)
        if model:
            cfg.model = model
        if base_url:
            cfg.base_url = base_url
        if api_key:
            cfg.api_key = api_key
        return cfg


# Singleton resolved at import time
_default_config: Optional[LLMConfig] = None


def get_config() -> LLMConfig:
    global _default_config
    if _default_config is None:
        _default_config = LLMConfig()
    return _default_config


def set_config(cfg: LLMConfig) -> None:
    """Called by CLI commands to override the active config."""
    global _default_config
    _default_config = cfg


# ─────────────────────────────────────────────────────────────────────────────
# Anthropic backend
# ─────────────────────────────────────────────────────────────────────────────

async def _anthropic_chat(
    messages: list[dict],
    system: str,
    max_tokens: int,
    tools: Optional[list] = None,
    cfg: LLMConfig = None,
) -> dict:
    import anthropic as sdk

    client = sdk.AsyncAnthropic(api_key=cfg.api_key)
    kwargs: dict[str, Any] = dict(
        model=cfg.model,
        max_tokens=max_tokens,
        system=system,
        messages=messages,
    )
    if tools:
        kwargs["tools"] = tools

    resp = await client.messages.create(**kwargs)
    return _normalize_anthropic(resp)


def _normalize_anthropic(resp) -> dict:
    """Convert Anthropic response to normalised format."""
    text_parts = []
    tool_calls = []

    for block in resp.content:
        if block.type == "text":
            text_parts.append(block.text)
        elif block.type == "tool_use":
            tool_calls.append({
                "id": block.id,
                "name": block.name,
                "input": block.input,
            })

    return {
        "text": "\n".join(text_parts),
        "tool_calls": tool_calls,
        "stop_reason": resp.stop_reason,
        "raw": resp,
    }


# ─────────────────────────────────────────────────────────────────────────────
# OpenAI-compatible backend (OpenAI, Ollama, OpenRouter, custom)
# ─────────────────────────────────────────────────────────────────────────────

async def _openai_chat(
    messages: list[dict],
    system: str,
    max_tokens: int,
    tools: Optional[list] = None,
    cfg: LLMConfig = None,
) -> dict:
    from openai import AsyncOpenAI

    full_messages = [{"role": "system", "content": system}] + messages

    client = AsyncOpenAI(
        api_key=cfg.api_key,
        base_url=cfg.base_url,
    )

    kwargs: dict[str, Any] = dict(
        model=cfg.model,
        max_tokens=max_tokens,
        messages=full_messages,
    )

    # Convert Anthropic-style tools to OpenAI format
    if tools:
        kwargs["tools"] = [_tool_to_openai(t) for t in tools]
        kwargs["tool_choice"] = "auto"

    resp = await client.chat.completions.create(**kwargs)
    return _normalize_openai(resp)


def _tool_to_openai(tool: dict) -> dict:
    """Convert Anthropic tool definition → OpenAI function call format."""
    return {
        "type": "function",
        "function": {
            "name": tool["name"],
            "description": tool.get("description", ""),
            "parameters": tool.get("input_schema", {"type": "object", "properties": {}}),
        }
    }


def _normalize_openai(resp) -> dict:
    """Convert OpenAI response to normalised format."""
    choice = resp.choices[0]
    msg = choice.message
    text = msg.content or ""
    tool_calls = []

    if msg.tool_calls:
        import json
        for tc in msg.tool_calls:
            try:
                inp = json.loads(tc.function.arguments)
            except Exception:
                inp = {}
            tool_calls.append({
                "id": tc.id,
                "name": tc.function.name,
                "input": inp,
            })

    return {
        "text": text,
        "tool_calls": tool_calls,
        "stop_reason": choice.finish_reason,
        "raw": resp,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def chat(
    messages: list[dict],
    system: str = "You are a helpful assistant.",
    max_tokens: int = 2048,
    tools: Optional[list] = None,
    cfg: Optional[LLMConfig] = None,
) -> dict:
    """
    Send a chat request to the configured LLM.

    Returns a normalised dict:
        {
          "text":       str,          # model text reply
          "tool_calls": list[dict],   # [{id, name, input}]
          "stop_reason": str,
          "raw": ...                  # raw provider response
        }
    """
    if cfg is None:
        cfg = get_config()

    if cfg.provider == Provider.ANTHROPIC:
        return await _anthropic_chat(messages, system, max_tokens, tools, cfg)
    else:
        return await _openai_chat(messages, system, max_tokens, tools, cfg)


async def chat_text(
    prompt: str,
    system: str = "You are a helpful assistant.",
    max_tokens: int = 2048,
    cfg: Optional[LLMConfig] = None,
) -> str:
    """Convenience: send a single prompt, return text string."""
    result = await chat(
        [{"role": "user", "content": prompt}],
        system=system,
        max_tokens=max_tokens,
        cfg=cfg,
    )
    return result["text"]
