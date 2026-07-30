"""
phantom/core/llm.py

Unified LLM client abstraction — production grade.
Supports: Anthropic, OpenAI, Ollama (local), OpenRouter, any OpenAI-compatible endpoint.

Features:
  - Auto-detect provider from environment
  - Exponential backoff + jitter on transient errors (429, 529, 5xx, timeout)
  - Per-call timeout (default 90s)
  - Anthropic prompt caching (cache_control on system blocks)
  - Token usage + cost tracking per call
  - Normalised response dict across all providers
  - chat_text() convenience for simple one-shot calls

Provider selection priority:
  1. LLM_PROVIDER env var (explicit)
  2. Auto-detect from available keys:
     - ANTHROPIC_API_KEY  → anthropic
     - OPENAI_API_KEY     → openai
     - OPENROUTER_API_KEY → openrouter
     - Nothing            → ollama (local, no key needed)
"""
from __future__ import annotations

import asyncio
import os
import random
import time
from enum import Enum
from typing import Any, Optional

from config.settings import settings


# ─────────────────────────────────────────────────────────────────────────────
# Cost table (USD per 1M tokens, as of mid-2025)
# ─────────────────────────────────────────────────────────────────────────────

_COST_PER_1M: dict[str, dict[str, float]] = {
    # model_id: {input, output, cache_read, cache_write}
    "claude-sonnet-4-6":          {"input": 3.0,   "output": 15.0,  "cache_read": 0.30,  "cache_write": 3.75},
    "claude-3-5-sonnet-20241022": {"input": 3.0,   "output": 15.0,  "cache_read": 0.30,  "cache_write": 3.75},
    "claude-3-5-haiku-20241022":  {"input": 0.8,   "output": 4.0,   "cache_read": 0.08,  "cache_write": 1.0},
    "claude-3-opus-20240229":     {"input": 15.0,  "output": 75.0,  "cache_read": 1.50,  "cache_write": 18.75},
    "gpt-4o":                     {"input": 2.5,   "output": 10.0,  "cache_read": 0.0,   "cache_write": 0.0},
    "gpt-4o-mini":                {"input": 0.15,  "output": 0.60,  "cache_read": 0.0,   "cache_write": 0.0},
    "llama3.1":                   {"input": 0.0,   "output": 0.0,   "cache_read": 0.0,   "cache_write": 0.0},
}


def _cost_usd(model: str, usage: dict) -> float:
    """Estimate cost in USD from a token usage dict."""
    rates = _COST_PER_1M.get(model, {"input": 0.0, "output": 0.0, "cache_read": 0.0, "cache_write": 0.0})
    inp    = usage.get("input_tokens", 0)
    out    = usage.get("output_tokens", 0)
    cr     = usage.get("cache_read_tokens", 0)
    cw     = usage.get("cache_write_tokens", 0)
    return (
        inp    * rates["input"]        / 1_000_000
        + out  * rates["output"]       / 1_000_000
        + cr   * rates["cache_read"]   / 1_000_000
        + cw   * rates["cache_write"]  / 1_000_000
    )


# ─────────────────────────────────────────────────────────────────────────────
# Custom exceptions
# ─────────────────────────────────────────────────────────────────────────────

class LLMError(RuntimeError):
    """Base LLM error."""

class LLMRateLimitError(LLMError):
    """429 / 529 — should retry with backoff."""

class LLMTimeoutError(LLMError):
    """Request timed out."""

class LLMProviderError(LLMError):
    """5xx or unexpected provider error — may be transient."""


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
        return "ollama"
    return os.getenv("LLM_API_KEY", "sk-placeholder")


# ─────────────────────────────────────────────────────────────────────────────
# LLM Config
# ─────────────────────────────────────────────────────────────────────────────

class LLMConfig:
    def __init__(self):
        self.provider  = _detect_provider()
        self.model     = _detect_model(self.provider)
        self.base_url  = _detect_base_url(self.provider)
        self.api_key   = _detect_api_key(self.provider)
        # Retry settings
        self.max_retries: int   = 3
        self.base_delay: float  = 1.0   # seconds
        self.max_delay: float   = 60.0  # seconds
        # Per-call timeout
        self.call_timeout: float = 90.0
        # Prompt caching (Anthropic only)
        self.use_prompt_cache: bool = True

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
# Retry decorator — exponential backoff with full jitter
# ─────────────────────────────────────────────────────────────────────────────

def _is_retryable(exc: Exception) -> bool:
    """Return True if the exception is a transient error worth retrying."""
    if isinstance(exc, (LLMRateLimitError, LLMTimeoutError, LLMProviderError)):
        return True
    # Catch raw HTTP errors from anthropic/openai SDKs
    name = type(exc).__name__
    msg  = str(exc).lower()
    if any(k in name.lower() for k in ("ratelimit", "overload", "timeout", "connection")):
        return True
    if any(k in msg for k in ("529", "429", "503", "502", "timeout", "timed out", "overloaded")):
        return True
    return False


async def _with_retry(coro_factory, cfg: LLMConfig):
    """
    Execute coro_factory() with exponential backoff + full jitter.
    coro_factory is a callable that returns a fresh coroutine each call.
    """
    last_exc: Exception = RuntimeError("No attempts made")
    for attempt in range(cfg.max_retries + 1):
        try:
            return await asyncio.wait_for(coro_factory(), timeout=cfg.call_timeout)
        except asyncio.TimeoutError as e:
            last_exc = LLMTimeoutError(f"LLM call timed out after {cfg.call_timeout}s")
            if attempt >= cfg.max_retries:
                break
        except Exception as e:
            last_exc = e
            if not _is_retryable(e):
                raise  # Non-transient: fail immediately
            if attempt >= cfg.max_retries:
                break

        # Full jitter: sleep random in [0, min(cap, base * 2^attempt)]
        cap   = min(cfg.max_delay, cfg.base_delay * (2 ** attempt))
        delay = random.uniform(0, cap)
        await asyncio.sleep(delay)

    raise last_exc


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

    # Build system block — use cache_control if enabled
    if cfg.use_prompt_cache:
        system_param = [
            {
                "type": "text",
                "text": system,
                "cache_control": {"type": "ephemeral"},   # Anthropic prompt caching
            }
        ]
    else:
        system_param = system

    kwargs: dict[str, Any] = dict(
        model=cfg.model,
        max_tokens=max_tokens,
        system=system_param,
        messages=messages,
    )
    if tools:
        kwargs["tools"] = tools

    # Add beta header for prompt caching
    extra_headers = {}
    if cfg.use_prompt_cache:
        extra_headers["anthropic-beta"] = "prompt-caching-2024-07-31"

    async def _call():
        try:
            if extra_headers:
                return await client.messages.create(**kwargs, extra_headers=extra_headers)
            return await client.messages.create(**kwargs)
        except sdk.RateLimitError as e:
            raise LLMRateLimitError(str(e)) from e
        except sdk.APIStatusError as e:
            if e.status_code in (529, 503, 502, 500):
                raise LLMProviderError(str(e)) from e
            raise

    resp = await _with_retry(_call, cfg)
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
                "id":    block.id,
                "name":  block.name,
                "input": block.input,
            })

    # Token usage
    usage = {}
    if hasattr(resp, "usage") and resp.usage:
        u = resp.usage
        usage = {
            "input_tokens":        getattr(u, "input_tokens", 0),
            "output_tokens":       getattr(u, "output_tokens", 0),
            "cache_read_tokens":   getattr(u, "cache_read_input_tokens", 0),
            "cache_write_tokens":  getattr(u, "cache_creation_input_tokens", 0),
        }

    return {
        "text":        "\n".join(text_parts),
        "tool_calls":  tool_calls,
        "stop_reason": resp.stop_reason,
        "usage":       usage,
        "cost_usd":    _cost_usd(resp.model, usage),
        "raw":         resp,
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
    from openai import AsyncOpenAI, RateLimitError, APIStatusError

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

    if tools:
        kwargs["tools"]       = [_tool_to_openai(t) for t in tools]
        kwargs["tool_choice"] = "auto"

    async def _call():
        try:
            return await client.chat.completions.create(**kwargs)
        except RateLimitError as e:
            raise LLMRateLimitError(str(e)) from e
        except APIStatusError as e:
            if e.status_code in (503, 502, 500):
                raise LLMProviderError(str(e)) from e
            raise

    resp = await _with_retry(_call, cfg)
    return _normalize_openai(resp, cfg.model)


def _tool_to_openai(tool: dict) -> dict:
    """Convert Anthropic tool definition → OpenAI function call format."""
    return {
        "type": "function",
        "function": {
            "name":        tool["name"],
            "description": tool.get("description", ""),
            "parameters":  tool.get("input_schema", {"type": "object", "properties": {}}),
        }
    }


def _normalize_openai(resp, model: str = "") -> dict:
    """Convert OpenAI response to normalised format."""
    import json as _json
    choice = resp.choices[0]
    msg    = choice.message
    text   = msg.content or ""
    tool_calls = []

    if msg.tool_calls:
        for tc in msg.tool_calls:
            try:
                inp = _json.loads(tc.function.arguments)
            except Exception:
                inp = {}
            tool_calls.append({
                "id":    tc.id,
                "name":  tc.function.name,
                "input": inp,
            })

    usage = {}
    if resp.usage:
        usage = {
            "input_tokens":  resp.usage.prompt_tokens,
            "output_tokens": resp.usage.completion_tokens,
        }

    return {
        "text":        text,
        "tool_calls":  tool_calls,
        "stop_reason": choice.finish_reason,
        "usage":       usage,
        "cost_usd":    _cost_usd(model, usage),
        "raw":         resp,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def chat(
    messages: list[dict],
    system: str = "You are a helpful assistant.",
    max_tokens: int = 4096,
    tools: Optional[list] = None,
    cfg: Optional[LLMConfig] = None,
) -> dict:
    """
    Send a chat request to the configured LLM.

    Returns a normalised dict:
        {
          "text":        str,          # model text reply
          "tool_calls":  list[dict],   # [{id, name, input}]
          "stop_reason": str,
          "usage":       dict,         # {input_tokens, output_tokens, cache_*}
          "cost_usd":    float,        # estimated USD cost
          "raw": ...                   # raw provider response
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
