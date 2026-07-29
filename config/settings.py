"""
phantom/config/settings.py

Global configuration. All paths, keys, and feature flags live here.
Everything is read from environment variables (with sane defaults).

LLM provider selection (auto-detected if not set):
  1. LLM_PROVIDER  (anthropic | openai | ollama | openrouter | custom)
  2. LLM_MODEL     (e.g. claude-sonnet-4-6 / gpt-4o / llama3.1)
  3. LLM_BASE_URL  (for Ollama: http://localhost:11434/v1 or any OpenAI-compat URL)
  4. LLM_API_KEY   (generic key override)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _resolve_data_dir() -> Path:
    raw = os.getenv("PHANTOM_DATA_DIR", "~/.phantom")
    return Path(raw).expanduser().resolve()


@dataclass
class Settings:
    # ── LLM Provider (primary AI key — supports Anthropic, OpenAI, Ollama, any compat) ──
    # These are read by core/llm.py. Settings just stores them for convenience.
    anthropic_api_key: str   = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    openai_api_key: str      = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    openrouter_api_key: str  = field(default_factory=lambda: os.getenv("OPENROUTER_API_KEY", ""))

    # Generic overrides (used by core/llm.py)
    llm_provider: str  = field(default_factory=lambda: os.getenv("LLM_PROVIDER", ""))
    llm_model: str     = field(default_factory=lambda: os.getenv("LLM_MODEL", ""))
    llm_base_url: str  = field(default_factory=lambda: os.getenv("LLM_BASE_URL", ""))
    llm_api_key: str   = field(default_factory=lambda: os.getenv("LLM_API_KEY", ""))

    # ── Optional enrichment keys ───────────────────────────────────────────
    shodan_api_key: str       = field(default_factory=lambda: os.getenv("SHODAN_API_KEY", ""))
    virustotal_api_key: str   = field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY", ""))
    smspool_api_key: str      = field(default_factory=lambda: os.getenv("SMSPOOL_API_KEY", ""))
    textverified_api_key: str = field(default_factory=lambda: os.getenv("TEXTVERIFIED_API_KEY", ""))

    # ── Paths ──────────────────────────────────────────────────────────────
    data_dir: Path = field(default_factory=_resolve_data_dir)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "phantom.db"

    @property
    def tools_dir(self) -> Path:
        return self.data_dir / "tools"

    @property
    def wordlists_dir(self) -> Path:
        return self.data_dir / "wordlists"

    @property
    def manifest_path(self) -> Path:
        return Path(__file__).parent.parent / "registry" / "manifest.json"

    # ── Feature flags ──────────────────────────────────────────────────────
    docker_mode: bool = field(
        default_factory=lambda: os.getenv("PHANTOM_DOCKER_MODE", "true").lower() == "true"
    )

    # ── Email ──────────────────────────────────────────────────────────────
    email_domain: str = field(default_factory=lambda: os.getenv("PHANTOM_EMAIL_DOMAIN", ""))
    email_port: int   = field(default_factory=lambda: int(os.getenv("PHANTOM_EMAIL_PORT", "2525")))

    def ensure_dirs(self) -> None:
        """Create all required directories if they don't exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.wordlists_dir.mkdir(parents=True, exist_ok=True)

    def validate(self) -> list[str]:
        """
        Return a list of validation warnings. Empty = all good.
        NOT fatal — Ollama works with no keys at all.
        """
        warnings = []
        has_any_key = any([
            self.anthropic_api_key,
            self.openai_api_key,
            self.openrouter_api_key,
            self.llm_api_key,
        ])
        if not has_any_key:
            # Ollama is fine without a key — just inform
            warnings.append(
                "No LLM API key found. Defaulting to Ollama (local). "
                "Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OPENROUTER_API_KEY to use cloud models."
            )
        return warnings

    def llm_summary(self) -> str:
        """One-line description of the active LLM config for CLI display."""
        from core.llm import get_config
        try:
            return get_config().summary()
        except Exception:
            return "unknown"


# Singleton — import this everywhere
settings = Settings()
