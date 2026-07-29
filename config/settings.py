"""
phantom/config/settings.py

Global configuration. All paths, keys, and feature flags live here.
Everything is read from environment variables (with sane defaults).
"""
from __future__ import annotations

import os
from pathlib import Path
from dataclasses import dataclass, field


def _resolve_data_dir() -> Path:
    raw = os.getenv("PHANTOM_DATA_DIR", "~/.phantom")
    return Path(raw).expanduser().resolve()


@dataclass
class Settings:
    # ── API Keys ──────────────────────────────────────────────────────────
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "")
    )
    shodan_api_key: str = field(
        default_factory=lambda: os.getenv("SHODAN_API_KEY", "")
    )
    virustotal_api_key: str = field(
        default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY", "")
    )
    smspool_api_key: str = field(
        default_factory=lambda: os.getenv("SMSPOOL_API_KEY", "")
    )
    textverified_api_key: str = field(
        default_factory=lambda: os.getenv("TEXTVERIFIED_API_KEY", "")
    )

    # ── Paths ─────────────────────────────────────────────────────────────
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
        # Shipped with the package
        return Path(__file__).parent.parent / "registry" / "manifest.json"

    # ── Feature flags ─────────────────────────────────────────────────────
    docker_mode: bool = field(
        default_factory=lambda: os.getenv("PHANTOM_DOCKER_MODE", "true").lower() == "true"
    )

    # ── Email ─────────────────────────────────────────────────────────────
    email_domain: str = field(
        default_factory=lambda: os.getenv("PHANTOM_EMAIL_DOMAIN", "")
    )
    email_port: int = field(
        default_factory=lambda: int(os.getenv("PHANTOM_EMAIL_PORT", "2525"))
    )

    # ── Model ─────────────────────────────────────────────────────────────
    claude_model: str = "claude-sonnet-4-6"

    def ensure_dirs(self) -> None:
        """Create all required directories if they don't exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.wordlists_dir.mkdir(parents=True, exist_ok=True)

    def validate(self) -> list[str]:
        """Return a list of validation errors. Empty = all good."""
        errors = []
        if not self.anthropic_api_key:
            errors.append("ANTHROPIC_API_KEY is not set")
        return errors


# Singleton — import this everywhere
settings = Settings()
