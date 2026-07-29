"""
tests/test_settings.py

Tests for configuration loading and validation.
"""
from __future__ import annotations

import pytest


class TestSettings:
    def test_db_path_inside_data_dir(self, tmp_data_dir):
        from config.settings import Settings
        s = Settings()
        s.data_dir = tmp_data_dir
        assert s.db_path == tmp_data_dir / "phantom.db"

    def test_tools_dir_inside_data_dir(self, tmp_data_dir):
        from config.settings import Settings
        s = Settings()
        s.data_dir = tmp_data_dir
        assert s.tools_dir == tmp_data_dir / "tools"

    def test_ensure_dirs_creates_all(self, tmp_path):
        from config.settings import Settings
        s = Settings()
        s.data_dir = tmp_path / "phantom_test_dirs"
        s.ensure_dirs()
        assert s.data_dir.exists()
        assert s.tools_dir.exists()
        assert s.wordlists_dir.exists()

    def test_validate_no_key_returns_warning(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.delenv("LLM_API_KEY", raising=False)

        from config.settings import Settings
        s = Settings()
        warnings = s.validate()
        assert len(warnings) > 0
        assert any("Ollama" in w or "key" in w.lower() for w in warnings)

    def test_validate_with_key_no_warnings(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

        from config.settings import Settings
        s = Settings()
        warnings = s.validate()
        assert warnings == []
