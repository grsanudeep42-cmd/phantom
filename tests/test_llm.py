"""
tests/test_llm.py

Tests for the LLM provider abstraction.
"""
from __future__ import annotations

import os
import pytest
from unittest.mock import AsyncMock, patch


class TestLLMConfig:
    def test_auto_detects_anthropic(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        # Reset singleton and patch settings so _detect_provider sees the key
        import core.llm as llm_mod
        from config import settings as settings_mod
        monkeypatch.setattr(settings_mod.settings, "anthropic_api_key", "sk-ant-test")
        llm_mod._default_config = None

        from core.llm import LLMConfig, Provider
        cfg = LLMConfig()
        assert cfg.provider == Provider.ANTHROPIC
        assert cfg.api_key == "sk-ant-test"

    def test_auto_detects_openai(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        import core.llm as llm_mod
        llm_mod._default_config = None

        from core.llm import LLMConfig, Provider
        cfg = LLMConfig()
        assert cfg.provider == Provider.OPENAI

    def test_auto_detects_ollama_fallback(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        import core.llm as llm_mod
        llm_mod._default_config = None

        from core.llm import LLMConfig, Provider
        cfg = LLMConfig()
        assert cfg.provider == Provider.OLLAMA

    def test_explicit_env_override(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("LLM_MODEL", "gpt-4o")
        import core.llm as llm_mod
        llm_mod._default_config = None

        from core.llm import LLMConfig, Provider
        cfg = LLMConfig()
        assert cfg.provider == Provider.OPENAI
        assert cfg.model == "gpt-4o"
        monkeypatch.delenv("LLM_MODEL", raising=False)

    def test_from_cli_ollama(self, monkeypatch):
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        from core.llm import LLMConfig, Provider
        cfg = LLMConfig.from_cli(
            provider="ollama",
            model="llama3.1",
            base_url="http://localhost:11434/v1",
        )
        assert cfg.provider == Provider.OLLAMA
        assert cfg.model == "llama3.1"
        assert cfg.base_url == "http://localhost:11434/v1"

    def test_from_cli_model_only(self, monkeypatch):
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
        from core.llm import LLMConfig, Provider
        cfg = LLMConfig.from_cli(model="claude-haiku-3-5")
        # Provider auto-detected, model overridden
        assert cfg.model == "claude-haiku-3-5"

    def test_summary_anthropic(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        from core.llm import LLMConfig, Provider
        cfg = LLMConfig()
        cfg.provider = Provider.ANTHROPIC
        cfg.model = "claude-sonnet-4-6"
        summary = cfg.summary()
        assert "anthropic" in summary.lower()
        assert "claude-sonnet-4-6" in summary

    def test_summary_ollama_says_local(self, monkeypatch):
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        from core.llm import LLMConfig, Provider
        cfg = LLMConfig()
        cfg.provider = Provider.OLLAMA
        cfg.model = "llama3.1"
        cfg.api_key = ""
        summary = cfg.summary()
        assert "ollama" in summary.lower()

    def test_set_get_config(self, monkeypatch):
        import core.llm as llm_mod
        from core.llm import LLMConfig, set_config, get_config, Provider
        cfg = LLMConfig.from_cli(provider="ollama", model="mistral")
        set_config(cfg)
        assert get_config().model == "mistral"
        assert get_config().provider == Provider.OLLAMA
        # Cleanup
        llm_mod._default_config = None


class TestChatText:
    @pytest.mark.asyncio
    async def test_chat_text_anthropic(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        import core.llm as llm_mod
        llm_mod._default_config = None

        from core.llm import LLMConfig, set_config, Provider
        cfg = LLMConfig.from_cli(provider="anthropic", model="claude-sonnet-4-6", api_key="sk-ant-test")
        set_config(cfg)

        mock_response = {"text": "Hello from mock", "tool_calls": []}
        with patch("core.llm._anthropic_chat", new=AsyncMock(return_value=mock_response)):
            from core.llm import chat_text
            result = await chat_text("Hello", system="You are helpful", max_tokens=100)
            assert result == "Hello from mock"
        llm_mod._default_config = None

    @pytest.mark.asyncio
    async def test_chat_text_openai(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        import core.llm as llm_mod
        llm_mod._default_config = None

        from core.llm import LLMConfig, set_config, Provider
        cfg = LLMConfig.from_cli(provider="openai", model="gpt-4o", api_key="sk-test")
        set_config(cfg)

        mock_response = {"text": "OpenAI reply", "tool_calls": []}
        with patch("core.llm._openai_chat", new=AsyncMock(return_value=mock_response)):
            from core.llm import chat_text
            result = await chat_text("Test", system="", max_tokens=100)
            assert result == "OpenAI reply"
        llm_mod._default_config = None
