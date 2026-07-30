"""
tests/test_js_tools.py

Tests for phantom-mcp/tools/js_tools.py
Focus: URL filtering, secret detection patterns, output structure, session wiring.
No real network calls — runner and aiohttp are mocked.
"""
from __future__ import annotations

import sys
import types as _types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

import pytest

# ── Path setup ────────────────────────────────────────────────────────────────
_TOOLS_DIR = Path(__file__).parent.parent / "phantom-mcp" / "tools"
_ROOT = Path(__file__).parent.parent
for p in [str(_TOOLS_DIR), str(_ROOT)]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Stub mcp.types if not installed
if "mcp" not in sys.modules:
    mcp_mod = _types.ModuleType("mcp")
    mcp_types_mod = _types.ModuleType("mcp.types")

    class _FakeTool:
        def __init__(self, name, description="", inputSchema=None):
            self.name = name
            self.description = description
            self.inputSchema = inputSchema or {}

    mcp_types_mod.Tool = _FakeTool
    mcp_mod.types = mcp_types_mod
    sys.modules["mcp"] = mcp_mod
    sys.modules["mcp.types"] = mcp_types_mod

from js_tools import (  # noqa: E402
    get_tool_definitions,
    get_handler,
    _is_js_url,
    _deduplicate,
    _deduplicate_secrets,
    _scan_content_for_secrets,
    _SECRET_PATTERNS,
)


# ─────────────────────────────────────────────────────────────────────────────
# Tool definitions
# ─────────────────────────────────────────────────────────────────────────────

class TestToolDefinitions:
    def test_tool_registered(self):
        defs = get_tool_definitions()
        names = {d.name for d in defs}
        assert "phantom_js_analyze" in names

    def test_required_params(self):
        defs = get_tool_definitions()
        tool = next(d for d in defs if d.name == "phantom_js_analyze")
        assert "url" in tool.inputSchema["required"]
        assert "session_id" in tool.inputSchema["required"]

    def test_handler_registered(self):
        assert get_handler("phantom_js_analyze") is not None

    def test_unknown_handler_returns_none(self):
        assert get_handler("phantom_nonexistent") is None


# ─────────────────────────────────────────────────────────────────────────────
# URL filtering
# ─────────────────────────────────────────────────────────────────────────────

class TestIsJsUrl:
    def test_basic_js_extension(self):
        assert _is_js_url("https://example.com/app.js") is True

    def test_js_with_query(self):
        assert _is_js_url("https://example.com/bundle.js?v=123") is True

    def test_mjs_extension(self):
        assert _is_js_url("https://example.com/module.mjs") is True

    def test_non_js_rejected(self):
        assert _is_js_url("https://example.com/style.css") is False
        assert _is_js_url("https://example.com/image.png") is False
        assert _is_js_url("https://example.com/page.html") is False

    def test_path_containing_js_not_extension(self):
        # /js/path.css should not match
        assert _is_js_url("https://example.com/js/style.css") is False


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication
# ─────────────────────────────────────────────────────────────────────────────

class TestDeduplicate:
    def test_removes_duplicates(self):
        result = _deduplicate(["a", "b", "a", "c", "b"])
        assert result == ["a", "b", "c"]

    def test_preserves_order(self):
        result = _deduplicate(["c", "a", "b"])
        assert result == ["c", "a", "b"]

    def test_empty_input(self):
        assert _deduplicate([]) == []

    def test_strips_whitespace(self):
        result = _deduplicate(["  /api/v1  ", "/api/v1"])
        assert len(result) == 1


class TestDeduplicateSecrets:
    def test_deduplicates_by_type_and_value(self):
        secrets = [
            {"type": "aws_access_key", "value": "AKIAIOSFODNN7EXAMPLE12"},
            {"type": "aws_access_key", "value": "AKIAIOSFODNN7EXAMPLE12"},
            {"type": "jwt", "value": "eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig"},
        ]
        result = _deduplicate_secrets(secrets)
        assert len(result) == 2


# ─────────────────────────────────────────────────────────────────────────────
# Secret scanning
# ─────────────────────────────────────────────────────────────────────────────

class TestSecretPatterns:
    def test_aws_key_detected(self):
        content = "export const KEY = 'AKIAIOSFODNN7EXAMPLE';"
        out: dict = {"secrets": [], "internal_urls": []}
        _scan_content_for_secrets(content, "https://example.com/app.js", out)
        types_found = {s["type"] for s in out["secrets"]}
        assert "aws_access_key" in types_found

    def test_private_key_detected(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        out: dict = {"secrets": [], "internal_urls": []}
        _scan_content_for_secrets(content, "https://example.com/app.js", out)
        types_found = {s["type"] for s in out["secrets"]}
        assert "private_key" in types_found

    def test_jwt_detected(self):
        content = "token = 'eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.c2lnbmF0dXJl';"
        out: dict = {"secrets": [], "internal_urls": []}
        _scan_content_for_secrets(content, "https://example.com/app.js", out)
        types_found = {s["type"] for s in out["secrets"]}
        assert "jwt" in types_found

    def test_internal_url_detected(self):
        content = "const BASE = 'http://192.168.1.50/api';"
        out: dict = {"secrets": [], "internal_urls": []}
        _scan_content_for_secrets(content, "https://example.com/app.js", out)
        assert len(out["internal_urls"]) > 0
        assert "192.168.1.50" in out["internal_urls"][0]

    def test_internal_localhost_detected(self):
        content = "const url = 'http://localhost:8080/debug';"
        out: dict = {"secrets": [], "internal_urls": []}
        _scan_content_for_secrets(content, "https://example.com/app.js", out)
        assert len(out["internal_urls"]) > 0

    def test_api_key_near_keyword(self):
        # 'api_key = ...' — key adjacent to keyword (underscore counts)
        content = 'const apikey="sk-supersecretkey123456789abcdef";'
        out: dict = {"secrets": [], "internal_urls": []}
        _scan_content_for_secrets(content, "https://example.com/app.js", out)
        types_found = {s["type"] for s in out["secrets"]}
        assert "api_key_near_keyword" in types_found

    def test_no_false_positive_on_short_value(self):
        content = "id = '123';"  # too short for api_key pattern
        out: dict = {"secrets": [], "internal_urls": []}
        _scan_content_for_secrets(content, "https://example.com/app.js", out)
        api_key_hits = [s for s in out["secrets"] if s["type"] == "api_key_near_keyword"]
        assert len(api_key_hits) == 0

    def test_clean_content_no_secrets(self):
        content = "function hello() { return 'world'; }"
        out: dict = {"secrets": [], "internal_urls": []}
        _scan_content_for_secrets(content, "https://example.com/app.js", out)
        assert out["secrets"] == []
        assert out["internal_urls"] == []


# ─────────────────────────────────────────────────────────────────────────────
# Handler — integration-level (mocked runner)
# ─────────────────────────────────────────────────────────────────────────────

class TestJsAnalyzeHandler:
    @pytest.mark.asyncio
    async def test_returns_expected_keys(self):
        """Handler returns all expected top-level keys."""
        mock_katana = MagicMock()
        mock_katana.stdout = ""
        mock_katana.exit_code = 0

        with patch("registry.runner.run_tool", new=AsyncMock(return_value=mock_katana)):
            from js_tools import _handle_js_analyze
            result = await _handle_js_analyze({
                "url": "https://example.com",
                "session_id": "test-session",
            })

        assert "js_files" in result
        assert "endpoints" in result
        assert "secrets" in result
        assert "internal_urls" in result
        assert "summary" in result

    @pytest.mark.asyncio
    async def test_no_js_files_returns_empty(self):
        """When katana finds no JS, all arrays are empty."""
        mock_katana = MagicMock()
        mock_katana.stdout = "https://example.com/page.html\nhttps://example.com/style.css\n"
        mock_katana.exit_code = 0

        with patch("registry.runner.run_tool", new=AsyncMock(return_value=mock_katana)):
            from js_tools import _handle_js_analyze
            result = await _handle_js_analyze({
                "url": "https://example.com",
                "session_id": "sess",
            })

        assert result["js_files"] == []
        assert result["endpoints"] == []

    @pytest.mark.asyncio
    async def test_katana_error_is_handled(self):
        """Handler gracefully catches runner errors and continues."""
        with patch("registry.runner.run_tool", side_effect=Exception("tool not found")):
            from js_tools import _handle_js_analyze
            result = await _handle_js_analyze({
                "url": "https://example.com",
                "session_id": "sess",
            })

        assert "katana_error" in result
        assert result["js_files"] == []
