"""
tests/test_standalone_tools.py

Tests for phantom-mcp/tools/standalone_tools.py
Focus: argument construction, wordlist resolution, output parsing.
No real network calls — runner is mocked.
"""
from __future__ import annotations

import sys
import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Load standalone_tools directly without triggering the phantom-mcp package
# __init__.py (which requires the mcp package not installed in the test env)
_TOOLS_DIR = Path(__file__).parent.parent / "phantom-mcp" / "tools"
_ROOT = Path(__file__).parent.parent
for p in [str(_TOOLS_DIR), str(_ROOT)]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Stub out mcp.types before importing standalone_tools
if "mcp" not in sys.modules:
    import types as _types
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

from standalone_tools import (  # noqa: E402
    _resolve_wordlist,
    _PORT_PROFILES,
    get_tool_definitions,
    get_handler,
)


# ─────────────────────────────────────────────────────────────────────────────
# Wordlist resolution
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveWordlist:
    def test_returns_requested_if_exists(self, tmp_path):
        wl = tmp_path / "custom.txt"
        wl.write_text("a\nb\n")
        assert _resolve_wordlist(str(wl)) == str(wl)

    def test_falls_back_to_bundled_when_missing(self):
        result = _resolve_wordlist("/nonexistent/path.txt")
        # Should return something — bundled or seclists
        assert isinstance(result, str)
        assert len(result) > 0

    def test_empty_string_uses_fallback(self):
        result = _resolve_wordlist("")
        assert isinstance(result, str)


# ─────────────────────────────────────────────────────────────────────────────
# Port profiles
# ─────────────────────────────────────────────────────────────────────────────

class TestPortProfiles:
    def test_common_profile_present(self):
        assert "common" in _PORT_PROFILES
        assert "1000" in _PORT_PROFILES["common"]

    def test_all_profile_scans_everything(self):
        assert "-p-" in _PORT_PROFILES["all"]

    def test_web_profile_has_443(self):
        assert "443" in _PORT_PROFILES["web"]


# ─────────────────────────────────────────────────────────────────────────────
# Tool definitions
# ─────────────────────────────────────────────────────────────────────────────

class TestToolDefinitions:
    def test_all_five_tools_registered(self):
        defs = get_tool_definitions()
        names = {d.name for d in defs}
        expected = {"phantom_nmap", "phantom_nuclei", "phantom_subfinder", "phantom_httpx", "phantom_ffuf"}
        assert expected == names

    def test_all_tools_have_required_target(self):
        """Most tools should require a target or domain/targets."""
        for t in get_tool_definitions():
            schema = t.inputSchema
            required = schema.get("required", [])
            assert len(required) >= 1, f"{t.name} has no required params"


# ─────────────────────────────────────────────────────────────────────────────
# Handler routing
# ─────────────────────────────────────────────────────────────────────────────

class TestGetHandler:
    def test_returns_handler_for_each_tool(self):
        for name in ["phantom_nmap", "phantom_nuclei", "phantom_subfinder", "phantom_httpx", "phantom_ffuf"]:
            assert get_handler(name) is not None

    def test_unknown_tool_returns_none(self):
        assert get_handler("phantom_nonexistent") is None


# ─────────────────────────────────────────────────────────────────────────────
# phantom_ffuf — FUZZ validation
# ─────────────────────────────────────────────────────────────────────────────

class TestFfufHandler:
    @pytest.mark.asyncio
    async def test_rejects_url_without_fuzz(self):
        from tools.standalone_tools import _handle_ffuf
        result = await _handle_ffuf({"url": "https://example.com/api"})
        assert "error" in result
        assert "FUZZ" in result["error"]

    @pytest.mark.asyncio
    async def test_accepts_url_with_fuzz(self):
        mock_result = MagicMock()
        mock_result.stdout = '{"results": []}'
        mock_result.exit_code = 0

        with patch("registry.runner.run_tool", new=AsyncMock(return_value=mock_result)) as mock_run:
            from standalone_tools import _handle_ffuf
            result = await _handle_ffuf({"url": "https://example.com/FUZZ"})
            assert "error" not in result
            assert "hits" in result


# ─────────────────────────────────────────────────────────────────────────────
# phantom_subfinder — output parsing
# ─────────────────────────────────────────────────────────────────────────────

class TestSubfinderHandler:
    @pytest.mark.asyncio
    async def test_parses_subdomains(self):
        mock_result = MagicMock()
        mock_result.stdout = "sub1.example.com\nsub2.example.com\nbad_line\n"
        mock_result.exit_code = 0

        with patch("registry.runner.run_tool", new=AsyncMock(return_value=mock_result)):
            from standalone_tools import _handle_subfinder
            result = await _handle_subfinder({"domain": "example.com"})

        assert result["subdomain_count"] == 2
        assert "sub1.example.com" in result["subdomains"]
        # Lines without dots should be filtered out
        assert "bad_line" not in result["subdomains"]
