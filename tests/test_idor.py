"""
tests/test_idor.py

Tests for phantom-mcp/tools/idor_tools.py
Focus: IDOR target identification, URL building, response comparison logic.
No real network calls — aiohttp is mocked.
"""
from __future__ import annotations

import sys
import types as _types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

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

from idor_tools import (  # noqa: E402
    get_tool_definitions,
    get_handler,
    _identify_idor_targets,
    _build_url,
    _compare_responses,
    _make_finding,
)


# ─────────────────────────────────────────────────────────────────────────────
# Tool definitions
# ─────────────────────────────────────────────────────────────────────────────

class TestToolDefinitions:
    def test_tool_registered(self):
        defs = get_tool_definitions()
        names = {d.name for d in defs}
        assert "phantom_idor_hunt" in names

    def test_required_params(self):
        defs = get_tool_definitions()
        tool = next(d for d in defs if d.name == "phantom_idor_hunt")
        assert "session_id" in tool.inputSchema["required"]
        assert "base_url" in tool.inputSchema["required"]

    def test_handler_registered(self):
        assert get_handler("phantom_idor_hunt") is not None

    def test_unknown_handler_none(self):
        assert get_handler("phantom_xyzzy") is None


# ─────────────────────────────────────────────────────────────────────────────
# IDOR target identification
# ─────────────────────────────────────────────────────────────────────────────

class TestIdentifyIdorTargets:
    BASE = "https://example.com"

    def test_numeric_path_segment(self):
        endpoints = ["https://example.com/users/123/profile"]
        targets = _identify_idor_targets(endpoints, self.BASE)
        types = {t["param_type"] for t in targets}
        assert "path_numeric" in types
        assert any(t["original_value"] == "123" for t in targets)

    def test_uuid_path_segment(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        endpoints = [f"https://example.com/items/{uuid}"]
        targets = _identify_idor_targets(endpoints, self.BASE)
        types = {t["param_type"] for t in targets}
        assert "path_uuid" in types
        assert any(t["original_value"] == uuid for t in targets)

    def test_numeric_query_param(self):
        endpoints = ["https://example.com/order?id=456"]
        targets = _identify_idor_targets(endpoints, self.BASE)
        types = {t["param_type"] for t in targets}
        assert "query_numeric" in types
        assert any(t["original_value"] == "456" for t in targets)

    def test_uuid_query_param(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        endpoints = [f"https://example.com/docs?doc_id={uuid}"]
        targets = _identify_idor_targets(endpoints, self.BASE)
        assert any(t["param_type"] == "query_uuid" for t in targets)

    def test_no_idor_target_on_clean_url(self):
        endpoints = ["https://example.com/login", "https://example.com/about"]
        targets = _identify_idor_targets(endpoints, self.BASE)
        assert targets == []

    def test_multiple_endpoints_aggregated(self):
        endpoints = [
            "https://example.com/users/1",
            "https://example.com/orders/2",
        ]
        targets = _identify_idor_targets(endpoints, self.BASE)
        assert len(targets) >= 2

    def test_non_id_query_param_ignored(self):
        """A numeric value in a non-ID-like parameter name should not be flagged."""
        endpoints = ["https://example.com/search?page=3&limit=10"]
        targets = _identify_idor_targets(endpoints, self.BASE)
        # 'page' and 'limit' are not in _NUMERIC_ID_PARAM
        assert targets == []


# ─────────────────────────────────────────────────────────────────────────────
# URL building
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildUrl:
    def test_replaces_path_numeric(self):
        target = {
            "url": "https://example.com/users/123",
            "param_type": "path_numeric",
            "original_value": "123",
            "param_name": "path_segment",
        }
        result = _build_url(target, "124")
        assert "/124" in result
        assert "/123" not in result

    def test_replaces_query_param(self):
        target = {
            "url": "https://example.com/api?id=42",
            "param_type": "query_numeric",
            "original_value": "42",
            "param_name": "id",
        }
        result = _build_url(target, "0")
        assert "id=0" in result
        assert "id=42" not in result

    def test_replaces_uuid_path(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        target = {
            "url": f"https://example.com/items/{uuid}",
            "param_type": "path_uuid",
            "original_value": uuid,
            "param_name": "path_segment",
        }
        new_uuid = "00000000-0000-0000-0000-000000000000"
        result = _build_url(target, new_uuid)
        assert new_uuid in result
        assert uuid not in result


# ─────────────────────────────────────────────────────────────────────────────
# Response comparison
# ─────────────────────────────────────────────────────────────────────────────

class TestCompareResponses:
    def _target(self):
        return {
            "url": "https://example.com/users/123",
            "param_type": "path_numeric",
            "original_value": "123",
            "param_name": "path_segment",
        }

    def test_delete_success_flagged(self):
        baseline = {"status": 403, "body_hash": "abc", "content_length": 100, "body_preview": ""}
        mutated = {"status": 204, "body_hash": "xyz", "content_length": 0, "body_preview": ""}
        finding = _compare_responses(
            baseline, mutated,
            "https://example.com/users/122",
            "DELETE", "numeric_minus_1", "123", "122", self._target()
        )
        assert finding is not None
        assert finding["finding_type"] == "unauthorized_delete"
        assert finding["confidence"] == "confirmed"

    def test_get_different_content_flagged(self):
        baseline = {"status": 200, "body_hash": "hash_a", "content_length": 1000, "body_preview": "user_a_data"}
        mutated = {"status": 200, "body_hash": "hash_b", "content_length": 1200, "body_preview": "user_b_data"}
        finding = _compare_responses(
            baseline, mutated,
            "https://example.com/users/124",
            "GET", "numeric_plus_1", "123", "124", self._target()
        )
        assert finding is not None
        assert finding["finding_type"] == "different_data_returned"
        assert finding["confidence"] == "potential"

    def test_same_response_not_flagged(self):
        baseline = {"status": 200, "body_hash": "same_hash", "content_length": 500, "body_preview": "data"}
        mutated = {"status": 200, "body_hash": "same_hash", "content_length": 500, "body_preview": "data"}
        finding = _compare_responses(
            baseline, mutated,
            "https://example.com/users/124",
            "GET", "numeric_plus_1", "123", "124", self._target()
        )
        assert finding is None

    def test_method_bypass_flagged(self):
        baseline = {"status": 403, "body_hash": "h1", "content_length": 50, "body_preview": "forbidden"}
        mutated = {"status": 200, "body_hash": "h2", "content_length": 500, "body_preview": "secret data"}
        finding = _compare_responses(
            baseline, mutated,
            "https://example.com/users/123",
            "PUT", "boundary_zero", "123", "0", self._target()
        )
        assert finding is not None
        assert finding["finding_type"] == "method_based_auth_bypass"

    def test_error_response_not_flagged(self):
        baseline = {"status": 200, "body_hash": "h1", "content_length": 500, "body_preview": ""}
        mutated = {"status": -1, "body_hash": "", "content_length": 0}
        finding = _compare_responses(
            baseline, mutated,
            "https://example.com/users/0",
            "GET", "boundary_zero", "123", "0", self._target()
        )
        assert finding is None


# ─────────────────────────────────────────────────────────────────────────────
# Finding structure
# ─────────────────────────────────────────────────────────────────────────────

class TestMakeFinding:
    def test_finding_has_required_fields(self):
        target = {
            "url": "https://example.com/users/123",
            "param_type": "path_numeric",
            "original_value": "123",
            "param_name": "path_segment",
        }
        baseline = {"status": 200, "content_length": 500, "body_preview": "owner data"}
        mutated = {"status": 200, "content_length": 700, "body_preview": "other user data"}
        finding = _make_finding(
            target, "122", "GET", "different_data_returned",
            "potential", baseline, mutated, "Different data returned."
        )
        assert "cvss_score" in finding
        assert "severity" in finding
        assert "reproduction_steps" in finding
        assert "hackerone_title" in finding
        assert finding["confidence"] == "potential"

    def test_confirmed_delete_has_high_cvss(self):
        target = {
            "url": "https://example.com/items/99",
            "param_type": "path_numeric",
            "original_value": "99",
            "param_name": "path_segment",
        }
        finding = _make_finding(
            target, "98", "DELETE", "unauthorized_delete",
            "confirmed", {"status": 403}, {"status": 204}, "desc"
        )
        assert finding["cvss_score"] >= 9.0
        assert finding["severity"] == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# Handler — no-endpoint early exit
# ─────────────────────────────────────────────────────────────────────────────

class TestIdorHuntHandler:
    @pytest.mark.asyncio
    async def test_no_endpoints_returns_error(self):
        """If session has no endpoints and no extra_endpoints, return error."""
        with patch("core.session.get_findings", return_value=[]):
            from idor_tools import _handle_idor_hunt
            result = await _handle_idor_hunt({
                "session_id": "no-endpoints-session",
                "base_url": "https://example.com",
            })
        assert "error" in result or result.get("idor_targets_identified") == 0
