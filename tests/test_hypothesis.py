"""
tests/test_hypothesis.py

Tests for the AI hypothesis engine (mocked LLM).
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, patch

from core.hypothesis import Hypothesis, generate


MOCK_HYPOTHESES = json.dumps([
    {
        "hypothesis": "Login endpoint may be vulnerable to SQL injection",
        "suggested_tool": "sqlmap",
        "confidence": 0.9,
        "reasoning": "Open port 3306 and PHP stack detected"
    },
    {
        "hypothesis": "Check for directory traversal in file parameter",
        "suggested_tool": "ffuf",
        "confidence": 0.7,
        "reasoning": "File serving endpoint found"
    }
])


class TestHypothesisGenerate:
    @pytest.mark.asyncio
    async def test_returns_empty_with_no_findings(self, sample_session):
        result = await generate(sample_session)
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_hypotheses_with_findings(self, sample_session_with_findings):
        with patch("core.hypothesis.chat_text", new=AsyncMock(return_value=MOCK_HYPOTHESES)):
            result = await generate(sample_session_with_findings)
            assert len(result) == 2
            assert isinstance(result[0], Hypothesis)

    @pytest.mark.asyncio
    async def test_sorted_by_confidence(self, sample_session_with_findings):
        with patch("core.hypothesis.chat_text", new=AsyncMock(return_value=MOCK_HYPOTHESES)):
            result = await generate(sample_session_with_findings)
            confidences = [h.confidence for h in result]
            assert confidences == sorted(confidences, reverse=True)

    @pytest.mark.asyncio
    async def test_hypothesis_fields_populated(self, sample_session_with_findings):
        with patch("core.hypothesis.chat_text", new=AsyncMock(return_value=MOCK_HYPOTHESES)):
            result = await generate(sample_session_with_findings)
            h = result[0]
            assert h.suggested_tool == "sqlmap"
            assert h.confidence == 0.9
            assert h.reasoning

    @pytest.mark.asyncio
    async def test_llm_failure_returns_empty(self, sample_session_with_findings):
        """Hypothesis engine failure should be non-fatal."""
        with patch("core.hypothesis.chat_text", new=AsyncMock(side_effect=Exception("LLM error"))):
            result = await generate(sample_session_with_findings)
            assert result == []

    @pytest.mark.asyncio
    async def test_persists_to_db(self, sample_session_with_findings):
        from core import session as db
        with patch("core.hypothesis.chat_text", new=AsyncMock(return_value=MOCK_HYPOTHESES)):
            await generate(sample_session_with_findings)
            saved = db.get_hypotheses(sample_session_with_findings.id)
            assert len(saved) == 2

    @pytest.mark.asyncio
    async def test_strips_markdown_fences(self, sample_session_with_findings):
        wrapped = f"```json\n{MOCK_HYPOTHESES}\n```"
        with patch("core.hypothesis.chat_text", new=AsyncMock(return_value=wrapped)):
            result = await generate(sample_session_with_findings)
            assert len(result) == 2
