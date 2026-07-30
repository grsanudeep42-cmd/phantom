import pytest
from unittest.mock import patch, MagicMock

from core.chainer import chain_finding, fire_chain_analysis

@pytest.mark.asyncio
async def test_analyze_chain_basic():
    # Mock LLM generation
    with patch("core.session.add_finding") as mock_add_finding, \
         patch("core.session.add_finding") as mock_add_finding, \
         patch("core.session.get_findings") as mock_get_findings, \
         patch("core.llm.chat_text") as mock_chat_text, \
         patch("core.chainer._persist_chains") as mock_persist_chains:
        
        mock_finding_1 = MagicMock()
        mock_finding_1.id = "find_1"
        mock_finding_1.type = "XSS"
        mock_finding_1.severity = "high"
        mock_finding_1.description = "Reflected XSS"
        
        mock_finding_2 = MagicMock()
        mock_finding_2.id = "find_2"
        mock_finding_2.type = "CSRF"
        mock_finding_2.severity = "medium"
        mock_finding_2.description = "CSRF on email"
        
        mock_get_findings.return_value = [mock_finding_1, mock_finding_2]
        
        mock_chat_text.return_value = '''```json
[
  {
    "steps": ["XSS to CSRF"],
    "combined_severity": "critical",
    "next_test": "Check CSRF token bypass",
    "potential_impact": "account takeover",
    "confidence": 0.9,
    "component_types": ["XSS", "CSRF"]
  }
]
```'''
        
        await chain_finding("find_1", "session_123")
        mock_persist_chains.assert_called_once()

def test_fire_chain_analysis():
    with patch("asyncio.get_running_loop") as mock_get_running_loop:
        mock_loop = MagicMock()
        mock_get_running_loop.return_value = mock_loop
        fire_chain_analysis("find_1", "session_123")
        mock_loop.create_task.assert_called_once()
