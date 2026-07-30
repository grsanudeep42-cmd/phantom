import pytest
import asyncio
from unittest.mock import patch, MagicMock

from agents.intel_agent import phantom_understand_target

@pytest.mark.asyncio
async def test_phantom_understand_target_no_scope():
    # If no scope, it should still work but just not do out-of-scope stuff
    # Wait, the tool itself requires a session_id
    with patch("core.session.get_session") as mock_get_session, \
         patch("agents.intel_agent.kv_set") as mock_kv_set, \
         patch("agents.intel_agent.chat_text") as mock_generate:
        
        mock_session = MagicMock()
        mock_session.target = "example.com"
        mock_session.scope = ["example.com"]
        mock_get_session.return_value = mock_session
        
        mock_generate.return_value = '''```json
{
  "threat_model": [
    {"class": "IDOR", "confidence": "high", "reasoning": "Uses API."}
  ],
  "hunting_plan": [
    "Check API for IDOR"
  ]
}
```'''

        with patch("agents.intel_agent.asyncio.create_subprocess_exec") as mock_exec:
            # Mock subprocess for whatweb and katana
            process_mock = MagicMock()
            process_mock.communicate.return_async = (b"output", b"")
            process_mock.returncode = 0
            mock_exec.return_value = process_mock
            
            result = await phantom_understand_target("example.com", "session_123")
            
            assert result is not None
            assert "IDOR" in result.threat_model[0]["class"]
            mock_kv_set.assert_called()
