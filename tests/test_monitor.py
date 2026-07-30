import pytest
from unittest.mock import patch, MagicMock

from agents.monitor_agent import MonitorDiff, phantom_monitor_run

def test_monitor_diff_has_changes():
    diff = MonitorDiff("example.com")
    assert not diff.has_changes()
    
    diff.new_subdomains = ["test.example.com"]
    assert diff.has_changes()
    
    diff = MonitorDiff("example.com")
    diff.new_endpoints = ["/api/v2/users"]
    assert diff.has_changes()

@pytest.mark.asyncio
async def test_phantom_monitor_run():
    with patch("agents.monitor_agent.get_session_kv") as mock_kv_get, \
         patch("agents.monitor_agent.set_session_kv") as mock_kv_set, \
         patch("agents.monitor_agent.save_monitor_snapshot") as mock_snapshot_save, \
         patch("agents.monitor_agent.get_latest_snapshot") as mock_snapshot_get, \
         patch("agents.monitor_agent._scan_subdomains") as mock_scan_sub:
         
        mock_snapshot_get.return_value = {"data": []}
        mock_scan_sub.return_value = ["a.example.com", "b.example.com"]
        
        # We only mock subdomains for simplicity in this unit test
        with patch("agents.monitor_agent._scan_endpoints", return_value=[]), \
             patch("agents.monitor_agent._scan_tech_stack", return_value={}), \
             patch("agents.monitor_agent._scan_ports", return_value=[]), \
             patch("agents.monitor_agent._check_takeovers", return_value=[]):
             
            diff = await phantom_monitor_run("example.com")
            
            assert "a.example.com" in diff.new_subdomains
            assert "b.example.com" in diff.new_subdomains
            assert diff.has_changes()
