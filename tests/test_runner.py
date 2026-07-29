"""
tests/test_runner.py

Tests for the tool runner (subprocess + Docker mocking).
"""
from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from registry.runner import ToolResult, _run_subprocess, _run_docker


class TestToolResult:
    def test_success_exit_zero(self):
        r = ToolResult("nmap", [], "output", "", 0, 1.0, False)
        assert r.success() is True

    def test_failure_nonzero(self):
        r = ToolResult("nmap", [], "", "error", 1, 1.0, False)
        assert r.success() is False

    def test_summary_truncates(self):
        long_output = "A" * 1000
        r = ToolResult("nmap", [], long_output, "", 0, 1.0, False)
        assert len(r.summary(max_chars=100)) <= 104  # 100 + "…"

    def test_summary_uses_stderr_if_no_stdout(self):
        r = ToolResult("nmap", [], "", "error msg", 1, 1.0, False)
        assert "error msg" in r.summary()

    def test_to_json(self):
        import json
        r = ToolResult("nmap", ["-sV"], "80 open", "", 0, 2.5, False)
        data = json.loads(r.to_json())
        assert data["tool"] == "nmap"
        assert data["exit_code"] == 0


class TestSubprocessRunner:
    @pytest.mark.asyncio
    async def test_run_echo(self):
        result = await _run_subprocess("echo", ["hello phantom"], timeout=10)
        assert result.exit_code == 0
        assert "hello phantom" in result.stdout

    @pytest.mark.asyncio
    async def test_run_nonexistent_tool(self):
        result = await _run_subprocess("definitely_not_a_real_binary_xyz", [], timeout=5)
        assert result.exit_code == 127  # File not found

    @pytest.mark.asyncio
    async def test_timeout(self):
        result = await _run_subprocess("sleep", ["30"], timeout=1)
        assert result.exit_code == -1
        assert "Timed out" in result.stderr

    @pytest.mark.asyncio
    async def test_output_capture(self):
        result = await _run_subprocess("echo", ["PHANTOM_TEST_OUTPUT"], timeout=5)
        assert "PHANTOM_TEST_OUTPUT" in result.stdout

    @pytest.mark.asyncio
    async def test_duration_recorded(self):
        result = await _run_subprocess("echo", ["x"], timeout=5)
        assert result.duration > 0
        assert result.duration < 5.0


class TestDockerRunner:
    @pytest.mark.asyncio
    async def test_docker_sandboxed_flags(self):
        """Verify the Docker command includes security flags."""
        captured_args = []

        async def mock_exec(*args, **kwargs):
            captured_args.extend(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"ok", b""))
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await _run_docker("phantom-tools:latest", ["nmap", "-sV", "127.0.0.1"], timeout=5)

        cmd_str = " ".join(str(a) for a in captured_args)
        assert "--no-new-privileges" in cmd_str
        assert "--cap-drop" in cmd_str
        assert "--memory" in cmd_str

    @pytest.mark.asyncio
    async def test_docker_tool_prefix_replaced(self):
        """tool: prefix should be resolved to phantom-tools:latest image."""
        from registry.runner import _PHANTOM_TOOLS_IMAGE
        captured_image = []

        async def mock_exec(*args, **kwargs):
            # Find docker image arg (after 'run' args)
            for i, arg in enumerate(args):
                if "phantom-tools" in str(arg):
                    captured_image.append(str(arg))
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await _run_docker("tool:nmap", ["nmap", "--version"], timeout=5)

        assert any(_PHANTOM_TOOLS_IMAGE in img for img in captured_image)


class TestRunTool:
    @pytest.mark.asyncio
    async def test_unavailable_tool_raises(self, fresh_db):
        from registry.runner import run_tool, ToolNotAvailableError
        with patch("registry.loader.ensure_tool") as mock_ensure:
            mock_result = MagicMock()
            mock_result.available = False
            mock_result.error = "not found"
            mock_ensure.return_value = mock_result
            mock_ensure = AsyncMock(return_value=mock_result)

            with patch("registry.runner.ensure_tool", new=AsyncMock(return_value=mock_result)):
                with pytest.raises(ToolNotAvailableError):
                    await run_tool("nonexistent_tool_xyz", [])

    @pytest.mark.asyncio
    async def test_subprocess_fallback_when_no_docker(self, fresh_db, monkeypatch):
        from registry.runner import run_tool
        from unittest.mock import AsyncMock, MagicMock

        mock_load = MagicMock()
        mock_load.available = True
        mock_load.executable_path = "echo"

        mock_result = ToolResult("echo", ["phantom"], "phantom", "", 0, 0.1, False)

        with patch("registry.runner.ensure_tool", new=AsyncMock(return_value=mock_load)), \
             patch("registry.runner._is_docker_available", return_value=False), \
             patch("registry.runner._run_subprocess", new=AsyncMock(return_value=mock_result)):
            result = await run_tool("echo", ["phantom"])
            assert result.stdout == "phantom"
