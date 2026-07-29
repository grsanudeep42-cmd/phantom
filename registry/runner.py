"""
phantom/registry/runner.py

Executes security tools in isolation.
Docker mode: each tool runs in its own container.
Subprocess fallback: runs with timeout + output capture.

RULE: All agents call this. No agent calls subprocess directly.
"""
from __future__ import annotations

import asyncio
import shlex
import shutil
import time
from dataclasses import asdict, dataclass
from typing import Optional

from config.settings import settings
from registry.loader import ensure_tool

# Max output we'll keep in memory (10 MB)
MAX_OUTPUT_BYTES = 10 * 1024 * 1024


# ─────────────────────────────────────────────────────────────────────────────
# Result type
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ToolResult:
    tool: str
    args: list
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    truncated: bool
    truncated_at_bytes: int = 0

    def to_json(self) -> str:
        import json
        return json.dumps(asdict(self), indent=2)

    def success(self) -> bool:
        return self.exit_code == 0

    def summary(self, max_chars: int = 500) -> str:
        """Short summary for session logging."""
        output = (self.stdout or self.stderr or "").strip()
        if len(output) > max_chars:
            return output[:max_chars] + "…"
        return output


class ToolNotAvailableError(Exception):
    """Raised when a tool can't be installed or found."""
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Docker runner
# ─────────────────────────────────────────────────────────────────────────────

def _is_docker_available() -> bool:
    return shutil.which("docker") is not None


async def _run_docker(
    docker_image: str,
    args: list[str],
    timeout: int,
) -> ToolResult:
    """Run a tool via Docker container."""
    start = time.monotonic()
    docker_args = [
        "docker", "run", "--rm", "--network=host",
        docker_image,
    ] + args

    try:
        proc = await asyncio.create_subprocess_exec(
            *docker_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return ToolResult(
                tool=docker_image,
                args=args,
                stdout="",
                stderr="Timed out",
                exit_code=-1,
                duration=time.monotonic() - start,
                truncated=False,
            )

        truncated = False
        truncated_at = 0

        if len(stdout_bytes) > MAX_OUTPUT_BYTES:
            truncated = True
            truncated_at = len(stdout_bytes)
            stdout_bytes = stdout_bytes[:MAX_OUTPUT_BYTES]

        return ToolResult(
            tool=docker_image,
            args=args,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            exit_code=proc.returncode or 0,
            duration=time.monotonic() - start,
            truncated=truncated,
            truncated_at_bytes=truncated_at,
        )
    except Exception as e:
        return ToolResult(
            tool=docker_image,
            args=args,
            stdout="",
            stderr=str(e),
            exit_code=-1,
            duration=time.monotonic() - start,
            truncated=False,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Subprocess runner
# ─────────────────────────────────────────────────────────────────────────────

async def _run_subprocess(
    executable: str,
    args: list[str],
    timeout: int,
) -> ToolResult:
    """Run a tool as a subprocess with output capture."""
    start = time.monotonic()
    cmd = [executable] + args

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return ToolResult(
                tool=executable,
                args=args,
                stdout="",
                stderr=f"Timed out after {timeout}s",
                exit_code=-1,
                duration=time.monotonic() - start,
                truncated=False,
            )

        truncated = False
        truncated_at = 0

        if len(stdout_bytes) > MAX_OUTPUT_BYTES:
            truncated = True
            truncated_at = len(stdout_bytes)
            stdout_bytes = stdout_bytes[:MAX_OUTPUT_BYTES]

        return ToolResult(
            tool=executable,
            args=args,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            exit_code=proc.returncode or 0,
            duration=time.monotonic() - start,
            truncated=truncated,
            truncated_at_bytes=truncated_at,
        )
    except FileNotFoundError:
        return ToolResult(
            tool=executable,
            args=args,
            stdout="",
            stderr=f"Executable not found: {executable}",
            exit_code=127,
            duration=time.monotonic() - start,
            truncated=False,
        )
    except Exception as e:
        return ToolResult(
            tool=executable,
            args=args,
            stdout="",
            stderr=str(e),
            exit_code=-1,
            duration=time.monotonic() - start,
            truncated=False,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def run_tool(
    tool_id: str,
    args: list[str],
    timeout: int = 300,
) -> ToolResult:
    """
    Main entry point. Agents call this. Never call subprocess directly.

    1. Ensure tool is installed (lazy via loader.py)
    2. Try Docker if available and configured
    3. Fall back to subprocess
    """
    # Ensure tool is available
    load_result = await ensure_tool(tool_id)
    if not load_result.available:
        raise ToolNotAvailableError(
            f"Tool '{tool_id}' is not available: {load_result.error}"
        )

    executable = load_result.executable_path

    # Docker path — executable starts with "docker:"
    if executable.startswith("docker:"):
        docker_image = executable[len("docker:"):]
        return await _run_docker(docker_image, args, timeout)

    # Docker mode + docker available: prefer container
    if settings.docker_mode and _is_docker_available():
        from registry.loader import get_tool_spec
        tool_spec = get_tool_spec(tool_id)
        docker_image = tool_spec.get("install", {}).get("docker", "") if tool_spec else ""
        if docker_image:
            return await _run_docker(docker_image, args, timeout)

    # Subprocess fallback
    return await _run_subprocess(executable, args, timeout)


async def run_command(
    command: str,
    timeout: int = 60,
) -> ToolResult:
    """
    Run an arbitrary shell command string (for built-in one-liners that don't need a manifest entry).
    Used by agents for curl, cat, etc.
    """
    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return ToolResult(
                tool="shell",
                args=[command],
                stdout="",
                stderr=f"Timed out after {timeout}s",
                exit_code=-1,
                duration=time.monotonic() - start,
                truncated=False,
            )

        truncated = False
        truncated_at = 0
        if len(stdout_bytes) > MAX_OUTPUT_BYTES:
            truncated = True
            truncated_at = len(stdout_bytes)
            stdout_bytes = stdout_bytes[:MAX_OUTPUT_BYTES]

        return ToolResult(
            tool="shell",
            args=[command],
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            exit_code=proc.returncode or 0,
            duration=time.monotonic() - start,
            truncated=truncated,
            truncated_at_bytes=truncated_at,
        )
    except Exception as e:
        return ToolResult(
            tool="shell",
            args=[command],
            stdout="",
            stderr=str(e),
            exit_code=-1,
            duration=time.monotonic() - start,
            truncated=False,
        )
