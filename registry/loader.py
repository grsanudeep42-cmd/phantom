"""
phantom/registry/loader.py

On-demand tool loader. Checks local availability, version, then installs if needed.
Never pre-installs anything. Zero bloat at startup.
"""
from __future__ import annotations

import asyncio
import json
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config.settings import settings
from core.session import init_db


# ─────────────────────────────────────────────────────────────────────────────
# Manifest loading
# ─────────────────────────────────────────────────────────────────────────────

_manifest_cache: Optional[dict] = None


def load_manifest() -> dict:
    global _manifest_cache
    if _manifest_cache is None:
        manifest_path = settings.manifest_path
        if not manifest_path.exists():
            raise FileNotFoundError(f"Tool manifest not found at {manifest_path}")
        with open(manifest_path) as f:
            _manifest_cache = json.load(f)
    return _manifest_cache


def get_tool_spec(tool_id: str) -> Optional[dict]:
    manifest = load_manifest()
    for tool in manifest.get("tools", []):
        if tool["id"] == tool_id:
            return tool
    return None


def list_tools() -> list[dict]:
    return load_manifest().get("tools", [])


# ─────────────────────────────────────────────────────────────────────────────
# Tool cache (SQLite)
# ─────────────────────────────────────────────────────────────────────────────

@contextmanager
def _db():
    init_db()
    conn = sqlite3.connect(str(settings.db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_cached(tool_id: str) -> Optional[sqlite3.Row]:
    with _db() as conn:
        return conn.execute(
            "SELECT * FROM tool_cache WHERE tool_id = ?", (tool_id,)
        ).fetchone()


def _cache_tool(
    tool_id: str,
    version: str,
    executable_path: str,
    install_method: str,
) -> None:
    now = _now()
    with _db() as conn:
        conn.execute(
            """INSERT INTO tool_cache (tool_id, version, executable_path, install_method, cached_at, last_checked_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(tool_id) DO UPDATE SET
                   version=excluded.version,
                   executable_path=excluded.executable_path,
                   install_method=excluded.install_method,
                   last_checked_at=excluded.last_checked_at""",
            (tool_id, version, executable_path, install_method, now, now),
        )


def _update_last_checked(tool_id: str) -> None:
    with _db() as conn:
        conn.execute(
            "UPDATE tool_cache SET last_checked_at = ? WHERE tool_id = ?",
            (_now(), tool_id),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Version detection
# ─────────────────────────────────────────────────────────────────────────────

def _parse_version(output: str, regex: str) -> Optional[str]:
    match = re.search(regex, output)
    return match.group(1) if match else None


def _version_ok(current: str, minimum: str) -> bool:
    """Returns True if current >= minimum (semver-ish comparison)."""
    def parts(v: str) -> tuple:
        return tuple(int(x) for x in v.split(".")[:3])
    try:
        return parts(current) >= parts(minimum)
    except (ValueError, AttributeError):
        return True  # if we can't parse, assume ok


def _check_installed_version(tool_spec: dict) -> Optional[str]:
    """Run the version command, return version string or None if not installed."""
    version_cmd = tool_spec.get("version_cmd", "")
    version_regex = tool_spec.get("version_regex", "")
    if not version_cmd:
        return None

    # Find the binary name (first word of version_cmd)
    binary = version_cmd.split()[0]
    if not shutil.which(binary):
        return None

    try:
        result = subprocess.run(
            version_cmd.split(),
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        return _parse_version(output, version_regex)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Installation
# ─────────────────────────────────────────────────────────────────────────────

def _get_platform() -> str:
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "darwin":
        return "darwin"
    else:
        return "linux"  # best effort


def _install_tool(tool_spec: dict) -> bool:
    """
    Attempt to install the tool using the appropriate method.
    Returns True on success, False on failure.
    """
    sys_platform = _get_platform()
    install_cmds = tool_spec.get("install", {})
    install_cmd = install_cmds.get(sys_platform, "")

    if not install_cmd:
        return False

    print(f"  Installing {tool_spec['id']} via: {install_cmd}")

    # Detect method from the command
    if install_cmd.startswith("apt"):
        method = "apt"
        # Need sudo for apt
        if "sudo" not in install_cmd and sys_platform == "linux":
            install_cmd = f"sudo {install_cmd}"
    elif install_cmd.startswith("brew"):
        method = "brew"
    elif install_cmd.startswith("pip") or "pip install" in install_cmd:
        method = "pip"
    elif install_cmd.startswith("go install"):
        method = "go"
    else:
        method = "manual"

    try:
        result = subprocess.run(
            install_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            print(f"  Install failed (exit {result.returncode}): {result.stderr[:200]}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"  Install timed out for {tool_spec['id']}")
        return False
    except Exception as e:
        print(f"  Install error for {tool_spec['id']}: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ToolLoadResult:
    tool_id: str
    available: bool
    executable_path: str
    version: str
    install_method: str
    error: str = ""


async def ensure_tool(tool_id: str) -> ToolLoadResult:
    """
    Main entry point. Ensures the tool is installed, up to date, and returns its path.
    This is called before every tool execution.
    """
    tool_spec = get_tool_spec(tool_id)
    if not tool_spec:
        return ToolLoadResult(
            tool_id=tool_id,
            available=False,
            executable_path="",
            version="",
            install_method="",
            error=f"Tool '{tool_id}' not found in manifest",
        )

    min_version = tool_spec.get("min_version", "0.0")
    binary_name = tool_spec["id"]

    # 1. Check if it's already installed and version is ok
    current_version = _check_installed_version(tool_spec)
    if current_version and _version_ok(current_version, min_version):
        binary_path = shutil.which(binary_name) or binary_name
        _cache_tool(tool_id, current_version, binary_path, "system")
        return ToolLoadResult(
            tool_id=tool_id,
            available=True,
            executable_path=binary_path,
            version=current_version,
            install_method="system",
        )

    # 2. Tool is missing or outdated — install it
    print(f"\n[phantom] Tool '{tool_id}' not found or outdated. Installing...")
    success = await asyncio.to_thread(_install_tool, tool_spec)

    if not success:
        # 3. Fall back to Docker if install failed
        docker_image = tool_spec.get("install", {}).get("docker", "")
        if docker_image and settings.docker_mode:
            # Docker runner will handle this — mark as docker-installed
            _cache_tool(tool_id, "docker", f"docker:{docker_image}", "docker")
            return ToolLoadResult(
                tool_id=tool_id,
                available=True,
                executable_path=f"docker:{docker_image}",
                version="docker",
                install_method="docker",
            )
        return ToolLoadResult(
            tool_id=tool_id,
            available=False,
            executable_path="",
            version="",
            install_method="",
            error=f"Failed to install '{tool_id}' via all methods",
        )

    # 4. Re-check version after install
    current_version = _check_installed_version(tool_spec) or "unknown"
    binary_path = shutil.which(binary_name) or binary_name
    _cache_tool(tool_id, current_version, binary_path, "installed")

    return ToolLoadResult(
        tool_id=tool_id,
        available=True,
        executable_path=binary_path,
        version=current_version,
        install_method="installed",
    )


def get_all_tool_statuses() -> list[dict]:
    """Check which tools are installed (for `phantom tools status` command)."""
    statuses = []
    for tool_spec in list_tools():
        version = _check_installed_version(tool_spec)
        min_version = tool_spec.get("min_version", "0")
        if version:
            ok = _version_ok(version, min_version)
            status = "ok" if ok else "outdated"
        else:
            version = "not installed"
            status = "missing"
        statuses.append({
            "id": tool_spec["id"],
            "category": tool_spec["category"],
            "description": tool_spec["description"],
            "version": version,
            "min_version": min_version,
            "status": status,
        })
    return statuses
