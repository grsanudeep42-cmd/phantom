"""
phantom/registry/updater.py

Checks for stale tools and auto-updates them.
Called by `phantom tools update` and optionally at session start.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

from registry.cache import list_cached_tools
from registry.loader import (
    _check_installed_version,
    _install_tool,
    _version_ok,
    get_tool_spec,
    _cache_tool,
)


@dataclass
class UpdateResult:
    tool_id: str
    old_version: str
    new_version: str
    updated: bool
    error: str = ""


async def check_and_update(tool_id: Optional[str] = None) -> list[UpdateResult]:
    """
    Check all cached tools (or just one) for stale versions and update.
    Returns a list of UpdateResult for each tool checked.
    """
    cached = list_cached_tools()
    if tool_id:
        cached = [c for c in cached if c.tool_id == tool_id]

    results = []
    for cached_tool in cached:
        spec = get_tool_spec(cached_tool.tool_id)
        if not spec:
            continue

        current = _check_installed_version(spec)
        min_v = spec.get("min_version", "0.0")

        if current and _version_ok(current, min_v):
            results.append(UpdateResult(
                tool_id=cached_tool.tool_id,
                old_version=cached_tool.version,
                new_version=current,
                updated=False,
            ))
            continue

        # Needs update
        old_v = current or cached_tool.version
        success = await asyncio.to_thread(_install_tool, spec)
        if success:
            new_v = _check_installed_version(spec) or "updated"
            import shutil as _shutil
            path = _shutil.which(cached_tool.tool_id) or cached_tool.executable_path
            _cache_tool(cached_tool.tool_id, new_v, path, "updated")
            results.append(UpdateResult(
                tool_id=cached_tool.tool_id,
                old_version=old_v,
                new_version=new_v,
                updated=True,
            ))
        else:
            results.append(UpdateResult(
                tool_id=cached_tool.tool_id,
                old_version=old_v,
                new_version=old_v,
                updated=False,
                error="Update failed",
            ))

    return results
