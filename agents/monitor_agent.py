"""
phantom/agents/monitor_agent.py

Module 3 — Continuous Change Detection (Phase 10).

phantom_monitor_run(target, session_id)

  Runs a structured diff against the last scan snapshot for this target.

  Check 1 — New subdomains   (subfinder + crt.sh CT logs)
  Check 2 — New endpoints    (katana crawl diff)
  Check 3 — Tech stack       (whatweb diff → CVE lookup for new versions)
  Check 4 — New ports        (naabu quick scan diff)
  Check 5 — DNS / takeover   (resolve all known subdomains for unclaimed services)

Returns MonitorDiff dataclass.
Webhook POST to PHANTOM_WEBHOOK_URL env var if set.

CLI usage:
  phantom monitor add <target>
  phantom monitor run [target]
  phantom monitor list
  phantom monitor diff <target>
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MonitorDiff:
    target: str
    checked_at: str = ""
    new_subdomains: list[str] = field(default_factory=list)
    new_endpoints: list[str] = field(default_factory=list)
    stack_changes: list[str] = field(default_factory=list)
    new_ports: list[str] = field(default_factory=list)
    takeover_candidates: list[str] = field(default_factory=list)

    def has_changes(self) -> bool:
        return bool(
            self.new_subdomains or self.new_endpoints or self.stack_changes
            or self.new_ports or self.takeover_candidates
        )

    def summary(self) -> str:
        parts = []
        if self.new_subdomains:    parts.append(f"{len(self.new_subdomains)} new subdomain(s)")
        if self.new_endpoints:     parts.append(f"{len(self.new_endpoints)} new endpoint(s)")
        if self.stack_changes:     parts.append(f"{len(self.stack_changes)} tech stack change(s)")
        if self.new_ports:         parts.append(f"{len(self.new_ports)} new port(s)")
        if self.takeover_candidates: parts.append(f"{len(self.takeover_candidates)} takeover candidate(s)")
        return ", ".join(parts) if parts else "no changes detected"

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Unclaimed service detection (subdomain takeover signals)
# ─────────────────────────────────────────────────────────────────────────────

_TAKEOVER_SIGNALS: list[tuple[str, str]] = [
    ("github.io",            "There isn't a GitHub Pages site here"),
    ("herokuapp.com",        "No such app"),
    ("s3.amazonaws.com",     "NoSuchBucket"),
    ("netlify.com",          "Not Found"),
    ("shopify.com",          "Sorry, this shop is currently unavailable"),
    ("bitbucket.io",         "Repository not found"),
    ("azurewebsites.net",    "404 Web Site not found"),
    ("cloudfront.net",       "Bad Request"),
    ("fastly.net",           "Fastly error: unknown domain"),
    ("pantheon.io",          "404 error unknown site"),
    ("wpengine.com",         "The site you were looking for couldn't be found"),
]


async def _check_takeover(subdomain: str) -> Optional[str]:
    """Return service name if subdomain appears vulnerable to takeover."""
    try:
        import aiohttp
        url = f"http://{subdomain}"
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            async with sess.get(url, ssl=False, allow_redirects=True) as resp:
                body = await resp.text(errors="replace")
                for _, signal in _TAKEOVER_SIGNALS:
                    if signal.lower() in body.lower():
                        return subdomain
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# crt.sh Certificate Transparency
# ─────────────────────────────────────────────────────────────────────────────

async def _crtsh_subdomains(domain: str) -> set[str]:
    """Fetch subdomains from crt.sh certificate transparency logs."""
    subs: set[str] = set()
    try:
        import aiohttp
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            async with sess.get(url, ssl=False) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    for entry in data:
                        name = entry.get("name_value", "")
                        for line in name.splitlines():
                            line = line.strip().lstrip("*.")
                            if line and line.endswith(domain):
                                subs.add(line)
    except Exception:
        pass
    return subs


# ─────────────────────────────────────────────────────────────────────────────
# Check 1 — Subdomains
# ─────────────────────────────────────────────────────────────────────────────

async def _check_subdomains(target: str, last_subs: set[str]) -> tuple[list[str], set[str]]:
    from registry.runner import run_tool, ToolNotAvailableError
    current: set[str] = set()

    # subfinder
    try:
        result = await run_tool("subfinder", ["-d", target, "-silent"], timeout=90)
        for line in result.stdout.splitlines():
            s = line.strip()
            if s:
                current.add(s)
    except (ToolNotAvailableError, Exception):
        pass

    # crt.sh
    crt_subs = await _crtsh_subdomains(target)
    current |= crt_subs

    new_subs = sorted(current - last_subs)
    return new_subs, current


# ─────────────────────────────────────────────────────────────────────────────
# Check 2 — Endpoints
# ─────────────────────────────────────────────────────────────────────────────

async def _check_endpoints(url: str, last_endpoints: set[str]) -> tuple[list[str], set[str]]:
    from registry.runner import run_tool, ToolNotAvailableError
    base = url if url.startswith("http") else f"https://{url}"
    current: set[str] = set()

    try:
        result = await run_tool(
            "katana", ["-u", base, "-d", "2", "-silent", "-nc"], timeout=90
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("http"):
                current.add(line)
    except (ToolNotAvailableError, Exception):
        pass

    new_endpoints = sorted(current - last_endpoints)
    return new_endpoints, current


# ─────────────────────────────────────────────────────────────────────────────
# Check 3 — Tech stack changes
# ─────────────────────────────────────────────────────────────────────────────

async def _check_stack(url: str, last_stack: set[str]) -> tuple[list[str], set[str]]:
    from registry.runner import run_tool, ToolNotAvailableError
    base = url if url.startswith("http") else f"http://{url}"
    current: set[str] = set()

    try:
        result = await run_tool("whatweb", [base, "--log-brief=-"], timeout=30)
        # Parse "Foo[bar]" style entries
        for match in re.finditer(r'([\w\-]+)\[([^\]]+)\]', result.stdout):
            entry = f"{match.group(1)}[{match.group(2)}]"
            current.add(entry)
    except (ToolNotAvailableError, Exception):
        pass

    changes = sorted(current.symmetric_difference(last_stack))
    return changes, current


# ─────────────────────────────────────────────────────────────────────────────
# Check 4 — Ports
# ─────────────────────────────────────────────────────────────────────────────

async def _check_ports(target: str, last_ports: set[str]) -> tuple[list[str], set[str]]:
    from registry.runner import run_tool, ToolNotAvailableError
    # Strip protocol/path for raw host
    host = re.sub(r'^https?://', '', target).split('/')[0]
    current: set[str] = set()

    try:
        result = await run_tool(
            "naabu", ["-host", host, "-top-ports", "1000", "-silent"], timeout=120
        )
        for line in result.stdout.splitlines():
            p = line.strip()
            if p and re.match(r'^\d+$', p.split(":")[-1]):
                current.add(p)
    except (ToolNotAvailableError, Exception):
        # Fallback to nmap top-100
        try:
            result = await run_tool(
                "nmap", ["-p-", "--open", "-T4", "-oG", "-", host], timeout=180
            )
            for line in result.stdout.splitlines():
                for m in re.finditer(r'(\d+)/open', line):
                    current.add(m.group(1))
        except Exception:
            pass

    new_ports = sorted(current - last_ports)
    return new_ports, current


# ─────────────────────────────────────────────────────────────────────────────
# Check 5 — DNS / takeover candidates
# ─────────────────────────────────────────────────────────────────────────────

import asyncio as _asyncio

async def _check_takeovers(subdomains: list[str]) -> list[str]:
    if not subdomains:
        return []
    tasks = [_check_takeover(sub) for sub in subdomains[:50]]  # Cap concurrency
    results = await _asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, str)]


# ─────────────────────────────────────────────────────────────────────────────
# Snapshot helpers (wrappers around session.py)
# ─────────────────────────────────────────────────────────────────────────────

def _load_snapshot(target: str, scan_type: str) -> dict:
    try:
        from core import session as db
        snapshots = db.get_monitor_snapshots(target, scan_type, limit=1)
        if snapshots:
            return json.loads(snapshots[0]["data"])
    except Exception:
        pass
    return {}


def _save_snapshot(target: str, scan_type: str, data: dict) -> None:
    try:
        from core import session as db
        db.add_monitor_snapshot(target, scan_type, json.dumps(data))
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Webhook notification
# ─────────────────────────────────────────────────────────────────────────────

async def _send_webhook(diff: MonitorDiff) -> None:
    webhook_url = os.environ.get("PHANTOM_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return
    try:
        import aiohttp
        payload = {
            "text": f"PHANTOM Monitor — {diff.target}: {diff.summary()}",
            "diff": asdict(diff),
        }
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            await sess.post(webhook_url, json=payload, ssl=False)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

async def phantom_monitor_run(target: str, session_id: str = "") -> MonitorDiff:
    """
    Run all 5 change-detection checks against stored snapshots.
    Creates a new session for newly discovered subdomains.
    Sends webhook if PHANTOM_WEBHOOK_URL is set.
    """
    diff = MonitorDiff(
        target=target,
        checked_at=datetime.now(timezone.utc).isoformat(),
    )

    # Load previous snapshots
    prev_subs      = set(_load_snapshot(target, "subdomains").get("items", []))
    prev_endpoints = set(_load_snapshot(target, "endpoints").get("items", []))
    prev_stack     = set(_load_snapshot(target, "stack").get("items", []))
    prev_ports     = set(_load_snapshot(target, "ports").get("items", []))

    # Run all checks concurrently
    sub_task      = _asyncio.create_task(_check_subdomains(target, prev_subs))
    endpoint_task = _asyncio.create_task(_check_endpoints(target, prev_endpoints))
    stack_task    = _asyncio.create_task(_check_stack(target, prev_stack))
    port_task     = _asyncio.create_task(_check_ports(target, prev_ports))

    new_subs, curr_subs         = await sub_task
    new_endpoints, curr_eps     = await endpoint_task
    stack_changes, curr_stack   = await stack_task
    new_ports, curr_ports       = await port_task

    diff.new_subdomains = new_subs
    diff.new_endpoints  = new_endpoints
    diff.stack_changes  = stack_changes
    diff.new_ports      = new_ports

    # Check 5 — Takeover candidates from ALL known subdomains
    all_known_subs = list(curr_subs | prev_subs)
    diff.takeover_candidates = await _check_takeovers(all_known_subs[:60])

    # Save updated snapshots
    _save_snapshot(target, "subdomains", {"items": sorted(curr_subs)})
    _save_snapshot(target, "endpoints",  {"items": sorted(curr_eps)})
    _save_snapshot(target, "stack",      {"items": sorted(curr_stack)})
    _save_snapshot(target, "ports",      {"items": sorted(curr_ports)})

    # Auto-create high-priority session for new subdomains
    if new_subs and session_id:
        try:
            from core import session as db
            for sub in new_subs[:5]:  # Cap to 5 auto-sessions
                new_sess = db.create_session(
                    target=sub,
                    mode="grey",
                    scope=[sub, f"*.{sub}"],
                )
                db.add_finding(
                    new_sess.id,
                    "monitor_discovery",
                    f"New subdomain detected by monitor: {sub} (parent: {target})",
                    "high",
                    f"Monitor diff at {diff.checked_at}",
                )
        except Exception:
            pass

    # Save diff as finding in the monitoring session
    if session_id:
        try:
            from core import session as db
            db.add_finding(
                session_id,
                "monitor_diff",
                f"Monitor run: {diff.summary()}",
                "high" if diff.has_changes() else "info",
                diff.to_json()[:1000],
            )
        except Exception:
            pass

    # Webhook notification
    if diff.has_changes():
        await _send_webhook(diff)

    return diff


# ─────────────────────────────────────────────────────────────────────────────
# Monitor list management (CLI helpers)
# ─────────────────────────────────────────────────────────────────────────────

def monitor_add(target: str) -> None:
    """Register a target for continuous monitoring."""
    from core import session as db
    db.set_session_kv("__monitor__", f"target:{target}", "active")


def monitor_list() -> list[dict]:
    """Return all monitored targets with last-run info."""
    from core import session as db
    try:
        # Query monitor_snapshots for unique targets
        rows = db.get_monitor_snapshots(target=None, scan_type="subdomains", limit=100)
        seen: dict[str, dict] = {}
        for row in rows:
            t = row["target"]
            if t not in seen:
                seen[t] = {"target": t, "last_run": row["timestamp"]}
        return list(seen.values())
    except Exception:
        return []


async def monitor_diff(target: str) -> Optional[MonitorDiff]:
    """Return the most recent diff for a target by re-running against snapshots."""
    return await phantom_monitor_run(target)
