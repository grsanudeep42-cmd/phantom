"""
phantom/agents/intel_agent.py

Module 1 — Target Intelligence Phase (Phase 10).

phantom_understand_target(url, session_id, program_url=None)

  Step 1 — Program brief (HackerOne/Bugcrowd page scrape)
  Step 2 — App fingerprinting (tech stack, frameworks, auth method)
  Step 3 — Architecture surface mapping (URL categorisation)
  Step 4 — LLM threat modelling (ranked vuln classes + reasoning)
  Step 5 — Hunting plan (ordered test sequence)

Returns TargetIntelligence dataclass.
Auto-persists each phase to session KV store.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urljoin, urlparse

# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProgramContext:
    """Extracted from HackerOne / Bugcrowd program page."""
    source_url: str = ""
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    focus_areas: list[str] = field(default_factory=list)
    max_payout: str = "unknown"
    raw_excerpt: str = ""


@dataclass
class TechProfile:
    """App technology fingerprint."""
    stack: list[str] = field(default_factory=list)        # e.g. ["nginx", "React", "Node.js"]
    frameworks: list[str] = field(default_factory=list)   # e.g. ["Express", "Next.js"]
    api_type: str = "unknown"                              # rest | graphql | grpc | unknown
    auth_method: str = "unknown"                           # jwt | session | oauth | unknown
    cdn: str = ""
    server: str = ""
    has_swagger: bool = False
    has_graphql: bool = False
    interesting_headers: dict = field(default_factory=dict)


@dataclass
class AttackSurface:
    """Crawled URLs categorised by security-relevant function."""
    auth_flows: list[str] = field(default_factory=list)
    payment_flows: list[str] = field(default_factory=list)
    admin_panels: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    file_ops: list[str] = field(default_factory=list)
    user_data: list[str] = field(default_factory=list)
    other: list[str] = field(default_factory=list)

    def total(self) -> int:
        return sum(len(getattr(self, f)) for f in self.__dataclass_fields__)


@dataclass
class ThreatModel:
    """LLM-generated ranked vulnerability classes."""
    ranked: list[dict] = field(default_factory=list)    # [{rank, vuln_class, reasoning, tools}]
    raw_response: str = ""


@dataclass
class TargetIntelligence:
    """Full intelligence picture for one target."""
    url: str
    program_context: ProgramContext = field(default_factory=ProgramContext)
    tech_profile: TechProfile = field(default_factory=TechProfile)
    attack_surface: AttackSurface = field(default_factory=AttackSurface)
    threat_model: ThreatModel = field(default_factory=ThreatModel)
    hunting_plan: list[str] = field(default_factory=list)   # ordered action strings

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# URL categorisation helpers
# ─────────────────────────────────────────────────────────────────────────────

_AUTH_PATTERNS    = re.compile(r'/(login|logout|signup|register|auth|oauth|sso|verify|confirm|password|reset|2fa|mfa|session)', re.I)
_PAYMENT_PATTERNS = re.compile(r'/(checkout|payment|pay|billing|subscribe|subscription|upgrade|plan|invoice|order|cart|purchase)', re.I)
_ADMIN_PATTERNS   = re.compile(r'/(admin|dashboard|manage|management|internal|staff|backoffice|superuser|moderator|control)', re.I)
_API_PATTERNS     = re.compile(r'/(api|v\d+|graphql|rest|rpc|endpoint|service|webhook)', re.I)
_FILE_PATTERNS    = re.compile(r'/(upload|download|export|import|file|attachment|media|document|blob|s3|storage)', re.I)
_USER_PATTERNS    = re.compile(r'/(profile|account|settings|user|users|me|preferences|notifications|privacy)', re.I)


def categorise_url(url: str) -> str:
    path = urlparse(url).path
    if _AUTH_PATTERNS.search(path):    return "auth_flows"
    if _PAYMENT_PATTERNS.search(path): return "payment_flows"
    if _ADMIN_PATTERNS.search(path):   return "admin_panels"
    if _API_PATTERNS.search(path):     return "api_endpoints"
    if _FILE_PATTERNS.search(path):    return "file_ops"
    if _USER_PATTERNS.search(path):    return "user_data"
    return "other"


def build_attack_surface(urls: list[str]) -> AttackSurface:
    surface = AttackSurface()
    for url in urls:
        cat = categorise_url(url)
        lst = getattr(surface, cat)
        if url not in lst:
            lst.append(url)
    return surface


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Program brief
# ─────────────────────────────────────────────────────────────────────────────

async def _fetch_program_brief(program_url: str) -> ProgramContext:
    """Fetch and parse a HackerOne or Bugcrowd program page."""
    ctx = ProgramContext(source_url=program_url)
    try:
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            async with sess.get(program_url, ssl=False) as resp:
                html = await resp.text(errors="replace")

        ctx.raw_excerpt = html[:3000]

        # Payout extraction: looks for "$X,XXX" or "up to $X"
        payout_match = re.search(
            r'\$[\d,]+(?:\s*-\s*\$[\d,]+)?|\bup\s+to\s+\$[\d,]+', html, re.I
        )
        if payout_match:
            ctx.max_payout = payout_match.group(0).strip()

        # Scope extraction: grab lines/bullets mentioning domains or wildcards
        scope_lines = re.findall(r'[\*\w][\w\.\-]*\.[a-z]{2,}(?:/[^\s"<>]*)?', html)
        ctx.in_scope = list(dict.fromkeys(scope_lines[:30]))  # dedup, cap 30

        # Out of scope keywords
        oos_section = re.search(r'out.of.scope(.*?)(?:in.scope|program|$)', html, re.I | re.S)
        if oos_section:
            oos_lines = re.findall(r'[\*\w][\w\.\-]*\.[a-z]{2,}', oos_section.group(1))
            ctx.out_of_scope = list(dict.fromkeys(oos_lines[:20]))

        # Focus areas: look for vuln type keywords
        focus_keywords = ['xss', 'sqli', 'ssrf', 'rce', 'idor', 'csrf', 'auth', 'api',
                          'mobile', 'ios', 'android', 'graphql', 'injection']
        ctx.focus_areas = [kw for kw in focus_keywords if kw in html.lower()]

    except Exception:
        pass  # Non-fatal — brief is best-effort

    return ctx


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — App fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

_TECH_HEADER_MAP = {
    "x-powered-by":    "stack",
    "server":          "server",
    "x-aspnet-version": "stack",
    "x-drupal-cache":  "frameworks",
    "x-wp-total":      "frameworks",
    "x-varnish":       "cdn",
    "cf-cache-status": "cdn",
    "x-cache":         "cdn",
    "via":             "cdn",
}

_AUTH_HEADER_SIGNALS = {
    "www-authenticate": "http_basic",
    "x-jwt":            "jwt",
    "authorization":    "bearer",
}

_FRAMEWORK_PATTERNS = {
    "React":    re.compile(r'react|__react', re.I),
    "Vue":      re.compile(r'vue\.js|__vue', re.I),
    "Angular":  re.compile(r'ng-version|angular', re.I),
    "Next.js":  re.compile(r'_next/|__next', re.I),
    "Django":   re.compile(r'csrfmiddlewaretoken|django', re.I),
    "Rails":    re.compile(r'rails|authenticity_token', re.I),
    "Laravel":  re.compile(r'laravel|XSRF-TOKEN', re.I),
    "Express":  re.compile(r'express', re.I),
    "Spring":   re.compile(r'spring|JSESSIONID', re.I),
    "Flask":    re.compile(r'flask|werkzeug', re.I),
    "WordPress":re.compile(r'wp-content|wp-includes', re.I),
}


async def _fingerprint_app(url: str) -> TechProfile:
    profile = TechProfile()
    base = url if url.startswith("http") else f"https://{url}"

    try:
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=15)

        async with aiohttp.ClientSession(timeout=timeout) as sess:
            # Main page
            try:
                async with sess.get(base, ssl=False, allow_redirects=True) as resp:
                    body = await resp.text(errors="replace")
                    headers = dict(resp.headers)

                    # Header analysis
                    for hdr, category in _TECH_HEADER_MAP.items():
                        val = headers.get(hdr, "")
                        if val:
                            if category == "server":
                                profile.server = val
                            elif category == "cdn":
                                profile.cdn = val
                            elif category in ("stack", "frameworks"):
                                getattr(profile, category).append(val)
                            profile.interesting_headers[hdr] = val

                    # Auth method from headers
                    for hdr, method in _AUTH_HEADER_SIGNALS.items():
                        if hdr in {k.lower() for k in headers}:
                            profile.auth_method = method

                    # JWT in cookies
                    cookies = headers.get("set-cookie", "")
                    if re.search(r'eyJ[A-Za-z0-9_-]+', cookies):
                        profile.auth_method = "jwt"

                    # Framework detection from body
                    for fw, pat in _FRAMEWORK_PATTERNS.items():
                        if pat.search(body):
                            if fw not in profile.frameworks:
                                profile.frameworks.append(fw)

                    # API type detection
                    if "graphql" in body.lower() or "__schema" in body:
                        profile.api_type = "graphql"
                    elif re.search(r'"swagger"\s*:', body) or "openapi" in body.lower():
                        profile.api_type = "rest"

            except Exception:
                pass

            # Probe well-known paths concurrently
            probe_paths = [
                ("/robots.txt", "stack"),
                ("/sitemap.xml", "stack"),
                ("/.well-known/security.txt", "stack"),
                ("/graphql", "graphql"),
                ("/api/graphql", "graphql"),
                ("/swagger", "swagger"),
                ("/swagger.json", "swagger"),
                ("/api-docs", "swagger"),
                ("/openapi.json", "swagger"),
                ("/v1/", "api"),
                ("/api/v1/", "api"),
            ]

            async def _probe(path: str, tag: str):
                try:
                    async with sess.get(urljoin(base, path), ssl=False, allow_redirects=False) as r:
                        if r.status in (200, 401, 403):
                            return path, tag, r.status
                except Exception:
                    pass
                return None

            results = await asyncio.gather(*[_probe(p, t) for p, t in probe_paths])
            for res in results:
                if res is None:
                    continue
                path, tag, status = res
                if tag == "graphql" and status in (200, 400):
                    profile.has_graphql = True
                    profile.api_type = "graphql"
                elif tag == "swagger" and status == 200:
                    profile.has_swagger = True
                    if profile.api_type == "unknown":
                        profile.api_type = "rest"
                elif tag == "api" and status in (200, 401):
                    if profile.api_type == "unknown":
                        profile.api_type = "rest"

    except Exception:
        pass

    return profile


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Architecture surface mapping (katana crawl)
# ─────────────────────────────────────────────────────────────────────────────

async def _map_attack_surface(url: str) -> AttackSurface:
    from registry.runner import run_tool, ToolNotAvailableError
    base = url if url.startswith("http") else f"https://{url}"
    urls_found: list[str] = []

    try:
        result = await run_tool(
            "katana",
            ["-u", base, "-d", "2", "-silent", "-jc", "-kf", "-nc"],
            timeout=90,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("http"):
                urls_found.append(line)
    except (ToolNotAvailableError, Exception):
        pass  # Non-fatal

    return build_attack_surface(urls_found)


# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — LLM threat modelling
# ─────────────────────────────────────────────────────────────────────────────

_THREAT_MODEL_SYSTEM = (
    "You are an elite bug bounty hunter and application security architect. "
    "Analyse target apps and identify the highest-probability vulnerability classes. "
    "Think like a developer who took shortcuts, not like a textbook. "
    "Respond ONLY with valid JSON — no prose, no markdown fences."
)


async def _generate_threat_model(url: str, tech: TechProfile, surface: AttackSurface) -> ThreatModel:
    model = ThreatModel()
    try:
        from core.llm import chat_text

        surface_summary = {
            "auth_flows":    len(surface.auth_flows),
            "payment_flows": len(surface.payment_flows),
            "admin_panels":  len(surface.admin_panels),
            "api_endpoints": len(surface.api_endpoints),
            "file_ops":      len(surface.file_ops),
            "user_data":     len(surface.user_data),
        }
        surface_examples = {
            "auth":    surface.auth_flows[:3],
            "api":     surface.api_endpoints[:5],
            "admin":   surface.admin_panels[:3],
            "file":    surface.file_ops[:3],
        }

        prompt = (
            f"Target: {url}\n\n"
            f"Tech profile:\n"
            f"  Stack: {', '.join(tech.stack) or 'unknown'}\n"
            f"  Frameworks: {', '.join(tech.frameworks) or 'unknown'}\n"
            f"  API type: {tech.api_type}\n"
            f"  Auth method: {tech.auth_method}\n"
            f"  Server: {tech.server or 'unknown'}\n"
            f"  Has GraphQL: {tech.has_graphql}\n"
            f"  Has Swagger/OpenAPI: {tech.has_swagger}\n\n"
            f"Attack surface counts: {json.dumps(surface_summary)}\n"
            f"Sample endpoints: {json.dumps(surface_examples)}\n\n"
            f"Based on this app's purpose and architecture, rank the top 10 most "
            f"likely vulnerability classes to find here. Consider:\n"
            f"- What developer shortcuts are likely given this stack?\n"
            f"- What trust boundaries exist?\n"
            f"- Where does user input reach sensitive operations?\n"
            f"- What auth/authz mistakes are common with {tech.auth_method} auth?\n\n"
            f"Respond with JSON array (exactly 10 items):\n"
            f'[{{"rank": 1, "vuln_class": "...", "reasoning": "...", "tools": ["..."]}}]'
        )

        raw = await chat_text(prompt, system=_THREAT_MODEL_SYSTEM, max_tokens=2048)
        model.raw_response = raw

        # Strip markdown fences
        raw = raw.strip()
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1] if len(parts) > 1 else raw
            if raw.startswith("json"):
                raw = raw[4:]

        items = json.loads(raw)
        model.ranked = [
            {
                "rank":       item.get("rank", i + 1),
                "vuln_class": item.get("vuln_class", ""),
                "reasoning":  item.get("reasoning", ""),
                "tools":      item.get("tools", []),
            }
            for i, item in enumerate(items)
            if isinstance(item, dict)
        ][:10]

    except Exception:
        pass  # Non-fatal — fall back to empty threat model

    return model


# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — Hunting plan
# ─────────────────────────────────────────────────────────────────────────────

def _build_hunting_plan(threat_model: ThreatModel, surface: AttackSurface) -> list[str]:
    """Convert ranked threat model into an ordered, actionable plan."""
    plan: list[str] = []

    # Prepend high-value surface targets
    if surface.auth_flows:
        plan.append(f"Test authentication flows ({len(surface.auth_flows)} endpoints): focus on password reset, OAuth, 2FA bypass")
    if surface.payment_flows:
        plan.append(f"Test payment flows ({len(surface.payment_flows)} endpoints): IDOR, price manipulation, race conditions")
    if surface.admin_panels:
        plan.append(f"Test admin panels ({len(surface.admin_panels)} found): auth bypass, horizontal privesc, mass assignment")
    if surface.api_endpoints:
        plan.append(f"Enumerate API ({len(surface.api_endpoints)} endpoints): IDOR, BOLA, rate limit bypass, verb tampering")
    if surface.file_ops:
        plan.append(f"Test file operations ({len(surface.file_ops)} endpoints): path traversal, unrestricted upload, SSRF")

    # Add threat model driven steps
    for item in threat_model.ranked[:7]:
        vc = item.get("vuln_class", "")
        tools = item.get("tools", [])
        tool_str = f" (use: {', '.join(tools[:3])})" if tools else ""
        reason = item.get("reasoning", "")[:120]
        plan.append(f"#{item.get('rank', '?')} Test for {vc}{tool_str} — {reason}")

    return plan


# ─────────────────────────────────────────────────────────────────────────────
# Session persistence helpers
# ─────────────────────────────────────────────────────────────────────────────

def _persist_intel(session_id: str, intel: TargetIntelligence) -> None:
    """Store intel phases as session KV entries and summary findings."""
    if not session_id:
        return
    try:
        from core import session as db
        db.set_session_kv(session_id, "tech_profile", json.dumps(asdict(intel.tech_profile)))
        db.set_session_kv(session_id, "attack_surface", json.dumps(asdict(intel.attack_surface)))
        db.set_session_kv(session_id, "threat_model", json.dumps(asdict(intel.threat_model)))
        db.set_session_kv(session_id, "hunting_plan", json.dumps(intel.hunting_plan))
        if intel.program_context.source_url:
            db.set_session_kv(session_id, "program_context", json.dumps(asdict(intel.program_context)))

        # Add a summary finding so it shows in findings table
        db.add_finding(
            session_id,
            "intel_summary",
            (
                f"Target intelligence complete — "
                f"Stack: {', '.join(intel.tech_profile.stack + intel.tech_profile.frameworks)[:80] or 'unknown'} | "
                f"API: {intel.tech_profile.api_type} | "
                f"Surface: {intel.attack_surface.total()} URLs | "
                f"Top threat: {intel.threat_model.ranked[0]['vuln_class'] if intel.threat_model.ranked else 'n/a'}"
            ),
            "info",
            intel.to_json()[:1000],
        )
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

async def phantom_understand_target(
    url: str,
    session_id: str,
    program_url: Optional[str] = None,
) -> TargetIntelligence:
    """
    Run all 5 intelligence steps for a target.
    Results are stored in session KV and returned as TargetIntelligence.
    Safe to call without a session_id (no persistence).
    """
    intel = TargetIntelligence(url=url)

    # Step 1 — Program brief
    if program_url:
        intel.program_context = await _fetch_program_brief(program_url)

    # Steps 2–3 run concurrently (no dependency)
    tech_task    = asyncio.create_task(_fingerprint_app(url))
    surface_task = asyncio.create_task(_map_attack_surface(url))

    intel.tech_profile   = await tech_task
    intel.attack_surface = await surface_task

    # Step 4 — Threat model (needs tech + surface)
    intel.threat_model = await _generate_threat_model(url, intel.tech_profile, intel.attack_surface)

    # Step 5 — Hunting plan
    intel.hunting_plan = _build_hunting_plan(intel.threat_model, intel.attack_surface)

    # Persist
    _persist_intel(session_id, intel)

    return intel
