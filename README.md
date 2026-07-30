# PHANTOM

> A general-purpose AI agent — security-first, but not security-only.

PHANTOM is an autonomous AI agent that **thinks, plans, and acts**. It ships with a world-class penetration testing pipeline as its flagship capability, but it's designed to be extended to any task that benefits from tool-use, memory, and multi-agent reasoning.

---

## What PHANTOM does

### Security (flagship)
- **Red Team** — Full offensive pipeline: OSINT → footprinting → vuln scan → fuzzing → AI analysis
- **Blue Team** — Log analysis, IOC extraction, hardening checklist, IR playbook, SIEM query generation
- **Grey Team** — Bug bounty / OSCP-style: recon + verified PoC, no blind exploitation
- **Beginner Mode** — Every action explained by AI before and after it runs

### Bug Bounty Volume Features (v0.4.0)
- **`phantom_js_analyze`** — Highest-ROI recon step: crawl all JS with Katana → extract hidden endpoints with LinkFinder → regex-scan for secrets (AWS keys, private keys, JWTs, internal URLs). Deduplicates and saves everything to session.
- **`phantom_idor_hunt`** — Automated IDOR hunting at scale: identifies numeric IDs, UUIDs, and hashed IDs across all discovered endpoints, tests ±1 mutations, boundary values, all HTTP methods, and cross-account UUID swaps. Auto-generates findings with CVSS scores and HackerOne-ready reproduction steps.
- **`phantom_ai_target`** — First-mover AI security testing: tests LLM-integrated apps for prompt injection, system prompt extraction, jailbreaks, and indirect prompt injection via external content. Auto-generates HackerOne-format reports for confirmed vulns.

### How PHANTOM Thinks (v0.5.0)
- **Target Intelligence (`phantom_understand_target`)** — Scrapes program scope (HackerOne/Bugcrowd), fingerprints the full tech stack, maps architecture, and uses Claude to build an ordered hunting plan.
- **Vuln Chaining Engine (`phantom_chain_finding`)** — Analyzes every new finding in real-time against session history and 7 common attack templates. Auto-generates high-priority hypotheses for multi-step attack paths (e.g. IDOR + SSRF).
- **Infrastructure Monitoring (`phantom monitor`)** — Continuous change detection tracking new subdomains (CT logs), new endpoints, tech stack shifts, and subdomain takeover candidates, alerting on high-value changes.

### Identity Layer
- Locale-aware fake persona generation (name, DOB, address, occupation)
- Disposable email (self-hosted via aiosmtpd or zero-config Guerrilla Mail fallback)
- SMS OTP via SMSPool or TextVerified
- Browser fingerprint spoofing (UA, timezone, locale headers)

### General AI Agent
- `phantom chat` — General-purpose AI chat, interactive or one-shot
- Session context — ask the AI about your scan results in plain English
- Works with any LLM — Anthropic, OpenAI, Ollama (local), OpenRouter, any OpenAI-compatible endpoint

### Infrastructure
- **Session Persistence** — Survives crashes. Resume any engagement from where it stopped.
- **On-Demand Tools** — Zero bloat at startup. Tools installed when first needed.
- **Report Generation** — HackerOne, Bugcrowd, and generic Markdown formats.
- **MCP Server** — Expose all capabilities to Claude Desktop and other MCP clients.

---

## Install

```bash
git clone https://github.com/grsanudeep42-cmd/phantom
cd phantom
pip install -e .
cp config/.env.example .env
# Edit .env — at minimum, set one LLM key (or leave blank for local Ollama)
phantom init
```

---

## LLM Support

PHANTOM works with **any LLM**. No API key required if you have Ollama running locally.

| Provider | How to enable |
|----------|--------------|
| **Ollama** (local, default) | Just run `ollama serve` — no key needed |
| **Anthropic** | Set `ANTHROPIC_API_KEY` |
| **OpenAI** | Set `OPENAI_API_KEY` |
| **OpenRouter** | Set `OPENROUTER_API_KEY` |
| **Custom endpoint** | Set `LLM_BASE_URL` + `LLM_API_KEY` |

**Override per command:**
```bash
phantom scan example.com --provider ollama --model llama3.1
phantom chat "explain XSS" --provider openai --model gpt-4o
phantom red target.com --provider anthropic --model claude-sonnet-4-6
```

---

## Quick Start

```bash
# First-time setup
phantom init

# General AI chat (any topic)
phantom chat
phantom chat "write a Python script to parse nginx logs"
phantom chat --provider ollama --model llama3.1 "explain SQL injection"

# Security scans
phantom scan example.com
phantom red example.com --scope "*.example.com"
phantom grey example.com --scope "*.example.com"
phantom blue example.com --log /var/log/nginx/access.log

# Identity generation
phantom identity gen --session <id> --locale IN --phone

# Reports
phantom report <session_id> --format hackerone

# Session management
phantom sessions list
phantom sessions findings <session_id>

# Continuous Monitoring
phantom monitor add example.com
phantom monitor run
```

---

## Bug Bounty Pipeline (v0.4.0)

The Phase 9 trio turns PHANTOM into a high-volume bug bounty machine:

```
# 1. JS Recon — highest ROI first step
phantom_js_analyze(url="https://target.com", session_id="<sid>")
# -> Discovers JS files, extracts hidden endpoints, finds leaked secrets

# 2. IDOR Hunt — sweep all discovered endpoints
phantom_idor_hunt(session_id="<sid>", base_url="https://target.com",
                  headers={"Authorization": "Bearer <token>"})
# -> Tests every numeric ID, UUID, and hash for unauthorized access

# 3. AI Target — test for LLM-specific vulns
phantom_ai_target(url="https://target.com/chat", session_id="<sid>",
                  api_endpoint="https://target.com/api/chat")
# -> Runs 4 test suites, auto-generates HackerOne report if vulnerable
```

---

## The Intelligence Engine (v0.5.0)

Phase 10 gives PHANTOM the ability to understand targets and build attack chains.

1. **Phase 0 / Target Intelligence** runs before any OSINT. It generates a comprehensive threat model mapping the attack surface.
2. **Asynchronous Chaining** runs silently in the background after every single finding, testing if that finding can be combined with previous findings (e.g., combining a stored XSS with a CSRF).
3. **Change Detection** runs on a cron via `phantom monitor run` to detect new endpoints or misconfigurations introduced by recent deploys.

---

## Architecture

```
phantom/
├── core/
│   ├── llm.py          <- Unified LLM abstraction (Anthropic/OpenAI/Ollama/any)
│   ├── orchestrator.py <- Agentic tool-use loop (provider-agnostic)
│   ├── hypothesis.py   <- AI next-action suggestion engine
│   ├── session.py      <- SQLite persistence (findings, actions, personas)
│   └── memory.py       <- Conversation-style context across turns
├── agents/
│   ├── red_agent.py       <- Full offensive pipeline
│   ├── blue_agent.py      <- Defensive analysis + hardening
│   ├── grey_agent.py      <- Bug bounty mode (PoC only)
│   ├── beginner_agent.py  <- Explained learning mode
│   ├── identity_agent.py  <- Persona + email + SMS orchestration
│   ├── intel_agent.py     <- [NEW] Target understanding & threat modeling
│   └── monitor_agent.py   <- [NEW] Infrastructure change detection
├── registry/
│   ├── manifest.json  <- Tool definitions (37 tools)
│   ├── loader.py      <- On-demand install (apt/brew/go/pip/docker)
│   └── runner.py      <- Docker-first + subprocess fallback
├── phantom-mcp/
│   ├── server/main.py <- MCP server (v0.4.0)
│   └── tools/
│       ├── js_tools.py      <- JS analysis + secret scanning
│       ├── idor_tools.py    <- IDOR hunting at scale
│       ├── ai_vuln_tools.py <- AI/LLM security testing
│       ├── intel_tools.py   <- [UPDATED] Target intelligence + CVEs
│       ├── monitor_tools.py <- [NEW] Change detection tools
│       ├── api_tools.py     <- JWT, XSS, API fuzzing
│       └── ...              <- 14 more tool modules
├── identity/
│   ├── persona.py         <- Locale-aware fake identity generation
│   ├── email_server.py    <- aiosmtpd self-hosted OR Guerrilla Mail
│   ├── sms.py             <- SMSPool + TextVerified
│   └── browser_profile.py <- UA + header fingerprint
├── reporting/
│   ├── generator.py       <- Jinja2 report engine
│   └── templates/         <- generic.j2, hackerone.j2, bugcrowd.j2
├── cli/
│   ├── main.py            <- Entry point, global --provider/--model flags
│   └── commands/          <- scan, red, blue, grey, learn, chat, report, ...
└── config/
    ├── settings.py        <- All env vars
    └── .env.example
```

---

## Tools (on-demand) — 37 registered

| Tool | Category | Purpose |
|------|----------|---------|
| nmap | recon | Port scan + service fingerprint |
| subfinder | osint | Passive subdomain discovery |
| nuclei | vuln_scan | Template-based CVE/OWASP scanning |
| httpx | recon | HTTP probing + tech detection |
| ffuf | fuzzing | Directory + parameter fuzzing |
| katana | recon | Next-gen JS crawler |
| **linkfinder** | **recon** | **JS endpoint extraction** |
| gobuster | fuzzing | Directory / DNS brute force |
| sqlmap | exploit | SQL injection detection |
| dalfox | exploit | XSS scanner + DOM analysis |
| amass | osint | Attack surface mapping |
| waybackurls | osint | Historical URL discovery |
| metasploit | exploit | Penetration testing framework |
| hashcat | crack | GPU password cracking |
| john | crack | Offline hash cracking |
| hydra | crack | Network brute-forcing |
| trivy | cloud | Container vulnerability scanning |
| checkov | cloud | IaC misconfiguration scanning |
| ... | ... | + 19 more tools |

---

## MCP Server

PHANTOM exposes all capabilities as MCP tools via `phantom-mcp`:

```bash
cd phantom-mcp && pip install -e .
# Add to Claude Desktop config
```

**v0.4.0 & v0.5.0 MCP tools (Phase 9 & 10 additions):**

| Tool | Description |
|------|-------------|
| `phantom_js_analyze` | JS crawl -> endpoint extraction -> secret scanning |
| `phantom_idor_hunt` | Automated IDOR hunting with CVSS scoring |
| `phantom_ai_target` | LLM app security testing + HackerOne reports |
| `phantom_understand_target` | Threat modeling, tech fingerprinting, hunting plans |
| `phantom_monitor_run` | Change detection + takeover identification |

All Phase 9/10 tools require scope validation (`phantom_set_scope` first).

---

## Roadmap

- [x] Phase 1 — Foundation (session, registry, CLI)
- [x] Phase 2 — Agent Brain (orchestrator, hypothesis engine)
- [x] Phase 3 — Red / Blue / Grey agents
- [x] Phase 4 — Identity layer (persona, email, SMS)
- [x] Phase 4b — Multi-provider LLM (Anthropic/OpenAI/Ollama/OpenRouter)
- [x] Phase 5 — MCP Server (`phantom-mcp`)
- [x] Phase 6 — Docker isolation, test suite, plugin API
- [x] Phase 7 — 15-tool expansion (masscan, netexec, hashcat, trivy, dalfox...)
- [x] Phase 8 — Scope middleware, standalone wrappers, CVE intelligence (NVD+EPSS)
- [x] Phase 9 — Bug Bounty Volume Features (JS analysis, IDOR hunt, AI target testing)
- [x] **Phase 10 — Intelligence & Chaining** (Intel phase, async chains, continuous monitor)
- [ ] Phase 11 — Collaborative multi-agent engagements, plugin marketplace

---

## Disclaimer

PHANTOM is for **authorised use only**. Always have explicit permission before testing any system. The authors are not responsible for misuse.

---

## License

MIT © Anudeep
