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
```

---

## Architecture

```
phantom/
├── core/
│   ├── llm.py          ← Unified LLM abstraction (Anthropic/OpenAI/Ollama/any)
│   ├── orchestrator.py ← Agentic tool-use loop (provider-agnostic)
│   ├── hypothesis.py   ← AI next-action suggestion engine
│   ├── session.py      ← SQLite persistence (findings, actions, personas)
│   └── memory.py       ← Conversation-style context across turns
├── agents/
│   ├── red_agent.py       ← Full offensive pipeline
│   ├── blue_agent.py      ← Defensive analysis + hardening
│   ├── grey_agent.py      ← Bug bounty mode (PoC only)
│   ├── beginner_agent.py  ← Explained learning mode
│   └── identity_agent.py  ← Persona + email + SMS orchestration
├── registry/
│   ├── manifest.json  ← Tool definitions (10 tools)
│   ├── loader.py      ← On-demand install (apt/brew/go/pip/docker)
│   └── runner.py      ← Docker-first + subprocess fallback
├── identity/
│   ├── persona.py         ← Locale-aware fake identity generation
│   ├── email_server.py    ← aiosmtpd self-hosted OR Guerrilla Mail
│   ├── sms.py             ← SMSPool + TextVerified
│   └── browser_profile.py ← UA + header fingerprint
├── reporting/
│   ├── generator.py       ← Jinja2 report engine
│   └── templates/         ← generic.j2, hackerone.j2, bugcrowd.j2
├── cli/
│   ├── main.py            ← Entry point, global --provider/--model flags
│   └── commands/          ← scan, red, blue, grey, learn, chat, report, ...
└── config/
    ├── settings.py        ← All env vars
    └── .env.example
```

---

## Tools (on-demand)

| Tool | Purpose |
|------|---------|
| nmap | Port scan + service fingerprint |
| subfinder | Passive subdomain discovery |
| nuclei | Template-based CVE/OWASP scanning |
| httpx | HTTP probing + tech detection |
| ffuf | Directory + parameter fuzzing |
| gobuster | Directory / DNS brute force |
| sqlmap | SQL injection detection |
| whatweb | CMS + tech fingerprinting |
| nikto | Web server vulnerability scan |
| theHarvester | Email + subdomain + host OSINT |

---

## MCP Server

PHANTOM exposes all capabilities as MCP tools (coming in `phantom-mcp`):

```bash
git clone https://github.com/grsanudeep42-cmd/phantom-mcp
cd phantom-mcp && pip install -e .
# Add to Claude Desktop config
```

---

## Roadmap

- [x] Phase 1 — Foundation (session, registry, CLI)
- [x] Phase 2 — Agent Brain (orchestrator, hypothesis engine)
- [x] Phase 3 — Red / Blue / Grey agents
- [x] Phase 4 — Identity layer (persona, email, SMS)
- [x] Phase 4b — Multi-provider LLM (Anthropic/OpenAI/Ollama/OpenRouter)
- [ ] Phase 5 — MCP Server (`phantom-mcp`)
- [ ] Phase 6 — Docker isolation, test suite, plugin API

---

## Disclaimer

PHANTOM is for **authorised use only**. Always have explicit permission before testing any system. The authors are not responsible for misuse.

---

## License

MIT © Anudeep
