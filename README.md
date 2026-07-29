# PHANTOM

> AI-powered penetration testing agent — thinks like a senior red teamer.

PHANTOM is not a tool collection. It is an **agent that reasons like an experienced pentester** — it knows what to grab, when to grab it, how to use it, and how to report it. It loads tools on demand, runs them in isolation, and uses Claude to reason about findings and generate next moves.

---

## Features

- **Red Team** — Full offensive pipeline: OSINT → footprinting → vuln scan → fuzzing → AI analysis
- **Blue Team** — Log analysis, IOC extraction, hardening checklist, IR playbook, SIEM queries
- **Grey Team** — Bug bounty / OSCP-style: recon + PoC confirmation, no blind exploitation
- **Beginner Mode** — Every action explained before + after, with learning suggestions
- **Identity Layer** — Fake personas with locale-aware data, disposable email, SMS OTP
- **MCP Server** — Expose all PHANTOM capabilities to Claude Desktop and other AI clients
- **Session Persistence** — Survives crashes. Resume any engagement from where it stopped.
- **On-Demand Tools** — Zero bloat at startup. Tools installed when first needed.

---

## Install

```bash
git clone https://github.com/grsanudeep42-cmd/phantom
cd phantom
pip install -e .
cp config/.env.example .env
# Edit .env — add your ANTHROPIC_API_KEY at minimum
phantom init
```

---

## Quick Start

```bash
# First-time setup (checks Docker, Go, keys)
phantom init

# Quick recon scan
phantom scan example.com

# Full red team engagement
phantom red example.com --scope "*.example.com"

# Bug bounty mode (no blind exploitation)
phantom grey example.com --scope "*.example.com"

# Blue team log analysis
phantom blue example.com --log /var/log/nginx/access.log

# Generate a HackerOne report
phantom report <session_id> --format hackerone

# Manage sessions
phantom sessions list
phantom sessions resume <session_id_prefix>
```

---

## Configuration

Copy `config/.env.example` to `.env` and fill in:

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | **Yes** | Powers the AI agent brain |
| `SMSPOOL_API_KEY` | No | SMS OTP for identity layer |
| `TEXTVERIFIED_API_KEY` | No | Alternative SMS provider |
| `SHODAN_API_KEY` | No | Enhanced OSINT |
| `VIRUSTOTAL_API_KEY` | No | Enhanced blue team IOC lookup |
| `PHANTOM_EMAIL_DOMAIN` | No | Self-hosted email domain (leave blank for Guerrilla Mail) |
| `PHANTOM_DOCKER_MODE` | No | `true` = run tools in Docker containers (default) |

---

## Architecture

```
phantom/
├── core/          # Orchestrator (Claude agent brain), session, memory, hypothesis engine
├── agents/        # red_agent, blue_agent, grey_agent, beginner_agent, identity_agent
├── registry/      # Tool manifest, on-demand loader, Docker/subprocess runner
├── identity/      # Persona generation, disposable email, SMS OTP
├── reporting/     # Jinja2 templates: HackerOne, Bugcrowd, generic
├── cli/           # Click CLI — all commands
└── config/        # Settings, .env.example
```

The `phantom-mcp` repo wraps this as an MCP server for use with Claude Desktop.

---

## Tools

PHANTOM manages these tools on demand (installed when first needed):

| Tool | Category | Purpose |
|------|----------|---------|
| nmap | Recon | Port scan + service fingerprint |
| subfinder | OSINT | Passive subdomain discovery |
| nuclei | Vuln Scan | Template-based CVE/OWASP scanning |
| httpx | Recon | HTTP probing + tech detection |
| ffuf | Fuzzing | Directory + parameter discovery |
| gobuster | Fuzzing | Directory/DNS brute force |
| sqlmap | Exploit | SQL injection detection |
| whatweb | Recon | CMS + tech fingerprinting |
| nikto | Vuln Scan | Web server vulnerability scan |
| theHarvester | OSINT | Email + subdomain + host OSINT |

---

## MCP Server

PHANTOM exposes all capabilities as MCP tools via `phantom-mcp`:

```bash
git clone https://github.com/grsanudeep42-cmd/phantom-mcp
cd phantom-mcp
pip install -e .
# Add to Claude Desktop MCP config
```

---

## Roadmap

- [x] Phase 1 — Foundation (session, registry, CLI, scan command)
- [x] Phase 2 — Agent Brain (orchestrator, red agent, hypothesis engine)
- [x] Phase 3 — Full Red/Blue/Grey agents
- [x] Phase 4 — Identity layer (persona, email, SMS)
- [ ] Phase 5 — MCP Server (phantom-mcp)
- [ ] Phase 6 — Docker isolation, beginner agent polish, full test suite

---

## Disclaimer

PHANTOM is for **authorised security testing only**. Always declare scope. Never test systems you don't have explicit permission to test. The authors are not responsible for misuse.

---

## License

MIT © Anudeep
