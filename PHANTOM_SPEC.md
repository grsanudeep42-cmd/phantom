# PHANTOM — Full Project Specification
> For: Antigravity (coder) | By: Anudeep (founder) | Role: Build exactly this.

---

## Repos

| Repo | Purpose |
|------|---------|
| `github.com/grsanudeep42-cmd/phantom` | Core engine — all logic lives here |
| `github.com/grsanudeep42-cmd/phantom-mcp` | MCP wrapper — exposes phantom as MCP server |

`phantom-mcp` imports from `phantom`. They are NOT the same codebase.

---

## Philosophy

PHANTOM is not a tool collection. It is an **agent that thinks like a senior pentester**.  
It knows what to grab, when to grab it, how to use it, and how to report it.  
It does not load 150 tools at startup. It loads what it needs, when it needs it.  
It runs on any machine. It works for beginners and elite bounty hunters equally.

---

## Repo 1: `phantom` (Core Engine)

### Folder Structure

```
phantom/
├── core/
│   ├── orchestrator.py        # Main agent brain — routes tasks, manages session
│   ├── session.py             # Session state — what was found, tried, pending
│   ├── memory.py              # Persistent context across turns (SQLite)
│   └── hypothesis.py          # Generates next-move hypotheses from findings
│
├── agents/
│   ├── red_agent.py           # Offensive: recon → exploit → report
│   ├── blue_agent.py          # Defensive: log analysis, hardening, IR playbooks
│   ├── grey_agent.py          # Bug bounty / OSCP-style: recon+vuln scan, no blind exploit
│   ├── beginner_agent.py      # Learn-while-hacking mode, explains everything
│   └── identity_agent.py      # Fake persona generation + SMS/email bypass
│
├── registry/
│   ├── manifest.json          # Master list of all available tools + metadata
│   ├── loader.py              # Downloads, caches, version-checks tools on demand
│   ├── cache.py               # Tool cache manager (SQLite metadata + disk storage)
│   ├── updater.py             # Checks for stale tools, auto-updates
│   └── runner.py              # Executes tools in Docker-isolated subprocess
│
├── identity/
│   ├── persona.py             # Generates fake name/DOB/address/occupation/backstory
│   ├── email_server.py        # Self-hosted temp email (aiosmtpd) OR API fallback
│   ├── browser_profile.py     # Consistent UA, fingerprint, timezone, locale per persona
│   └── sms.py                 # SMS OTP via SMSPool/TextVerified API (only ext. dep)
│
├── reporting/
│   ├── templates/
│   │   ├── hackerone.j2       # HackerOne report format
│   │   ├── bugcrowd.j2        # Bugcrowd report format
│   │   └── generic.j2         # Generic pentest report
│   └── generator.py           # Fills templates from session findings
│
├── cli/
│   ├── main.py                # Entry point: `phantom` command
│   ├── commands/
│   │   ├── scan.py            # `phantom scan <target>`
│   │   ├── red.py             # `phantom red <target>`
│   │   ├── blue.py            # `phantom blue <log/host>`
│   │   ├── identity.py        # `phantom identity gen`
│   │   └── report.py          # `phantom report <session_id>`
│   └── ui.py                  # Rich terminal output (colors, progress, banners)
│
├── data/
│   ├── phantom.db             # SQLite — sessions, tool cache, persona vault
│   └── wordlists/             # Managed SecList subsets, auto-downloaded
│
├── config/
│   ├── settings.py            # Global config (API keys, paths, Docker settings)
│   └── .env.example           # Template for user's env vars
│
├── tests/
├── requirements.txt
├── Dockerfile
└── README.md
```

---

### Module: `core/orchestrator.py`

The brain. Receives a task (natural language or structured), reasons about it, delegates to the right agent, manages tool calls.

**Responsibilities:**
- Parse user intent → determine mode (red/blue/grey/beginner)
- Call Claude API with `tool_use` for reasoning
- Delegate sub-tasks to specialized agents via A2A protocol pattern
- Maintain session context across turns
- Trigger hypothesis engine after each finding

**Key functions:**
```python
async def run(task: str, session_id: str, mode: str) -> AgentResponse
async def delegate(agent: str, subtask: str, context: Session) -> AgentResponse
async def reason(context: Session, findings: list) -> NextMove
```

---

### Module: `core/session.py`

Persistent memory of a single engagement. Survives crashes. Stored in SQLite.

**Schema:**
```
sessions:
  id, target, mode, started_at, status, scope (JSON array)

findings:
  id, session_id, type, severity, description, proof, timestamp

tried:
  id, session_id, tool, args, result_summary, timestamp

hypotheses:
  id, session_id, hypothesis, confidence, status (pending/confirmed/rejected)

personas:
  id, session_id, name, dob, address, email, phone, browser_profile_json, created_at
```

---

### Module: `core/hypothesis.py`

Generates structured "next move" hypotheses after every finding. Calls Claude to reason over the current session state.

**What it does:**
- After each tool result is stored, reads all findings + tried items from session
- Calls Claude with a structured prompt: "Given these findings, what should we try next and why?"
- Returns a ranked list of `Hypothesis` objects with confidence scores
- Orchestrator picks the highest-confidence pending hypothesis and executes it

**Schema:**
```python
@dataclass
class Hypothesis:
    id: str
    session_id: str
    hypothesis: str         # e.g. "Port 8080 is running Jenkins — try default creds"
    rationale: str          # Why Claude thinks this is worth trying
    suggested_tool: str     # e.g. "nuclei" or "hydra"
    suggested_args: dict    # e.g. {"template": "jenkins-default-creds"}
    confidence: float       # 0.0 – 1.0
    status: str             # pending | confirmed | rejected
    created_at: str
```

**Example Claude prompt pattern:**
```
You are a senior pentester reviewing findings from an active engagement.
Target: {target}
Findings so far: {findings_json}
Already tried: {tried_json}

Generate 3 next-move hypotheses ranked by confidence. For each:
- State what you suspect
- Why (based on the evidence)
- What tool to use
- What args to pass
Return as JSON array matching the Hypothesis schema.
```

**Key functions:**
```python
async def generate(session: Session) -> list[Hypothesis]
async def confirm(hypothesis_id: str, result: ToolResult) -> None
async def reject(hypothesis_id: str, reason: str) -> None
```

---

### Module: `registry/manifest.json`

Every tool PHANTOM can use. Format:

```json
{
  "schema_version": "1.0",
  "tools": [
    {
      "id": "nmap",
      "category": "recon",
      "description": "Port scanner and service fingerprinter",
      "install": {
        "linux": "apt-get install -y nmap",
        "darwin": "brew install nmap",
        "docker": "instrumentisto/nmap"
      },
      "version_cmd": "nmap --version",
      "version_regex": "Nmap ([\\d.]+)",
      "min_version": "7.9",
      "tags": ["recon", "network", "ports"]
    }
  ]
}
```

Categories: `recon | exploit | fuzzing | osint | forensics | crypto | web | network | cloud | social-eng`

---

### Module: `registry/loader.py`

**On every tool invocation:**
1. Check if tool exists locally
2. If yes → check version against manifest min_version
3. If outdated → auto-update
4. If missing → download + install (apt/brew/pip/docker)
5. Cache metadata in SQLite
6. Return executable path

**Never pre-installs anything. Zero bloat on startup.**

---

### Module: `registry/runner.py`

Executes tools in isolation.

**Docker mode (preferred):** Each tool runs in its own container. No env pollution. Safe.  
**Subprocess fallback:** If Docker not available, runs as subprocess with timeout + output capture.

```python
async def run_tool(tool_id: str, args: list, timeout: int = 300) -> ToolResult
```

Output always returns:
```python
@dataclass
class ToolResult:
    tool: str
    args: list
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    truncated: bool          # if output was too large
    truncated_at_bytes: int  # how much was dropped
```

---

### Error Handling Policy

**Claude API failures:**
- Retry up to 3 times with exponential backoff (1s, 4s, 16s)
- On 3rd failure → pause session, log error, notify user via Rich console
- Session state is always flushed to SQLite before API call — no lost work

**Tool install failures:**
- If apt/brew/pip install fails → try Docker image as fallback
- If Docker also fails → mark tool as `unavailable` in cache, continue engagement without it
- Log which tools are unavailable at session start

**Docker not available:**
- Auto-detect on startup, set `PHANTOM_DOCKER_MODE=false` internally
- All tool runs use subprocess mode
- Warn user once at session start: "Docker not found — running in subprocess mode (less isolated)"

**Subprocess tool crash:**
- Capture stderr, exit code, partial stdout
- Log as `ToolResult` with `exit_code != 0`
- Hypothesis engine sees this as a negative result and adjusts next moves

**General rule:** PHANTOM never crashes the whole session because one tool failed. It adapts.

---

### Agent: `agents/red_agent.py`

Full offensive pipeline. Thinks like an attacker.

**Phase flow:**
```
1. OSINT          → subdomains, emails, tech stack, exposed assets
2. Footprinting   → port scan, service version, OS detection  
3. Vuln Scan      → nuclei templates, CVE matching, custom checks
4. Exploit        → suggest → confirm scope → execute PoC
5. Post-Exploit   → pivot opportunities, sensitive data found
6. Report         → auto-generate in HackerOne/Bugcrowd format
```

**Tools per phase (loaded on demand):**
- OSINT: `amass`, `subfinder`, `theHarvester`, `shodan-cli`
- Footprinting: `nmap`, `masscan`, `whatweb`
- Vuln Scan: `nuclei`, `nikto`, `sqlmap`
- Exploit: `metasploit`, `searchsploit`
- Fuzzing: `ffuf`, `gobuster`

---

### Agent: `agents/blue_agent.py`

Defensive mode.

**Capabilities:**
- Parse and analyze logs (Apache, Nginx, syslog, Windows Event)
- Extract IOCs (IPs, domains, hashes) → lookup via VirusTotal, AbuseIPDB, Shodan
- Generate hardening checklist for target system/app
- Build incident response playbook from detected IOCs
- Generate SIEM queries (Splunk SPL, Elastic KQL) from findings

---

### Agent: `agents/grey_agent.py`

Bug bounty and OSCP-style engagements. Middle ground between red (full attack chain) and blue (pure defence).

**Core difference from red_agent:** Does NOT execute blind exploits. Stops at verified PoC and documents the finding. This is the correct mode for responsible disclosure and bug bounty submissions.

**Phase flow:**
```
1. OSINT          → passive recon only (no active probing yet)
2. Footprinting   → port scan, tech fingerprint
3. Vuln Scan      → nuclei + manual checks focused on OWASP Top 10
4. PoC Confirm    → verify vulnerability exists with minimal, non-destructive proof
5. Stop           → hand off to reporting, do NOT exploit further
6. Report         → CVSS scoring + HackerOne/Bugcrowd format auto-generated
```

**Key behaviors:**
- Asks for explicit confirmation before any active exploitation step
- CVSS score is calculated automatically from finding metadata
- Flags out-of-scope assets found during recon and stops immediately
- Prioritises findings by bounty impact (P1/P2/P3/P4/P5 classification)

**Tools per phase:**
- OSINT: `subfinder`, `theHarvester`, `waybackurls`
- Footprinting: `nmap`, `whatweb`, `wappalyzer`
- Vuln Scan: `nuclei`, `nikto`, `dalfox` (XSS), `sqlmap` (read-only mode)
- PoC: `curl`, `httpx`, custom request replayer

---

### Agent: `agents/beginner_agent.py`

Every action explained before execution. Learning mode.

**Behavior:**
- Before running any tool: explain what it does, why, what output means
- After findings: explain the vulnerability class (OWASP, CVE)
- Suggests what to learn next
- Has guided CTF mode (integrates with HackTheBox/TryHackMe API if key provided — optional, best-effort)
- Never skips explanations even if user says "just run it"

---

### Agent: `agents/identity_agent.py`

Fake persona generation for account creation, SMS bypass, testing auth flows.

**Invocation model:**
- Can be called manually: `phantom identity gen --locale=IN`
- Can be called automatically by `red_agent` or `grey_agent` when a task requires account creation (e.g. "test registration flow", "bypass email verification")
- One persona per session — same identity used throughout the whole engagement

**Persona object:**
```python
@dataclass
class Persona:
    name: str
    dob: str
    address: str
    city: str
    country: str
    occupation: str
    email: str          # from self-hosted temp email OR API fallback
    phone: str          # from SMSPool/TextVerified API
    browser_profile: BrowserProfile
    created_at: str
    session_id: str     # persona is tied to engagement session
```

**Persona is consistent.** Same name/email/phone used across the whole engagement. Stored in persona vault in SQLite.

**Locale-aware:** Can generate Indian, US, UK, EU personas with correct address formats.

---

### Module: `identity/email_server.py`

Disposable email with two modes. Mode is selected automatically based on config.

**Mode 1 — Self-hosted (preferred when `PHANTOM_EMAIL_DOMAIN` is set):**
- Stack: Python `aiosmtpd` + user's own domain (e.g. `phantom-mail.io`)
- Spin up SMTP listener on `0.0.0.0:2525` (non-root safe)
- Generate `<random>@phantom-mail.io` addresses per persona
- Receive emails, store in SQLite
- `get_inbox(email)` returns all received messages
- Emails auto-expire after 24 hours
- **Requirement:** User must own domain + set MX record. Setup guide in README.

**Mode 2 — API fallback (default, zero config):**
- Uses Guerrilla Mail API (free, no key needed)
- `https://api.guerrillamail.com/ajax.php`
- Generates a temp address, polls for new emails
- Works out of the box on any machine

**CLI:** `phantom identity inbox <email>`

The code uses a single interface — which backend is active is transparent to all callers.

```python
async def create_address(session_id: str) -> str
async def get_inbox(email: str) -> list[EmailMessage]
```

---

### Identity: SMS OTP

Only external dependency in the identity layer.

**APIs (user configures one):**
- SMSPool: `https://www.smspool.net/api/`
- TextVerified: `https://www.textverified.com/api/`

**Usage:**
```python
async def get_number(service: str, country: str = "US") -> str
async def get_otp(request_id: str, timeout: int = 120) -> str
```

---

### CLI: `phantom` command

```bash
# Init
phantom init                           # Setup ~/.phantom/, check Docker, validate keys

# Modes
phantom red <target>                    # Full red team engagement
phantom blue <target_or_log>            # Blue team analysis
phantom scan <target>                   # Quick recon only
phantom identity gen --locale=IN        # Generate Indian persona
phantom identity inbox <email>          # Check temp email inbox
phantom report <session_id>            # Generate report
phantom report <session_id> --format=hackerone

# Session management
phantom sessions list
phantom sessions resume <session_id>
phantom sessions clear <session_id>

# Tool registry
phantom tools list
phantom tools update
phantom tools status
```

---

## Repo 2: `phantom-mcp` (MCP Server)

### Folder Structure

```
phantom-mcp/
├── server.py              # FastMCP server — exposes phantom tools as MCP tools
├── tools/
│   ├── red_tools.py       # MCP tool definitions for red team ops
│   ├── blue_tools.py      # MCP tool definitions for blue team ops
│   ├── identity_tools.py  # MCP tool definitions for identity agent
│   ├── registry_tools.py  # MCP tool definitions for tool management
│   └── session_tools.py   # MCP tool definitions for session management
├── auth/
│   ├── scope.py           # Scope validator — every call checked against declared scope
│   └── api_key.py         # Optional API key auth for the MCP server
├── config/
│   └── settings.py        # MCP server config
├── requirements.txt
└── README.md
```

---

### MCP Tool Definitions (examples)

Every MCP tool wraps a phantom core function:

```python
@mcp.tool()
async def phantom_recon(target: str, session_id: str) -> str:
    """
    Run full recon on a target. Includes subdomain enum, port scan, tech fingerprint.
    Always declare scope before calling this.
    """
    result = await red_agent.recon(target, session_id)
    return result.to_json()

@mcp.tool()
async def phantom_generate_identity(locale: str = "US") -> str:
    """
    Generate a fake persona with name, email, phone number for the current session.
    Returns a Persona object as JSON.
    """
    persona = await identity_agent.generate(locale)
    return persona.to_json()

@mcp.tool()
async def phantom_get_inbox(email: str) -> str:
    """
    Check the temp email inbox for a given phantom email address.
    Returns list of received emails as JSON.
    """
    return await email_server.get_inbox(email)
```

---

### Scope Validation (non-negotiable)

Every tool call that touches a target goes through scope check first:

```python
async def validate_scope(target: str, session_id: str) -> bool:
    session = await get_session(session_id)
    if not session.scope:
        raise ScopeNotDeclaredError("Declare scope first: phantom_set_scope()")
    return is_in_scope(target, session.scope)
```

**If target is out of scope → HTTP 403 + logged. Tool does not run.**

---

## Orchestration Architecture

```
User / AI Client (Claude Desktop, Antigravity's model, etc.)
        │
        │  MCP protocol (phantom-mcp)
        ▼
┌─────────────────────────────┐
│     phantom-mcp/server.py   │   ← MCP tool definitions + auth + scope validation
└──────────────┬──────────────┘
               │  Python import
               ▼
┌─────────────────────────────┐
│   phantom/core/orchestrator  │  ← Claude API tool_use + A2A agent routing
└──┬──────┬──────┬────────────┘
   │      │      │
   ▼      ▼      ▼
red_   blue_  identity_    ← Specialized agents
agent  agent  agent
   │
   ▼
registry/loader.py          ← On-demand tool fetch + cache
   │
   ▼
registry/runner.py          ← Docker-isolated execution
   │
   ▼
Tool output → session.py → hypothesis.py → next move
```

---

## Tech Stack (Final, Locked)

| Layer | Tech | Why |
|-------|------|-----|
| Language | Python 3.12 | Best sec tool ecosystem, Claude SDK native |
| MCP Server | FastMCP | Fastest MCP server lib for Python |
| Agent Brain | Claude API (`claude-sonnet-4-6`) + `tool_use` | Native reasoning + tool calls |
| Inter-agent | A2A pattern (async function calls initially, upgrade to protocol later) | Agent specialization without overhead |
| Tool Runner | Docker subprocess (fallback: bare subprocess) | Isolation + safety |
| Tool Registry | JSON manifest + GitHub raw fetch + apt/brew/pip install | Zero bloat startup |
| Tool Cache | SQLite + disk (`~/.phantom/tools/`) | Fast local cache |
| Session Store | SQLite (`~/.phantom/phantom.db`) | Lightweight, zero deps |
| CLI | Python Click + Rich | Beautiful terminal output |
| Email Server | aiosmtpd + own domain (fallback: Guerrilla Mail API) | Works zero-config by default |
| SMS | SMSPool API (configurable) | Only external identity dep |
| Persona Gen | Faker lib (locale-aware) + custom templates | Consistent, realistic identities |
| Report Engine | Jinja2 templates | HackerOne/Bugcrowd/generic formats |

---

## Config / .env

```env
# Required
ANTHROPIC_API_KEY=sk-ant-...

# Identity (SMS only)
SMSPOOL_API_KEY=...
# OR
TEXTVERIFIED_API_KEY=...

# Optional
PHANTOM_DOCKER_MODE=true       # default: true
PHANTOM_DATA_DIR=~/.phantom    # default: ~/.phantom
PHANTOM_EMAIL_DOMAIN=          # leave blank to use Guerrilla Mail fallback
PHANTOM_EMAIL_PORT=2525
SHODAN_API_KEY=...             # optional, enhances OSINT
VIRUSTOTAL_API_KEY=...         # optional, enhances blue team
```

---

## Build Order for Antigravity

Build in this exact sequence. Each phase is independently testable.

**Phase 1 — Foundation**
- `core/session.py` + SQLite schema
- `registry/manifest.json` with 10 starter tools
- `registry/loader.py` + `registry/runner.py` (subprocess mode first, Docker later)
- `cli/main.py` with `phantom scan <target>` working end-to-end

**Phase 2 — Agent Brain**
- `core/orchestrator.py` with Claude API tool_use integration
- `agents/red_agent.py` — recon phase only first
- `core/hypothesis.py`
- Session persistence + resume working

**Phase 3 — Full Red Team**
- Complete red_agent.py all phases
- `agents/blue_agent.py`
- `agents/grey_agent.py`
- `reporting/generator.py` with HackerOne template

**Phase 4 — Identity Layer**
- `identity/persona.py`
- `identity/email_server.py`
- `identity/sms.py`
- `agents/identity_agent.py`
- `cli/commands/identity.py`

**Phase 5 — MCP Server**
- `phantom-mcp/server.py`
- All tool definitions
- Scope validation
- Test with Claude Desktop

**Phase 6 — Polish**
- Docker support for tool runner
- `agents/beginner_agent.py`
- `cli/ui.py` rich terminal output
- Auto-updater for tool registry
- Full test suite

---

## Notes for Antigravity

- Never load tools at startup. Always lazy-load via `registry/loader.py`.
- Every tool execution goes through `runner.py`. Never call subprocess directly from agents.
- Session ID is always passed around. Nothing runs without an active session.
- Scope must be declared before any offensive tool runs. Enforce this hard.
- The identity layer email server needs to run as a background thread/process — start it when phantom starts if `PHANTOM_EMAIL_DOMAIN` is set. Otherwise use Guerrilla Mail API (no background process needed).
- Claude API model: always use `claude-sonnet-4-6`. Don't hardcode other models.
- All agent outputs must be serializable to JSON — use dataclasses + `to_json()` everywhere.
- Use async throughout. This is an async-first codebase.
- Rich for ALL terminal output. No raw print statements.
- `phantom init` must be the first command a new user runs. It sets up dirs, validates keys, detects Docker.
- `manifest.json` includes `schema_version`. Always check this on load.
- `ToolResult` includes `truncated_at_bytes` so hypothesis engine knows how much context it's missing.
