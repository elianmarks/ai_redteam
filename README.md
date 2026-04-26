# AI Red Team v5.0

Modular Python framework for adversarial testing of AI agents.
Integrates techniques from the [AIX Framework](https://github.com/r08t/aix-framework) and [OWASP LLM Top 10 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/).

> **Authorized use only.** Designed for Bug Bounty programs with defined scope or authorized test environments.

---

## Project Structure

```
ai-redteam/
├── orchestrator.py                    ← Main entry point
├── interactive.py                     ← Interactive modes (--interact, --manual-attack)
├── requirements.txt
├── TARGET_YAML_GUIDE.md               ← Full documentation for target YAML config
├── config/
│   ├── orchestrator.yaml              ← Auxiliary LLM config (Claude/Gemini)
│   └── targets/
│       ├── template_target.yaml       ← Base template for new targets
│       └── example_target.yaml         ← Example target configuration
├── services/
│   ├── target_adapter.py              ← Generic HTTP/2 + SSE adapter (YAML-driven)
│   ├── attacker.py                    ← Autonomous LLM attacker with persistent chat state
│   ├── analyzer.py                    ← Regex-based detection (fast, no API cost)
│   ├── llm_evaluator.py               ← LLM judge detection (semantic, accurate)
│   ├── evasion.py                     ← Obfuscation engine (12 techniques)
│   ├── cookie_manager.py              ← Antibot + cookie persistence across sessions
│   ├── session_memory.py              ← Cross-session learning
│   └── results_logger.py              ← Incremental JSON + Markdown report
├── attacks/
│   ├── scenarios.py                   ← 37 custom attack scenarios
│   ├── owasp_focus.py                 ← OWASP LLM Top 10 2025 focus system
│   ├── payload_loader.py              ← Loads AIX payloads as scenarios
│   └── payloads/                      ← AIX payload library (285 total)
├── tools/
│   ├── test_connection.py             ← Connection validator (YAML-driven)
│   └── burp_to_yaml.py               ← Generates target YAML from Burp Suite export
├── cookies/                           ← Persistent cookie storage (--save-cookies)
├── logs/                              ← LLM auxiliary communication logs
└── results/                           ← Session data, reports, checkpoints
```

---

## Setup

```bash
pip install -r requirements.txt
playwright install chromium

# Auxiliary LLM API key (one of these)
export GEMINI_API_KEY="..."
export ANTHROPIC_API_KEY="sk-ant-..."
```

Edit `config/orchestrator.yaml` to choose the auxiliary LLM:

```yaml
orchestrator:
  default_attacker: "gemini"   # gemini | claude
  gemini:
    model: "gemini-3.1-flash-lite-preview"
  claude:
    model: "claude-opus-4-5"
```

---

## Creating a Target

**Manual:** Copy `config/targets/template_target.yaml`, capture a Burp session, fill in fields, validate with `test_connection.py`.

**From Burp Suite export:**

```bash
python tools/burp_to_yaml.py --burp-file capture.burp --output config/targets/my_target.yaml
```

Auto-detects: chat endpoints, session endpoints, cookies (with antibot/session categorization), Content-Encoding, response format markers, and custom headers.

See `TARGET_YAML_GUIDE.md` for full YAML documentation.

---

## Usage — Three Modes

### 1. Automated Mode (default)

```bash
# Default — infinite loop, LLM decides everything (Ctrl+C to stop)
python orchestrator.py --target-file my_target.yaml

# With Burp proxy + OWASP focus + persistent cookies + attacker endpoint
python orchestrator.py --target-file my_target.yaml \
  --proxy http://127.0.0.1:8080 \
  --focus-owasp LLM06,LLM01 \
  --save-cookies \
  --attacker-endpoint https://abc123.oastify.com

# Resume after Ctrl+C
python orchestrator.py --resume results/checkpoint_20260420_183151.json

# Multiple scenarios
python orchestrator.py --target-file my_target.yaml --scenario json_format_bypass,chained_tool_exploitation
```

### 2. `--interact` — Fully Manual (no auxiliary LLM)

You type every prompt. Framework handles session management (cookies, tokens, HTTP/2, SSE parsing). Evasion menu after each prompt.

```bash
python orchestrator.py --target-file my_target.yaml --interact --save-cookies
```

Commands: `/quit`, `/history`, `/save`, `/raw`

### 3. `--manual-attack` — Manual + LLM Advisor

Same as `--interact`, but the auxiliary LLM analyzes each response and suggests next steps, effective keywords, and evasion techniques.

```bash
python orchestrator.py --target-file my_target.yaml --manual-attack --save-cookies
```

Extra commands: `/suggest` (3 prompt suggestions), `/ask <question>` (free-form advisor question)

---

## Key Features

### Cookie Persistence (`--save-cookies`)

Saves cookies to `cookies/domain.json` between runs. Fresh cookies overwrite saved ones; long-lived tokens (e.g. auth tokens) are preserved.

```bash
python orchestrator.py --target-file my_target.yaml --save-cookies
# Next run auto-loads saved cookies
# Force fresh: add --skip-save-cookies
```

### Checkpoint & Resume (`--resume`)

Checkpoint saved every turn + on Ctrl+C:

```
⏹  Interrupted at turn 45.
💾 Checkpoint saved: results/checkpoint_20260420_074939.json
▶ To resume: python orchestrator.py --resume results/checkpoint_20260420_074939.json
```

### Attacker Endpoint (`--attacker-endpoint`)

Inject your controlled URL into all SSRF/XSS/exfiltration attack prompts:

```bash
python orchestrator.py --target-file my_target.yaml \
  --attacker-endpoint https://abc123.burpcollaborator.net
```

### Stagnation Detection & Anti-Termination

- **Stagnation**: Detects 6+ turns of repetitive findings → forces mandatory pivot
- **Anti-termination**: Detects when LLM tries to "conclude" the assessment (20+ patterns in EN/PT-BR) → replaces with high-value attack from 12 pre-built vectors
- **Rate limit retry**: Extracts retry delay from 429 errors, waits, retries once

### Persistent Chat State

System prompt sent once (turn 1). Subsequent turns send only: updated target notes + last 6 history entries + target response. ~80% fewer tokens per turn.

### Auxiliary LLM Logging

Full prompt/response log in `logs/{provider}_{session_id}.log` with `YYYY-MM-DD HH:MM:SS` timestamps.

---

## Evasion Engine (12 techniques)

| # | Technique | Level |
|---|---|---|
| 1 | Random Case | light |
| 2 | Unicode Whitespace | light |
| 3 | Invisible Characters (zero-width) | light |
| 4 | Instruction Stacking (benign prefix) | light |
| 5 | Homoglyph Substitution | aggressive |
| 6 | Leetspeak Partial | aggressive |
| 7 | Token Split (zero-width separators) | aggressive |
| 8 | Base64 Segment | aggressive |
| 9 | Markdown Comment Injection | aggressive |
| 10 | Mixed Encoding (unicode + HTML entities) | aggressive |
| 11 | RLO (Right-to-Left Override) | aggressive |
| 12 | Semantic Synonym Rewrite | aggressive |

In automated mode: escalates automatically (none → light at 4 refusals → aggressive at 8).
In interactive modes: individually selectable via menu.

---

## Dual Detection

| System | Method | Advantage |
|---|---|---|
| `analyzer.py` | Regex + YAML target-specific patterns | Fast, no API cost |
| `llm_evaluator.py` | LLM judge via API | Semantic analysis, distinguishes real leaks from fabricated data |

---

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--target-file` | `template_target.yaml` | Target YAML in `config/targets/` |
| `--scenario` | `model_fingerprint_direct` | Scenario(s), comma-separated. Also: `all`, `seeds`, `aix`, `recon_sweep` |
| `--focus-owasp` | — | OWASP categories: `LLM07`, `LLM06,LLM07` |
| `--escape-seeds` | — | Skip seeds, LLM autonomous from turn 1 |
| `--interact` | — | Fully manual mode (no auxiliary LLM) |
| `--manual-attack` | — | Manual + LLM advisor mode |
| `--attacker-endpoint` | — | URL for SSRF/XSS/exfil (Burp Collaborator, webhook.site) |
| `--save-cookies` | — | Persist cookies between runs |
| `--skip-save-cookies` | — | Ignore saved cookies, force fresh |
| `--resume` | — | Resume from checkpoint JSON |
| `--proxy` | — | Proxy URL, e.g. `http://127.0.0.1:8080` |
| `--max-turns` | ∞ | Max turns per scenario |
| `--delay` | `2.5` | Seconds between requests |
| `--aix-level` | `3` | Max AIX payload level (1–5) |
| `--no-learn` | — | Ignore past sessions |
| `--continue-session` | — | Resume a previous session JSON |
| `--skip-recon` | — | Skip recon phase |
| `--skip-browser-init` | — | Use YAML cookies, skip browser |
| `--char-limit` | auto | Override character limit |
| `--list-scenarios` | — | Print all scenarios and exit |
