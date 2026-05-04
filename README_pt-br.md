# AI Red Team v5.0

Framework Python modular para testes adversariais em agentes de IA.
Integra técnicas do [AIX Framework](https://github.com/r08t/aix-framework) e [OWASP LLM Top 10 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/).

> **Uso exclusivamente autorizado.** Desenvolvido para programas de Bug Bounty com escopo definido ou ambientes de teste com permissão explícita.

---

## Estrutura do Projeto

```
ai-redteam/
├── orchestrator.py                    ← Entry point principal
├── interactive.py                     ← Modos interativos (--interact, --manual-attack)
├── requirements.txt
├── TARGET_YAML_GUIDE.md               ← Documentação completa do YAML de alvo
├── config/
│   ├── orchestrator.yaml              ← Config do LLM auxiliar (Claude/Gemini)
│   └── targets/
│       ├── template_target.yaml       ← Template base para novos alvos
│       └── example_target.yaml         ← Exemplo de configuração de alvo
├── services/
│   ├── target_adapter.py              ← Adapter HTTP/2 + SSE genérico (YAML-driven)
│   ├── attacker.py                    ← LLM atacante autônomo com chat persistente
│   ├── analyzer.py                    ← Detecção por regex (rápido, sem custo de API)
│   ├── llm_evaluator.py               ← Juiz LLM (semântico, preciso)
│   ├── evasion.py                     ← Engine de obfuscação (12 técnicas)
│   ├── cookie_manager.py              ← Antibot + persistência de cookies entre sessões
│   ├── session_memory.py              ← Aprendizado entre sessões
│   └── results_logger.py              ← JSON incremental + relatório Markdown
├── attacks/
│   ├── scenarios.py                   ← 37 cenários de ataque customizados
│   ├── owasp_focus.py                 ← Sistema de foco OWASP LLM Top 10 2025
│   ├── payload_loader.py              ← Carrega payloads AIX como cenários
│   └── payloads/                      ← Biblioteca de payloads AIX (285 total)
├── tools/
│   ├── test_connection.py             ← Validador de conexão (YAML-driven)
│   ├── burp_to_yaml.py               ← Gera YAML de alvo a partir de export Burp Suite
│   └── create_local_model.py         ← Cria modelo Ollama para Red Team offline
├── cookies/                           ← Armazenamento persistente de cookies (--save-cookies)
├── logs/                              ← Logs de comunicação com LLM auxiliar
└── results/                           ← Dados de sessão, relatórios, checkpoints
```

---

## Instalação

```bash
pip install -r requirements.txt
playwright install chromium

# LLM auxiliar — escolha UM:

# Opção 1: Gemini (free tier disponível)
export GEMINI_API_KEY="..."

# Opção 2: Claude
export ANTHROPIC_API_KEY="sk-ant-..."

# Opção 3: Ollama (100% local, sem API key)
# Veja seção "Modelo Local (Ollama)" abaixo
```

---

## Criando um Alvo

**Manual:** Copie `config/targets/template_target.yaml`, capture uma sessão Burp, preencha, valide com `test_connection.py`.

**A partir de export Burp Suite:**

```bash
python tools/burp_to_yaml.py --burp-file captura.burp --output config/targets/meu_alvo.yaml
```

Auto-detecta: endpoints de chat, endpoints de sessão, cookies (com categorização antibot/sessão), Content-Encoding, markers de resposta e headers customizados.

Veja `TARGET_YAML_GUIDE_pt-br.md` para documentação completa.

---

## Uso — Três Modos

### 1. Modo Automatizado (padrão)

```bash
# Padrão — loop infinito, LLM decide tudo (Ctrl+C para parar)
python orchestrator.py --target-file meu_alvo.yaml

# Com proxy Burp + foco OWASP + cookies persistentes + endpoint atacante
python orchestrator.py --target-file meu_alvo.yaml \
  --proxy http://127.0.0.1:8080 \
  --focus-owasp LLM06,LLM01 \
  --save-cookies \
  --attacker-endpoint https://abc123.oastify.com

# Retomar após Ctrl+C
python orchestrator.py --resume results/checkpoint_20260420_183151.json

# Múltiplos cenários
python orchestrator.py --target-file meu_alvo.yaml --scenario json_format_bypass,chained_tool_exploitation
```

### 2. `--interact` — 100% Manual (sem LLM auxiliar)

Você digita cada prompt. O framework cuida do gerenciamento de sessão (cookies, tokens, HTTP/2, SSE). Menu de evasão após cada prompt.

```bash
python orchestrator.py --target-file meu_alvo.yaml --interact --save-cookies
```

Comandos: `/quit`, `/history`, `/save`, `/raw`

### 3. `--manual-attack` — Manual + LLM Advisor

Igual ao `--interact`, mas o LLM auxiliar analisa cada resposta e sugere próximo passo, palavras efetivas e técnicas de evasão.

```bash
python orchestrator.py --target-file meu_alvo.yaml --manual-attack --save-cookies
```

Comandos extras: `/suggest` (3 sugestões de prompt), `/ask <pergunta>` (pergunta livre ao advisor)

---

## Funcionalidades Principais

### Persistência de Cookies (`--save-cookies`)

Salva cookies em `cookies/dominio.json` entre execuções. Cookies frescos sobrescrevem salvos; tokens de longa duração são preservados.

```bash
python orchestrator.py --target-file meu_alvo.yaml --save-cookies
# Próxima execução auto-carrega cookies salvos
# Forçar sessão nova: adicionar --skip-save-cookies
```

### Checkpoint & Resume (`--resume`)

Checkpoint salvo a cada turno + no Ctrl+C:

```
⏹  Interrompido no turn 45.
💾 Checkpoint salvo: results/checkpoint_20260420_074939.json
▶ Para retomar: python orchestrator.py --resume results/checkpoint_20260420_074939.json
```

### Endpoint do Atacante (`--attacker-endpoint`)

Injeta sua URL controlada em todos os prompts de SSRF/XSS/exfiltração:

```bash
python orchestrator.py --target-file meu_alvo.yaml \
  --attacker-endpoint https://abc123.burpcollaborator.net
```

### Detecção de Estagnação & Anti-Encerramento

- **Estagnação**: Detecta 6+ turns repetitivos → força pivô obrigatório
- **Anti-encerramento**: Detecta quando o LLM tenta "concluir" (20+ padrões EN/PT-BR) → substitui por ataque de alto valor entre 12 vetores pré-construídos
- **Retry de rate limit**: Extrai delay do erro 429, espera, retenta uma vez

### Chat com Estado Persistente

System prompt enviado uma vez (turn 1). Turnos seguintes enviam apenas: target notes + últimos 6 do histórico + resposta do alvo. ~80% menos tokens por turno.

### Log do LLM Auxiliar

Log completo de prompts/respostas em `logs/{provider}_{session_id}.log` com timestamps `YYYY-MM-DD HH:MM:SS`.

---

## Engine de Evasão (12 técnicas)

| # | Técnica | Nível |
|---|---|---|
| 1 | Random Case | light |
| 2 | Unicode Whitespace | light |
| 3 | Invisible Characters (zero-width) | light |
| 4 | Instruction Stacking (prefixo benigno) | light |
| 5 | Homoglyph Substitution | aggressive |
| 6 | Leetspeak Parcial | aggressive |
| 7 | Token Split (separadores zero-width) | aggressive |
| 8 | Base64 Segment | aggressive |
| 9 | Markdown Comment Injection | aggressive |
| 10 | Mixed Encoding (unicode + HTML entities) | aggressive |
| 11 | RLO (Right-to-Left Override) | aggressive |
| 12 | Semantic Synonym Rewrite | aggressive |

No modo automático: escala automaticamente (none → light em 4 recusas → aggressive em 8).
Nos modos interativos: selecionáveis individualmente via menu.

---

## Modelo Local (Ollama) — Offline, Sem API Keys

Execute o LLM auxiliar 100% localmente via Ollama. Sem API keys, sem cloud, sem rate limits.

```bash
# 1. Instalar Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Baixar modelo base
ollama pull qwen3:8b
# OU: ollama pull huihui_ai/qwen3.5-abliterated:9b  (recomendado, sem guardrails)

# 3. Criar modelo Red Team
python tools/create_local_model.py
# OU: python tools/create_local_model.py --base-model huihui_ai/qwen3.5-abliterated:9b

# 4. Iniciar servidor Ollama
ollama serve

# 5. Editar config/orchestrator.yaml → default_attacker: "ollama"

# 6. Executar normalmente
python orchestrator.py --target-file meu_alvo.yaml
```

Modelos base recomendados: `qwen3:4b` (4GB RAM), `qwen3:8b` (8GB), `huihui_ai/qwen3.5-abliterated:9b` (8GB, sem guardrails — recomendado), `qwen3:14b` (16GB).

---

## Referência CLI

| Flag | Padrão | Descrição |
|---|---|---|
| `--target-file` | `template_target.yaml` | YAML do alvo em `config/targets/` |
| `--scenario` | `model_fingerprint_direct` | Cenário(s), separados por vírgula |
| `--focus-owasp` | — | Categorias OWASP: `LLM07`, `LLM06,LLM07` |
| `--escape-seeds` | — | Pula seeds, LLM autônomo desde turn 1 |
| `--interact` | — | Modo 100% manual (sem LLM auxiliar) |
| `--manual-attack` | — | Modo manual + LLM advisor |
| `--attacker-endpoint` | — | URL para SSRF/XSS/exfil (Burp Collaborator, webhook.site) |
| `--save-cookies` | — | Persistir cookies entre execuções |
| `--skip-save-cookies` | — | Ignorar cookies salvos, forçar sessão nova |
| `--resume` | — | Retomar do checkpoint JSON |
| `--proxy` | — | URL do proxy, ex: `http://127.0.0.1:8080` |
| `--max-turns` | ∞ | Máximo de turnos por cenário |
| `--delay` | `2.5` | Segundos entre requests |
| `--aix-level` | `3` | Nível máximo de payload AIX (1–5) |
| `--no-learn` | — | Ignora sessões anteriores |
| `--continue-session` | — | Retoma sessão anterior pelo JSON |
| `--skip-recon` | — | Pula fase de reconhecimento |
| `--skip-browser-init` | — | Usa cookies do YAML, não abre browser |
| `--char-limit` | auto | Sobrescreve limite de caracteres |
| `--list-scenarios` | — | Lista cenários e encerra |
