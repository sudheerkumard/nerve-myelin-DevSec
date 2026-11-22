# AI in NERVE Myelin

There are two parts:
- **AI application security**: finding weaknesses in your LLM, agent, RAG and MCP code.
- **The AI assistant**: helping your teams understand, triage and report findings.

## 1. AI application security rules

These rules run with the AI-BOM engine on every scan. They cover Python, JavaScript and TypeScript, and MCP configuration files. Each one is mapped to the **OWASP Top 10 for LLM Applications (2025)**.

| Rule | Finding | OWASP LLM | CWE |
|---|---|---|---|
| NM-AI-001 | Model pulled from a hub without a pinned revision | LLM03 | CWE-1104 |
| NM-AI-002 | `trust_remote_code=True` executes code shipped with a model | LLM03 | CWE-94 |
| NM-AI-003 | `torch.load` without `weights_only=True` | LLM03 | CWE-502 |
| NM-AI-004 | Prompt built by concatenating user input | LLM01 | CWE-1427 |
| NM-AI-005 | Agent exposed to an unrestricted shell tool | LLM06 | CWE-250 |
| NM-AI-006 / 007 | Model output executed as code (Python / JavaScript) | LLM05 | CWE-94 |
| NM-AI-008 | Model output used in a shell command | LLM05 | CWE-78 |
| NM-AI-009 | Model output used in a SQL query | LLM05 | CWE-89 |
| NM-AI-010 | Model output rendered as HTML without sanitising | LLM05 | CWE-79 |
| NM-AI-011 | Agent given a Python REPL / shell tool, or `allow_dangerous_code=True` | LLM06 | CWE-250 |
| NM-AI-012 | Agent allowed to make arbitrary HTTP requests | LLM06 | CWE-918 |
| NM-AI-013 / 014 | System prompt or prompt template built from request input | LLM01 | CWE-1427 |
| NM-AI-015 | Secret or credential written into a system prompt | LLM07 | CWE-200 |
| NM-AI-016 | Environment variables sent to the model | LLM02 | CWE-200 |
| NM-AI-017 | Prompt/response debug logging enabled | LLM02 | CWE-532 |
| NM-AI-018 | Caller chooses the model or endpoint | LLM10 | CWE-639 |
| NM-AI-019 | No output token limit | LLM10 | CWE-770 |
| NM-AI-020 | Model artefact loaded with pickle / joblib | LLM03 | CWE-502 |
| NM-AI-021 | Vector database without authentication, or with reset enabled | LLM08 | CWE-306 |
| NM-AI-022 | Model weights downloaded over plain HTTP | LLM03 | CWE-494 |
| NM-AI-023 | MCP server launched from an unpinned package (`npx -y pkg`) | LLM03 | CWE-1104 |
| NM-AI-024 | Secret value in an MCP server's `env` (reported once, by the secrets engine, when it matches a key format) | LLM02 | CWE-798 |
| NM-AI-025 | Remote MCP server over plain HTTP | LLM02 | CWE-319 |
| NM-AI-026 | MCP filesystem server with access to the whole disk or home directory | LLM06 | CWE-552 |
| NM-AI-027 | MCP server that lets the model run shell commands | LLM06 | CWE-78 |

These MCP configuration files are parsed: `mcp.json`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, `cline_mcp_settings.json`.

The secrets engine also recognises these LLM provider keys:

| Rule | Key type |
|---|---|
| NM-SEC-012 | OpenAI API keys |
| NM-SEC-013 | Anthropic API keys |
| NM-SEC-014 | Hugging Face tokens |
| NM-SEC-015 | Azure OpenAI / Cognitive Services keys |

When an AI rule and a generic code rule match the same line, only the AI finding is kept, because it explains that the input is model output.

Reports and dashboards include **OWASP Top 10 for LLM Applications (2025)** as a framework.

## 2. The AI assistant

| Feature | Where | What it does |
|---|---|---|
| **Explain & fix** | Finding drawer | Explains what the finding is, its impact here, why it matters (KEV, EPSS, reachability, exposure), step-by-step fix, how to verify, and links to CVE and CWE. |
| **Triage suggestion** | Finding drawer | Suggests a verdict: likely real, likely false positive, or needs review. It shows the evidence on both sides and can prefill the false-positive reason. It never changes the finding by itself. |
| **Ask NERVE Myelin** | Findings page | Answers questions in plain language, for example "critical secrets in payments-api older than 7 days", "known exploited dependency CVEs" or "AI findings in support-bot". It shows how it understood the question, then the matching findings. |
| **AI executive briefing** | Executive overview → Leadership | A short narrative for leadership, written only from the figures on the page. |

### Built-in by default, your model when you choose

Every feature works with **no model configured**: a built-in security knowledge base answers, so it runs even air-gapped.

To use a model, set the following:

```
MYELIN_AI_PROVIDER = anthropic | openai | azure_openai
MYELIN_AI_MODEL    = model or deployment name
MYELIN_AI_ENDPOINT = (Azure OpenAI or an OpenAI-compatible private gateway)
MYELIN_AI_KEY_REF  = env://MYELIN_AI_KEY   or   vault://secret/data/myelin/ai#key
MYELIN_AI_SEND_CODE = false                (default)
```

Integrations → **AI assistant** shows what is configured.

When a model is configured but does not answer, the built-in answer is shown instead; users never see an error.

### Data handling

- Secret values are never sent. A secrets finding is described by its rule and location only.
- Tokens and long random strings are redacted from every field before a call.
- Code evidence is sent only when `MYELIN_AI_SEND_CODE=true`, and then only the matched line.
- Model answers are suggestions. Triage decisions are always made and recorded by a person.
- Every AI request is written to the audit trail (`ai.explain`, `ai.triage`, `ai.ask`, `ai.briefing`) without its content.
