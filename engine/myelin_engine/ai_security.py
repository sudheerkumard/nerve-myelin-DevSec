# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""AI application security: LLM, agent, RAG and MCP weaknesses mapped to the OWASP Top 10 for LLM Applications (2025).

Code rules run on Python, JavaScript and TypeScript. MCP client/server configuration files (mcp.json, .mcp.json,
.cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json) are parsed as JSON.

Every rule needs a concrete code signal (a call, a flag, a data flow on the same line); vague "uses an LLM" patterns are
deliberately not reported.
"""
import json
import os
import re

CODE_EXT = (".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")
SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".pytest_cache", "vendor", ".tox"}
LLM_VAR = r"(completion|response|resp|result|answer|llm_output|model_output|ai_output|generated|reply|output_text|message\.content|choices\[0\])"

# (id, title, severity, OWASP LLM 2025, CWE, regex, extensions)
RULES = [
    ("NM-AI-006", "LLM output executed as code", "critical", "LLM05", "CWE-94",
     r"\b(exec|eval)\s*\(\s*[^)]*" + LLM_VAR, (".py",)),
    ("NM-AI-007", "LLM output executed as code (JavaScript)", "critical", "LLM05", "CWE-94",
     r"\b(eval|new\s+Function|vm\.runIn\w*Context)\s*\(\s*[^)]*" + LLM_VAR, (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")),
    ("NM-AI-008", "LLM output used in a shell command", "critical", "LLM05", "CWE-78",
     r"\b(os\.system|subprocess\.\w+|child_process\.\w+|execSync|spawnSync)\s*\([^)]*" + LLM_VAR, CODE_EXT),
    ("NM-AI-009", "LLM output used in a SQL query", "high", "LLM05", "CWE-89",
     r"\.(execute|executemany|raw|query)\s*\(\s*(f[\"']|[^)]*\+\s*)[^)]*" + LLM_VAR, CODE_EXT),
    ("NM-AI-010", "LLM output rendered as HTML without sanitising", "high", "LLM05", "CWE-79",
     r"(innerHTML\s*=|dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:|Markup\(|mark_safe\()\s*[^;]*" + LLM_VAR, CODE_EXT),
    ("NM-AI-011", "Agent given an unrestricted code or shell tool", "high", "LLM06", "CWE-250",
     r"\b(PythonREPLTool|PythonAstREPLTool|ShellTool|BashProcess|create_python_agent|TerminalTool)\s*\(|allow_dangerous_code\s*=\s*True", (".py",)),
    ("NM-AI-012", "Agent allowed to make arbitrary HTTP requests", "medium", "LLM06", "CWE-918",
     r"allow_dangerous_requests\s*=\s*True|\bRequestsToolkit\(", (".py",)),
    ("NM-AI-013", "Prompt built from request input (prompt injection)", "medium", "LLM01", "CWE-1427",
     r"(role[\"']?\s*:\s*[\"']system[\"'].*|system_prompt\s*=\s*f[\"'].*|SystemMessage\(\s*(content\s*=\s*)?f[\"'].*)\{?(request\.(args|form|json|values|GET|POST)|req\.(body|query|params)|user_input)",
     CODE_EXT),
    ("NM-AI-014", "Prompt template built from request input (JavaScript)", "medium", "LLM01", "CWE-1427",
     r"content\s*:\s*`[^`]*\$\{\s*(req\.(body|query|params)|request\.)", (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")),
    ("NM-AI-015", "Secret or credential placed in a system prompt", "high", "LLM07", "CWE-200",
     r"(?i)(system_prompt|role[\"']?\s*:\s*[\"']system).*(password|api[_ -]?key|secret|token)\s*(is|=|:)\s*[\"']?[A-Za-z0-9_\-]{8,}", CODE_EXT),
    ("NM-AI-016", "Environment secrets sent to the model", "high", "LLM02", "CWE-200",
     r"(content|prompt|messages)\s*[=:].*(os\.environ\b(?!\.get\([\"'](LANG|TZ|HOME)\b)|process\.env\b(?!\.(NODE_ENV|TZ)\b))", CODE_EXT),
    ("NM-AI-017", "Prompt and response logging of sensitive conversations enabled", "low", "LLM02", "CWE-532",
     r"\blangchain\.debug\s*=\s*True|\bset_debug\(\s*True\s*\)|\blitellm\.set_verbose\s*=\s*True", (".py",)),
    ("NM-AI-018", "Model or endpoint chosen by the caller", "medium", "LLM10", "CWE-639",
     r"\b(model|base_url|api_base)\s*=\s*(request\.(args|json|form|values)|req\.(body|query))", CODE_EXT),
    ("NM-AI-019", "Unbounded model output (no token limit)", "low", "LLM10", "CWE-770",
     r"\b(max_tokens|max_output_tokens|max_new_tokens)\s*[=:]\s*(None|-1|null)\b", CODE_EXT),
    ("NM-AI-020", "Model artefact loaded with pickle", "high", "LLM03", "CWE-502",
     r"\b(joblib\.load|pickle\.load|dill\.load|cloudpickle\.load)\s*\([^)]*(\.pkl|\.joblib|model|weights)", (".py",)),
    ("NM-AI-021", "Vector database reachable without authentication or with destructive reset", "medium", "LLM08", "CWE-306",
     r"allow_reset\s*=\s*True|\bQdrantClient\(\s*(url\s*=\s*)?[\"']http://(?!localhost|127\.0\.0\.1)|\bchromadb\.HttpClient\((?![^)]*(headers|settings))",
     (".py",)),
    ("NM-AI-022", "Model weights downloaded over plain HTTP", "high", "LLM03", "CWE-494",
     r"(from_pretrained|hf_hub_download|load_model|urlretrieve|torch\.hub\.load)\s*\(\s*[\"']http://", (".py",)),
]
_COMPILED = [(r[0], r[1], r[2], r[3], r[4], re.compile(r[5]), r[6]) for r in RULES]

MCP_FILES = ("mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "cline_mcp_settings.json")
SECRET_VALUE = re.compile(r"^(sk-|ghp_|github_pat_|xox[bp]-|AKIA|AIza|hf_|glpat-|eyJ)[A-Za-z0-9_\-.]{12,}$|^[A-Za-z0-9+/_\-]{32,}$")
REF_VALUE = re.compile(r"^\$\{?[A-Z_][A-Z0-9_]*\}?$|^\$\{(env|input):")
SHELL_SERVERS = re.compile(r"(?i)(server-commands|shell|terminal|desktop-commander|mcp-server-commands|run-command|exec)")
ROOT_PATHS = {"/", "~", "~/", "/home", "/root", "/Users", "C:\\", "C:/", "C:\\Users", "%USERPROFILE%", "${HOME}", "$HOME"}


# OWASP Top 10 for Agentic Applications (2026) category for each rule that concerns agents, tools or their supply chain.
AGENTIC = {"NM-AI-006": "ASI05", "NM-AI-007": "ASI05", "NM-AI-008": "ASI05", "NM-AI-011": "ASI05", "NM-AI-012": "ASI02",
           "NM-AI-013": "ASI01", "NM-AI-014": "ASI01", "NM-AI-021": "ASI06", "NM-AI-023": "ASI04", "NM-AI-024": "ASI03",
           "NM-AI-025": "ASI07", "NM-AI-026": "ASI02", "NM-AI-027": "ASI05", "NM-AI-028": "ASI01", "NM-AI-029": "ASI01",
           "NM-AI-030": "ASI02", "NM-AI-031": "ASI01", "NM-AI-032": "ASI03"}


def _finding(rid, title, sev, owasp, cwe, rel, line, repo, evidence, remediation):
    f = {"engine": "aibom", "rule_id": rid, "title": title, "severity": sev, "cwe": cwe, "owasp_llm": owasp,
         "file": rel, "line": line, "repo": repo, "evidence": evidence[:160], "remediation": remediation}
    if rid in AGENTIC:
        f["owasp_agentic"] = AGENTIC[rid]
    return f


# --------------------------------------------------------------------------- AI coding agents in the repository
# Instruction files that coding agents (Claude Code, Codex, Copilot, Cursor, Windsurf, Cline, Gemini, Junie, Amazon Q)
# read and follow automatically. Anyone who can change them can steer the agent.
AGENT_FILES = re.compile(r"(?i)(^|/)(AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules(/[^/]+)?|"
                         r"\.github/copilot-instructions\.md|\.github/instructions/[^/]+\.instructions\.md|"
                         r"\.cursor/rules/[^/]+\.mdc?|\.amazonq/rules/[^/]+\.md|\.junie/guidelines\.md)$")
HIDDEN_UNICODE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\U000e0000-\U000e007f]")
DANGEROUS_INSTRUCTION = re.compile(
    r"(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+instructions|do\s+not\s+(tell|inform|mention\s+(this\s+)?to)\s+(the\s+)?user|"
    r"without\s+(telling|informing|asking)\s+the\s+user|\b(curl|wget)\b[^|\n]*\|\s*(ba|z)?sh\b|"
    r"disable\s+(ssl|tls|certificate)\s+(verification|validation|checks?)|"
    r"(commit|push)\s+with\s+--no-verify|skip\s+(all\s+)?(security|pre-commit)\s+(checks?|hooks?|scans?)|"
    r"(send|upload|post|exfiltrate)\s+[^\n]{0,40}(secrets?|credentials|\.env\b|api\s+keys?|tokens?)\s+to\b)")
AGENT_CLI = re.compile(r"(anthropics/claude-code-action|openai/codex-action|google-github-actions/run-gemini-cli|"
                       r"\bclaude\s+(-p|--print)\b|\bcodex\s+exec\b|\bgemini\s+(-p|--prompt)\b|\baider\b\s+--(yes|message))")
SKIP_PERMS = re.compile(r"--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|"
                        r"bypassPermissions|--approval-mode[= ]yolo|--full-auto\b")
UNTRUSTED_EVENTS = re.compile(r"\b(issue_comment|issues|pull_request_target|discussion_comment|discussion|pull_request_review_comment)\b")


def _agent_settings(path, rel, repo):
    out = []
    try:
        raw = open(path, encoding="utf-8", errors="ignore").read()
        doc = json.loads(re.sub(r"(?m)^\s*//.*$", "", raw))
    except (OSError, ValueError):
        return out
    if not isinstance(doc, dict):
        return out
    lines = raw.splitlines()

    def at(token):
        return next((i for i, ln in enumerate(lines, 1) if token in ln), 1)
    perms = doc.get("permissions") if isinstance(doc.get("permissions"), dict) else {}
    allow = [str(a) for a in perms.get("allow") or []]
    hits = []
    if perms.get("defaultMode") == "bypassPermissions":
        hits.append(("defaultMode", "permissions.defaultMode: bypassPermissions"))
    for a in allow:
        if re.fullmatch(r"Bash(\((\*|:\*|\*:\*)?\))?", a):
            hits.append((a, f"permissions.allow: {a} (any shell command without asking)"))
    if doc.get("chat.tools.autoApprove") is True or doc.get("chat.tools.global.autoApprove") is True:
        hits.append(("autoApprove", "chat.tools.autoApprove: true (agent tools run without confirmation)"))
    if doc.get("autoAccept") is True:
        hits.append(("autoAccept", "autoAccept: true (agent tools run without confirmation)"))
    if doc.get("enableAllProjectMcpServers") is True:
        hits.append(("enableAllProjectMcpServers", "enableAllProjectMcpServers: true (every MCP server in the repo is trusted)"))
    for token, ev in hits:
        out.append(_finding("NM-AI-030", "Coding agent allowed to act without human approval", "high", "LLM06", "CWE-862",
                            rel, at(token), repo, ev,
                            "Commit only narrowly scoped allow rules (specific commands and paths) and keep approval prompts for "
                            "shell, network and file-write tools. A repository file that switches approvals off applies to everyone "
                            "who opens the project, including when a malicious issue or document steers the agent."))
    return out


def _agent_text(text, rel, repo):
    out = []
    for i, ln in enumerate(text.splitlines(), 1):
        m = HIDDEN_UNICODE.search(ln)
        if m:
            out.append(_finding("NM-AI-028", "Hidden Unicode characters in an AI agent instruction file", "critical", "LLM01", "CWE-1427",
                                rel, i, repo, f"U+{ord(m.group(0)):04X} at column {m.start() + 1}",
                                "Remove invisible and bidirectional control characters and review the decoded text: hidden "
                                "instructions in rule files ('rules file backdoor') make agents write backdoors that reviewers "
                                "cannot see. Block such characters in these files with a pre-commit check."))
            continue
        m = DANGEROUS_INSTRUCTION.search(ln)
        if m and re.search(r"(?i)\b(never|don't|do not|must not|should not|no)\b[^.!]{0,25}$", ln[:m.start()]):
            m = None                                       # a prohibition ("Never disable TLS verification") is the safe form
        if m:
            out.append(_finding("NM-AI-029", "AI agent instruction file tells the agent to bypass security or hide actions", "high",
                                "LLM01", "CWE-1427", rel, i, repo, m.group(0),
                                "Remove the instruction. Agent rule files are code: require review (CODEOWNERS) for changes and "
                                "never instruct agents to skip verification, hide actions or send data elsewhere."))
    return out


def _agent_in_ci(text, rel, repo):
    """An AI agent that reads issue / comment / PR text and runs with repository credentials."""
    m = AGENT_CLI.search(text)
    if not m:
        return []
    try:
        import yaml
        wf = yaml.safe_load(text) or {}
        on = wf.get(True, wf.get("on", {})) if isinstance(wf, dict) else {}
        triggers = set(on) if isinstance(on, (dict, list)) else {on}
    except Exception:  # noqa: BLE001 - unparsable workflow: fall back to the trigger line
        triggers = set(UNTRUSTED_EVENTS.findall(text))
    if not triggers & {"issue_comment", "issues", "pull_request_target", "discussion_comment", "discussion",
                       "pull_request_review_comment"}:
        return []
    line = text.count("\n", 0, m.start()) + 1
    skip = SKIP_PERMS.search(text)
    writes = re.search(r"(?m)^\s*(contents|pull-requests|issues|actions|packages)\s*:\s*write\b|permissions:\s*write-all", text)
    sev = "critical" if skip else "high"
    ev = m.group(0) + (f" · {skip.group(0)}" if skip else "") + (" · write permissions" if writes else "")
    return [{**_finding("NM-AI-031", "AI agent in CI acts on untrusted issue, comment or pull-request text", sev, "LLM01", "CWE-1427",
                     rel, line, repo, ev,
                     "Run the agent only for trusted actors (check author_association / a maintainer label), give the job "
                     "read-only permissions and no secrets beyond the model key, keep tool approvals on, and treat the issue or "
                     "comment text as untrusted input. Prompt injection in an issue title has been used to make agents push "
                     "malicious code and publish packages."), "exposure": "internet", "reachable": True}]


REMEDIATION = {
    "LLM01": "Keep instructions and untrusted input in separate messages, constrain the model with an allow-list of actions and treat its output as untrusted.",
    "LLM02": "Never send secrets or personal data to the model; redact before the call and keep prompt logs off in production.",
    "LLM03": "Pin model revisions, verify checksums, prefer safetensors and download over HTTPS from a trusted registry.",
    "LLM05": "Treat model output as untrusted input: validate against a schema, parameterise queries, escape HTML and never execute it.",
    "LLM06": "Give agents least-privilege tools, require human approval for side effects and sandbox any code execution.",
    "LLM07": "Keep secrets out of prompts; the system prompt can be extracted. Use server-side tools with their own authorisation.",
    "LLM08": "Require authentication on the vector store, disable reset in production and filter retrieval by tenant.",
    "LLM10": "Fix the model and endpoint server-side and set explicit token, rate and cost limits per user.",
}


def _scan_mcp(path, rel, repo):
    out = []
    try:
        raw = open(path, encoding="utf-8", errors="ignore").read()
        doc = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return out
    servers = doc.get("mcpServers") or doc.get("servers") or (doc.get("mcp") or {}).get("servers") or {}
    if not isinstance(servers, dict):
        return out
    lines = raw.splitlines()

    def line_of(token):
        for i, ln in enumerate(lines, 1):
            if token and token in ln:
                return i
        return 1
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command") or "")
        args = [str(a) for a in cfg.get("args") or []]
        pkgs = [a for a in args if not a.startswith("-")]
        if cmd.endswith(("npx", "npx.cmd", "bunx", "uvx", "pipx")) and pkgs:
            pkg = pkgs[0]
            pinned = re.search(r"@[\d^~]", pkg[1:]) if cmd.endswith(("npx", "npx.cmd", "bunx")) else ("==" in pkg or "@" in pkg)
            if not pinned:
                out.append(_finding("NM-AI-023", f"MCP server '{name}' runs an unpinned package ({pkg})", "high", "LLM03", "CWE-1104",
                                    rel, line_of(pkg), repo, f"{cmd} {' '.join(args)}",
                                    f"Pin an exact version (e.g. {pkg}@1.2.3) so a compromised release cannot run on every developer machine."))
        for k, v in (cfg.get("env") or {}).items():
            v = str(v)
            if SECRET_VALUE.match(v) and not REF_VALUE.match(v):
                out.append(_finding("NM-AI-024", f"Secret written into MCP server '{name}' configuration ({k})", "critical", "LLM02", "CWE-798",
                                    rel, line_of(v), repo, f"{k}=<redacted>",
                                    "Reference the secret from the environment or a secret manager (\"${" + k + "}\") and revoke the exposed value."))
        url = str(cfg.get("url") or cfg.get("serverUrl") or "")
        if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])", url):
            out.append(_finding("NM-AI-025", f"MCP server '{name}' reached over plain HTTP", "medium", "LLM02", "CWE-319",
                                rel, line_of(url), repo, url, "Use HTTPS with authentication for remote MCP servers."))
        if "filesystem" in " ".join([name] + args).lower() and any(a.rstrip("/\\") in {p.rstrip("/\\") for p in ROOT_PATHS} or a in ROOT_PATHS for a in args):
            out.append(_finding("NM-AI-026", f"MCP filesystem server '{name}' can read the whole disk or home directory", "high", "LLM06", "CWE-552",
                                rel, line_of(name), repo, " ".join(args), "Limit the server to the project directory it needs."))
        if SHELL_SERVERS.search(" ".join([name, cmd] + args)):
            out.append(_finding("NM-AI-027", f"MCP server '{name}' lets the model run shell commands", "high", "LLM06", "CWE-78",
                                rel, line_of(name), repo, f"{cmd} {' '.join(args)}",
                                "Remove it, or restrict it to an allow-list of commands with human approval for each call."))
    return out


def scan(root: str, repo: str = "local") -> list[dict]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root).replace("\\", "/")
            if fn in MCP_FILES or rel.endswith((".cursor/mcp.json", ".vscode/mcp.json")):
                out += _scan_mcp(p, rel, repo)
                continue
            if rel.endswith((".claude/settings.json", ".claude/settings.local.json", ".vscode/settings.json", ".gemini/settings.json")):
                out += _agent_settings(p, rel, repo)
                continue
            if AGENT_FILES.search(rel):
                try:
                    out += _agent_text(open(p, encoding="utf-8", errors="ignore").read(), rel, repo)
                except OSError:
                    pass
                continue
            if rel.startswith(".github/workflows/") and fn.endswith((".yml", ".yaml")):
                try:
                    out += _agent_in_ci(open(p, encoding="utf-8", errors="ignore").read(), rel, repo)
                except OSError:
                    pass
                continue
            if fn in ("package.json", "Makefile", "devcontainer.json") or fn.endswith((".sh", ".ps1")):
                try:
                    raw = open(p, encoding="utf-8", errors="ignore").read()
                except OSError:
                    raw = ""
                for i, ln in enumerate(raw.splitlines(), 1):
                    if ln.strip().startswith(("#", "//", "REM ")):
                        continue
                    m = SKIP_PERMS.search(ln)
                    if m and re.search(r"\b(claude|codex|gemini|cursor-agent|qwen|amp)\b", ln):
                        out.append(_finding("NM-AI-032", "Coding agent launched with approvals and sandbox disabled", "medium", "LLM06",
                                            "CWE-250", rel, i, repo, ln.strip(),
                                            "Run agents with approvals on, or inside an isolated container with no credentials and "
                                            "restricted network when unattended operation is required."))
                if not fn.endswith(CODE_EXT):
                    continue
            if not fn.endswith(CODE_EXT):
                continue
            try:
                lines = open(p, encoding="utf-8", errors="ignore").read().splitlines()
            except OSError:
                continue
            for i, ln in enumerate(lines, 1):
                s = ln.strip()
                if s.startswith(("#", "//", "*")):
                    continue
                for rid, title, sev, owasp, cwe, rx, exts in _COMPILED:
                    if fn.endswith(exts) and rx.search(ln):
                        f = _finding(rid, title, sev, owasp, cwe, rel, i, repo, s, REMEDIATION[owasp])
                        f["reachable"] = True              # first-party code, same treatment as SAST
                        out.append(f)
                        break
    return out
