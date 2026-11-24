# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""NERvvE DevSecOps MCP server: security scanning tools for AI coding assistants (Model Context Protocol, stdio).

    myelin mcp                       # register in Claude Code, Cursor, VS Code / Copilot, Windsurf, Cline …

Tools
  scan_path      scan a folder with the built-in engines and return prioritised findings
  scan_snippet   check a code or configuration snippet before the assistant writes it to disk
  check_package  is a dependency name a known malicious release, a look-alike of a popular package, or unpublished?
  explain_rule   what a NERvvE DevSecOps rule detects and how to fix it
  gate           pass / warn / block decision for a folder under the default (or a given) policy

The server only reads files under the folders it is asked to scan, never sends source code anywhere, and works offline.
Messages are JSON-RPC 2.0, one per line, as defined by the MCP stdio transport.
"""
import json
import os
import sys
import tempfile

from . import __version__, orchestrator, policy, supply_chain

PROTOCOL = "2025-06-18"
TOOLS = [
    {"name": "scan_path", "description": "Scan a local folder for vulnerabilities, secrets, insecure configuration, pipeline and "
     "supply-chain risks. Returns the highest-priority findings first.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "limit": {"type": "integer", "default": 25}},
                     "required": ["path"]}},
    {"name": "scan_snippet", "description": "Check a code or configuration snippet (with its intended file name) before writing it.",
     "inputSchema": {"type": "object", "properties": {"filename": {"type": "string"}, "content": {"type": "string"}},
                     "required": ["filename", "content"]}},
    {"name": "check_package", "description": "Check a dependency before adding it: known malicious release, possible typosquat "
     "of a popular package.", "inputSchema": {"type": "object", "properties": {
         "ecosystem": {"type": "string", "enum": ["npm", "pypi"]}, "name": {"type": "string"}, "version": {"type": "string"}},
         "required": ["ecosystem", "name"]}},
    {"name": "explain_rule", "description": "Explain a NERvvE DevSecOps rule id (e.g. NM-CICD-013) and how to fix it.",
     "inputSchema": {"type": "object", "properties": {"rule_id": {"type": "string"}}, "required": ["rule_id"]}},
    {"name": "gate", "description": "Policy decision (pass / warn / block) for a folder.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "policy": {"type": "string"}}, "required": ["path"]}},
]


def _brief(f):
    return {k: f.get(k) for k in ("priority", "severity", "rule_id", "title", "file", "line", "package", "version", "fixed_version",
                                  "cve", "remediation") if f.get(k) is not None}


def _allowed(path: str) -> str:
    p = os.path.realpath(os.path.expanduser(path))
    roots = [os.path.realpath(r) for r in os.environ.get("MYELIN_MCP_ROOTS", os.getcwd()).split(os.pathsep) if r]
    if not any(p == r or p.startswith(r + os.sep) for r in roots):
        raise ValueError(f"{path} is outside the allowed folders ({', '.join(roots)}); set MYELIN_MCP_ROOTS to widen")
    if not os.path.isdir(p):
        raise ValueError(f"{path} is not a folder")
    return p


def _rules():
    from . import ai_security, builtin_rules, cd_posture, cicd_posture, secrets
    out = {}
    for rid, title, sev, owasp, fix in ((k, *v) for k, v in cicd_posture.RULES.items()):
        out[rid] = {"title": title, "severity": sev, "framework": owasp, "fix": fix}
    for rid, (title, sev, cwe) in supply_chain.RULES.items():
        out[rid] = {"title": title, "severity": sev, "cwe": cwe, "fix": supply_chain.REMEDIATION[rid]}
    for r in ai_security.RULES:
        out[r[0]] = {"title": r[1], "severity": r[2], "owasp_llm": r[3], "cwe": r[4], "fix": ai_security.REMEDIATION.get(r[3], "")}
    for r in builtin_rules.SAST:
        out[r[0]] = {"title": r[2], "severity": r[3], "cwe": r[4]}
    for rid, title, _rx, sev in secrets.PATTERNS:
        out[rid] = {"title": title, "severity": sev, "fix": "Revoke and rotate the credential and move it to a secrets manager."}
    for rid, v in getattr(cd_posture, "RULES", {}).items():
        out[rid] = {"title": v[0], "severity": v[1], "framework": v[2]}
    return out


def call(name: str, args: dict) -> dict:
    os.environ.setdefault("MYELIN_OFFLINE", "1")
    if name == "scan_path":
        res = orchestrator.scan(_allowed(args["path"]), repo=os.path.basename(args["path"].rstrip("/")) or "local", use_external=False)
        fs = [f for f in res["findings"] if f.get("engine") != "meta"]
        return {"findings": [_brief(f) for f in fs[: int(args.get("limit") or 25)]], "total": len(fs),
                "by_priority": {p: sum(f["priority"] == p for f in fs) for p in ("P0", "P1", "P2", "P3")}}
    if name == "scan_snippet":
        fn = os.path.normpath(args["filename"]).lstrip(os.sep)
        if fn.startswith(".."):
            raise ValueError("filename must be relative")
        with tempfile.TemporaryDirectory(prefix="myelin-mcp-") as d:
            p = os.path.join(d, fn)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(str(args["content"])[:500_000])
            res = orchestrator.scan(d, repo="snippet", use_external=False)
        fs = [f for f in res["findings"] if f.get("engine") != "meta"]
        return {"findings": [_brief(f) for f in fs], "clean": not fs}
    if name == "check_package":
        eco, pkg, ver = args["ecosystem"], args["name"], str(args.get("version") or "")
        mal = supply_chain.MALICIOUS_VERSIONS.get((eco, supply_chain._canon(eco, pkg), ver)) or \
            supply_chain.MALICIOUS_VERSIONS.get((eco, supply_chain._canon(eco, pkg), "*"))
        look = supply_chain.typosquat_target(eco, pkg)
        verdict = "block" if mal else "review" if look else "no known issue"
        return {"verdict": verdict, "malicious": mal, "lookalike_of": look,
                "note": "Also confirm the package exists on the registry and has an established history before installing."}
    if name == "explain_rule":
        r = _rules().get(str(args["rule_id"]).upper())
        if not r:
            raise ValueError(f"unknown rule {args['rule_id']}")
        return {"rule_id": str(args["rule_id"]).upper(), **r}
    if name == "gate":
        res = orchestrator.scan(_allowed(args["path"]), repo="local", use_external=False)
        pol = policy.load(args["policy"]) if args.get("policy") else policy.DEFAULT_POLICY
        d = policy.evaluate([f for f in res["findings"] if f.get("engine") != "meta"], pol)
        return {"decision": d["decision"], "blocking": d.get("blocking", 0), "warnings": d.get("warnings", 0)}
    raise ValueError(f"unknown tool {name}")


def handle(msg: dict):
    mid, method = msg.get("id"), msg.get("method")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": PROTOCOL, "capabilities": {"tools": {"listChanged": False}},
                                                         "serverInfo": {"name": "nerve-myelin", "version": __version__}}}
    if method in ("notifications/initialized", "notifications/cancelled") or mid is None:
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        p = msg.get("params") or {}
        try:
            out = call(p.get("name"), p.get("arguments") or {})
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": json.dumps(out, indent=1)}],
                                                             "structuredContent": out, "isError": False}}
        except Exception as e:  # noqa: BLE001 - a tool error is reported to the client, the server keeps running
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}


def serve(stdin=sys.stdin, stdout=sys.stdout):
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}) + "\n")
            stdout.flush()
            continue
        resp = handle(msg)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
    return 0
