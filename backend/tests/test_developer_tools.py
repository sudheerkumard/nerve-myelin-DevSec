# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""MCP server for AI coding assistants and the git pre-commit hook."""
import io
import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))
from myelin_engine import mcp_server  # noqa: E402

SAMPLE = os.path.join(ROOT, "demo", "vulnerable-app")


def _rpc(lines, monkeypatch):
    monkeypatch.setenv("MYELIN_MCP_ROOTS", ROOT)
    out = io.StringIO()
    mcp_server.serve(io.StringIO("\n".join(json.dumps(x) for x in lines) + "\n"), out)
    return [json.loads(x) for x in out.getvalue().splitlines()]


def test_mcp_handshake_tools_and_errors(monkeypatch):
    r = _rpc([{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
              {"jsonrpc": "2.0", "method": "notifications/initialized"},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
              {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "scan_path", "arguments": {"path": SAMPLE, "limit": 5}}},
              {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "check_package", "arguments": {"ecosystem": "npm", "name": "axois"}}},
              {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "scan_snippet", "arguments": {"filename": ".github/workflows/x.yml",
               "content": "on: push\njobs:\n  a:\n    steps:\n      - run: echo ${{ toJSON(secrets) }}\n"}}},
              {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "scan_path", "arguments": {"path": "/"}}},
              {"jsonrpc": "2.0", "id": 7, "method": "nope"}], monkeypatch)
    assert len(r) == 7                                              # the notification gets no response
    assert r[0]["result"]["serverInfo"]["name"] == "nerve-myelin" and "tools" in r[0]["result"]["capabilities"]
    assert {t["name"] for t in r[1]["result"]["tools"]} == {"scan_path", "scan_snippet", "check_package", "explain_rule", "gate"}
    scan = r[2]["result"]["structuredContent"]
    assert scan["total"] > 20 and len(scan["findings"]) == 5 and scan["findings"][0]["priority"] in ("P0", "P1")
    assert r[3]["result"]["structuredContent"] == {"verdict": "review", "malicious": None, "lookalike_of": "axios",
                                                    "note": r[3]["result"]["structuredContent"]["note"]}
    assert any(f["rule_id"] == "NM-CICD-013" for f in r[4]["result"]["structuredContent"]["findings"])
    assert r[5]["result"]["isError"] is True and "outside the allowed folders" in r[5]["result"]["content"][0]["text"]
    assert r[6]["error"]["code"] == -32601


def test_precommit_blocks_staged_secret(tmp_path):
    env = {**os.environ, "PYTHONPATH": os.path.join(ROOT, "engine"), "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x"}
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "ok.py").write_text("print('hello')\n")
    subprocess.run(["git", "add", "ok.py"], cwd=tmp_path, check=True)
    ok = subprocess.run([sys.executable, "-m", "myelin_engine.cli", "precommit"], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    (tmp_path / "ok.py").write_text("token = 'ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'\n")   # staged version is what counts
    subprocess.run(["git", "add", "ok.py"], cwd=tmp_path, check=True)
    bad = subprocess.run([sys.executable, "-m", "myelin_engine.cli", "precommit"], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert bad.returncode == 1 and "NM-SEC-002" in bad.stdout and "BLOCK" in bad.stdout
