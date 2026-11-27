#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Bake a demo snapshot into console/index.html so the console also runs without the API (offline demos, artifact hosting)."""
import json, os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))
from fastapi.testclient import TestClient
from app.main import app, CONTROLS

c = TestClient(app)
H = {"X-API-Key": "nm_demo_9f2c41e7b8"}
eps = ["/api/summary", "/api/repos", "/api/plans", "/api/tenant", "/api/sbom/payments-web", "/api/pipelines", "/api/posture/cicd",
       "/api/supply-chain", "/api/supply-chain/graph", "/api/v1/intelligence/vulnerabilities", "/api/v1/remediation/campaigns", "/api/v1/ai/briefing", "/api/v1/ai/status", "/api/compliance", "/api/policies", "/api/audit", "/api/integrations",
       "/api/v1/supply-chain/defence", "/api/v1/posture", "/api/v1/pqc", "/api/v1/cra", "/api/v1/cnapp", "/api/v1/cloud/identities"]
# recorded live-application assessment of the fictional demo API (shown on the "Live app testing" page offline)
sys.path.insert(0, os.path.join(ROOT, "backend"))
from tests.vapi import IDENTITIES, start as start_vapi
_srv, _ = start_vapi(8091)
t = c.post("/api/v1/dast/targets", headers=H, json={"name": "orion-payments-api", "base_url": "http://127.0.0.1:8091",
           "spec_url": "http://127.0.0.1:8091/openapi.json", "identities": IDENTITIES, "criticality": "high",
           "privileged": [{"path": "/api/v2/admin/*", "roles": ["admin"]}]}).json()
c.post(f"/api/v1/dast/targets/{t['id']}/run?wait=true", headers=H)
_srv.should_exit = True
dast_targets = c.get("/api/v1/dast/targets", headers=H).json()
for d in dast_targets:
    d["base_url"] = "https://api.orion-payments.example"            # present the recording with a production-style URL
dast_report = c.get(f"/api/v1/dast/targets/{t['id']}/report", headers=H).text.replace("http://127.0.0.1:8091", "https://api.orion-payments.example")
snap = {"api": {e: c.get(e).json() for e in eps}, "dast": {"targets": dast_targets, "report": dast_report}}
snap["api"]["/api/v1/runtime/events"] = c.get("/api/v1/runtime/events?hours=168", headers=H).json()
for _r in snap["api"]["/api/v1/posture"]["repos"]:                       # per-repository detail pages
    snap["api"][f"/api/v1/posture/{_r['repo']}"] = c.get(f"/api/v1/posture/{_r['repo']}", headers=H).json()
for _r in snap["api"]["/api/v1/pqc"]["repos"][:12]:
    snap["api"][f"/api/v1/cbom/{_r['repo']}"] = c.get(f"/api/v1/cbom/{_r['repo']}", headers=H).json()
keep = ("id","engine","rule_id","cve","title","severity","priority","mrs","sla_days","cvss","epss","kev","reachable","exposure","validated",
        "package","version","fixed_version","dependency_type","file","line","repo","business_unit","status","age_days","first_seen","assignee",
        "cwe","owasp_cicd","owasp_llm","owasp_agentic","remediation","evidence","autofix","license","ssvc","malicious","lookalike_of","code_url","validation","high_confidence",
        "category","cis","resource","source","path","linked_repos","provider","account","namespace","workload","image","tactics","techniques","event_count","last_event","principal")
from myelin_engine import frameworks as _FW
slim = lambda f: {**{k: f[k] for k in keep if f.get(k) is not None}, "frameworks": _FW.short(f)}
items, off = [], 0
while True:                                            # API pages at 1000 per request
    page = c.get("/api/findings", params={"status": "all", "limit": 1000, "offset": off}).json()
    items += page["items"]; off += 1000
    if off >= page["total"]:
        break
snap["findings"] = [slim(f) for f in items]
live = c.post("/api/scans/live", json={}, headers=H).json()
live["findings"] = [slim(f) for f in live["findings"]]
snap["live"] = live
# AI assistant answers for the offline demo: top findings and the suggested questions
_top = sorted([f for f in items if f.get("status") == "open"], key=lambda f: -(f.get("mrs") or 0))[:120]
snap["ai"] = {"explain": {f["id"]: c.post(f"/api/findings/{f['id']}/explain", headers=H).json() for f in _top},
              "triage": {f["id"]: c.post(f"/api/v1/ai/triage/{f['id']}", headers=H).json() for f in _top},
              "asks": []}
for q in ("Known exploited dependency vulnerabilities", "Critical secrets", "P0 findings past their SLA",
          "AI and LLM findings", "Reachable critical CVEs", "Pipeline findings older than 30 days", "Supply-chain attacks"):
    a = c.post("/api/v1/ai/ask", headers=H, json={"question": q}).json()
    a["findings"] = [slim(f) for f in a["findings"][:15]]
    snap["ai"]["asks"].append(a)
snap["controls"] = [{"framework": fw, "control": cid, "engines": sorted(e)} for fw, cid, _, e in CONTROLS]
# AutoFix results computed from the sample repository's real files (payments-web is a real scan of demo/vulnerable-app)
snap["autofix"] = {}
for f in items:
    if f.get("repo") == "payments-web" and f.get("status") == "open" and f.get("engine") in ("sca", "sast", "cicd", "supply"):
        r = c.post(f"/api/findings/{f['id']}/autofix", headers=H)
        if r.status_code == 200:
            snap["autofix"][f["id"]] = r.json()
tpl = open(os.path.join(ROOT, "console", "console.template.html")).read()
cfg = json.load(open(os.path.join(ROOT, "config", "frontend", "console.config.json")))
sample_out = tpl.replace("/*__SNAPSHOT__*/null", json.dumps(snap, separators=(",", ":")).replace("</", "<\\/"))
sample_out = sample_out.replace("/*__CONFIG__*/null", json.dumps(cfg, separators=(",", ":")).replace("</", "<\\/"))
os.makedirs(os.path.join(ROOT, "demo", "offline"), exist_ok=True)
offline_path = os.path.join(ROOT, "demo", "offline", "RAT-Flea-DevSec-Demo-Console.html")
open(offline_path, "w", encoding="utf-8").write(sample_out)

# Production console contains no embedded tenant fixture and no demo API key.
enterprise_cfg = dict(cfg)
enterprise_cfg["api"] = {**cfg.get("api", {}), "demoApiKey": ""}
# Customer/demo identity belongs only in the offline snapshot, never the enterprise console.
enterprise_cfg["defaultCustomer"] = {}
enterprise_out = tpl.replace("/*__SNAPSHOT__*/null", "null")
enterprise_out = enterprise_out.replace("/*__CONFIG__*/null", json.dumps(enterprise_cfg, separators=(",", ":")).replace("</", "<\\/"))
open(os.path.join(ROOT, "console", "index.html"), "w", encoding="utf-8").write(enterprise_out)
print(f"enterprise console written ({len(enterprise_out)//1024} KB, no sample data); offline demo written ({len(snap['findings'])} sample findings)")
