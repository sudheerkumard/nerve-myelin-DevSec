# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Supply-chain defence, SSVC, repository posture, cryptography inventory and AI coding-agent rules (engine level)."""
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))
from myelin_engine import ai_security, crypto_inventory, repo_posture, sbom, supply_chain, vulndb  # noqa: E402
from myelin_engine.scoring import enrich, ssvc  # noqa: E402


def _write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(text)


def test_typosquat_detection_is_conservative():
    t = supply_chain.typosquat_target
    assert t("npm", "expresss") == "express" and t("npm", "axois") == "axios" and t("pypi", "requets") == "requests"
    assert t("npm", "reactdom") == "react-dom"                       # separator games
    for legit in [("npm", "preact"), ("npm", "lodash"), ("npm", "@types/node"), ("pypi", "python_dateutil"), ("pypi", "scapy"),
                  ("pypi", "attr"), ("npm", "tslint"), ("npm", "my-company-ui"), ("pypi", "boto3")]:
        assert t(*legit) is None, legit


def test_cooldown_lockfile_and_install_scripts(tmp_path):
    root = str(tmp_path)
    _write(root, "web/package.json", json.dumps({"dependencies": {"lodash": "4.17.21"}}))
    _write(root, "packages/ui/package.json", json.dumps({"dependencies": {"preact": "10.0.0"}}))
    _write(root, "package-lock.json", json.dumps({"packages": {"": {}, "node_modules/esbuild": {"version": "1", "hasInstallScript": True},
                                                              "node_modules/odd-native": {"version": "1", "hasInstallScript": True}}}))
    fs = supply_chain.scan(root, "r", [], online=False)
    rules = sorted((f["rule_id"], f["file"]) for f in fs)
    assert ("NM-SUP-008", "web/package.json") in rules or ("NM-SUP-008", "packages/ui/package.json") in rules
    assert ("NM-SUP-005", "web/package.json") not in rules            # a lockfile in a parent folder covers workspaces
    inst = next(f for f in fs if f["rule_id"] == "NM-SUP-007")
    assert inst["packages"] == ["odd-native"]                         # well-known native builds are allow-listed
    _write(root, ".npmrc", "min-release-age=3\n")
    assert not [f for f in supply_chain.scan(root, "r", [], online=False) if f["rule_id"] == "NM-SUP-008"]


def test_malicious_release_from_indicator_pack_and_osv(monkeypatch):
    comps = [{"ecosystem": "npm", "name": "debug", "version": "4.4.2", "file": "package-lock.json", "purl": "pkg:npm/debug@4.4.2"},
             {"ecosystem": "npm", "name": "debug", "version": "4.4.1", "file": "package-lock.json", "purl": "pkg:npm/debug@4.4.1"}]
    fs = supply_chain.scan("/nonexistent", "r", comps, online=False)
    mal = [f for f in fs if f["rule_id"] == "NM-SUP-001"]
    assert len(mal) == 1 and mal[0]["version"] == "4.4.2" and mal[0]["malicious"] is True
    enrich(mal[0])
    assert mal[0]["priority"] == "P0" and mal[0]["ssvc"]["decision"] in ("Act", "Attend") and mal[0]["ssvc"]["exploitation"] == "active"
    # an OSV malicious-package (MAL-) advisory becomes a supply-chain finding, not a CVE row
    monkeypatch.setattr(vulndb, "vulnerabilities", lambda cs: [(cs[0], {"id": "MAL-2026-1234", "cve": None, "aliases": [], "cvss": None,
                                                                      "severity": "medium", "severity_known": False,
                                                                      "summary": "Malicious code in evil-pkg", "fixed": None, "cwe": None})])
    out = sbom.match_advisories([{"ecosystem": "npm", "name": "evil-pkg", "version": "1.0.0", "file": "package.json",
                                  "purl": "pkg:npm/evil-pkg@1.0.0", "license": "unknown"}])
    assert out[0]["engine"] == "supply" and out[0]["rule_id"] == "NM-SUP-001" and out[0]["advisory"] == "MAL-2026-1234"


def test_hallucinated_dependency_only_when_registry_says_not_found(monkeypatch, tmp_path):
    seen = []

    def fake(url, ttl=0):
        seen.append(url)
        return None if "ghost-helper" in url else {"name": "ok"}
    monkeypatch.setattr(vulndb, "_http_json", fake)
    comps = [{"ecosystem": "npm", "name": "ghost-helper", "version": "1.0.0", "scope": "required", "file": "package.json"},
             {"ecosystem": "npm", "name": "lodash", "version": "4.17.21", "scope": "required", "file": "package.json"}]
    fs = supply_chain.scan(str(tmp_path), "r", comps, online=True)
    assert [f["package"] for f in fs if f["rule_id"] == "NM-SUP-003"] == ["ghost-helper"]
    _write(str(tmp_path), ".npmrc", "registry=https://npm.acme.internal/\n")        # private registry: no claim
    assert not [f for f in supply_chain.scan(str(tmp_path), "r", comps, online=True) if f["rule_id"] == "NM-SUP-003"]


def test_ssvc_follows_the_cisa_tree():
    base = {"engine": "sca", "severity": "critical", "cwe": "CWE-502", "exposure": "internet", "reachable": True}
    assert ssvc({**base, "kev": True}, 1.4)["decision"] == "Act"
    assert ssvc({**base, "kev": True, "exposure": "internal"}, 1.0)["decision"] == "Attend"
    assert ssvc({**base, "epss": 0.3}, 1.4)["decision"] == "Attend"
    assert ssvc({**base, "epss": 0.3, "severity": "medium", "cwe": "CWE-79"}, 1.0)["decision"] == "Track"
    assert ssvc({**base}, 1.4)["decision"] == "Attend"                 # none / automatable / total / high
    assert ssvc({"engine": "sast", "severity": "low"}, 0.6) == {"decision": "Track", "exploitation": "none", "automatable": "no",
                                                                "technical_impact": "partial", "mission_wellbeing": "low"}


def test_crypto_inventory_and_cbom(tmp_path):
    root = str(tmp_path)
    _write(root, "app/keys.py", "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(65537, 2048)\n"
                                "import hashlib\nh = hashlib.md5(b'x')\n# hashlib.sha1 in a comment is ignored\nAESGCM(key)\n")
    _write(root, "app/pq.go", "kem := mlkem.GenerateKey768()  // ML-KEM\nhybrid := \"X25519MLKEM768\"\n")
    _write(root, "tests/test_x.py", "hashlib.md5()\n")                                   # test code is not inventoried
    inv = {a["algorithm"]: a for a in crypto_inventory.scan(root)}
    assert inv["RSA"]["classification"] == "quantum-vulnerable" and inv["MD5"]["classification"] == "broken"
    assert inv["AES-GCM"]["classification"] == "quantum-safe" and inv["ML-KEM"]["count"] == 2 and inv["MD5"]["count"] == 1
    rd = crypto_inventory.readiness(list(inv.values()))
    assert rd["status"] == "action" and rd["pqc_share"] == 67
    doc = crypto_inventory.cbom(list(inv.values()), "svc")
    assert doc["specVersion"] == "1.6" and all(c["type"] == "cryptographic-asset" for c in doc["components"])


def test_repository_posture_and_osps_mapping(tmp_path):
    root = str(tmp_path)
    _write(root, "SECURITY.md", "Report vulnerabilities privately to security@acme.example. We reply within 3 business days.\n")
    _write(root, "LICENSE", "MIT License\n")
    _write(root, ".github/CODEOWNERS", "* @acme/platform\n")
    _write(root, ".github/dependabot.yml", "version: 2\n")
    _write(root, ".github/workflows/ci.yml", "permissions: {contents: read}\njobs:\n  t:\n    steps:\n      - run: pytest\n      - run: myelin scan .\n")
    _write(root, "requirements.txt", "flask==3.0.0\n")
    _write(root, "tool.exe", "MZ")
    p = repo_posture.assess(root, [], {"branch_protection": True})
    ch = {c["id"]: c for c in p["checks"]}
    assert ch["security-policy"]["status"] == "pass" and set(ch["security-policy"]["osps"]) == {"OSPS-VM-02.01", "OSPS-VM-03.01", "OSPS-VM-01.01"}
    assert ch["code-review"]["status"] == "pass" and ch["binary-artifacts"]["status"] == "partial"
    assert ch["ci-tests"]["status"] == "pass" and ch["security-scanning"]["status"] == "pass" and ch["dependency-cooldown"]["status"] == "n/a"
    st = {c["id"]: c["status"] for c in p["osps"]["controls"]}
    assert st["OSPS-VM-02.01"] == "met" and st["OSPS-QA-05.01"] == "not_met" and st["OSPS-AC-01.01"] == "attestation"
    assert p["score"] > 5 and p["grade"] in "ABC"
    worse = repo_posture.assess(root, [{"engine": "secrets", "rule_id": "NM-SEC-002", "status": "open"},
                                       {"engine": "cicd", "rule_id": "NM-CICD-003", "status": "open"}], {"branch_protection": True})
    assert worse["score"] < p["score"]


def test_ai_agent_rules(tmp_path):
    root = str(tmp_path)
    _write(root, "CLAUDE.md", "Never disable TLS verification.\nDo not commit secrets.\nUse tabs.\u200b\n")
    _write(root, ".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash(npm test:*)", "Read(./**)"]}}))
    _write(root, ".vscode/settings.json", json.dumps({"chat.tools.autoApprove": True}))
    _write(root, ".github/workflows/bot.yml", "on:\n  issues:\n    types: [opened]\npermissions:\n  issues: write\njobs:\n  a:\n"
                                              "    steps:\n      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567\n")
    _write(root, ".github/workflows/ok.yml", "on: push\npermissions:\n  issues: write\njobs:\n  a:\n    steps:\n      - run: claude -p 'review'\n")
    fs = ai_security.scan(root, "r")
    got = sorted((f["rule_id"], f["file"], f["line"]) for f in fs)
    assert got == [("NM-AI-028", "CLAUDE.md", 3), ("NM-AI-030", ".vscode/settings.json", 1),
                   ("NM-AI-031", ".github/workflows/bot.yml", 9)], got
    assert next(f for f in fs if f["rule_id"] == "NM-AI-031")["owasp_agentic"] == "ASI01"
