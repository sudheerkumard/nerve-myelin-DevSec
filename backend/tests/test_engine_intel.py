# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Assessment-grade engines: live vulnerability data, transitive dependencies, licences, structural IaC, credentials."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))
from myelin_engine import iac_checks, orchestrator, sbom, secrets, suppress, vulndb  # noqa: E402

# --------------------------------------------------------------------------- fake OSV + PyPI
PYPI = {
    "/pypi/webkit/1.0.0/json": {"info": {"requires_dist": ["routerlib<2,>=1.4", "pytest ; extra == 'test'"], "license_expression": "MIT"}},
    "/pypi/routerlib/json": {"releases": {"1.4.0": [{"yanked": False}], "1.5.2": [{"yanked": False}], "1.6.0rc1": [{}], "2.0.0": [{}]}},
    "/pypi/routerlib/1.5.2/json": {"info": {"requires_dist": ["copyleftlib"], "classifiers": ["License :: OSI Approved :: BSD License"]}},
    "/pypi/copyleftlib/json": {"releases": {"3.1.0": [{"yanked": False}]}},
    "/pypi/copyleftlib/3.1.0/json": {"info": {"requires_dist": None, "license": "GPL-3.0-or-later"}},
}
OSV_VULNS = {
    "GHSA-aaaa-bbbb-cccc": {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1111"], "summary": "Path traversal in routerlib",
                            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                            "affected": [{"package": {"ecosystem": "PyPI", "name": "routerlib"},
                                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.5.3"}]}]}],
                            "database_specific": {"cwe_ids": ["CWE-22"]}},
}


class _Fake(BaseHTTPRequestHandler):
    def _send(self, obj, code=200):
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def do_GET(self):
        if self.path.startswith("/v1/vulns/"):
            v = OSV_VULNS.get(self.path.rsplit("/", 1)[1])
            return self._send(v or {}, 200 if v else 404)
        d = PYPI.get(self.path)
        return self._send(d or {}, 200 if d else 404)

    def do_POST(self):
        q = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["queries"]
        res = [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]} if x["package"]["name"] == "routerlib" and x["version"] == "1.5.2" else {}
               for x in q]
        self._send({"results": res})

    def log_message(self, *a):
        pass


@pytest.fixture()
def online(tmp_path, monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), _Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    monkeypatch.delenv("MYELIN_OFFLINE", raising=False)
    monkeypatch.setenv("MYELIN_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(vulndb, "OSV_URL", base)
    monkeypatch.setattr(vulndb, "PYPI_URL", base)
    yield base
    srv.shutdown()


def _repo(tmp_path, files):
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return str(tmp_path)


def test_transitive_dependencies_vulnerabilities_and_licences(online, tmp_path):
    root = _repo(tmp_path / "app", {"requirements.txt": "webkit==1.0.0\n", "app.py": "import webkit\n"})
    comps = sbom.inventory(root)
    by = {c["name"]: c for c in comps}
    assert by["routerlib"]["version"] == "1.5.2" and by["routerlib"]["via"] == "webkit"       # highest stable in range, not 2.0 / rc
    assert by["copyleftlib"]["scope"] == "transitive" and "pytest" not in by                 # extras-only deps are skipped
    assert by["webkit"]["license"] == "MIT" and by["routerlib"]["license"] == "BSD-3-Clause"
    fs = sbom.match_advisories(comps, "app", reachable_hint=({"webkit"}, set()))
    vuln = next(f for f in fs if f["engine"] == "sca")
    assert vuln["rule_id"] == "CVE-2026-1111" and vuln["cvss"] == 9.8 and vuln["severity"] == "critical"
    assert vuln["fixed_version"] == "1.5.3" and vuln["dependency_type"] == "transitive" and vuln["introduced_by"] == "webkit"
    assert vuln["reachable"] is True and vuln["cwe"] == "CWE-22"
    lic = next(f for f in fs if f["engine"] == "license")
    assert lic["rule_id"] == "NM-LIC-001" and lic["package"] == "copyleftlib"
    cdx = sbom.cyclonedx(comps, "app")
    assert {c["name"] for c in cdx["components"]} == {"webkit", "routerlib", "copyleftlib"}
    assert all(c["scope"] in ("required", "optional") for c in cdx["components"])


def test_pypi_fallback_when_osv_unreachable(online, monkeypatch, tmp_path):
    PYPI["/pypi/oldlib/1.0/json"] = {"info": {}, "vulnerabilities": [
        {"id": "PYSEC-2026-1", "aliases": ["CVE-2026-2222"], "details": "### Summary\n\nRemote code execution in **oldlib** parser.",
         "fixed_in": ["1.2", "1.1"], "withdrawn": None}]}
    monkeypatch.setattr(vulndb, "OSV_URL", "http://127.0.0.1:9")                              # closed port
    fs = sbom.match_advisories([vulndb._c("pypi", "oldlib", "1.0", "requirements.txt", "required")], "x")
    f = fs[0]
    assert f["rule_id"] == "CVE-2026-2222" and f["fixed_version"] == "1.1"
    assert f["title"] == "oldlib@1.0: Remote code execution in oldlib parser." and "severity not published" in f["evidence"]
    assert "PyPI advisory database" in vulndb.STATUS["sources"]


def test_offline_mode_uses_bundled_pack_only(tmp_path, monkeypatch):
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    root = _repo(tmp_path / "o", {"requirements.txt": "pyyaml==5.3\nflask>=2.0\n"})
    comps = sbom.inventory(root)
    assert [c["name"] for c in comps] == ["pyyaml"]                                         # unpinned: not resolvable offline
    assert any(f["rule_id"] == "CVE-2020-14343" for f in sbom.match_advisories(comps, "o"))


def test_cvss_and_licence_classification():
    assert vulndb._cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert vulndb._cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert vulndb._cvss3("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N") == 0.0
    k = sbom.licence_kind
    assert (k("GPL-3.0-only"), k("LGPL-2.1"), k("MIT OR GPL-2.0"), k("Apache-2.0"), k("unknown")) == ("strong", "weak", None, None, None)


def test_lockfiles_give_exact_transitive_versions(tmp_path, monkeypatch):
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    root = _repo(tmp_path / "js", {
        "package.json": json.dumps({"dependencies": {"express": "^4.18.0"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/express": {"version": "4.18.2"},
                                         "node_modules/semver": {"version": "7.5.1"}, "node_modules/jest": {"version": "29.0.0", "dev": True}}})})
    comps = sbom.inventory(root)
    got = {(c["name"], c["version"], c["scope"]) for c in comps}
    assert ("semver", "7.5.1", "transitive") in got and ("jest", "29.0.0", "dev") in got
    assert any(f["rule_id"] == "CVE-2022-25883" for f in sbom.match_advisories(comps, "js"))


# --------------------------------------------------------------------------- IaC
DOCKERFILE = """FROM python:latest AS build
RUN pip install --trusted-host pypi.org -r req.txt
FROM python:3.12-slim
ENV DB_PASSWORD=Sup3rS3cret!
ADD https://example.com/tool.tgz /opt/
RUN curl -fsSL https://get.example.com | sh
COPY --from=build /app /app
CMD ["python", "app.py"]
"""
COMPOSE = """services:
  api:
    image: acme/api:1.0
    privileged: true
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
    environment:
      DB_PASSWORD: hunter2hunter2
      API_TOKEN: ${API_TOKEN}
  db:
    image: postgres:16
    ports: ["5432:5432"]
  cache:
    image: redis:7
    ports: ["127.0.0.1:6379:6379"]
"""
K8S = """apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: web
          image: acme/web:latest
          securityContext: {privileged: true}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: hardened}
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 10001}
      containers:
        - name: app
          image: acme/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
          resources: {limits: {cpu: 500m, memory: 256Mi}}
"""


def test_structural_iac(tmp_path):
    root = _repo(tmp_path / "iac", {"Dockerfile": DOCKERFILE, "docker-compose.yml": COMPOSE, "k8s/app.yaml": K8S,
                                    "chart/templates/d.yaml": "kind: Deployment\nspec: {{ .Values.x }}\n"})
    fs = iac_checks.scan_path(root, "r")
    ids = {(f["rule_id"], f["file"]) for f in fs}
    for rid in ("NM-IAC-010", "NM-IAC-011", "NM-IAC-012", "NM-IAC-013", "NM-IAC-014", "NM-IAC-015", "NM-IAC-016"):
        assert (rid, "Dockerfile") in ids, rid
    for rid in ("NM-IAC-020", "NM-IAC-021", "NM-IAC-025", "NM-IAC-026"):
        assert (rid, "docker-compose.yml") in ids, rid
    assert sum(1 for f in fs if f["rule_id"] == "NM-IAC-026") == 1                         # ${API_TOKEN} is a reference
    assert sum(1 for f in fs if f["rule_id"] == "NM-IAC-025") == 1                         # 127.0.0.1-bound redis is fine
    web = {f["rule_id"] for f in fs if "Deployment/web " in f["title"]}
    assert {"NM-IAC-030", "NM-IAC-033", "NM-IAC-034", "NM-IAC-035", "NM-IAC-039"} <= web
    assert not [f for f in fs if "Deployment/hardened" in f["title"]]                      # a hardened workload is clean
    assert not [f for f in fs if "templates" in f["file"]]


def test_dockerfile_nonroot_is_clean():
    ok = "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nRUN useradd -u 10001 app\nUSER 10001\nHEALTHCHECK CMD true\n"
    assert iac_checks.dockerfile(ok, "Dockerfile", "r") == []


# --------------------------------------------------------------------------- credentials
@pytest.mark.parametrize("line,hit", [
    ("#    admin / Nerve@Admin#2026          (role: admin)", True),
    ("<tr><td><b>admin</b></td><td>Nerve@Admin#2026</td><td>full access</td></tr>", True),
    ("| `analyst` | `Nerve@Analyst#2026` | analyst |", True),
    ("default password: Winter#2026!", True),
    ("    password: pbkdf2_sha256$600000$GlGVyBW05PvGwxBeTQxGrw==$abc", False),
    ("host=PLC-01 user=operator dur=12s", False),
    ("contact: admin / ops@example.com", False),
    ("admin user list is cached", False),
])
def test_default_credentials(tmp_path, line, hit):
    root = _repo(tmp_path / "c", {"config/users.yaml": line + "\n"})
    assert bool([f for f in secrets.scan_path(root, "r") if f["rule_id"] == "NM-SEC-011"]) is hit


def test_credentials_in_tests_are_ignored(tmp_path):
    root = _repo(tmp_path / "t", {"tests/test_login.py": "# admin / Nerve@Admin#2026\n"})
    assert not [f for f in secrets.scan_path(root, "r") if f["rule_id"] == "NM-SEC-011"]


def test_full_scan_reports_intelligence_sources(tmp_path, monkeypatch):
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    res = orchestrator.scan(os.path.join(ROOT, "demo", "vulnerable-app"), "payments-web", use_external=False)
    assert res["intelligence"]["offline"] is True and res["intelligence"]["sources"] == ["bundled advisory pack"]
    engines = {f["engine"] for f in res["findings"]}
    assert {"sca", "sast", "secrets", "iac", "cicd"} <= engines


@pytest.mark.parametrize("code,hit", [
    ("""ov.insertAdjacentHTML("beforeend", '<button class="btn" onclick="go()">Go</button>');""", False),
    ("""el.insertAdjacentHTML('beforeend', '<b>' + name + '</b>');""", True),
    ("""document.write(location.hash);""", True),
    ("""node.outerHTML = '<i>x</i>';""", False),
])
def test_dom_sinks_only_flag_dynamic_html(tmp_path, code, hit):
    from myelin_engine import builtin_rules
    root = _repo(tmp_path / "js", {"app.js": code + "\n"})
    assert bool([f for f in builtin_rules.scan_path(root, "r") if f["rule_id"] == "NM-SAST-019"]) is hit


def test_paths_and_references_are_not_secrets():
    assert not iac_checks._literal_secret("VAULT_TOKEN_FILE", "/run/vault/api-token")
    assert not iac_checks._literal_secret("CLIENT_SECRET_REF", "vault://secret/x#y")
    assert not iac_checks._literal_secret("API_TOKEN", "${API_TOKEN}")
    assert iac_checks._literal_secret("DB_PASSWORD", "hunter2hunter2")





def test_inline_suppression_requires_rule_and_rationale_and_is_audited(tmp_path):
    root = _repo(tmp_path / "suppression", {
        "auth.py": """jwt.decode(token, options={"verify_signature": False})  # myelin:ignore[NM-SAST-009] -- issuer routing only
subprocess.run(cmd, shell=True)  # myelin:ignore[NM-SAST-003]
"""
    })
    findings = [
        {"id": "F1", "rule_id": "NM-SAST-009", "engine": "sast", "file": "auth.py", "line": 1, "severity": "critical"},
        {"id": "F2", "rule_id": "NM-SAST-003", "engine": "sast", "file": "auth.py", "line": 2, "severity": "high"},
    ]
    kept, ignored = suppress.apply(root, findings)
    assert ignored == 0
    assert kept[0]["status"] == "suppressed"
    assert kept[0]["suppression"]["reason"] == "issuer routing only"
    assert kept[1].get("status") != "suppressed"


def test_inline_suppression_without_reason_does_not_hide_finding(tmp_path):
    root = _repo(tmp_path / "no-reason", {
        "network.yaml": "cidr: 0.0.0.0/0 # myelin:ignore[NM-IAC-003]\n"
    })
    finding = {"id": "F1", "rule_id": "NM-IAC-003", "engine": "iac", "file": "network.yaml", "line": 1}
    kept, ignored = suppress.apply(root, [finding])
    assert ignored == 0
    assert len(kept) == 1 and kept[0].get("status") != "suppressed"


def test_inline_suppression_can_target_only_one_rule(tmp_path):
    root = _repo(tmp_path / "specific", {
        "auth.py": "# myelin:ignore[NM-SAST-009] -- issuer is used only for trusted IdP routing\n"
    })
    findings = [
        {"id": "F1", "rule_id": "NM-SAST-009", "file": "auth.py", "line": 1},
        {"id": "F2", "rule_id": "NM-SAST-003", "file": "auth.py", "line": 1},
    ]
    kept, _ = suppress.apply(root, findings)
    assert kept[0]["status"] == "suppressed"
    assert kept[1].get("status") != "suppressed"


def test_cyclonedx_contains_dependency_graph_and_manifest_evidence(tmp_path):
    comps = [
        {"ecosystem": "pypi", "name": "rootlib", "version": "1.0", "purl": "pkg:pypi/rootlib@1.0",
         "scope": "required", "license": "MIT", "file": "requirements.txt"},
        {"ecosystem": "pypi", "name": "transitive", "version": "2.0", "purl": "pkg:pypi/transitive@2.0",
         "scope": "required", "license": "BSD-3-Clause", "file": "requirements.txt", "via": "rootlib"},
    ]
    bom = sbom.cyclonedx(comps, "payments-service")
    app = bom["metadata"]["component"]["bom-ref"]
    deps = {item["ref"]: item["dependsOn"] for item in bom["dependencies"]}
    assert deps[app] == ["pkg:pypi/rootlib@1.0"]
    assert deps["pkg:pypi/rootlib@1.0"] == ["pkg:pypi/transitive@2.0"]
    assert deps["pkg:pypi/transitive@2.0"] == []
    transitive = next(c for c in bom["components"] if c["name"] == "transitive")
    assert transitive["bom-ref"] == transitive["purl"]
    assert {"name": "myelin:manifest", "value": "requirements.txt"} in transitive["properties"]
    assert {"name": "myelin:introduced-by", "value": "rootlib"} in transitive["properties"]
