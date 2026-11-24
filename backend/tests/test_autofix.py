# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""AutoFix: patches come from the real file content; pull requests go through each provider's API."""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import autofix as AF, scm  # noqa: E402

FILES = {
    "requirements.txt": "django==4.2.7\nrequests==2.31.0  # http\n",
    "package.json": '{\n  "dependencies": { "lodash": "^4.17.15", "axios": "1.4.0" }\n}\n',
    "src/app.py": "import requests, yaml\nr = requests.get(u, verify=False)\ncfg = yaml.load(open('c.yml'))\n",
    ".github/workflows/ci.yml": "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci\n        env:\n          NODE_AUTH_TOKEN: x\n",
}


def read(p):
    return FILES.get(p)


def test_dependency_upgrades_edit_the_manifest():
    r = AF.propose({"engine": "sca", "package": "django", "version": "4.2.7", "fixed_version": "4.2.15", "file": "requirements.txt"}, read)
    assert r["changes"][0]["after"].startswith("django==4.2.15\n") and "+django==4.2.15" in r["diff"]
    lock = AF.propose({"engine": "sca", "package": "lodash", "version": "4.17.15", "fixed_version": "4.17.21",
                       "file": "package-lock.json", "cve": "CVE-2021-23337"}, read)
    assert lock["changes"][0]["path"] == "package.json" and '"lodash": "^4.17.21"' in lock["changes"][0]["after"]
    assert "Regenerate the lockfile" in lock["explanation"] and "CVE-2021-23337" in lock["title"]
    none = AF.propose({"engine": "sca", "package": "left-pad", "version": "1.0.0", "fixed_version": "1.3.0", "file": "package.json",
                       "remediation": "upgrade"}, read)
    assert none["changes"] == [] and none["guidance"] == "upgrade"


def test_code_and_pipeline_fixes_change_only_the_reported_line():
    tls = AF.propose({"engine": "sast", "rule_id": "NM-SAST-004", "file": "src/app.py", "line": 2}, read)
    assert "r = requests.get(u)\n" in tls["changes"][0]["after"]
    y = AF.propose({"engine": "sast", "rule_id": "NM-SAST-006", "file": "src/app.py", "line": 3}, read)
    assert "yaml.safe_load(open('c.yml'))" in y["changes"][0]["after"]
    wrong = AF.propose({"engine": "sast", "rule_id": "NM-SAST-004", "file": "src/app.py", "line": 1}, read)
    assert wrong["changes"] == []                                   # the pattern is not on the reported line
    perm = AF.propose({"engine": "cicd", "rule_id": "NM-CICD-004", "file": ".github/workflows/ci.yml", "line": 1}, read)
    assert "permissions:\n  contents: read\n\njobs:" in perm["changes"][0]["after"]
    pin = AF.propose({"engine": "cicd", "rule_id": "NM-CICD-001", "file": ".github/workflows/ci.yml", "line": 5}, read,
                     lambda action, ref: "b4ffde65f46336ab88eb53be808477a3936bae11")
    assert "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4" in pin["changes"][0]["after"]
    ign = AF.propose({"engine": "cicd", "rule_id": "NM-CICD-015", "file": ".github/workflows/ci.yml", "line": 6}, read)
    assert "npm ci --ignore-scripts" in ign["changes"][0]["after"]
    cool = AF.propose({"engine": "supply", "rule_id": "NM-SUP-008", "file": "package.json"}, read)
    assert cool["changes"][0] == {"path": ".npmrc", "before": "", "after": "min-release-age=3\n"}


def _recorder(responses):
    calls = []

    def t(method, url, headers, body):
        calls.append((method, url, headers, json.loads(body) if body else None))
        for (m, frag), resp in responses.items():
            if m == method and frag in url:
                return resp
        return 404, None
    return t, calls


def test_github_pull_request(monkeypatch):
    t, calls = _recorder({("GET", "/git/ref/heads/main"): (200, {"object": {"sha": "abc"}}), ("POST", "/git/refs"): (201, {}),
                          ("GET", "/contents/requirements.txt"): (200, {"sha": "blob1"}), ("PUT", "/contents/requirements.txt"): (200, {}),
                          ("POST", "/pulls"): (201, {"number": 42, "html_url": "https://github.com/acme/app/pull/42"})})
    monkeypatch.setattr(AF, "TRANSPORT", t)
    info = scm.detect("https://github.com/acme/app")
    prop = AF.propose({"engine": "sca", "package": "django", "version": "4.2.7", "fixed_version": "4.2.15", "file": "requirements.txt"}, read)
    pr = AF.open_pull_request(info, "ghp_x", "main", "myelin/fix-1", prop, "body")
    assert pr == {"number": 42, "url": "https://github.com/acme/app/pull/42", "provider": "github"}
    put = next(c for c in calls if c[0] == "PUT")
    assert put[3]["sha"] == "blob1" and base64.b64decode(put[3]["content"]).decode().startswith("django==4.2.15")
    assert all(c[2]["Authorization"] == "Bearer ghp_x" for c in calls)


def test_gitlab_and_azure_pull_requests(monkeypatch):
    prop = AF.propose({"engine": "cicd", "rule_id": "NM-CICD-004", "file": ".github/workflows/ci.yml", "line": 1}, read)
    t, calls = _recorder({("POST", "/repository/commits"): (201, {}), ("POST", "/merge_requests"): (201, {"iid": 7, "web_url": "https://gitlab.com/g/p/-/merge_requests/7"}),
                          ("GET", "/api/v4/projects/"): (200, {"default_branch": "develop"})})
    monkeypatch.setattr(AF, "TRANSPORT", t)
    mr = AF.open_pull_request(scm.detect("https://gitlab.com/g/p"), "glpat-x", None, "myelin/fix-2", prop, "body")
    assert mr["number"] == 7 and calls[1][3]["start_branch"] == "develop" and calls[1][3]["actions"][0]["action"] == "update"
    t2, calls2 = _recorder({("GET", "/refs?filter=heads/main"): (200, {"value": [{"objectId": "f" * 40}]}), ("POST", "/pushes"): (201, {}),
                            ("POST", "/pullrequests"): (201, {"pullRequestId": 9})})
    monkeypatch.setattr(AF, "TRANSPORT", t2)
    az = AF.open_pull_request(scm.detect("https://dev.azure.com/org/proj/_git/app"), "pat", "main", "myelin/fix-3", prop, "body")
    assert az["number"] == 9 and az["url"].endswith("/pullrequest/9")
    push = next(c for c in calls2 if "/pushes" in c[1])[3]
    assert push["commits"][0]["parents"] == ["f" * 40] and push["commits"][0]["changes"][0]["item"]["path"] == "/.github/workflows/ci.yml"


def test_provider_errors_are_explained(monkeypatch):
    t, _ = _recorder({("GET", "/git/ref/heads/main"): (403, {"message": "Resource not accessible by personal access token"})})
    monkeypatch.setattr(AF, "TRANSPORT", t)
    prop = AF.propose({"engine": "sca", "package": "django", "version": "4.2.7", "fixed_version": "4.2.15", "file": "requirements.txt"}, read)
    try:
        AF.open_pull_request(scm.detect("https://github.com/acme/app"), "ghp_x", "main", "b", prop, "")
        raise AssertionError("expected an error")
    except AF.AutofixError as e:
        assert "HTTP 403" in str(e) and "write access" in str(e)
    try:
        AF.open_pull_request(scm.detect("https://bitbucket.org/a/b"), "x", "main", "b", prop, "")
        raise AssertionError("expected an error")
    except AF.AutofixError as e:
        assert "GitHub, GitLab and Azure DevOps" in str(e)
