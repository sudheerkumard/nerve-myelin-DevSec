# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""GitHub connector (GitHub.com and GitHub Enterprise Server) via a GitHub App.

Least privilege: a GitHub App installed only on the repositories the customer chooses, with read-only
permissions (Metadata, Contents, Actions, Administration, Code scanning alerts). Each sync mints a
one-hour installation token that requests exactly those read permissions. No personal access tokens.
Secret (JSON): {"app_id": "...", "installation_id": "...", "private_key": "<PEM private key of the GitHub App>"}
"""
import base64
import sys
import time

import jwt

from .base import Connector, ConnectorError, SyncResult, register

READ_PERMISSIONS = {"metadata": "read", "contents": "read", "actions": "read", "administration": "read", "security_events": "read"}


@register
class GitHubConnector(Connector):
    kind = "github"
    title = "GitHub (App, read-only)"
    config_fields = {"organization": "GitHub organization or user", "?api_url": "API URL (GitHub Enterprise Server: https://<host>/api/v3)",
                     "?max_repos": "Maximum repositories per sync (default 500)"}
    least_privilege = {"summary": "GitHub App, repository-selected install, read-only: metadata, contents, actions, administration, code scanning alerts",
                       "policy_file": "config/connectors/github-app-manifest.json"}

    @property
    def api(self):
        url = (self.config.get("api_url") or "https://api.github.com").rstrip("/")
        if not url.startswith("https://"):
            raise ConnectorError("api_url must use HTTPS")
        return url

    def _app_jwt(self, cred) -> str:
        now = int(time.time())
        return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": str(cred["app_id"])}, cred["private_key"], algorithm="RS256")

    def _token(self) -> str:
        cred = self.secret_json()
        r = self.http.post(f"{self.api}/app/installations/{cred['installation_id']}/access_tokens",
                           headers={"Authorization": f"Bearer {self._app_jwt(cred)}", "Accept": "application/vnd.github+json"},
                           json={"permissions": READ_PERMISSIONS})
        if r.status_code != 201:
            raise ConnectorError(f"GitHub App token request failed ({r.status_code})")
        return r.json()["token"]

    def _get(self, tok, path, **params):
        return self.http.get(f"{self.api}{path}", params=params or None,
                             headers={"Authorization": f"Bearer {tok}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})

    def test(self) -> dict:
        tok = self._token()
        r = self._get(tok, "/installation/repositories", per_page=1)
        if r.status_code != 200:
            raise ConnectorError(f"cannot list repositories ({r.status_code})")
        return {"ok": True, "repositories_visible": r.json().get("total_count", 0)}

    def sync(self) -> SyncResult:
        sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "..", "..", "engine"))
        from myelin_engine.cicd_posture import RULES, scan_github

        tok, out = self._token(), SyncResult()
        repos, page, cap = [], 1, int(self.config.get("max_repos") or 500)
        while len(repos) < cap:
            r = self._get(tok, "/installation/repositories", per_page=100, page=page)
            batch = r.json().get("repositories", []) if r.status_code == 200 else []
            repos += [x for x in batch if x["owner"]["login"].lower() == self.config["organization"].lower()]
            if len(batch) < 100:
                break
            page += 1
        for repo in repos[:cap]:
            full, branch = repo["full_name"], repo.get("default_branch", "main")
            out.assets.append({"type": "repository", "id": full, "private": repo.get("private"), "default_branch": branch})
            w = self._get(tok, f"/repos/{full}/contents/.github/workflows", ref=branch)
            for item in (w.json() if w.status_code == 200 and isinstance(w.json(), list) else []):
                if not item["name"].endswith((".yml", ".yaml")):
                    continue
                f = self._get(tok, f"/repos/{full}/contents/{item['path']}", ref=branch)
                if f.status_code != 200:
                    continue
                text = base64.b64decode(f.json().get("content", "")).decode("utf-8", "ignore")
                for finding in scan_github(text, item["path"], full):
                    out.findings.append({**finding, "source": "github-connector"})
                out.evidence.append((f"{full}/{item['path']}", "pipeline-definition", text.encode(), "text/yaml"))
            prot = self._get(tok, f"/repos/{full}/branches/{branch}/protection")
            if prot.status_code == 404:
                title, sev, owasp, fix = RULES["NM-CICD-012"]
                out.findings.append({"engine": "cicd", "rule_id": "NM-CICD-012", "title": title, "severity": sev, "owasp_cicd": owasp,
                                     "remediation": fix, "repo": full, "file": f"branch:{branch}", "exposure": "internal", "source": "github-connector"})
        return out
