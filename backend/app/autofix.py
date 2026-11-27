# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""AutoFix: deterministic fixes computed from the repository's own files, and pull requests opened through the provider.

A fix is produced only when a safe, mechanical change exists for the finding (dependency upgrade in the manifest,
pinning or least-privilege changes in a workflow, a known-safe API replacement on the reported line, a dependency
cooldown setting). Anything else gets guidance, never an invented patch. The change is applied to the file content
fetched at the scanned commit, so the diff is exactly what the pull request will contain.

Pull requests: GitHub (REST), GitLab (merge requests) and Azure DevOps Repos (pushes + pull requests). The repository
token needs write access to contents and pull requests; it is read from the vault and never returned.
"""
import base64
import difflib
import json
import re
import urllib.parse
import urllib.request

from . import scm

TIMEOUT = 30
TRANSPORT = None   # test hook: callable(method, url, headers, body_bytes) -> (status, json_or_None)


class AutofixError(ValueError):
    pass


# ------------------------------------------------------------------------------------------------ fix generation
def _replace_line(text: str, line: int | None, rx: str, repl, flags=0) -> str | None:
    lines = text.splitlines(keepends=True)
    idx = range(len(lines)) if not line else [line - 1] if 0 < line <= len(lines) else []
    for i in idx:
        new = re.sub(rx, repl, lines[i], count=1, flags=flags)
        if new != lines[i]:
            lines[i] = new
            return "".join(lines)
    return None


SAST_FIXES = {   # rule -> (pattern on the reported line, replacement, explanation, needs-review)
    "NM-SAST-004": (r",\s*verify\s*=\s*False|verify\s*=\s*False\s*,\s*", "", "TLS verification restored (system CA bundle).", False),
    "NM-SAST-006": (r"\byaml\.load\(([^)]*?)(,\s*Loader\s*=\s*yaml\.(Full|Unsafe)?Loader)?\)", r"yaml.safe_load(\1)",
                    "yaml.load replaced by yaml.safe_load (no object construction).", False),
    "NM-SAST-005": (r"hashlib\.(md5|sha1)\(", "hashlib.sha256(", "Weak hash replaced by SHA-256. Check stored values that "
                    "must keep matching old digests.", True),
    "NM-SAST-008": (r",\s*debug\s*=\s*True", "", "Debug server mode removed.", False),
    "NM-SAST-013": (r"tempfile\.mktemp\(", "tempfile.mkstemp(", "mktemp replaced by mkstemp (returns an open handle and path).", True),
    "NM-SAST-029": (r"InsecureSkipVerify\s*:\s*true", "InsecureSkipVerify: false", "Go TLS verification restored.", False),
    "NM-SAST-016": (r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]", 'allow_origins=["https://app.example.com"]',
                    "Wildcard CORS replaced by an explicit origin list; set your real origins.", True),
}


def _sca_fix(f, text):
    pkg, old, new, path = f.get("package"), str(f.get("version") or ""), f.get("fixed_version"), f.get("file") or ""
    if not (pkg and old and new):
        return None
    name = path.rsplit("/", 1)[-1]
    if re.match(r"requirements.*\.(txt|in)$", name):
        rx = rf"(?im)^(\s*{re.escape(pkg)}(\[[^\]]*\])?\s*==\s*){re.escape(old)}\b"
        out = re.sub(rx, lambda m: m.group(1) + new, text, count=1)
    elif name == "package.json":
        rx = rf'("{re.escape(pkg)}"\s*:\s*"[\^~]?){re.escape(old)}(")'
        out = re.sub(rx, lambda m: m.group(1) + new + m.group(2), text, count=1)
    elif name == "pom.xml":
        art = pkg.split(":")[-1]
        rx = rf"(<artifactId>{re.escape(art)}</artifactId>\s*<version>){re.escape(old)}(</version>)"
        out = re.sub(rx, lambda m: m.group(1) + new + m.group(2), text, count=1)
    elif name == "go.mod":
        rx = rf"(?m)^(\s*{re.escape(pkg)}\s+v){re.escape(old.lstrip('v'))}\b"
        out = re.sub(rx, lambda m: m.group(1) + new.lstrip("v"), text, count=1)
    else:
        return None
    return out if out != text else None


def _cicd_fix(f, text, resolve_sha):
    rid, line = f.get("rule_id"), f.get("line")
    if rid == "NM-CICD-004":
        if re.search(r"(?m)^permissions\s*:", text):
            return None, ""
        m = re.search(r"(?m)^jobs\s*:", text)
        if not m:
            return None, ""
        return text[:m.start()] + "permissions:\n  contents: read\n\n" + text[m.start():], \
            "Workflow token limited to read-only contents; grant more per job only where needed."
    if rid == "NM-CICD-001" and resolve_sha:
        m = re.search(r"uses:\s*['\"]?([\w.-]+/[\w./-]+)@([^\s'\"#]+)", (text.splitlines()[line - 1] if line and line <= len(text.splitlines()) else ""))
        if not m:
            return None, ""
        action, ref = m.group(1), m.group(2)
        sha = resolve_sha(action, ref)
        if not sha:
            return None, ""
        out = _replace_line(text, line, rf"{re.escape(action)}@{re.escape(ref)}(\s*#[^\n]*)?", f"{action}@{sha} # {ref}")
        return out, f"{action} pinned to commit {sha[:12]} (was {ref})."
    if rid == "NM-CICD-015":
        out = _replace_line(text, line, r"\b(npm\s+(ci|install|i)|pnpm\s+(install|i)|yarn\s+install)\b(?![^\n]*--ignore-scripts)",
                            lambda m: m.group(0) + " --ignore-scripts")
        return out, "Dependency lifecycle scripts disabled in a job that holds secrets."
    if rid == "NM-CICD-021":
        out = _replace_line(text, line, r"\bnpm\s+publish\b(?![^\n]*--provenance)", "npm publish --provenance")
        return out, "Publishes with signed provenance (also grant `id-token: write` to this job and prefer trusted publishing)."
    if rid == "NM-CICD-018":
        out = _replace_line(text, line, r"(?im)^\s*ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*['\"]?true['\"]?\s*\n", "")
        return out, "Insecure workflow commands switched off."
    return None, ""


def propose(f: dict, read_file, resolve_sha=None) -> dict:
    """{"changes": [{"path", "before", "after"}], "diff", "title", "explanation", "review"} or {"changes": [], "guidance"}."""
    eng, rid, path = f.get("engine"), f.get("rule_id"), f.get("file") or ""
    changes, why, review = [], "", False
    if eng in ("sca",) and f.get("fixed_version"):
        target = path
        if path.endswith(("package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
            target = path.rsplit("/", 1)[0] + "/package.json" if "/" in path else "package.json"
        text = read_file(target)
        after = _sca_fix({**f, "file": target}, text) if text is not None else None
        if after:
            changes.append({"path": target, "before": text, "after": after})
            why = f"{f['package']} {f['version']} → {f['fixed_version']} in {target}."
            review = bool(f.get("dependency_type") == "transitive")
            if target != path:
                why += " Regenerate the lockfile (npm install) in the pull request branch."
    elif eng == "sast" and rid in SAST_FIXES and path:
        rx, repl, why, review = SAST_FIXES[rid]
        text = read_file(path)
        after = _replace_line(text, f.get("line"), rx, repl) if text is not None else None
        if after:
            changes.append({"path": path, "before": text, "after": after})
    elif eng == "cicd" and path:
        text = read_file(path)
        if text is not None:
            after, why = _cicd_fix(f, text, resolve_sha)
            if after and after != text:
                changes.append({"path": path, "before": text, "after": after})
    elif rid == "NM-SUP-008":
        base = path.rsplit("/", 1)[0] if "/" in path else ""
        npmrc = (base + "/" if base else "") + ".npmrc"
        text = read_file(npmrc) or ""
        changes.append({"path": npmrc, "before": text, "after": (text.rstrip("\n") + "\n" if text.strip() else "") + "min-release-age=3\n"})
        why = "New releases must be 3 days old before npm installs them (npm 11.10+; for pnpm set minimumReleaseAge)."
    if not changes:
        return {"changes": [], "guidance": f.get("remediation") or "No safe automatic change exists for this finding; follow the remediation guidance."}
    diff = "".join("".join(difflib.unified_diff(c["before"].splitlines(keepends=True), c["after"].splitlines(keepends=True),
                                                f"a/{c['path']}", f"b/{c['path']}")) for c in changes)
    title = (f"fix(deps): bump {f['package']} to {f['fixed_version']}" + (f" ({f['cve']})" if f.get("cve") else "")) if eng == "sca" \
        else f"fix(security): {f.get('title', rid)}"[:120]
    return {"changes": changes, "diff": diff, "title": title, "explanation": why, "review": review}


# ------------------------------------------------------------------------------------------------ provider calls
def _call(method, url, headers, body=None):
    data = json.dumps(body).encode() if body is not None else None
    if TRANSPORT:
        return TRANSPORT(method, url, headers, data)
    host = urllib.parse.urlsplit(url).hostname or ""
    scm._guard_host(host)
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": "RAT-Flea-DevSec-AutoFix",
                                 "Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # myelin:ignore[NM-SAST-010] -- provider API host from scm.detect
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except ValueError:
            return e.code, None


def _ok(status, body, what):
    if not 200 <= status < 300:
        msg = (body or {}).get("message") if isinstance(body, dict) else None
        raise AutofixError(f"{what} failed (HTTP {status}{': ' + str(msg)[:200] if msg else ''}). The repository token needs "
                           "write access to contents and pull requests.")
    return body


def _gh_api(info):
    return "https://api.github.com" if info["host"] == "github.com" else f"{info['base']}/api/v3"


def github_resolver(info, token):
    def resolve(action, ref):
        owner_repo = "/".join(action.split("/")[:2])
        st, body = _call("GET", f"https://api.github.com/repos/{owner_repo}/commits/{urllib.parse.quote(ref)}",
                         {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {token}"} if token else {})})
        return (body or {}).get("sha") if st == 200 and isinstance(body, dict) else None
    return resolve


def default_branch(info, token) -> str:
    p = info["provider"]
    if p == "github":
        st, body = _call("GET", f"{_gh_api(info)}/repos/{info['path']}", {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
        return (body or {}).get("default_branch") or "main"
    if p == "gitlab":
        st, body = _call("GET", f"{info['base']}/api/v4/projects/{urllib.parse.quote(info['path'], safe='')}", {"PRIVATE-TOKEN": token})
        return (body or {}).get("default_branch") or "main"
    if p == "azure":
        st, body = _call("GET", f"https://dev.azure.com/{info['org']}/{urllib.parse.quote(info['project'])}/_apis/git/repositories/"
                         f"{urllib.parse.quote(info['repo'])}?api-version=7.1", {"Authorization": scm._auth_header(token, "pat")})
        return str((body or {}).get("defaultBranch") or "refs/heads/main").replace("refs/heads/", "")
    return "main"


PR_PROVIDERS = ("github", "gitlab", "azure")


def open_pull_request(info, token, base_branch, branch, proposal, body_text) -> dict:
    if not token:
        raise AutofixError("connect this repository with a token that can write contents and pull requests")
    p, changes, title = info["provider"], proposal["changes"], proposal["title"]
    if p not in PR_PROVIDERS:
        raise AutofixError(f"pull requests are supported for GitHub, GitLab and Azure DevOps (not {scm.PROVIDERS.get(p, p)})")
    base_branch = base_branch or default_branch(info, token)
    if p == "github":
        api, h = f"{_gh_api(info)}/repos/{info['path']}", {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        ref = _ok(*_call("GET", f"{api}/git/ref/heads/{urllib.parse.quote(base_branch)}", h), "reading the base branch")
        _ok(*_call("POST", f"{api}/git/refs", h, {"ref": f"refs/heads/{branch}", "sha": ref["object"]["sha"]}), "creating the branch")
        for c in changes:
            st, cur = _call("GET", f"{api}/contents/{urllib.parse.quote(c['path'])}?ref={urllib.parse.quote(branch)}", h)
            payload = {"message": title, "branch": branch, "content": base64.b64encode(c["after"].encode()).decode()}
            if st == 200 and isinstance(cur, dict) and cur.get("sha"):
                payload["sha"] = cur["sha"]
            _ok(*_call("PUT", f"{api}/contents/{urllib.parse.quote(c['path'])}", h, payload), f"committing {c['path']}")
        pr = _ok(*_call("POST", f"{api}/pulls", h, {"title": title, "head": branch, "base": base_branch, "body": body_text}), "opening the pull request")
        return {"number": pr.get("number"), "url": pr.get("html_url"), "provider": "github"}
    if p == "gitlab":
        pid = urllib.parse.quote(info["path"], safe="")
        api, h = f"{info['base']}/api/v4/projects/{pid}", {"PRIVATE-TOKEN": token}
        actions = [{"action": "update" if c["before"] else "create", "file_path": c["path"], "content": c["after"]} for c in changes]
        _ok(*_call("POST", f"{api}/repository/commits", h, {"branch": branch, "start_branch": base_branch, "commit_message": title,
                                                             "actions": actions}), "committing the change")
        mr = _ok(*_call("POST", f"{api}/merge_requests", h, {"source_branch": branch, "target_branch": base_branch, "title": title,
                                                              "description": body_text, "remove_source_branch": True}), "opening the merge request")
        return {"number": mr.get("iid"), "url": mr.get("web_url"), "provider": "gitlab"}
    if p == "azure":
        api = (f"https://dev.azure.com/{info['org']}/{urllib.parse.quote(info['project'])}/_apis/git/repositories/"
               f"{urllib.parse.quote(info['repo'])}")
        h = {"Authorization": scm._auth_header(token, "pat")}
        refs = _ok(*_call("GET", f"{api}/refs?filter=heads/{urllib.parse.quote(base_branch)}&api-version=7.1", h), "reading the base branch")
        old = (refs.get("value") or [{}])[0].get("objectId")
        if not old:
            raise AutofixError(f"branch {base_branch} not found")
        push = {"refUpdates": [{"name": f"refs/heads/{branch}", "oldObjectId": "0" * 40}],
                "commits": [{"comment": title, "parents": [old], "changes": [
                    {"changeType": "edit" if c["before"] else "add", "item": {"path": "/" + c["path"]},
                     "newContent": {"content": c["after"], "contentType": "rawtext"}} for c in changes]}]}
        _ok(*_call("POST", f"{api}/pushes?api-version=7.1", h, push), "pushing the change")
        pr = _ok(*_call("POST", f"{api}/pullrequests?api-version=7.1", h, {"sourceRefName": f"refs/heads/{branch}",
                        "targetRefName": f"refs/heads/{base_branch}", "title": title, "description": body_text[:4000]}), "opening the pull request")
        return {"number": pr.get("pullRequestId"), "url": f"{info['url']}/pullrequest/{pr.get('pullRequestId')}", "provider": "azure"}
    raise AutofixError(f"pull requests are supported for GitHub, GitLab and Azure DevOps (not {scm.PROVIDERS.get(p, p)})")


def pr_body(f, proposal) -> str:
    return (f"**RAT Flea DevSec AutoFix** for `{f.get('rule_id')}` — {f.get('title')}\n\n{proposal.get('explanation', '')}\n\n"
            f"- Repository: {f.get('repo')} · file: `{f.get('file')}`" + (f":{f['line']}" if f.get("line") else "") + "\n"
            f"- Priority {f.get('priority')} · risk score {f.get('mrs')}\n\n"
            + ("> Review required: this change can alter behaviour.\n\n" if proposal.get("review") else "")
            + "When the next scan no longer reports the issue, RAT Flea DevSec closes the finding and its ticket.")
