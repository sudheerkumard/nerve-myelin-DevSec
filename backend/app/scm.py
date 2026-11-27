# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Source-code providers: fetch a read-only snapshot of a repository from wherever it is hosted.

  provider      how                                              credential (pasted once, kept in the vault)
  github        REST tarball (github.com, GitHub Enterprise)      fine-grained token, Contents: read
  gitlab        REST archive (gitlab.com, self-managed)           token with read_repository
  bitbucket     archive download (bitbucket.org)                  repository access token, or user:app-password
  azure         Azure DevOps Repos REST zip (dev.azure.com,       personal access token, Code (Read)
                *.visualstudio.com)
  codecommit    Git over HTTPS (git-codecommit.<region>...)        HTTPS Git credentials "username:password"
  gcp           Git over HTTPS (Cloud Source Repositories,        service-account key JSON (role Source Reader)
                Secure Source Manager)                            or an OAuth access token
  git           Git over HTTPS, any server (Gitea, Bitbucket      "username:password", "Bearer <token>" or a token
                Data Center, self-hosted GitLab/GitHub)

Hardening: only https (http for private lab servers when MYELIN_SCM_ALLOW_HTTP=1); hosts resolving to loopback,
link-local, metadata or private addresses are refused unless MYELIN_SCM_ALLOW_PRIVATE=1 (self-hosted servers);
redirects are not followed for Git; Git runs with an empty home and system config, no hooks, no symlinks, no
submodules, no LFS, a credential sent only as a header (never in the URL or argv); archives are size-capped and
extracted with traversal/link/device protection; checkouts are deleted after the scan.
"""
from urllib.parse import quote
import base64
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

MAX_ARCHIVE = 300 * 1024 * 1024
MAX_EXTRACTED = 1024 * 1024 * 1024
MAX_FILES = 100_000
GIT_TIMEOUT = 600

PROVIDERS = {
    "github": "GitHub", "gitlab": "GitLab", "bitbucket": "Bitbucket", "azure": "Azure DevOps Repos",
    "codecommit": "AWS CodeCommit", "gcp": "Google Cloud (Source Repositories / Secure Source Manager)", "git": "Any Git server (HTTPS)",
}
TOKEN_HELP = {
    "github": "Fine-grained token → this repository → Contents: Read-only",
    "gitlab": "Project access token with read_repository",
    "bitbucket": "Repository access token (Read), or username:app-password",
    "azure": "Personal access token with Code (Read)",
    "codecommit": "IAM → HTTPS Git credentials for AWS CodeCommit, as username:password",
    "gcp": "Service-account key JSON (role Source Repository Reader / Secure Source Manager Repo Reader), or an access token",
    "git": "username:password, a personal access token, or 'Bearer <token>'",
}


class ScmError(ValueError):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


# ------------------------------------------------------------------ URL detection
def detect(url: str, provider: str | None = None) -> dict:
    """Parse a repository address. Returns {provider, url, host, path, ...provider fields}."""
    url = (url or "").strip()
    url = re.sub(r"^(https?://)[^/@]+@", r"\1", url)                      # drop "user@" (Azure clone URLs)
    u = urllib.parse.urlsplit(url)
    allow_http = os.environ.get("MYELIN_SCM_ALLOW_HTTP") == "1"
    if u.scheme not in (("https", "http") if allow_http else ("https",)) or not u.hostname:
        raise ScmError("paste the repository's https address (as shown by the 'Clone' button)")
    host, path = u.hostname.lower(), u.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if ".." in path.split("/"):
        raise ScmError("invalid repository path")
    p = provider if provider and provider != "auto" else None
    if p is None:
        if host == "github.com":
            p = "github"
        elif host == "gitlab.com":
            p = "gitlab"
        elif host == "bitbucket.org":
            p = "bitbucket"
        elif host == "dev.azure.com" or host.endswith(".visualstudio.com"):
            p = "azure"
        elif re.match(r"git-codecommit(-fips)?\.[a-z0-9-]+\.amazonaws\.com$", host) or host.endswith("console.aws.amazon.com"):
            p = "codecommit"
        elif host == "source.developers.google.com" or host.endswith(".sourcemanager.dev"):
            p = "gcp"
        else:
            p = "git"
    if p not in PROVIDERS:
        raise ScmError(f"unknown provider '{p}'")
    base = f"{u.scheme}://{u.netloc.split('@')[-1]}"
    info = {"provider": p, "host": host, "path": path, "base": base}
    parts = path.split("/")
    if p in ("github", "bitbucket"):
        if len(parts) != 2:
            raise ScmError(f"a {PROVIDERS[p]} address looks like {base}/owner/repository")
        info["url"] = f"{base}/{path}"
    elif p == "gitlab":
        if len(parts) < 2:
            raise ScmError("a GitLab address looks like https://gitlab.com/group/project")
        info["url"] = f"{base}/{path}"
    elif p == "azure":
        m = re.match(r"^(?:([^/]+)/)?([^/]+)/_git/([^/]+)$", path)
        if not m:
            raise ScmError("an Azure DevOps address looks like https://dev.azure.com/organisation/project/_git/repository")
        org = m.group(1) if host == "dev.azure.com" else host.split(".")[0]
        if not org:
            raise ScmError("an Azure DevOps address looks like https://dev.azure.com/organisation/project/_git/repository")
        info.update(org=org, project=urllib.parse.unquote(m.group(2)), repo=urllib.parse.unquote(m.group(3)),
                    url=f"https://dev.azure.com/{org}/{m.group(2)}/_git/{m.group(3)}")
    elif p == "codecommit":
        m = re.search(r"codecommit/repositories/([^/]+)", path)
        if m:                                                              # console URL -> HTTPS clone URL
            region = host.split(".")[0]
            info.update(url=f"https://git-codecommit.{region}.amazonaws.com/v1/repos/{m.group(1)}")
        elif re.match(r"^v1/repos/[^/]+$", path):
            info["url"] = f"{base}/{path}"
        else:
            raise ScmError("an AWS CodeCommit address looks like https://git-codecommit.<region>.amazonaws.com/v1/repos/<name>")
    else:
        info["url"] = f"{base}/{path}" + (".git" if p == "git" and not path.endswith(".git") else "")
    return info


# ------------------------------------------------------------------ helpers
def _guard_host(host):
    if os.environ.get("MYELIN_SCM_ALLOW_PRIVATE") == "1":
        return
    import ipaddress
    import socket
    try:
        addrs = {a[4][0] for a in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        raise ScmError(f"cannot resolve {host}") from None
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ScmError(f"{host} resolves to an internal address; self-hosted servers need MYELIN_SCM_ALLOW_PRIVATE=1 "
                           "on the platform")


def _http(url, headers, limit=MAX_ARCHIVE, want_json=False):
    req = urllib.request.Request(url, headers={"User-Agent": "RAT-Flea-DevSec", **headers})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:  # myelin:ignore[NM-SAST-010] -- provider API host fixed by detect()
            data = r.read(limit + 1)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403, 404):
            raise ScmError(f"the provider answered HTTP {e.code}: the repository or branch does not exist, or it is private and "
                           "the access token is missing, expired or lacks read access to its contents") from None
        raise ScmError(f"the provider answered HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        raise ScmError(f"cannot reach the provider: {getattr(e, 'reason', e)}") from None
    if len(data) > limit:
        raise ScmError(f"the repository archive is larger than {limit // (1024 * 1024)} MB")
    return json.loads(data) if want_json else data


def _basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _auth_header(token, default_user="git"):
    if not token:
        return None
    t = token.strip()
    if t.lower().startswith(("bearer ", "basic ")):
        return t
    if ":" in t and not t.startswith("{"):
        user, _, pw = t.partition(":")
        return _basic(user, pw)
    return _basic(default_user, t)


def gcp_access_token(credential: str) -> str:
    """A raw access token, or a service-account key JSON exchanged for a 1-hour token (JWT bearer grant)."""
    c = credential.strip()
    if not c.startswith("{"):
        return c[7:] if c.lower().startswith("bearer ") else c
    try:
        key = json.loads(c)
        import jwt  # PyJWT (with cryptography)
        now = int(time.time())
        assertion = jwt.encode({"iss": key["client_email"], "scope": "https://www.googleapis.com/auth/cloud-platform",
                                "aud": key.get("token_uri", "https://oauth2.googleapis.com/token"), "iat": now, "exp": now + 3600},
                               key["private_key"], algorithm="RS256", headers={"kid": key.get("private_key_id")})
    except (ValueError, KeyError) as e:
        raise ScmError(f"the Google credential is not a valid service-account key JSON ({type(e).__name__})") from None
    body = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}).encode()
    req = urllib.request.Request(key.get("token_uri", "https://oauth2.googleapis.com/token"), data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # myelin:ignore[NM-SAST-010] -- token_uri from the service-account key
            return json.loads(r.read())["access_token"]
    except urllib.error.HTTPError as e:
        raise ScmError(f"Google refused the service-account key (HTTP {e.code})") from None


# ------------------------------------------------------------------ archive providers
def _archive_request(info, branch, token):
    p, base = info["provider"], info["base"]
    if p == "github":
        api = "https://api.github.com" if info["host"] == "github.com" else f"{base}/api/v3"     # GitHub Enterprise Server
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            h["Authorization"] = f"Bearer {token.strip()}"
        return f"{api}/repos/{info['path']}/tarball" + (f"/{urllib.parse.quote(branch, safe='')}" if branch else ""), h, "tar"
    if p == "gitlab":
        h = {"PRIVATE-TOKEN": token.strip()} if token else {}
        return (f"{base}/api/v4/projects/{urllib.parse.quote(info['path'], safe='')}/repository/archive.tar.gz"
                + (f"?sha={urllib.parse.quote(branch, safe='')}" if branch else "")), h, "tar"
    if p == "bitbucket":
        t = (token or "").strip()
        h = {"Authorization": (_auth_header(t) if ":" in t else f"Bearer {t}")} if t else {}   # user:app-password or access token
        ref = branch
        if not ref:
            meta = _http(f"https://api.bitbucket.org/2.0/repositories/{info['path']}", h, 1_000_000, want_json=True)
            ref = (meta.get("mainbranch") or {}).get("name") or "main"
        return f"https://bitbucket.org/{info['path']}/get/{urllib.parse.quote(ref, safe='')}.tar.gz", h, "tar"
    if p == "azure":
        h = {"Authorization": _basic("", token.strip())} if token else {}
        q = {"scopePath": "/", "recursionLevel": "Full", "download": "true", "$format": "zip", "api-version": "7.1"}
        if branch:
            q.update({"versionDescriptor.version": branch, "versionDescriptor.versionType": "branch"})
        repo_api = (f"https://dev.azure.com/{urllib.parse.quote(info['org'])}/{urllib.parse.quote(info['project'])}"
                    f"/_apis/git/repositories/{urllib.parse.quote(info['repo'])}")
        return f"{repo_api}/items?{urllib.parse.urlencode(q)}", h, "zip"
    raise ScmError("not an archive provider")


def _azure_commit(info, branch, token):
    h = {"Authorization": _basic("", token.strip())} if token else {}
    q = {"searchCriteria.$top": "1", "api-version": "7.1"}
    if branch:
        q["searchCriteria.itemVersion.version"] = branch
    url = (f"https://dev.azure.com/{urllib.parse.quote(info['org'])}/{urllib.parse.quote(info['project'])}/_apis/git/repositories/"
           f"{urllib.parse.quote(info['repo'])}/commits?{urllib.parse.urlencode(q)}")
    try:
        return ((_http(url, h, 2_000_000, want_json=True).get("value") or [{}])[0]).get("commitId", "")
    except ScmError:
        return ""


def _extract(data: bytes, kind: str, dest: str) -> str:
    total, count = 0, 0
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for m in zf.infolist():
                count += 1
                if count > MAX_FILES:
                    raise ScmError(f"the repository has more than {MAX_FILES} files")
                name = m.filename
                if name.startswith(("/", "\\")) or ".." in Path(name).parts or (m.external_attr >> 16) & 0o170000 == 0o120000:
                    continue                                                          # absolute, escaping or symlink
                total += m.file_size
                if total > MAX_EXTRACTED:
                    raise ScmError("the repository is larger than 1 GB when extracted")
                target = os.path.join(dest, name)
                if m.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(m) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            members = []
            for m in tf.getmembers():
                count += 1
                if count > MAX_FILES:
                    raise ScmError(f"the repository has more than {MAX_FILES} files")
                if m.name.startswith("/") or ".." in Path(m.name).parts or not (m.isfile() or m.isdir()):
                    continue
                total += max(m.size, 0)
                if total > MAX_EXTRACTED:
                    raise ScmError("the repository is larger than 1 GB when extracted")
                members.append(m)
            try:
                tf.extractall(dest, members=members, filter="data")
            except TypeError:
                tf.extractall(dest, members=members)
    tops = [d for d in os.listdir(dest)]
    if len(tops) == 1 and os.path.isdir(os.path.join(dest, tops[0])):
        return os.path.join(dest, tops[0])
    return dest


# ------------------------------------------------------------------ git providers
def _git(info, branch, token, dest):
    if not shutil.which("git"):
        raise ScmError("Git is not installed on this platform node (needed for this provider)")
    u = urllib.parse.urlsplit(info["url"])
    _guard_host(u.hostname)
    header = None
    if info["provider"] == "gcp" and token:
        header = f"Authorization: Bearer {gcp_access_token(token)}"
    elif token:
        header = "Authorization: " + _auth_header(token)
    home = os.path.join(dest, ".home")
    os.makedirs(home, exist_ok=True)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_LFS_SKIP_SMUDGE": "1", "GIT_ASKPASS": "/bin/false", "SSH_ASKPASS": "/bin/false",
           "GIT_ALLOW_PROTOCOL": "https:http" if os.environ.get("MYELIN_SCM_ALLOW_HTTP") == "1" else "https"}
    cfg = [("http.followRedirects", "false"), ("core.symlinks", "false"), ("core.hooksPath", "/dev/null"),
           ("submodule.recurse", "false"), ("core.fsmonitor", "false"), ("protocol.file.allow", "never")]
    if header:
        cfg.append(("http.extraHeader", header))                               # via environment: never in argv or the URL
    env["GIT_CONFIG_COUNT"] = str(len(cfg))
    for i, (k, v) in enumerate(cfg):
        env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = k, v
    work = os.path.join(dest, "src")
    base = ["git", "clone", "--single-branch", "--no-tags", "--quiet"] + (["--branch", branch] if branch else [])
    last = None
    for depth in (["--depth", "1"], []):                                       # dumb-HTTP servers cannot do shallow clones
        shutil.rmtree(work, ignore_errors=True)
        try:
            cp = subprocess.run(base + depth + ["--", info["url"], work], env=env, capture_output=True, text=True, timeout=GIT_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise ScmError("cloning took longer than 10 minutes") from None
        if cp.returncode == 0:
            break
        last = (cp.stderr or "").strip().splitlines()[-1:] or ["clone failed"]
        if not re.search(r"shallow|dumb http|depth", cp.stderr or "", re.I):
            break
    else:
        pass
    if not os.path.isdir(os.path.join(work, ".git")):
        msg = re.sub(r"(Authorization:\s*)\S+(\s+\S+)?", r"\1***", last[0] if last else "clone failed")
        if re.search(r"401|403|Authentication|could not read Username|not found|does not exist", msg, re.I):
            msg += " - check the address and that the credential can read this repository"
        raise ScmError(f"git: {msg}")
    commit = subprocess.run(["git", "-C", work, "rev-parse", "HEAD"], env=env, capture_output=True, text=True).stdout.strip()
    size = sum(f.stat().st_size for f in Path(work).rglob("*") if f.is_file() and ".git" not in f.parts)
    if size > MAX_EXTRACTED:
        raise ScmError("the repository is larger than 1 GB")
    shutil.rmtree(os.path.join(work, ".git"), ignore_errors=True)
    shutil.rmtree(home, ignore_errors=True)
    return work, commit


# ------------------------------------------------------------------ entry point
def fetch(url: str, provider: str | None, branch: str | None, token: str | None, dest: str) -> tuple[str, str]:
    """Download a snapshot into dest. Returns (source root directory, commit id or '')."""
    info = detect(url, provider)
    if info["provider"] in ("codecommit", "gcp", "git"):
        return _git(info, branch, token, dest)
    if info["provider"] in ("github", "gitlab") and info["host"] not in ("github.com", "gitlab.com"):
        _guard_host(info["host"])                                              # GitHub Enterprise / self-managed GitLab
    req_url, headers, kind = _archive_request(info, branch, token)
    data = _http(req_url, {k: v for k, v in headers.items() if v})
    is_zip, is_gz = data[:4] == b"PK\x03\x04", data[:2] == b"\x1f\x8b"
    if (kind == "zip" and not is_zip) or (kind == "tar" and not is_gz and data[257:262] != b"ustar"):
        if data.lstrip()[:15].lower().startswith((b"<!doctype", b"<html")):
            raise ScmError(f"{PROVIDERS[info['provider']]} returned a sign-in page instead of the repository: the access token "
                           "is invalid or expired, or lacks read access to the code")
        raise ScmError(f"{PROVIDERS[info['provider']]} did not return a repository archive (unexpected response)")
    try:
        root = _extract(data, kind, dest)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError) as e:
        raise ScmError(f"the repository archive could not be read ({type(e).__name__})") from None
    commit = ""
    m = re.search(r"-([0-9a-f]{7,40})$", os.path.basename(root))
    if m:
        commit = m.group(1)
    elif info["provider"] == "azure":
        commit = _azure_commit(info, branch, token)
    return root, commit


def blob_url(provider: str, url: str, commit: str, path: str, line=None) -> str | None:
    """Link to a file (and line) at the scanned commit in the repository's web UI."""
    if not (url and path and commit) or path.startswith(("/", "..")) or "://" in path:
        return None
    base = url.rstrip("/")
    base = base[:-4] if base.endswith(".git") else base
    p = "/".join(quote(x) for x in path.replace("\\", "/").split("/"))
    ln = int(line) if str(line or "").isdigit() else None
    if provider == "github":
        return f"{base}/blob/{commit}/{p}" + (f"#L{ln}" if ln else "")
    if provider == "gitlab":
        return f"{base}/-/blob/{commit}/{p}" + (f"#L{ln}" if ln else "")
    if provider == "bitbucket":
        return f"{base}/src/{commit}/{p}" + (f"#lines-{ln}" if ln else "")
    if provider == "azure":
        return f"{base}?path=/{p}&version=GC{commit}" + (f"&line={ln}&lineEnd={ln}&lineStartColumn=1&lineEndColumn=200" if ln else "")
    return None
