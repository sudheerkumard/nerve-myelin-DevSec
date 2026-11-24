# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""One-click import of many repositories.

  discover()       list the repositories of a GitHub organisation/user, GitLab group, Azure DevOps organisation or
                   project, or Bitbucket workspace (with the same read-only credential used for scanning)
  extract_file()   find repository addresses in any file someone shared: spreadsheets (.xlsx, .csv, .tsv), documents
                   (.docx, .pptx, .md, .txt, .html, .xml), configuration (.json, .yaml) — https and git@ SSH clone URLs.
                   A table with a header row (url / repository, branch, name, criticality, provider) keeps those columns.
Nothing is created here; the caller previews the result and then imports the selected entries.
"""
import base64
import csv
import io
import json
import re
import urllib.parse
import zipfile
from xml.etree import ElementTree as ET

from . import scm

MAX_FILE = 10 * 1024 * 1024
MAX_REPOS = 1000
URL_RX = re.compile(r"""(https?://[^\s"'<>()\[\]{},;|`\\]+|git@[\w.-]+:[\w./~-]+|ssh://git@[\w.-]+(?::\d+)?/[\w./~-]+)""")
GENERIC_GIT_HINT = re.compile(r"\.git$|/scm/|/git/|/_git/|/r/[^/]+$")
HEADER_ALIASES = {"url": ("url", "repo url", "repository url", "repository", "repo", "clone url", "git url", "address", "link"),
                  "branch": ("branch", "ref", "default branch"), "name": ("name", "repo name", "repository name", "project", "application"),
                  "criticality": ("criticality", "tier", "priority", "business criticality"),
                  "provider": ("provider", "host", "platform", "scm")}


class ImportError_(ValueError):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


# ------------------------------------------------------------------ address normalisation
def normalise(raw: str):
    """Repository info for a candidate address, or None when it is not a repository address."""
    u = raw.strip().rstrip(".").rstrip("/")
    m = re.match(r"^git@([\w.-]+):(.+?)(\.git)?$", u) or re.match(r"^ssh://git@([\w.-]+)(?::\d+)?/(.+?)(\.git)?$", u)
    if m:                                                               # SSH clone URL -> https
        host, path = m.group(1), m.group(2)
        if host == "ssh.dev.azure.com":                                 # git@ssh.dev.azure.com:v3/org/project/repo
            parts = path.split("/")
            if len(parts) == 4 and parts[0] == "v3":
                u = f"https://dev.azure.com/{parts[1]}/{parts[2]}/_git/{parts[3]}"
            else:
                return None
        else:
            u = f"https://{host}/{path}"
    u = re.sub(r"/(tree|blob|-/tree|-/blob|src|commits?|pulls?|issues|merge_requests)(/.*)?$", "", u)   # browser links into a repo
    u = re.sub(r"\?.*$", "", u)
    try:
        info = scm.detect(u)
    except scm.ScmError:
        return None
    if info["provider"] == "git" and not GENERIC_GIT_HINT.search(urllib.parse.urlsplit(raw.strip()).path or ""):
        return None                                                     # an ordinary web link, not a Git remote
    if info["provider"] == "gitlab" and len(info["path"].split("/")) < 2:
        return None
    return info


# ------------------------------------------------------------------ file formats
def _xlsx_rows(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall("m:si", ns):
                shared.append("".join(t.text or "" for t in si.iter("{%s}t" % ns["m"])))
        # hyperlinks targets (cells often show a label but link to the repository)
        links = []
        for name in sorted(n for n in z.namelist() if re.match(r"xl/worksheets/_rels/sheet\d+\.xml\.rels$", n)):
            for rel in ET.fromstring(z.read(name)):
                if rel.get("TargetMode") == "External" and rel.get("Target"):
                    links.append(rel.get("Target"))
        rows = []
        for name in sorted(n for n in z.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml$", n)):
            root = ET.fromstring(z.read(name))
            for row in root.iter("{%s}row" % ns["m"]):
                cells = {}
                for c in row.findall("m:c", ns):
                    col = re.sub(r"\d", "", c.get("r", "A"))
                    v = c.find("m:v", ns)
                    if c.get("t") == "s" and v is not None:
                        val = shared[int(v.text)] if v.text and v.text.isdigit() and int(v.text) < len(shared) else ""
                    elif c.get("t") == "inlineStr":
                        val = "".join(t.text or "" for t in c.iter("{%s}t" % ns["m"]))
                    else:
                        val = v.text if v is not None else ""
                    cells[col] = val or ""
                if cells:
                    width = max(_col_index(k) for k in cells) + 1
                    rows.append([cells.get(_col_name(i), "") for i in range(width)])
            rows.append([])
        return rows, links


def _col_index(col):
    n = 0
    for ch in col:
        n = n * 26 + (ord(ch.upper()) - 64)
    return n - 1


def _col_name(i):
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def _office_text(data, pattern):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        parts, links = [], []
        for name in sorted(n for n in z.namelist() if re.match(pattern, n)):
            xml = z.read(name).decode("utf-8", "ignore")
            parts.append(re.sub(r"<w:p[ >]|<a:p[ >]|</w:tc>|</a:tc>", "\n", xml))
        for name in z.namelist():
            if name.endswith(".rels"):
                links += re.findall(r'Target="(https?://[^"]+)"[^>]*TargetMode="External"', z.read(name).decode("utf-8", "ignore"))
        text = re.sub(r"<[^>]+>", " ", "\n".join(parts))
        return text + "\n" + "\n".join(links)


def _decode(data):
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            text = data.decode(enc)
            if enc == "utf-16" and "\x00" in text:
                continue
            return text
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "ignore")


def _table(rows):
    """Use a header row when one names the URL column; otherwise None."""
    for hi, row in enumerate(rows[:10]):
        heads = [str(c).strip().lower() for c in row]
        col = {}
        for key, names in HEADER_ALIASES.items():
            for i, h in enumerate(heads):
                if h in names:
                    col.setdefault(key, i)
        if "url" in col:
            out = []
            for r in rows[hi + 1:]:
                if len(r) > col["url"] and str(r[col["url"]]).strip():
                    out.append({k: str(r[i]).strip() for k, i in col.items() if i < len(r) and str(r[i]).strip()})
            return out
    return None


def extract_file(filename: str, data: bytes) -> dict:
    if len(data) > MAX_FILE:
        raise ImportError_("the file is larger than 10 MB")
    low = (filename or "").lower()
    rows, text, extra = None, "", []
    try:
        if low.endswith((".xlsx", ".xlsm")):
            grid, extra = _xlsx_rows(data)
            rows = _table([r for r in grid if r])
            text = "\n".join("\t".join(r) for r in grid)
        elif low.endswith(".docx"):
            text = _office_text(data, r"word/(document|header\d*|footer\d*)\.xml$")
        elif low.endswith(".pptx"):
            text = _office_text(data, r"ppt/slides/slide\d+\.xml$")
        elif low.endswith((".xls", ".doc", ".ppt")):
            raise ImportError_("legacy Office formats (.xls/.doc/.ppt) are not supported: save as .xlsx/.docx/.pptx or .csv")
        elif low.endswith(".pdf"):
            raise ImportError_("PDF is not supported: copy the list into a .txt/.csv file, or export the document as .docx")
        else:
            text = _decode(data)
            if low.endswith((".csv", ".tsv")) or ("," in text.splitlines()[0] if text.strip() else False):
                dialect = "excel-tab" if low.endswith(".tsv") or "\t" in text.splitlines()[0] else "excel"
                rows = _table(list(csv.reader(io.StringIO(text), dialect=dialect)))
            elif low.endswith(".json"):
                try:
                    text = json.dumps(json.loads(text))                # normalise escapes such as \/
                except ValueError:
                    pass
    except (zipfile.BadZipFile, ET.ParseError, KeyError) as e:
        raise ImportError_(f"the file could not be read ({type(e).__name__}); is it really {low.rsplit('.', 1)[-1]}?") from None
    candidates = []
    if rows:
        for r in rows:
            candidates.append((r.get("url"), r))
    for u in URL_RX.findall(text) + extra:
        candidates.append((u, {}))
    return _collect(candidates)


def _collect(candidates):
    found, seen, ignored = [], set(), 0
    for raw, meta in candidates:
        info = normalise(raw or "")
        if not info:
            ignored += 1
            continue
        key = info["url"].lower()
        if key in seen:
            continue
        seen.add(key)
        crit = str(meta.get("criticality", "")).lower()
        found.append({"url": info["url"], "provider": info["provider"], "name": meta.get("name") or (info.get("repo") or info["path"].split("/")[-1]),
                      "branch": meta.get("branch") or None, "criticality": crit if crit in ("low", "medium", "high", "critical") else None})
        if len(found) >= MAX_REPOS:
            break
    return {"repositories": found, "ignored_links": ignored}


# ------------------------------------------------------------------ discovery
def _get(url, headers):
    return scm._http(url, headers, limit=20_000_000, want_json=True)


def discover(provider: str, target: str, token: str | None, include_archived=False) -> dict:
    """List repositories under an organisation / group / project / workspace."""
    t = (token or "").strip()
    target = (target or "").strip().rstrip("/")
    out = []
    if provider == "github":
        base, owner = "https://api.github.com", target
        m = re.match(r"^https://([^/]+)/([^/]+)$", target)
        if m:
            owner = m.group(2)
            if m.group(1) != "github.com":
                base = f"https://{m.group(1)}/api/v3"
        h = {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {t}"} if t else {})}
        kind = "orgs"
        for page in range(1, 11):
            try:
                batch = _get(f"{base}/{kind}/{owner}/repos?per_page=100&type=all&page={page}", h)
            except scm.ScmError:
                if page == 1 and kind == "orgs":
                    kind = "users"
                    batch = _get(f"{base}/users/{owner}/repos?per_page=100&type=owner&page={page}", h)
                else:
                    raise
            for r in batch:
                if r.get("archived") and not include_archived:
                    continue
                out.append({"url": r["html_url"], "provider": "github", "name": r["name"], "branch": None,
                            "default_branch": r.get("default_branch"), "private": r.get("private"), "archived": r.get("archived")})
            if len(batch) < 100:
                break
    elif provider == "gitlab":
        m = re.match(r"^https://([^/]+)/(.+)$", target)
        host, group = (m.group(1), m.group(2)) if m else ("gitlab.com", target)
        h = {"PRIVATE-TOKEN": t} if t else {}
        for page in range(1, 11):
            batch = _get(f"https://{host}/api/v4/groups/{urllib.parse.quote(group, safe='')}/projects?include_subgroups=true"
                         f"&per_page=100&page={page}&archived={'true' if include_archived else 'false'}&order_by=path", h)
            for r in batch:
                out.append({"url": r["web_url"], "provider": "gitlab", "name": r["path"], "branch": None,
                            "default_branch": r.get("default_branch"), "private": r.get("visibility") != "public", "archived": r.get("archived")})
            if len(batch) < 100:
                break
    elif provider == "azure":
        m = re.match(r"^(?:https://dev\.azure\.com/)?([^/]+)(?:/([^/]+))?$", target) or \
            re.match(r"^https://([^.]+)\.visualstudio\.com(?:/([^/]+))?$", target)
        if not m:
            raise ImportError_("give the Azure DevOps organisation (https://dev.azure.com/org) or project (https://dev.azure.com/org/project)")
        org, project = m.group(1), m.group(2)
        h = {"Authorization": "Basic " + base64.b64encode(f":{t}".encode()).decode()} if t else {}
        url = f"https://dev.azure.com/{urllib.parse.quote(org)}/" + (f"{urllib.parse.quote(project)}/" if project else "") + \
              "_apis/git/repositories?api-version=7.1"
        for r in _get(url, h).get("value") or []:
            if r.get("isDisabled"):
                continue
            out.append({"url": r.get("webUrl") or r.get("remoteUrl"), "provider": "azure", "name": r["name"], "branch": None,
                        "default_branch": (r.get("defaultBranch") or "").replace("refs/heads/", "") or None,
                        "private": True, "archived": False, "project": (r.get("project") or {}).get("name")})
    elif provider == "bitbucket":
        ws = re.sub(r"^https://bitbucket\.org/", "", target)
        h = {"Authorization": (scm._auth_header(t) if ":" in t else f"Bearer {t}")} if t else {}
        url = f"https://api.bitbucket.org/2.0/repositories/{urllib.parse.quote(ws)}?pagelen=100"
        for _ in range(10):
            page = _get(url, h)
            for r in page.get("values") or []:
                out.append({"url": ((r.get("links") or {}).get("html") or {}).get("href"), "provider": "bitbucket", "name": r.get("slug"),
                            "branch": None, "default_branch": (r.get("mainbranch") or {}).get("name"), "private": r.get("is_private"),
                            "archived": False})
            url = page.get("next")
            if not url:
                break
    else:
        raise ImportError_("organisation listing is available for GitHub, GitLab, Azure DevOps and Bitbucket; for AWS CodeCommit, "
                           "Google Cloud and other servers, import a file listing the repository addresses")
    out = [r for r in out if r.get("url")][:MAX_REPOS]
    return {"repositories": out, "count": len(out)}
