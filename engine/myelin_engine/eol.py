# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""End-of-life runtimes, frameworks, base images and libraries.

Software past its end of life gets no security fixes, so every vulnerability found in it from then on stays open.
Detection covers what a repository declares:

* container base images (Dockerfile, Containerfile and docker-compose ``image:``): language runtimes, web servers,
  databases and operating-system images, including Debian/Ubuntu code names in tags (``python:3.7-slim-buster``);
* runtime pins: ``.nvmrc``, ``.node-version``, ``package.json`` engines, ``.python-version``, ``runtime.txt``,
  ``Pipfile``, ``global.json``, ``<TargetFramework>`` in .NET projects, ``go.mod``, ``.ruby-version``, ``Gemfile``,
  ``composer.json`` (``php``), GitHub Actions ``setup-*`` versions and ``.tool-versions``;
* frameworks and libraries in the dependency inventory (AngularJS, Angular, Django, Spring Boot, Vue, jQuery,
  Bootstrap, log4j and others), matched by package URL.

Dates come from endoflife.date: a bundled snapshot works offline (``data/eol.json.gz``, rebuilt with
``scripts/build_eol_data.py``); when online, the live API refreshes the products that were detected.
"""
from __future__ import annotations

import datetime
import gzip
import json
import os
import re
import urllib.request

DATA = os.path.join(os.path.dirname(__file__), "data", "eol.json.gz")
API = os.environ.get("MYELIN_EOL_URL", "https://endoflife.date/api/v1/products")
SOON_DAYS = 180
SKIP = {".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv", "__pycache__", "bin", "obj"}

DEBIAN = {"jessie": "8", "stretch": "9", "buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13"}
UBUNTU = {"trusty": "14.04", "xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04",
          "noble": "24.04", "kinetic": "22.10", "lunar": "23.04", "mantic": "23.10", "oracular": "24.10"}
# Docker Hub images whose product is not listed by package URL in the dataset.
IMAGE_PRODUCT = {
    "python": "python", "node": "nodejs", "php": "php", "ruby": "ruby", "golang": "go", "openjdk": "openjdk-builds-from-oracle",
    "eclipse-temurin": "eclipse-temurin", "amazoncorretto": "amazon-corretto", "nginx": "nginx", "httpd": "apache-http-server",
    "tomcat": "tomcat", "postgres": "postgresql", "mysql": "mysql", "mariadb": "mariadb", "redis": "redis",
    "mongo": "mongo", "ubuntu": "ubuntu", "debian": "debian", "alpine": "alpine-linux", "centos": "centos",
    "elasticsearch": "elasticsearch", "rabbitmq": "rabbitmq", "dotnet/aspnet": "dotnet", "dotnet/runtime": "dotnet",
    "dotnet/sdk": "dotnet", "dotnet/core/aspnet": "dotnet", "dotnet/core/runtime": "dotnet", "dotnet/core/sdk": "dotnet",
    "jenkins/jenkins": "jenkins", "haproxy": "haproxy", "memcached": "memcached", "kong": "kong", "traefik": "traefik",
    "wordpress": "wordpress", "drupal": "drupal", "django": "django", "gradle": "gradle", "maven": "maven",
}
RUNTIME_CATEGORIES = {"lang", "framework", "server-app", "db", "os", "service"}

_cache: dict = {}


def _today() -> datetime.date:
    return datetime.date.today()


def load() -> dict:
    if "products" not in _cache:
        try:
            with gzip.open(DATA, "rt", encoding="utf-8") as fh:
                doc = json.load(fh)
        except OSError:
            doc = {"products": {}}
        _cache["products"] = doc.get("products") or {}
        _cache["generated"] = doc.get("generated")
        idx = {}
        for name, p in _cache["products"].items():
            for purl in p.get("purls") or []:
                key = re.sub(r"@.*$", "", purl.lower()).replace("%40", "@")
                idx.setdefault(key, name)
        _cache["purl_index"] = idx
    return _cache["products"]


def _refresh(product: str) -> None:
    """Live endoflife.date data for one detected product (no-op offline or when the API is unreachable)."""
    from . import vulndb
    if vulndb.offline() or product in _cache.setdefault("refreshed", set()) or _cache.get("api_down"):
        return
    _cache["refreshed"].add(product)
    try:
        req = urllib.request.Request(f"{API}/{product}", headers={"User-Agent": "rat-flea-devsec", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as r:  # noqa: S310  # myelin:ignore[NM-SAST-010] -- fixed endoflife.date API or operator mirror
            doc = json.load(r)
    except Exception:
        _cache["api_down"] = True
        return
    rels = []
    for r in (doc.get("result") or {}).get("releases") or []:
        eol = r.get("eolFrom") if r.get("eolFrom") else r.get("isEol", False)
        rels.append({"releaseCycle": str(r.get("name")), "eol": eol, "releaseDate": r.get("releaseDate"),
                     "lts": r.get("isLts"), "latest": (r.get("latest") or {}).get("name")})
    if rels:
        load()[product] = {**load().get(product, {}), "releases": rels, "live": True}


def cycle_for(product: str, version: str):
    p = load().get(product)
    if not p or not version:
        return None
    v = str(version).strip().lstrip("vV=^~>< ").split("+")[0]
    best = None
    for r in p.get("releases") or []:
        c = str(r.get("releaseCycle"))
        if v == c or v.startswith(c + ".") or v.startswith(c + "-"):
            if best is None or len(c) > len(str(best["releaseCycle"])):
                best = r
    return best


# Products whose security patches stop at the end of standard support (endoflife.date "eoas"), not at "eol"
# (for AWS Lambda, "eol" is the end of the deprecated phase in which functions can still be updated).
SECURITY_ENDS_AT_EOAS = {"aws-lambda"}


def status(release: dict, product: str | None = None) -> tuple[str, str | None]:
    """('eol' | 'soon' | 'supported', date)."""
    eol = release.get("eoas") if product in SECURITY_ENDS_AT_EOAS and release.get("eoas") else release.get("eol")
    if eol is True:
        return "eol", None
    if not eol:
        return "supported", None
    try:
        d = datetime.date.fromisoformat(str(eol)[:10])
    except ValueError:
        return "supported", None
    if d <= _today():
        return "eol", d.isoformat()
    if (d - _today()).days <= SOON_DAYS:
        return "soon", d.isoformat()
    return "supported", d.isoformat()


def upgrade_target(product: str, current: str | None = None) -> str | None:
    """The newest supported cycle, preferring a long-term-support one (same family for runtime lists such as
    Lambda's python3.x / nodejs20.x)."""
    rel = [r for r in load().get(product, {}).get("releases") or [] if status(r, product)[0] == "supported"]
    fam = re.match(r"^([a-z]+)", str(current or "")) if product in SECURITY_ENDS_AT_EOAS else None
    if fam:
        rel = [r for r in rel if str(r["releaseCycle"]).startswith(fam.group(1))] or rel
    lts = [r for r in rel if r.get("lts")]
    pick = (lts or rel)[:1]
    if not pick:
        return None
    r = pick[0]
    return f"{r['releaseCycle']}" + (f" (latest {r['latest']})" if r.get("latest") else "")


def finding(product: str, version: str, where: str, line: int | None, repo: str, how: str, direct=True):
    _refresh(product)
    rel = cycle_for(product, version)
    if not rel:
        return None
    st, date = status(rel, product)
    if st == "supported":
        return None
    p = load()[product]
    title = p.get("title") or product
    cyc = rel["releaseCycle"]
    target = upgrade_target(product, cyc)
    library = p.get("category") not in RUNTIME_CATEGORIES or how.startswith(("dependency", "library copied"))
    if st == "eol":
        sev = "medium" if library else "high"
        t = f"{title} {cyc} is end of life" + (f" (since {date})" if date else "")
        rid = "NM-EOL-001"
    else:
        sev = "low"
        t = f"{title} {cyc} reaches end of life on {date}"
        rid = "NM-EOL-002"
    return {"engine": "sca", "rule_id": rid, "title": t, "severity": sev, "cwe": "CWE-1104", "repo": repo,
            "file": where, "line": line, "package": title, "version": str(version), "ecosystem": "eol",
            "fixed_version": target, "eol_date": date, "eol_product": product, "category": "eol",
            "source_tool": "endoflife.date" + (" (live)" if p.get("live") else f" snapshot {_cache.get('generated')}"),
            "evidence": f"{how}: {version}", "direct": direct,
            "remediation": (f"Upgrade {title} from {cyc} to a supported release" + (f": {target}" if target else "")
                            + ". After end of life no security fixes are published, so every new vulnerability stays open.")}


# ----------------------------------------------------------------------------------------- detection
_FROM = re.compile(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?([^\s@]+?)(?::([\w.\-]+))?(?:@sha256:\w+)?(?:\s+AS\s+\S+)?\s*$")
_IMAGE = re.compile(r"(?im)^\s*image:\s*[\"']?([^\s\"'@]+?):([\w.\-]+)")


def _image(ref: str, tag: str | None):
    """[(product, version)] for an image reference and tag."""
    if not tag or tag in ("latest", "stable", "lts", "current"):
        return []
    name = ref.lower()
    for reg in ("docker.io/", "index.docker.io/", "mcr.microsoft.com/", "public.ecr.aws/docker/library/", "library/"):
        if name.startswith(reg):
            name = name[len(reg):]
    load()
    prod = IMAGE_PRODUCT.get(name) or _cache["purl_index"].get(f"pkg:docker/library/{name}") or _cache["purl_index"].get(f"pkg:docker/{name}")
    out = []
    m = re.match(r"(\d+(?:\.\d+){0,2})", tag)
    if prod and m and prod in load():
        out.append((prod, m.group(1)))
    for code, ver in DEBIAN.items():
        if re.search(rf"(^|-){code}($|-)", tag):
            out.append(("debian", ver))
    for code, ver in UBUNTU.items():
        if re.search(rf"(^|-){code}($|-)", tag):
            out.append(("ubuntu", ver))
    a = re.search(r"(?:^|-)alpine(\d+\.\d+)", tag)
    if a:
        out.append(("alpine-linux", a.group(1)))
    return out


def _exact_major(spec: str) -> str | None:
    """'14', '14.x', '^14', '~14.17', '14.17.0', '>=14 <15' → '14' / '14.17'; open ranges ('>=14') → None."""
    s = str(spec or "").strip().strip("\"'")
    m = re.fullmatch(r"[v=^~]?\s*(\d+)(?:\.(\d+|x|\*))?(?:\.(?:\d+|x|\*))?", s)
    if m:
        if s.startswith("^") or m.group(2) in (None, "x", "*"):
            return m.group(1)
        return f"{m.group(1)}.{m.group(2)}"
    m = re.fullmatch(r">=?\s*(\d+)(?:\.\d+)*\s*<\s*(\d+)(?:\.0)*", s)
    if m and int(m.group(2)) == int(m.group(1)) + 1:
        return m.group(1)
    return None


def _all_eol(product: str, prefix: str) -> str | None:
    """For a caret/major-only pin: the version to report when every matching cycle is past end of life."""
    rels = [r for r in load().get(product, {}).get("releases") or []
            if str(r["releaseCycle"]) == prefix or str(r["releaseCycle"]).startswith(prefix + ".")]
    if rels and all(status(r)[0] == "eol" for r in rels):
        return prefix if any(str(r["releaseCycle"]) == prefix for r in rels) else str(rels[-1]["releaseCycle"])
    return None


def _read(path, limit=400_000):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def scan(root: str | None, repo: str, components: list[dict] | None = None) -> list[dict]:
    load()
    found: dict = {}

    def add(product, version, rel, line, how, direct=True):
        if product not in load() or not version:
            return
        f = finding(product, version, rel, line, repo, how, direct)
        if f:
            key = (product, f["title"])
            found.setdefault(key, f)

    def line_of(text, needle):
        i = text.find(needle)
        return text.count("\n", 0, i) + 1 if i >= 0 else None

    for d, dirs, files in (os.walk(root) if root else ()):
        dirs[:] = [x for x in dirs if x not in SKIP and not x.startswith(".") or x in (".github",)]
        for fn in files:
            p = os.path.join(d, fn)
            rel = os.path.relpath(p, root).replace("\\", "/")
            low = fn.lower()
            if low in ("dockerfile", "containerfile") or low.endswith(".dockerfile") or low.startswith("dockerfile."):
                t = _read(p)
                for m in _FROM.finditer(t):
                    for prod, ver in _image(m.group(1), m.group(2)):
                        add(prod, ver, rel, t.count("\n", 0, m.start()) + 1, f"base image {m.group(1)}:{m.group(2)}")
            elif re.fullmatch(r"(docker-)?compose[\w.-]*\.ya?ml", low):
                t = _read(p)
                for m in _IMAGE.finditer(t):
                    for prod, ver in _image(m.group(1), m.group(2)):
                        add(prod, ver, rel, t.count("\n", 0, m.start()) + 1, f"image {m.group(1)}:{m.group(2)}")
            elif low in (".nvmrc", ".node-version"):
                v = _exact_major(_read(p).strip().split()[0] if _read(p).strip() else "")
                if v:
                    add("nodejs", v, rel, 1, fn)
            elif low == ".python-version":
                v = _read(p).strip().split("\n")[0]
                if re.match(r"\d+\.\d+", v):
                    add("python", v, rel, 1, fn)
            elif low == "runtime.txt":
                m = re.search(r"python-(\d+\.\d+)", _read(p))
                if m:
                    add("python", m.group(1), rel, 1, fn)
            elif low == "pipfile":
                m = re.search(r"python_version\s*=\s*[\"'](\d+\.\d+)", _read(p))
                if m:
                    add("python", m.group(1), rel, line_of(_read(p), "python_version"), "Pipfile python_version")
            elif low == ".ruby-version":
                v = _read(p).strip().replace("ruby-", "")
                if re.match(r"\d+\.\d+", v):
                    add("ruby", v, rel, 1, fn)
            elif low == "gemfile":
                m = re.search(r"(?m)^\s*ruby\s+[\"'](?:~>\s*)?(\d+\.\d+)", _read(p))
                if m:
                    add("ruby", m.group(1), rel, line_of(_read(p), m.group(0).strip()), "Gemfile ruby")
            elif low == ".tool-versions":
                for i, ln in enumerate(_read(p).splitlines(), 1):
                    m = re.match(r"\s*(nodejs|python|ruby|golang|php|java)\s+(\d+(?:\.\d+)*)", ln)
                    if m:
                        prod = {"golang": "go", "java": "eclipse-temurin"}.get(m.group(1), m.group(1))
                        add(prod, m.group(2), rel, i, ".tool-versions")
            elif low == "go.mod":
                t = _read(p)
                m = re.search(r"(?m)^go\s+(\d+\.\d+)", t)
                if m:
                    add("go", m.group(1), rel, t.count("\n", 0, m.start()) + 1, "go.mod go directive")
            elif low == "global.json":
                try:
                    v = (json.loads(_read(p)).get("sdk") or {}).get("version")
                except (ValueError, AttributeError):
                    v = None
                if v:
                    m = re.match(r"(\d+)\.(\d+)", str(v))
                    if m:
                        add("dotnet", m.group(1) if int(m.group(1)) >= 5 else f"{m.group(1)}.{m.group(2)}", rel, 1, "global.json SDK")
            elif low.endswith((".csproj", ".fsproj", ".vbproj")) or low == "directory.build.props":
                t = _read(p)
                for m in re.finditer(r"<TargetFrameworks?>([^<]+)</TargetFrameworks?>", t):
                    for tf in m.group(1).split(";"):
                        tf = tf.strip().lower()
                        n = re.fullmatch(r"net(?:coreapp)?(\d+)\.(\d+)(?:-[\w.]+)?", tf)
                        if n:
                            maj = int(n.group(1))
                            add("dotnet", str(maj) if maj >= 5 else f"{maj}.{n.group(2)}", rel,
                                t.count("\n", 0, m.start()) + 1, f"TargetFramework {tf}")
                        f4 = re.fullmatch(r"net(4)(\d)(\d)?", tf)
                        if f4:
                            add("dotnetfx", ".".join(x for x in f4.groups() if x), rel, t.count("\n", 0, m.start()) + 1,
                                f"TargetFramework {tf}")
                for m in re.finditer(r"<TargetFrameworkVersion>v(\d\.\d(?:\.\d)?)</TargetFrameworkVersion>", t):
                    add("dotnetfx", m.group(1), rel, t.count("\n", 0, m.start()) + 1, "TargetFrameworkVersion")
            elif low == "package.json" and "node_modules" not in rel:
                try:
                    eng = (json.loads(_read(p)).get("engines") or {}).get("node")
                except (ValueError, AttributeError):
                    eng = None
                v = _exact_major(eng) if eng else None
                v = _all_eol("nodejs", v) if v and "." not in v else v
                if v:
                    add("nodejs", v, rel, line_of(_read(p), '"engines"'), f"package.json engines.node {eng}")
            elif low == "composer.json" and "vendor/" not in rel:
                try:
                    php = (json.loads(_read(p)).get("require") or {}).get("php")
                except (ValueError, AttributeError):
                    php = None
                m = re.fullmatch(r"\s*[\^~]?\s*(\d+)\.(\d+)(?:\.\d+)?\s*", str(php or ""))
                if m:
                    ver = f"{m.group(1)}.{m.group(2)}"
                    if str(php).strip().startswith("^"):
                        later = [r for r in load()["php"]["releases"] if str(r["releaseCycle"]).startswith(m.group(1) + ".")
                                 and tuple(map(int, str(r["releaseCycle"]).split("."))) >= (int(m.group(1)), int(m.group(2)))]
                        if later and not all(status(r)[0] == "eol" for r in later):
                            ver = None
                    if ver:
                        add("php", ver, rel, line_of(_read(p), '"php"'), f"composer.json require.php {php}")
            elif rel.startswith(".github/workflows/") and low.endswith((".yml", ".yaml")):
                t = _read(p)
                for m in re.finditer(r"uses:\s*actions/setup-(node|python|go|java|dotnet|ruby)@[^\n]*(?:\n(?:\s+.*\n){0,6}?)\s+"
                                     r"(?:node|python|go|java|dotnet|ruby)-version:\s*[\"']?([\d.x]+)", t):
                    prod = {"node": "nodejs", "go": "go", "java": "eclipse-temurin", "dotnet": "dotnet", "ruby": "ruby",
                            "python": "python"}[m.group(1)]
                    ver = m.group(2).replace(".x", "")
                    if prod == "dotnet":
                        ver = ver.split(".")[0] if int(ver.split(".")[0]) >= 5 else ".".join(ver.split(".")[:2])
                    add(prod, ver, rel, t.count("\n", 0, m.start()) + 1, f"actions/setup-{m.group(1)}")
    # frameworks and libraries from the dependency inventory
    idx = _cache["purl_index"]
    for c in components or []:
        eco = {"go": "golang"}.get(c.get("ecosystem"), c.get("ecosystem"))
        name = str(c.get("name") or "")
        if eco == "maven" and ":" in name:
            name = name.replace(":", "/", 1)
        prod = idx.get(f"pkg:{eco}/{name}".lower())
        if prod:
            add(prod, c.get("version"), c.get("file") or c.get("manifest"), None,
                f"{'library copied into the repository' if c.get('scope') == 'embedded' else 'dependency'} {c.get('name')}",
                direct=c.get("scope") != "transitive")
    return list(found.values())
