# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Operating-system packages: inventory, version comparison and advisory matching.

Inventory (from a root filesystem: an extracted container image, a VM or device image, a firmware root, a mounted
disk, or a repository that commits one):

* the distribution and release from ``/etc/os-release`` (and the alpine/debian/redhat release files),
* Debian/Ubuntu ``/var/lib/dpkg/status`` and distroless ``/var/lib/dpkg/status.d/*``,
* Alpine and Wolfi/Chainguard ``/lib/apk/db/installed``,
* RPM distributions ``rpmdb.sqlite`` (RHEL 9+, Fedora, AlmaLinux, Rocky, Amazon Linux 2023, openSUSE),
* OpenWrt and embedded ``/usr/lib/opkg/status``,
* the kernel from ``/lib/modules/<version>``.

Matching: online, the OSV API (Debian, Ubuntu, Alpine, AlmaLinux, Rocky Linux, Red Hat, SUSE, Wolfi, Chainguard and
more, evaluated server side); offline, or when OSV is unreachable, the OS section of the offline advisory pack, with
each distribution's own version ordering (dpkg, apk, rpm) applied locally.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import sqlite3
import struct

# ------------------------------------------------------------------------------------- version comparison
def _order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    """dpkg verrevcmp."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i, j = i + 1, j + 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first:
                first = (a[i] > b[j]) - (a[i] < b[j])
            i, j = i + 1, j + 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first:
            return first
    return 0


def _split_evr(v: str):
    v = v.strip()
    epoch, _, rest = v.partition(":") if re.match(r"^\d+:", v) else ("0", "", v)
    upstream, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch or 0), upstream, rev


def dpkg_cmp(a: str, b: str) -> int:
    """Debian policy 5.6.12 ordering (epoch, upstream, revision; '~' sorts before everything)."""
    ea, ua, ra = _split_evr(a)
    eb, ub, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_part(ua, ub) or _dpkg_part(ra or "0", rb or "0")


def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    seg = re.compile(r"(~|\^|\d+|[A-Za-z]+)")
    xa, xb = seg.findall(a), seg.findall(b)
    for p, q in zip(xa, xb):
        if p == q:
            continue
        if p == "~" or q == "~":
            return -1 if p == "~" else 1
        if p == "^" or q == "^":
            return 1 if p == "^" else -1
        if p.isdigit() != q.isdigit():
            return 1 if p.isdigit() else -1
        if p.isdigit():
            return -1 if int(p) < int(q) else 1
        return -1 if p < q else 1
    if len(xa) == len(xb):
        return 0
    longer, sign = (xa, 1) if len(xa) > len(xb) else (xb, -1)
    nxt = longer[min(len(xa), len(xb))]
    if nxt == "~":
        return -sign
    if nxt == "^":
        return sign if len(xa) > len(xb) else -sign
    return sign


def rpm_cmp(a: str, b: str) -> int:
    """rpmvercmp over epoch, version and release."""
    ea, va, ra = _split_evr(a)
    eb, vb, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _rpmvercmp(va, vb) or (_rpmvercmp(ra, rb) if ra and rb else 0)


_APK_SUFFIX = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "": 0, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}


def _apk_key(v: str):
    m = re.match(r"^([\d.]+)([a-z]?)((?:_[a-z]+\d*)*)(?:~[0-9a-f]+)?(?:-r(\d+))?$", v.strip())
    if not m:
        return ((0,), 0, ((0, 0),), 0)
    nums = tuple(int(x) for x in m.group(1).strip(".").split(".") if x != "")
    sufs = tuple((_APK_SUFFIX.get(re.match(r"[a-z]+", s).group(0), 0), int(re.sub(r"^[a-z]+", "", s) or 0))
                 for s in m.group(3).split("_") if s) or ((0, 0),)
    return nums, ord(m.group(2)) if m.group(2) else 0, sufs, int(m.group(4) or 0)


def apk_cmp(a: str, b: str) -> int:
    ka, kb = _apk_key(a), _apk_key(b)
    return (ka > kb) - (ka < kb)


CMP = {"deb": dpkg_cmp, "apk": apk_cmp, "rpm": rpm_cmp, "opkg": dpkg_cmp}


# ------------------------------------------------------------------------------------- distribution
FAMILY = {"debian": "deb", "ubuntu": "deb", "raspbian": "deb", "kali": "deb", "linuxmint": "deb", "pop": "deb",
          "alpine": "apk", "wolfi": "apk", "chainguard": "apk", "postmarketos": "apk",
          "rhel": "rpm", "centos": "rpm", "almalinux": "rpm", "rocky": "rpm", "ol": "rpm", "fedora": "rpm",
          "amzn": "rpm", "opensuse-leap": "rpm", "opensuse-tumbleweed": "rpm", "sles": "rpm", "photon": "rpm",
          "mariner": "rpm", "azurelinux": "rpm", "openwrt": "opkg"}
# endoflife.date product for each os-release ID
EOL_PRODUCT = {"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine-linux", "rhel": "rhel", "centos": "centos",
               "almalinux": "almalinux", "rocky": "rocky-linux", "ol": "oracle-linux", "fedora": "fedora",
               "amzn": "amazon-linux", "opensuse-leap": "opensuse", "sles": "sles", "photon": "photon",
               "mariner": "azure-linux", "azurelinux": "azure-linux"}


def _read(path, limit=8_000_000):
    try:
        if os.path.getsize(path) > limit:
            return ""
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def distro(root: str) -> dict | None:
    """{'id', 'version', 'codename', 'name', 'family'} from os-release (or the older release files)."""
    info = {}
    for rel in ("etc/os-release", "usr/lib/os-release"):
        text = _read(os.path.join(root, rel))
        if text:
            for ln in text.splitlines():
                k, _, v = ln.partition("=")
                if k and v:
                    info[k.strip()] = v.strip().strip('"').strip("'")
            break
    did = (info.get("ID") or "").lower()
    ver = info.get("VERSION_ID") or ""
    if not did:
        if os.path.isfile(os.path.join(root, "etc/alpine-release")):
            did, ver = "alpine", _read(os.path.join(root, "etc/alpine-release")).strip()
        elif os.path.isfile(os.path.join(root, "etc/debian_version")):
            did, ver = "debian", _read(os.path.join(root, "etc/debian_version")).strip()
        elif os.path.isfile(os.path.join(root, "etc/redhat-release")):
            t = _read(os.path.join(root, "etc/redhat-release"))
            m = re.search(r"release (\d+(?:\.\d+)?)", t)
            did, ver = ("centos" if "CentOS" in t else "rhel"), (m.group(1) if m else "")
        elif os.path.isfile(os.path.join(root, "etc/openwrt_release")):
            t = _read(os.path.join(root, "etc/openwrt_release"))
            m = re.search(r"DISTRIB_RELEASE='?([^'\n]+)", t)
            did, ver = "openwrt", (m.group(1) if m else "")
    if not did:
        return None
    if did == "debian" and not ver and os.path.isfile(os.path.join(root, "etc/debian_version")):
        ver = _read(os.path.join(root, "etc/debian_version")).strip()
    return {"id": did, "version": ver, "codename": info.get("VERSION_CODENAME") or "",
            "name": info.get("PRETTY_NAME") or f"{did} {ver}".strip(), "family": FAMILY.get(did)}


def release_key(d: dict) -> str:
    """The release the advisory data is keyed by: Debian/RHEL family major, Ubuntu and Alpine major.minor."""
    v = d.get("version") or ""
    if d["id"] in ("ubuntu",):
        return ".".join(v.split(".")[:2])
    if d["id"] in ("alpine", "postmarketos"):
        return ".".join(v.split(".")[:2])
    if d["id"] in ("wolfi", "chainguard", "opensuse-tumbleweed"):
        return ""
    if d["id"] == "amzn":
        return v.split(".")[0]
    return v.split(".")[0]


# ------------------------------------------------------------------------------------- package databases
def _paragraphs(text):
    for block in re.split(r"\n\s*\n", text):
        fields, last = {}, None
        for ln in block.splitlines():
            if ln[:1] in (" ", "\t") and last:
                fields[last] += "\n" + ln.strip()
            elif ":" in ln:
                k, _, v = ln.partition(":")
                last = k.strip()
                fields[last] = v.strip()
        if fields.get("Package"):
            yield fields


def _dpkg(text, rel, eco="deb"):
    out = []
    for p in _paragraphs(text):
        if "Status" in p and "installed" not in p["Status"].split()[-1:]:
            continue
        src = p.get("Source") or p["Package"]
        src_name, _, src_ver = src.partition(" ")
        out.append({"name": p["Package"], "version": p.get("Version", ""), "source": src_name.strip(),
                    "source_version": src_ver.strip("() ") or p.get("Version", ""), "arch": p.get("Architecture"),
                    "file": rel, "kind": eco, "license": None})
    return out


def _apk(text, rel):
    out, cur = [], {}
    for ln in text.splitlines() + [""]:
        if not ln.strip():
            if cur.get("P") and cur.get("V"):
                out.append({"name": cur["P"], "version": cur["V"], "source": cur.get("o") or cur["P"],
                            "source_version": cur["V"], "arch": cur.get("A"), "file": rel, "kind": "apk",
                            "license": cur.get("L")})
            cur = {}
            continue
        if len(ln) > 2 and ln[1] == ":":
            cur.setdefault(ln[0], ln[2:])
    return out


RPM_TAGS = {1000: "name", 1001: "version", 1002: "release", 1003: "epoch", 1022: "arch", 1044: "sourcerpm", 1014: "license"}


def _rpm_header(blob: bytes) -> dict:
    """Parse an RPM header blob as stored in rpmdb.sqlite (index count, data size, index entries, data store)."""
    if len(blob) < 8:
        return {}
    il, dl = struct.unpack(">II", blob[:8])
    if il > 100_000 or 8 + il * 16 + dl > len(blob) + 16:
        return {}
    store = blob[8 + il * 16:]
    out = {}
    for k in range(il):
        tag, typ, off, cnt = struct.unpack(">IIII", blob[8 + k * 16:24 + k * 16])
        name = RPM_TAGS.get(tag)
        if not name or off >= len(store):
            continue
        if typ == 4:                                       # INT32
            out[name] = struct.unpack(">I", store[off:off + 4])[0]
        elif typ in (6, 9, 8):                             # STRING, I18NSTRING, STRING_ARRAY (first)
            end = store.find(b"\0", off)
            out[name] = store[off:end if end >= 0 else None].decode("utf-8", "replace")
    return out


def _rpmdb_sqlite(path, rel):
    out = []
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        rows = con.execute("SELECT blob FROM Packages").fetchall()
        con.close()
    except sqlite3.Error:
        return out
    for (blob,) in rows:
        h = _rpm_header(bytes(blob))
        if not h.get("name") or h["name"] == "gpg-pubkey":
            continue
        evr = (f"{h['epoch']}:" if h.get("epoch") else "") + f"{h.get('version', '')}-{h.get('release', '')}"
        srpm = h.get("sourcerpm") or ""
        m = re.match(r"^(.+)-[^-]+-[^-]+\.src\.rpm$", srpm)
        out.append({"name": h["name"], "version": evr, "source": m.group(1) if m else h["name"], "source_version": evr,
                    "arch": h.get("arch"), "file": rel, "kind": "rpm", "license": h.get("license")})
    return out


DB_FILES = {
    "var/lib/dpkg/status": "dpkg", "lib/apk/db/installed": "apk", "var/lib/rpm/rpmdb.sqlite": "rpm",
    "usr/lib/sysimage/rpm/rpmdb.sqlite": "rpm", "usr/lib/opkg/status": "opkg", "var/lib/opkg/status": "opkg",
}
UNSUPPORTED_DB = {"var/lib/rpm/Packages": "Berkeley DB RPM database (RHEL/CentOS 7, Amazon Linux 2)",
                  "var/lib/rpm/Packages.db": "NDB RPM database (SUSE)"}


def find_roots(path: str, max_depth: int = 6) -> list[str]:
    """Directories under path that look like a root filesystem (have an os-release or a package database)."""
    roots = []
    base = path.rstrip("/")
    for d, dirs, files in os.walk(path):
        depth = d[len(base):].count(os.sep)
        if depth > max_depth:
            dirs[:] = []
            continue
        dirs[:] = [x for x in dirs if x not in (".git", "node_modules", "proc", "sys", "dev", "__pycache__")]
        if "etc" in dirs and (os.path.isfile(os.path.join(d, "etc", "os-release")) or
                              any(os.path.isfile(os.path.join(d, k)) for k in DB_FILES)):
            roots.append(d)
            dirs[:] = [x for x in dirs if x not in ("usr", "var", "lib", "etc", "bin", "sbin", "opt")]
    return roots


def inventory(root: str, rel_root: str = "") -> dict:
    """{'distro', 'packages': [...], 'kernel': [...], 'unsupported': [...]} for one root filesystem."""
    pkgs, unsupported = [], []
    pre = (rel_root.rstrip("/") + "/") if rel_root else ""
    for rel, kind in DB_FILES.items():
        p = os.path.join(root, rel)
        if not os.path.isfile(p):
            continue
        if kind == "dpkg":
            pkgs += _dpkg(_read(p, 64_000_000), pre + rel)
        elif kind == "opkg":
            pkgs += _dpkg(_read(p, 64_000_000), pre + rel, "opkg")
        elif kind == "apk":
            pkgs += _apk(_read(p, 64_000_000), pre + rel)
        elif kind == "rpm":
            pkgs += _rpmdb_sqlite(p, pre + rel)
    sd = os.path.join(root, "var/lib/dpkg/status.d")
    if os.path.isdir(sd):                                    # distroless images: one file per package
        for fn in sorted(os.listdir(sd)):
            if not fn.endswith(".md5sums"):
                pkgs += _dpkg(_read(os.path.join(sd, fn)), pre + "var/lib/dpkg/status.d/" + fn)
    for rel, what in UNSUPPORTED_DB.items():
        if os.path.isfile(os.path.join(root, rel)) and not any(p["kind"] == "rpm" for p in pkgs):
            unsupported.append(f"{pre}{rel}: {what} is not read by the built-in scanner; scan the image with Trivy")
    kernel = []
    mods = os.path.join(root, "lib/modules")
    if os.path.isdir(mods):
        kernel = sorted(x for x in os.listdir(mods) if re.match(r"^\d+\.\d+", x))
    seen, uniq = set(), []
    for p in pkgs:
        k = (p["name"], p["version"], p.get("arch"))
        if k not in seen:
            seen.add(k)
            uniq.append(p)
    return {"distro": distro(root), "packages": uniq, "kernel": kernel, "unsupported": unsupported, "root": rel_root}


# ------------------------------------------------------------------------------------- purl / OSV ecosystem
PURL_NS = {"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine", "wolfi": "wolfi", "chainguard": "chainguard",
           "rhel": "redhat", "centos": "centos", "almalinux": "almalinux", "rocky": "rocky", "ol": "oracle",
           "fedora": "fedora", "amzn": "amazon", "opensuse-leap": "opensuse", "sles": "suse", "openwrt": "openwrt"}


def purl(p: dict, d: dict | None) -> str:
    kind = {"deb": "deb", "apk": "apk", "rpm": "rpm", "opkg": "generic"}[p["kind"]]
    ns = PURL_NS.get((d or {}).get("id"), (d or {}).get("id") or "unknown")
    q = []
    if p.get("arch"):
        q.append(f"arch={p['arch']}")
    if d and d.get("version"):
        q.append(f"distro={ns}-{d['version']}")
    return f"pkg:{kind}/{ns}/{p['name']}@{p['version']}" + ("?" + "&".join(q) if q else "")


def osv_ecosystem(d: dict) -> str | None:
    i, v = d["id"], d.get("version") or ""
    major = v.split(".")[0]
    if i == "debian" and major:
        return f"Debian:{major}"
    if i == "ubuntu" and v:
        lts = v.endswith(".04") and int(v.split(".")[0]) % 2 == 0
        return f"Ubuntu:{'.'.join(v.split('.')[:2])}" + (":LTS" if lts else "")
    if i == "alpine" and v:
        return "Alpine:v" + ".".join(v.split(".")[:2])
    if i == "almalinux" and major:
        return f"AlmaLinux:{major}"
    if i == "rocky" and major:
        return f"Rocky Linux:{major}"
    if i == "wolfi":
        return "Wolfi"
    if i == "chainguard":
        return "Chainguard"
    if i == "opensuse-leap" and v:
        return f"openSUSE:Leap {v}"
    if i == "sles" and v:
        return f"SUSE:Linux Enterprise Server {v.split('.')[0]}" + (f" SP{v.split('.')[1]}" if "." in v else "")
    if i == "mariner" and v:
        return f"Mariner:{v}"
    if i == "azurelinux" and v:
        return f"Azure Linux:{v}"
    return None


# ------------------------------------------------------------------------------------- offline OS advisories
_PACK = {"sig": None, "data": {}}


def _pack_file(distro_id: str):
    from .vulndb import OSV_EXPORT_MANIFEST, export_dir
    d = export_dir()
    if not d:
        return None, None
    try:
        with open(os.path.join(d, OSV_EXPORT_MANIFEST), encoding="utf-8") as fh:
            entry = (json.load(fh).get("os") or {}).get(distro_id)
    except (OSError, ValueError):
        return None, None
    if not entry or os.path.basename(entry.get("file", "")) != entry.get("file"):
        return None, None
    return os.path.join(d, entry["file"]), entry


def offline_advisories(distro_id: str) -> dict | None:
    """{release: {package: [[fixed, [ids], severity, title], ...]}} for one distribution, from the advisory pack."""
    import hashlib
    group = {"rhel": "rocky", "centos": "rocky", "ol": "rocky"}.get(distro_id, distro_id)
    if group in _PACK["data"]:
        return _PACK["data"][group]
    path, entry = _pack_file(group)
    if not path:
        _PACK["data"][group] = None
        return None
    try:
        raw = open(path, "rb").read()
        if hashlib.sha256(raw).hexdigest() != entry.get("sha256"):
            _PACK["data"][group] = None
            return None
        data = json.loads(gzip.decompress(raw))
    except (OSError, ValueError):
        data = None
    _PACK["data"][group] = data
    return data


SEV = {"critical": "critical", "important": "high", "high": "high", "moderate": "medium", "medium": "medium",
       "low": "low", "negligible": "low", "unimportant": "low", "unknown": "medium", None: "medium"}


def match_offline(inv: dict) -> list[tuple[dict, dict]]:
    """(package, advisory) pairs from the offline pack for one root filesystem."""
    d = inv.get("distro")
    if not d or not d.get("family") or d["family"] == "opkg":
        return []
    data = offline_advisories(d["id"])
    if not data:
        return []
    rel = release_key(d)
    table = data.get(rel) or data.get("") or {}
    cmp = CMP[d["family"]]
    out = []
    for p in inv["packages"]:
        rows = []
        for key, ver in ((p["source"], p["source_version"]), (p["name"], p["version"])):
            if key in table:
                rows = [(r, ver) for r in table[key]]
                break
        for (fixed, ids, sev, title), ver in rows:
            try:
                affected = fixed is None or cmp(ver, fixed) < 0
            except (ValueError, IndexError):
                continue
            if affected:
                out.append((p, {"id": ids[0], "aliases": ids[1:], "fixed": fixed, "severity": SEV.get((sev or "").lower()) if sev else None,
                                "summary": title or "", "source": "offline advisory pack"}))
    return out


def _osv_fixed(doc, eco, name):
    for a in doc.get("affected") or []:
        pk = a.get("package") or {}
        if pk.get("ecosystem") == eco and pk.get("name") == name:
            for r in a.get("ranges") or []:
                for e in r.get("events") or []:
                    if e.get("fixed"):
                        return e["fixed"]
    return None


def match_online(inv: dict) -> list[tuple[dict, dict]] | None:
    """OSV querybatch for the packages of one root filesystem (None when OSV is unreachable or offline)."""
    from concurrent.futures import ThreadPoolExecutor

    from . import vulndb
    d = inv.get("distro")
    eco = osv_ecosystem(d) if d else None
    if not eco or vulndb.offline():
        return None
    by_src = d["family"] in ("deb",) or d["id"] == "alpine"
    keys = []
    for p in inv["packages"]:
        keys.append((p["source"], p["source_version"]) if by_src else (p["name"], p["version"]))
    uniq = sorted(set(keys))
    hits = {}
    for start in range(0, len(uniq), 500):
        batch = uniq[start:start + 500]
        res = vulndb._http_json(f"{vulndb.OSV_URL}/v1/querybatch",
                                {"queries": [{"package": {"name": n, "ecosystem": eco}, "version": v} for n, v in batch]},
                                ttl=6 * 3600)
        if not isinstance(res, dict) or len(res.get("results") or []) != len(batch):
            return None
        for k, r in zip(batch, res["results"]):
            ids = [v["id"] for v in (r or {}).get("vulns") or []]
            if ids:
                hits[k] = ids
    all_ids = sorted({i for v in hits.values() for i in v})
    with ThreadPoolExecutor(max_workers=8) as ex:
        docs = dict(zip(all_ids, ex.map(lambda i: vulndb._safe(vulndb._http_json, f"{vulndb.OSV_URL}/v1/vulns/{i}"), all_ids)))
    vulndb.scan_status()["sources"].add(f"OSV ({eco})")
    out = []
    for p, k in zip(inv["packages"], keys):
        for i in hits.get(k, []):
            doc = docs.get(i) or {"id": i}
            if doc.get("withdrawn"):
                continue
            cvss, sev = vulndb._severity_of(doc) if doc.get("severity") or doc.get("database_specific") else (None, None)
            ub = next((s.get("score") for s in doc.get("severity") or [] if s.get("type") == "Ubuntu"), None)
            ids = [doc["id"]] + list(doc.get("aliases") or []) + list(doc.get("upstream") or []) + list(doc.get("related") or [])
            out.append((p, {"id": doc["id"], "aliases": ids[1:], "fixed": _osv_fixed(doc, eco, k[0]), "cvss": cvss,
                            "severity": sev if cvss is not None else SEV.get(str(ub or "").lower(), None),
                            "summary": vulndb._summary(doc) if doc.get("summary") or doc.get("details") else "",
                            "source": "OSV"}))
    return out
