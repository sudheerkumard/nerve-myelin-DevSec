# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Everything below the application: operating-system packages, native binaries, firmware, drivers and the
databases/middleware/platforms declared in infrastructure code. Called by the orchestrator for the SCA engine.

Findings are grouped the way they are fixed: one finding per OS source package and fixed version ("upgrade openssl
to 3.0.13-0ubuntu3.5: fixes 7 CVEs"), one per native component, one per image; every CVE stays listed in it.
"""
from __future__ import annotations

import os
import re
import shutil

from . import binaries, cpe, eol, infra, ospkg

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, None: 0}


def _sev(adv):
    s = adv.get("severity")
    if s in SEV_RANK and s:
        return s
    m = cpe.cve_meta(next((i for i in [adv["id"]] + list(adv.get("aliases") or []) if str(i).startswith("CVE-")), adv["id"]))
    return m.get("severity") or "medium"


def _cvss(adv):
    if adv.get("cvss") is not None:
        return adv["cvss"]
    cve = next((i for i in [adv["id"]] + list(adv.get("aliases") or []) if str(i).startswith("CVE-")), None)
    return cpe.cve_meta(cve).get("cvss") if cve else None


def _cve(adv):
    return next((i for i in [adv["id"]] + list(adv.get("aliases") or []) if str(i).startswith("CVE-")), adv["id"])


def os_findings(inv: dict, repo: str) -> tuple[list[dict], list[dict]]:
    """(components, findings) for one root filesystem."""
    d = inv.get("distro") or {}
    comps, out = [], []
    for p in inv["packages"]:
        comps.append({"ecosystem": p["kind"], "name": p["name"], "version": p["version"], "file": p["file"],
                      "purl": ospkg.purl(p, d), "scope": "os", "via": None, "license": p.get("license") or "unknown",
                      "detection": f"{p['kind']} package database"})
    root = (inv.get("root") or "").rstrip("/")
    where = (root + "/" if root else "") + "etc/os-release"
    # the distribution release and the kernel
    prod = ospkg.EOL_PRODUCT.get(d.get("id"))
    if prod and d.get("version"):
        f = eol.finding(prod, d["version"], where, None, repo, f"operating system {d.get('name')}")
        if f:
            f["category"] = "eol"
            out.append(f)
    for k in inv.get("kernel") or []:
        m = re.match(r"(\d+\.\d+)", k)
        if m:
            f = eol.finding("linux", m.group(1), (root + "/" if root else "") + f"lib/modules/{k}", None, repo, f"Linux kernel {k}")
            if f:
                out.append(f)
    if not d.get("family") or not inv["packages"]:
        return comps, out
    pairs = ospkg.match_online(inv)
    source = "OSV"
    if pairs is None:
        pairs = ospkg.match_offline(inv)
        source = "offline advisory pack"
        from .vulndb import scan_status
        if pairs or ospkg.offline_advisories(d["id"]):
            scan_status()["sources"].add(f"{d.get('name') or d['id']} advisories ({source})")
        elif d["family"] != "opkg":
            scan_status()["errors"].add(f"no advisory data for {d.get('name') or d['id']} packages (online OSV or offline pack)")
    groups: dict = {}
    for p, adv in pairs:
        key = (p["source"] if d["family"] in ("deb", "apk") else p["name"], adv.get("fixed"))
        g = groups.setdefault(key, {"pkgs": {}, "advs": {}})
        g["pkgs"][p["name"]] = p
        g["advs"].setdefault(adv["id"], adv)
    for (pkg, fixed), g in groups.items():
        advs = sorted(g["advs"].values(), key=lambda a: (-SEV_RANK.get(_sev(a), 0), -(_cvss(a) or 0)))
        top = advs[0]
        sev = _sev(top)
        installed = next(iter(g["pkgs"].values()))
        ver = installed["source_version"] if d["family"] in ("deb", "apk") else installed["version"]
        cves = [_cve(a) for a in advs]
        names = sorted(g["pkgs"])
        out.append({
            "engine": "sca", "rule_id": "NM-OS-001" if fixed else "NM-OS-002", "category": "os-package",
            "title": (f"{pkg} {ver}: {len(cves)} vulnerabilit{'y' if len(cves) == 1 else 'ies'} fixed in {fixed}" if fixed else
                      f"{pkg} {ver}: {len(cves)} vulnerabilit{'y' if len(cves) == 1 else 'ies'} without a released fix"),
            "severity": sev if fixed else ("low" if sev in ("low", "medium") else "medium"),
            "cvss": _cvss(top), "cve": _cve(top), "advisories": cves[:300], "repo": repo, "file": installed["file"],
            "package": pkg, "version": ver, "fixed_version": fixed, "ecosystem": f"{d['id']}-{d.get('version', '')}",
            "purl": ospkg.purl(installed, d), "binary_packages": names[:60], "advisory_source": source,
            "summary": (top.get("summary") or cpe.cve_meta(_cve(top)).get("summary") or "")[:200],
            "evidence": f"{d.get('name')}: {', '.join(names[:6])}{' …' if len(names) > 6 else ''} from source {pkg} {ver}; "
                        + ", ".join(cves[:10]) + (f" and {len(cves) - 10} more" if len(cves) > 10 else ""),
            "remediation": (f"Update the {pkg} packages to {fixed} or later (apt-get/apk/dnf upgrade, or rebuild the image on "
                            "a current base) and redeploy." if fixed else
                            f"No fixed {pkg} package is published for {d.get('name')} yet. Remove the package if it is not "
                            "needed, mitigate with configuration, or move to a release that has the fix; re-scan to pick "
                            "up the fix when it is released."),
        })
    return comps, out


def rootfs_checks(root: str, rel: str, repo: str) -> list[dict]:
    """Weak or empty password hashes and telnet in an extracted firmware or image root filesystem."""
    out = []
    pre = (rel.rstrip("/") + "/") if rel else ""
    for f in ("etc/shadow", "etc/passwd"):
        p = os.path.join(root, f)
        try:
            lines = open(p, encoding="utf-8", errors="replace").read().splitlines() if os.path.isfile(p) else []
        except OSError:
            lines = []
        for n, ln in enumerate(lines, 1):
            parts = ln.split(":")
            if len(parts) < 2 or not parts[0]:
                continue
            user, h = parts[0], parts[1]
            shell = parts[-1] if f == "etc/passwd" else ""
            weak = None
            if h == "" and (f == "etc/shadow" or not os.path.isfile(os.path.join(root, "etc/shadow"))):
                weak = "has no password"
            elif h.startswith("$1$"):
                weak = "uses an MD5-crypt password hash"
            elif re.fullmatch(r"[./0-9A-Za-z]{13}", h):
                weak = "uses a DES-crypt password hash"
            elif f == "etc/passwd" and h not in ("x", "*", "!", "!!", "") and not h.startswith("!"):
                weak = "stores its password hash in the world-readable passwd file"
            if weak and not shell.endswith(("nologin", "false")):
                out.append({"engine": "secrets", "rule_id": "NM-FW-001", "title": f"Account '{user}' {weak}",
                            "severity": "critical" if user == "root" or h == "" else "high", "cwe": "CWE-521",
                            "repo": repo, "file": pre + f, "line": n, "category": "firmware",
                            "evidence": f"{user}:{'<empty>' if h == '' else h[:6] + '…'}",
                            "remediation": "Ship the image without a usable password for this account (lock it) or with a "
                                           "per-device credential set at first boot; use SHA-512 or yescrypt hashes."})
    for f in ("etc/inittab", "etc/inetd.conf", "etc/init.d/rcS", "etc/rc.local", "etc/init.d/telnet"):
        p = os.path.join(root, f)
        try:
            text = open(p, encoding="utf-8", errors="replace").read() if os.path.isfile(p) else ""
        except OSError:
            text = ""
        m = re.search(r"(?m)^[^#\n]*\btelnetd\b", text)
        if m:
            out.append({"engine": "iac", "rule_id": "NM-FW-002", "title": "Telnet service started at boot",
                        "severity": "high", "cwe": "CWE-319", "repo": repo, "file": pre + f,
                        "line": text.count("\n", 0, m.start()) + 1, "category": "firmware",
                        "evidence": m.group(0).strip()[:120],
                        "remediation": "Remove telnetd from the image; use SSH with key authentication, or no remote shell."})
    return out


def native_findings(comps: list[dict], repo: str) -> list[dict]:
    """Known vulnerabilities and end of life for components identified in binaries and firmware (CPE matching)."""
    out, done = [], set()
    for c in comps:
        if c["ecosystem"] != "binary":
            continue
        key = (c["name"], c["version"], c["file"])
        if key in done:
            continue
        done.add(key)
        if c.get("eol"):
            m = re.match(r"(\d+\.\d+)", c["version"])
            f = eol.finding(c["eol"], m.group(1) if c["eol"] in ("linux",) and m else c["version"], c["file"], None, repo,
                            f"library copied into the repository {c['name']}")
            if f:
                out.append(f)
        hits = cpe.lookup(c["cpe"], c["version"])
        if not hits:
            continue
        hits.sort(key=lambda h: (-SEV_RANK.get(h.get("severity"), 0), -(h.get("cvss") or 0)))
        top = hits[0]
        fixed = sorted({h["fixed"] for h in hits if h.get("fixed")}, key=cpe._key)
        out.append({"engine": "sca", "rule_id": "NM-BIN-002", "category": "binary",
                    "title": f"{c['name']} {c['version']} in {os.path.basename(c['file'].split('!/')[-1])}: "
                             f"{len(hits)} known vulnerabilit{'y' if len(hits) == 1 else 'ies'} ({top['id']})",
                    "severity": top.get("severity") or "medium", "cvss": top.get("cvss"), "cve": top["id"], "cwe": top.get("cwe"),
                    "repo": repo, "file": c["file"], "package": c["name"], "version": c["version"], "ecosystem": "binary",
                    "fixed_version": fixed[-1] if fixed else None, "advisories": [h["id"] for h in hits][:300],
                    "detection": c.get("detection"), "cpe": c["cpe"],
                    "evidence": f"{c.get('detection')}; matched by CPE {c['cpe'][0]}: " + ", ".join(h["id"] for h in hits[:10])
                                + (f" and {len(hits) - 10} more" if len(hits) > 10 else ""),
                    "summary": (top.get("summary") or "")[:200],
                    "remediation": (f"Rebuild or update the component that ships {c['name']} {c['version']} to {fixed[-1]} or "
                                    f"later (static copies need a rebuild against the fixed library; firmware needs a vendor "
                                    f"update)." if fixed else
                                    f"Update {c['name']} to its newest release; for firmware, apply the vendor's latest "
                                    "image.")})
    return out


def scan(path: str, repo: str) -> dict:
    """{'components', 'findings', 'language_components', 'notes'} for everything below the application layer."""
    comps, findings, notes = [], [], []
    try:
        findings += infra.scan(path, repo)
    except Exception as e:  # noqa: BLE001 - one malformed template must not stop the scan
        notes.append(f"infrastructure versions: {type(e).__name__}")
    b = binaries.scan(path, repo)
    findings += b["findings"]
    notes += b.get("notes") or []
    native = [c for c in b["components"] if c["ecosystem"] == "binary"]
    lang = [c for c in b["components"] if c["ecosystem"] != "binary"]
    findings += native_findings(native, repo)
    roots = [(r, os.path.relpath(r, path).replace("\\", "/").lstrip("./") if r != path else "") for r in ospkg.find_roots(path)]
    for tmp, rel in b["roots"]:
        found = ospkg.find_roots(tmp, max_depth=10)
        roots += [(r, rel + "!/" + os.path.relpath(r, tmp).replace("\\", "/")) for r in found] or [(tmp, rel)]
    for r, rel in roots:
        inv = ospkg.inventory(r, rel)
        c, f = os_findings(inv, repo)
        comps += c
        findings += f
        notes += inv["unsupported"]
        if r != path or inv.get("distro"):
            findings += rootfs_checks(r, rel, repo)
        if any(r == t or r.startswith(t + os.sep) for t in b.get("temps", [])):
            # an unpacked firmware root: scan its binaries too
            sub = binaries.scan(r, repo)
            for x in sub["components"]:
                x["file"] = f"{rel}!/{x['file']}"
            findings += native_findings([x for x in sub["components"] if x["ecosystem"] == "binary"], repo)
            lang += [x for x in sub["components"] if x["ecosystem"] != "binary"]
            native += [x for x in sub["components"] if x["ecosystem"] == "binary"]
    for t in b.get("temps", []):
        shutil.rmtree(t, ignore_errors=True)
    for c in native:
        comps.append({"ecosystem": "binary", "name": c["name"], "version": c["version"], "file": c["file"],
                      "purl": f"pkg:generic/{c['name']}@{c['version']}", "scope": "embedded", "via": None,
                      "license": "unknown", "detection": c.get("detection"),
                      "cpe": f"cpe:2.3:{c['cpe'][0]}:{c['version']}:*:*:*:*:*:*:*"})
    for c in lang:
        name = c["name"]
        c.update({"purl": f"pkg:{'golang' if c['ecosystem'] == 'go' else c['ecosystem']}/{name.replace(':', '/')}@{c['version']}",
                  "scope": "embedded", "via": None, "license": "unknown"})
    return {"components": comps, "findings": findings, "language_components": lang, "notes": notes}
