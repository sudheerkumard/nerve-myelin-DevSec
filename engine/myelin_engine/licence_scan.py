# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Licences found in the source tree itself, and conflicts with the project's own licence.

Dependency metadata is only half of licence compliance. This module reads the files:

* licence texts (LICENSE, LICENCE, COPYING, UNLICENSE and variants) anywhere in the tree, identified by the
  characteristic wording of each licence (about 30 SPDX licences, plus non-OSI restrictions such as the JSON
  licence's "Good, not Evil" clause, the Commons Clause, the Business Source and Server Side Public licences);
* ``SPDX-License-Identifier:`` tags in source file headers;
* copyright statements in licence files (for the attribution notice).

Findings:

* NM-LIC-101  third-party code under a copyleft or restrictive licence copied into the repository (a licence file
  in a sub-folder that differs from the project's licence);
* NM-LIC-102  source files that declare a copyleft licence in an SPDX header, different from the project's;
* NM-LIC-103  a dependency whose licence conflicts with the project's licence (for example a GPL dependency in an
  MIT-licensed or proprietary project, or Apache-2.0 code in a GPL-2.0-only project);
* NM-LIC-104  a licence that restricts use and is not an open-source licence.
"""
from __future__ import annotations

import os
import re

from .license_policy import _classify

SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "target", "obj", "bin", ".tox"}
# LICENSE, LICENCE.md, LICENSE-MIT, LICENSE.APACHE, COPYING.LIB, UNLICENSE, COPYRIGHT.txt (not license_policy.py)
LICENCE_FILE = re.compile(r"(?i)^(?:un)?licen[cs]e(?:s)?(?:[-_.][a-z0-9.\-]+?)?(?:\.(?:txt|md|rst|html?|adoc))?$"
                          r"|^copying(?:[-_.][a-z0-9.\-]+?)?(?:\.(?:txt|md))?$|^copyright(?:\.txt|\.md)?$")
_CODE_EXT = re.compile(r"(?i)\.(py|js|ts|tsx|jsx|java|kt|cs|go|rs|c|h|cpp|rb|php|json|ya?ml|xml|toml|cfg|ini|sh|ps1)$")
SOURCE_EXT = (".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".kt", ".cs", ".go", ".rs", ".c", ".h", ".cc", ".cpp",
              ".hpp", ".rb", ".php", ".swift", ".scala", ".m", ".sh", ".css", ".scss", ".vue")

# (SPDX id, all of these phrases (case-insensitive, whitespace-normalised), none of these)
TEXTS = [
    ("AGPL-3.0", ["gnu affero general public license", "version 3"], []),
    ("LGPL-3.0", ["gnu lesser general public license", "version 3"], []),
    ("LGPL-2.1", ["gnu lesser general public license", "version 2.1"], []),
    ("LGPL-2.0", ["gnu library general public license", "version 2"], []),
    ("GPL-3.0", ["gnu general public license", "version 3"], ["lesser general", "affero"]),
    ("GPL-2.0", ["gnu general public license", "version 2"], ["lesser general", "library general", "affero"]),
    ("SSPL-1.0", ["server side public license"], []),
    ("BUSL-1.1", ["business source license"], []),
    ("Elastic-2.0", ["elastic license 2.0"], []),
    ("MPL-2.0", ["mozilla public license", "2.0"], []),
    ("MPL-1.1", ["mozilla public license", "1.1"], []),
    ("EPL-2.0", ["eclipse public license", "v 2.0"], []),
    ("EPL-1.0", ["eclipse public license", "v 1.0"], []),
    ("EUPL-1.2", ["european union public licen", "1.2"], []),
    ("CDDL-1.0", ["common development and distribution license"], []),
    ("CPAL-1.0", ["common public attribution license"], []),
    ("OSL-3.0", ["open software license", "3.0"], []),
    ("Apache-2.0", ["apache license", "version 2.0"], []),
    ("Apache-1.1", ["apache software license", "version 1.1"], []),
    ("Artistic-2.0", ["artistic license 2.0"], []),
    ("BSL-1.0", ["boost software license - version 1.0"], []),
    ("CC0-1.0", ["cc0 1.0 universal"], []),
    ("CC-BY-NC-4.0", ["attribution-noncommercial 4.0"], []),
    ("CC-BY-SA-4.0", ["attribution-sharealike 4.0"], []),
    ("CC-BY-4.0", ["creative commons attribution 4.0"], ["noncommercial", "sharealike", "noderivatives"]),
    ("Unlicense", ["this is free and unencumbered software released into the public domain"], []),
    ("WTFPL", ["do what the fuck you want to public license"], []),
    ("JSON", ["the software shall be used for good, not evil"], []),
    ("Zlib", ["this software is provided 'as-is', without any express or implied", "altered source versions must be plainly marked"], []),
    ("ISC", ["permission to use, copy, modify, and/or distribute this software for any purpose with or without fee"], []),
    ("ISC", ["permission to use, copy, modify, and distribute this software for any purpose with or without fee"], []),
    ("BSD-4-Clause", ["redistribution and use in source and binary forms", "all advertising materials mentioning"], []),
    ("BSD-3-Clause", ["redistribution and use in source and binary forms", "neither the name"], []),
    ("BSD-3-Clause", ["redistribution and use in source and binary forms", "may be used to endorse or promote"], []),
    ("BSD-2-Clause", ["redistribution and use in source and binary forms", "this list of conditions"], []),
    ("MIT", ["permission is hereby granted, free of charge, to any person obtaining a copy"], []),
    ("PostgreSQL", ["permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee"], []),
]
# Restrictions that make an otherwise permissive licence non-open-source.
RESTRICTIVE = {"JSON", "SSPL-1.0", "BUSL-1.1", "Elastic-2.0", "CC-BY-NC-4.0", "Commons-Clause"}
_OR_LATER = re.compile(r"(?i)or\s*\(?at your option\)?\s*any later version")
# The full GNU licence texts end with a "How to apply" appendix that always contains the "any later version" wording,
# so -or-later is only read from a notice that precedes the terms (or a notice-only file), never from the appendix.
_TERMS = re.compile(r"(?i)TERMS AND CONDITIONS")
_COPY = re.compile(r"(?im)^\s*(?:[#*/;-]+\s*)?(copyright\s*(?:\(c\)|©)?\s*(?:\d{4}(?:\s*[-,]\s*\d{4})*)[^\n]{2,120})$")
_SPDX = re.compile(r"SPDX-License-Identifier:\s*((?:[A-Za-z0-9][A-Za-z0-9.+\-]*|\(|\))(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9(][A-Za-z0-9.+\-()]*)*)")
PERMISSIVE_PROJECT = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense", "0BSD", "BSL-1.0", "Zlib",
                      "CC0-1.0", "PostgreSQL"}


def identify(text: str) -> str | None:
    """SPDX identifier for a licence text, or None."""
    t = re.sub(r"\s+", " ", text.lower())[:60_000]
    if "commons clause" in t and "license condition" in t:
        return "Commons-Clause"
    head = t[:250]                                         # GNU texts name themselves in the title (GPL-3.0 §13 cites AGPL)
    hits = [(head.find(k), f) for k, f in (("gnu affero general public license", "AGPL"), ("gnu lesser general public license", "LGPL"),
                                            ("gnu library general public license", "LGPL"), ("gnu general public license", "GPL"))
            if k in head]
    fam = min(hits)[1] if hits else None                   # the first one named is the title
    for spdx, must, never in TEXTS:
        if fam and spdx.split("-")[0] in ("AGPL", "LGPL", "GPL") and spdx.split("-")[0] != fam:
            continue
        if all(m in t for m in must) and (fam == spdx.split("-")[0] or not any(n in t for n in never)):
            if spdx in ("GPL-3.0", "GPL-2.0", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "LGPL-2.0"):
                m = _TERMS.search(text)
                notice = text[:m.start()] if m else text
                return spdx + ("-or-later" if _OR_LATER.search(notice) else "-only")
            return spdx
    return None


def _kind(spdx: str | None) -> str:
    if not spdx:
        return "unknown"
    if spdx in RESTRICTIVE:
        return "restrictive"
    first = re.split(r"\s+(?:AND|OR|WITH)\s+", spdx.strip("() "))[0]
    return _classify(first)


def inventory(root: str, max_files: int = 40_000) -> dict:
    licence_files, tags, copyrights = [], {}, []
    n = 0
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP]
        rel_dir = os.path.relpath(d, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        for fn in files:
            n += 1
            if n > max_files:
                break
            p = os.path.join(d, fn)
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
            try:
                if LICENCE_FILE.match(fn) and not _CODE_EXT.search(fn) and os.path.getsize(p) < 300_000:
                    text = open(p, encoding="utf-8", errors="replace").read()
                    lic = identify(text)
                    licence_files.append({"file": rel, "dir": rel_dir, "licence": lic or "unrecognised"})
                    for m in _COPY.finditer(text[:20_000]):
                        c = m.group(1).strip()
                        if "copyright holders" not in c.lower() and c not in copyrights and len(copyrights) < 300:
                            copyrights.append(c)
                elif fn.endswith(SOURCE_EXT) and os.path.getsize(p) < 2_000_000:
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        head = fh.read(3000)
                    m = _SPDX.search(head)
                    if m:
                        tags.setdefault(m.group(1).strip().rstrip("."), []).append(rel)
            except OSError:
                continue
    root_lic = next((f["licence"] for f in sorted(licence_files, key=lambda f: len(f["file"])) if not f["dir"]
                     and f["licence"] != "unrecognised"), None)
    if root_lic and re.match(r"^(A|L)?GPL-\d\.\d", root_lic) and tags:
        fam = root_lic.rsplit("-", 1)[0] if root_lic.endswith(("-only", "-later")) else root_lic
        fam = fam.replace("-or", "")
        top = max(tags.items(), key=lambda kv: len(kv[1]))[0]
        if top.startswith(fam + "-") and top in (fam + "-only", fam + "-or-later"):
            root_lic = top                                # the project's own SPDX headers say which variant it uses
    return {"project_licence": root_lic, "licence_files": licence_files, "spdx_tags": tags, "copyrights": copyrights}


def _conflict(project: str | None, dep: str) -> str | None:
    """Why a dependency licence conflicts with the project licence, or None."""
    kind = _kind(dep)
    proj = project or "proprietary"
    pkind = "proprietary" if proj == "proprietary" else _kind(proj)
    if kind in ("strong_copyleft", "network_copyleft"):
        if pkind in ("permissive", "proprietary", "weak_copyleft"):
            what = "has no open-source licence (treated as proprietary)" if proj == "proprietary" else f"is licensed {proj}"
            return (f"The project {what}, but {dep} requires the combined work to be distributed under {dep}"
                    + (" — including when it is only offered over a network" if kind == "network_copyleft" else "") + ".")
        if proj.startswith("GPL-2.0-only") and dep.startswith(("GPL-3.0", "AGPL-3.0")):
            return f"GPL-2.0-only code cannot be combined with {dep} code."
    if proj.startswith("GPL-2.0-only") and dep.split()[0] in ("Apache-2.0", "MPL-1.1", "EPL-1.0", "EPL-2.0", "CDDL-1.0"):
        return f"{dep} is incompatible with GPL-2.0-only (its additional licence terms), so the two cannot be combined."
    return None


def findings(root: str, repo: str, components: list[dict] | None = None, inv: dict | None = None) -> list[dict]:
    inv = inv or inventory(root)
    proj = inv["project_licence"]
    out = []
    for f in inv["licence_files"]:
        lic, kind = f["licence"], _kind(f["licence"])
        if not f["dir"] or lic == "unrecognised" or lic == proj:
            continue
        if kind in ("strong_copyleft", "network_copyleft", "restrictive"):
            sev = "high" if kind != "weak_copyleft" else "medium"
            out.append({
                "engine": "license", "rule_id": "NM-LIC-104" if kind == "restrictive" else "NM-LIC-101",
                "title": (f"Third-party code under {lic} copied into {f['dir']}/" if kind != "restrictive"
                          else f"{f['dir']}/ is under {lic}, which restricts use and is not an open-source licence"),
                "severity": sev, "file": f["file"], "line": 1, "repo": repo, "license": lic, "cwe": None,
                "package": f["dir"].split("/")[-1], "version": None, "category": "embedded-licence",
                "remediation": (f"Code in {f['dir']}/ is distributed under {lic}. "
                                + ("If you ship this repository's product, the copyleft terms apply to the combined work: "
                                   "replace the code, isolate it as a separate program, or get legal approval."
                                   if kind != "restrictive" else
                                   "Check the restriction against how the product is used (field of use, competing "
                                   "services, production use) and replace the code if it does not fit."))})
        elif kind == "weak_copyleft":
            out.append({"engine": "license", "rule_id": "NM-LIC-101", "title": f"Third-party code under {lic} copied into {f['dir']}/",
                        "severity": "low", "file": f["file"], "line": 1, "repo": repo, "license": lic,
                        "package": f["dir"].split("/")[-1], "category": "embedded-licence",
                        "remediation": f"Changes to the files in {f['dir']}/ must be published under {lic}; keep its licence "
                                       "notice and list it in your third-party notices."})
    for tag, files in inv["spdx_tags"].items():
        kind = _kind(tag)
        if tag == proj or kind not in ("strong_copyleft", "network_copyleft", "restrictive"):
            continue
        if proj and _kind(proj) == kind:
            continue
        out.append({"engine": "license", "rule_id": "NM-LIC-102",
                    "title": f"{len(files)} source file(s) declare {tag} (SPDX header)", "severity": "medium",
                    "file": files[0], "line": 1, "repo": repo, "license": tag, "package": None, "category": "file-licence",
                    "locations": [{"file": x, "line": 1} for x in files[:20]], "occurrences": len(files),
                    "remediation": f"These files are under {tag}, unlike the project ({proj or 'no licence file'}). Confirm "
                                   "they are meant to be, or replace them; copyleft terms extend to the work they are part of."})
    seen = set()
    for c in components or []:
        lic = str(c.get("license") or "")
        if not lic or lic.lower() in ("unknown", "noassertion"):
            continue
        why = _conflict(proj, lic)
        if not why or (c.get("name"), lic) in seen:
            continue
        seen.add((c.get("name"), lic))
        out.append({"engine": "license", "rule_id": "NM-LIC-103",
                    "title": f"Licence conflict: {c['name']} ({lic}) in a {proj + ' licensed' if proj else 'proprietary (no open-source licence)'} project",
                    "severity": "high" if c.get("scope") != "dev" else "medium", "file": c.get("file"), "line": None,
                    "repo": repo, "license": lic, "package": c["name"], "version": c.get("version"),
                    "category": "licence-conflict", "dependency_type": "transitive" if c.get("scope") == "transitive" else "direct",
                    "remediation": why + " Replace the component, obtain a commercial licence, or change the project's licence "
                                         "with legal approval. Development-only tools that are not shipped are usually not affected."})
    return out
