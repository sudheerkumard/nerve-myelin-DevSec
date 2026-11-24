# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Governed suppression.

  .myelinignore (repository root) — gitignore-style globs for paths that are not shipped code
      (intentionally vulnerable fixtures, test vectors, vendored samples). Excluded findings are counted
      in the scan result, never silently lost.

  Inline:  # myelin:ignore[NM-SEC-001] -- reason the finding does not apply
      on the flagged line or the line above. A rule id and a reason are both mandatory; a bare
      `myelin:ignore` is ignored. Suppressed findings keep status "suppressed" with the reason and
      location, so they remain visible in reports and audit evidence and do not affect the gate.
"""
import fnmatch
import os
import re

COMMENT = ("#", "//", "--", "/*", "*", "<!--", ";")
INLINE = re.compile(r"myelin:ignore\[([A-Za-z0-9_.:,\- ]+)\]\s*--\s*(\S.{3,})")


def load_ignore(root: str) -> list[str]:
    path = os.path.join(root, ".myelinignore")
    if not os.path.isfile(path):
        return []
    pats = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#"):
            pats.append(line.lstrip("/"))
    return pats


def path_ignored(rel: str, patterns: list[str]) -> bool:
    rel = (rel or "").lstrip("./")
    for p in patterns:
        if p.endswith("/"):
            if rel.startswith(p) or ("/" + p) in ("/" + rel):
                return True
        elif fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p + "/*") or fnmatch.fnmatch(os.path.basename(rel), p):
            return True
    return False


def _inline(root: str, f: dict, cache: dict) -> dict | None:
    rel, line = f.get("file"), f.get("line")
    if not rel or not line:
        return None
    full = os.path.join(root, rel)
    if full not in cache:
        try:
            cache[full] = open(full, encoding="utf-8", errors="ignore").read().splitlines()
        except OSError:
            cache[full] = []
    lines = cache[full]
    for n in (line, line - 1):
        if 1 <= n <= len(lines):
            text = lines[n - 1]
            if n != line and not text.lstrip().startswith(COMMENT):   # line above must be a standalone comment
                continue
            m = INLINE.search(text)
            if m and f.get("rule_id") in {r.strip() for r in m.group(1).split(",")}:
                return {"type": "inline", "reason": m.group(2).strip(), "location": f"{rel}:{n}"}
    return None


def apply(root: str, findings: list[dict]) -> tuple[list[dict], int]:
    patterns = load_ignore(root) if os.path.isdir(root) else []
    kept, ignored, cache = [], 0, {}
    for f in findings:
        if patterns and path_ignored(f.get("file", ""), patterns):
            ignored += 1
            continue
        if os.path.isdir(root):
            s = _inline(root, f, cache)
            if s:
                f["status"], f["suppression"] = "suppressed", s
        kept.append(f)
    return kept, ignored
