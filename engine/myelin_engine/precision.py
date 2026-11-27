# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Precision pass for taint and configuration findings from the bundled Opengrep rules.

Pattern-based taint analysis follows every branch and treats a collection as tainted once any element is. This pass
removes the findings it can prove impossible from the source code itself, and resolves crypto algorithms that are
read from configuration files:

* constant conditions: ``if (<constant>) x = param; else x = "safe";`` and ``x = <constant> ? "safe" : param;``
* switch on a constant: ``switch ("ABC".charAt(1)) { case 'B': x = "safe"; ... }``
* collections with known contents: ``list.add("a"); list.add(param); list.remove(0); x = list.get(1);`` and
  ``map.put("k1", "a"); map.put("k2", param); x = map.get("k1");``
* configured algorithms: ``Cipher.getInstance(props.getProperty("alg", "AES/GCM/NoPadding"))`` is checked against the
  value in the project's .properties files (or the default when the key is not configured).

A finding is removed only when the value that reaches the sink is proven to be a literal. Anything the pass cannot
evaluate is kept, so the pass can only lower false positives, never hide a flow it does not understand.
"""
from __future__ import annotations

import os
import re

_LIT = re.compile(r'^\s*(\(\s*String\s*\)\s*)?("(?:[^"\\]|\\.)*"|\d+|null|true|false)\s*$')
_SKIP = {".git", "node_modules", "target", "build", "dist", ".gradle", ".idea", "vendor", "__pycache__", ".venv"}

WEAK_CIPHER = re.compile(r"(?i)^((DES|DESede|TripleDES|3DES|RC2|RC4|ARCFOUR|Blowfish)(/.*)?|.*/ECB/.*|AES|RSA)$")
WEAK_HASH = re.compile(r"(?i)^(MD2|MD4|MD5|SHA-?1|SHA)$")


def _is_literal(expr: str) -> bool:
    return bool(_LIT.match(expr or ""))


def _statement(lines: list[str], i: int) -> str:
    """The statement that starts on line index i (joined until the terminating semicolon)."""
    out = []
    for j in range(i, min(i + 8, len(lines))):
        out.append(lines[j].split("//")[0].strip())
        if ";" in lines[j]:
            break
    return " ".join(out)


def _int_vars(lines: list[str], upto: int) -> dict[str, int]:
    found = {}
    for ln in lines[max(0, upto - 60):upto + 1]:
        for m in re.finditer(r"\b(?:int|long|short|final int)\s+(\w+)\s*=\s*(-?\d+)\s*;", ln):
            found[m.group(1)] = int(m.group(2))
    return found


def _const_eval(expr: str, ints: dict[str, int]):
    """Evaluate an integer/boolean Java expression made only of literals and known int locals. None when unknown."""
    e = re.sub(r"\b([A-Za-z_]\w*)\b", lambda m: str(ints[m.group(1)]) if m.group(1) in ints else m.group(0), expr)
    if re.search(r"[A-Za-z_\"']", e.replace("true", "").replace("false", "")):
        return None
    e = e.replace("&&", " and ").replace("||", " or ").replace("!=", " != ").replace("true", "True").replace("false", "False")
    e = re.sub(r"!(?!=)", " not ", e)
    e = re.sub(r"(?<![/])/(?![/])", "//", e)        # Java integer division
    if not re.fullmatch(r"[\d\s()+\-*/%<>=!andortTrueFals]*", e):
        return None
    try:
        return eval(e, {"__builtins__": {}}, {})   # noqa: S307 - digits, operators and booleans only (checked above)
    except Exception:
        return None


def _split_ternary(rhs: str):
    """'cond ? a : b' -> (cond, a, b), top level only."""
    depth, q, c, instr = 0, None, None, False
    for k, ch in enumerate(rhs):
        if ch == '"' and (k == 0 or rhs[k - 1] != "\\"):
            instr = not instr
            continue
        if instr:
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0 and ch == "?" and q is None:
            q = k
        elif depth == 0 and ch == ":" and q is not None and c is None:
            c = k
    if q is None or c is None:
        return None
    return rhs[:q].strip(), rhs[q + 1:c].strip(), rhs[c + 1:].strip()


def _assign(stmt: str, var: str):
    m = re.match(rf"^(?:[\w.<>\[\]]+\s+)?{re.escape(var)}\s*=\s*(.+?);?\s*$", stmt)
    return m.group(1) if m else None


def _ternary_dead(lines, i, var) -> bool | None:
    rhs = _assign(_statement(lines, i), var)
    t = rhs and _split_ternary(rhs)
    if not t:
        return None
    val = _const_eval(t[0], _int_vars(lines, i))
    if val is None:
        return None
    return _is_literal(t[1] if val else t[2])


def _if_dead(lines, i, var) -> bool | None:
    """'if (C) v = A; else v = B;' on one or two lines: the branch taken assigns a literal."""
    window = " ".join(lines[j].split("//")[0].strip() for j in range(max(0, i - 2), min(len(lines), i + 3)))
    m = re.search(rf"if\s*\((.+?)\)\s*{re.escape(var)}\s*=\s*([^;]+);\s*else\s+{re.escape(var)}\s*=\s*([^;]+);", window)
    if not m:
        return None
    val = _const_eval(m.group(1), _int_vars(lines, i))
    if val is None:
        return None
    return _is_literal(m.group(2) if val else m.group(3))


def _switch_dead(lines, i, var) -> bool | None:
    """The tainted assignment sits in a switch whose selector is a constant and the matching case assigns a literal."""
    depth = 0
    for j in range(i, max(0, i - 60), -1):
        ln = lines[j].split("//")[0]
        depth += ln.count("}") - ln.count("{") if j != i else 0
        m = re.search(r"switch\s*\(\s*(\w+)\s*\)\s*\{", ln)
        if m and depth < 0:
            break
    else:
        return None
    sel, start = m.group(1), j
    value = None
    for ln in lines[max(0, start - 15):start]:
        g = re.search(rf"\b{sel}\s*=\s*'(.)'\s*;", ln) or re.search(rf"\b{sel}\s*=\s*(-?\d+)\s*;", ln)
        if g:
            value = g.group(1)
        c = re.search(rf"\b{sel}\s*=\s*(\w+)\.charAt\((\d+)\)\s*;", ln)
        if c:
            src = next((re.search(rf'\b{c.group(1)}\s*=\s*"([^"]*)"', x) for x in lines[max(0, start - 20):start]
                        if re.search(rf'\b{c.group(1)}\s*=\s*"', x)), None)
            if src and int(c.group(2)) < len(src.group(1)):
                value = src.group(1)[int(c.group(2))]
    if value is None:
        return None
    # walk the switch body: find the case group for `value` (or default) and the first assignment to var in it
    body, depth, active, matched = [], 0, False, False
    for ln in lines[start:start + 120]:
        s = ln.split("//")[0]
        depth += s.count("{") - s.count("}")
        body.append(s.strip())
        if depth <= 0 and len(body) > 1:
            break
    labels_hit = False
    for s in body[1:]:
        cm = re.match(r"case\s+'?([^':]+)'?\s*:", s)
        if cm:
            if not active:
                labels_hit = cm.group(1) == value
            active = labels_hit or active
            continue
        if s.startswith("default"):
            active = active or not matched
            continue
        if active:
            matched = True
            rhs = _assign(s, var)
            if rhs is not None:
                return _is_literal(rhs)
            if s.startswith("break") or s.startswith("return"):
                active = False
    return None


def _collection_dead(lines, i, var) -> bool | None:
    stmt = _statement(lines, i)
    rhs = _assign(stmt, var)
    if rhs is None:
        return None
    rhs = re.sub(r"^\(\s*String\s*\)\s*", "", rhs)
    lm = re.fullmatch(r"(\w+)\.get\((\d+)\)", rhs)
    mm = re.fullmatch(r'(\w+)\.get\(("[^"]*")\)', rhs)
    if not (lm or mm):
        return None
    name = (lm or mm).group(1)
    decl = next((j for j in range(i - 1, max(-1, i - 40), -1)
                 if re.search(rf"\b{name}\s*=\s*new\s+[\w.]*(ArrayList|LinkedList|HashMap|Hashtable|LinkedHashMap|TreeMap)\b", lines[j])), None)
    if decl is None:
        return None
    items, kv = [], {}
    for ln in lines[decl + 1:i]:
        s = ln.split("//")[0].strip()
        if not re.search(rf"\b{name}\.", s):
            continue
        if a := re.fullmatch(rf"{name}\.add\((.+)\);", s):
            items.append(a.group(1).strip())
        elif a := re.fullmatch(rf"{name}\.add\((\d+),\s*(.+)\);", s):
            items.insert(int(a.group(1)), a.group(2).strip())
        elif r := re.fullmatch(rf"{name}\.remove\((\d+)\);", s):
            if int(r.group(1)) >= len(items):
                return None
            items.pop(int(r.group(1)))
        elif p := re.fullmatch(rf'{name}\.put\(("[^"]*"),\s*(.+)\);', s):
            kv[p.group(1)] = p.group(2).strip()
        else:
            return None                             # an operation this pass does not model
    if lm:
        k = int(lm.group(2))
        return _is_literal(items[k]) if k < len(items) else None
    return _is_literal(kv[mm.group(2)]) if mm.group(2) in kv else None


CHECKS = (_ternary_dead, _if_dead, _switch_dead, _collection_dead)


def infeasible(lines: list[str], trace: dict) -> bool:
    """True when one step of the reported data flow is proven to carry a literal instead of the tainted value."""
    for v in trace.get("intermediate_vars") or []:
        try:
            line = v["location"]["start"]["line"] - 1
            var = str(v.get("content") or "")
        except (KeyError, TypeError):
            continue
        if not re.fullmatch(r"[A-Za-z_]\w*", var) or not (0 <= line < len(lines)):
            continue
        for check in CHECKS:
            try:
                if check(lines, line, var):
                    return True
            except (re.error, IndexError, ValueError):
                continue
    return False


def _properties(root: str) -> dict[str, str]:
    props: dict[str, str] = {}
    n = 0
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in _SKIP]
        for fn in files:
            if not fn.endswith(".properties") or n > 400:
                continue
            n += 1
            try:
                with open(os.path.join(d, fn), encoding="utf-8", errors="replace") as fh:
                    for ln in fh:
                        m = re.match(r"\s*([\w.\-]+)\s*[=:]\s*(.*?)\s*$", ln)
                        if m and not ln.lstrip().startswith(("#", "!")):
                            props.setdefault(m.group(1), m.group(2))
            except OSError:
                continue
    return props


def _mv(r: dict, name: str) -> str | None:
    mv = ((r.get("extra") or {}).get("metavars") or {}).get(name) or {}
    return mv.get("abstract_content")


def refine(doc: dict, root: str) -> dict:
    """Drop Opengrep results proven infeasible and resolve configuration-driven algorithms (in place)."""
    results = doc.get("results") or []
    if not results:
        return doc
    cache: dict[str, list[str]] = {}
    props = None
    keep = []
    for r in results:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        path = r.get("path") or ""
        full = path if os.path.isabs(path) else os.path.join(root, path)
        if not os.path.exists(full) and os.path.exists(path):
            full = path
        kind = meta.get("nervve-config-check")
        if kind:
            if props is None:
                props = _properties(root)
            key, default = _mv(r, "$KEY"), _mv(r, "$DEF")
            value = props.get(key or "", default)
            if value is None:
                continue                             # algorithm unknown: nothing proven
            weak = (WEAK_HASH if kind == "hash" else WEAK_CIPHER).match(value.strip())
            if not weak:
                continue
            extra["lines"] = f"{(extra.get('lines') or '').strip()}  [{key} = {value}]"
            keep.append(r)
            continue
        trace = extra.get("dataflow_trace")
        if trace and full.endswith((".java", ".kt")):
            if full not in cache:
                try:
                    with open(full, encoding="utf-8", errors="replace") as fh:
                        cache[full] = fh.read().splitlines()
                except OSError:
                    cache[full] = []
            if cache[full] and infeasible(cache[full], trace):
                continue
        keep.append(r)
    doc["results"] = keep
    doc.setdefault("nervve", {})["pruned"] = len(results) - len(keep)
    return doc
