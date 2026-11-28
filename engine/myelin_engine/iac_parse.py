# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Read infrastructure templates into resource records, with no external tool.

* Terraform (HCL): ``resource`` and ``data`` blocks with attributes, nested blocks (as lists of dicts), lists, maps,
  heredocs and ``jsonencode(...)`` objects (IAM policies). Anything computed (``var.x``, ``aws_s3_bucket.b.id``,
  functions) is kept as an :class:`Expr` so checks can tell "unknown" from "false".
* CloudFormation (YAML or JSON, short-form intrinsic tags such as ``!Ref`` and ``!Sub``).
* Azure Resource Manager templates (JSON) and Bicep (resource declarations with their object bodies).

Each record: ``{"fmt", "type", "name", "file", "line", "attrs"}``.
"""
from __future__ import annotations

import json
import os
import re

MAX = 3_000_000
SKIP = {".git", "node_modules", ".terraform", "vendor", "dist", "build", "target", "__pycache__", ".venv"}


class Expr(str):
    """A value computed at plan time (a reference, variable or function call)."""


def is_lit(v) -> bool:
    return v is not None and not isinstance(v, Expr)


# ------------------------------------------------------------------------------------------ HCL
class _HCL:
    def __init__(self, text):
        self.s, self.i, self.n = text, 0, len(text)

    def line(self, pos=None):
        return self.s.count("\n", 0, self.i if pos is None else pos) + 1

    def ws(self, newlines=True):
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]
            if c in " \t\r" or (newlines and c == "\n"):
                self.i += 1
            elif c == "#" or s.startswith("//", self.i):
                j = s.find("\n", self.i)
                self.i = n if j < 0 else j
            elif s.startswith("/*", self.i):
                j = s.find("*/", self.i + 2)
                self.i = n if j < 0 else j + 2
            else:
                break

    def ident(self):
        m = re.compile(r"[A-Za-z_][\w\-]*").match(self.s, self.i)
        if not m:
            return None
        self.i = m.end()
        return m.group(0)

    def string(self):
        assert self.s[self.i] == '"'
        self.i += 1
        out, depth = [], 0
        while self.i < self.n:
            c = self.s[self.i]
            if c == "\\" and self.i + 1 < self.n:
                nxt = self.s[self.i + 1]
                out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, "\\" + nxt))
                self.i += 2
                continue
            if self.s.startswith("${", self.i) or self.s.startswith("%{", self.i):
                depth += 1
                out.append(self.s[self.i:self.i + 2])
                self.i += 2
                continue
            if c == "}" and depth:
                depth -= 1
            if c == '"' and not depth:
                self.i += 1
                break
            out.append(c)
            self.i += 1
        text = "".join(out)
        return Expr(text) if "${" in text else text

    def heredoc(self):
        m = re.compile(r"<<-?\s*([A-Za-z_]\w*)\s*\n").match(self.s, self.i)
        tag = m.group(1)
        end = re.compile(rf"(?m)^\s*{tag}\s*$").search(self.s, m.end())
        body = self.s[m.end():end.start() if end else self.n]
        self.i = end.end() if end else self.n
        return Expr(body) if "${" in body else body

    def raw_expr(self):
        """Consume an expression we do not evaluate (references, function calls, conditionals)."""
        start, depth = self.i, 0
        while self.i < self.n:
            c = self.s[self.i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif c == '"':
                self.string()
                continue
            elif (c == "\n" or c == ",") and depth == 0:
                break
            self.i += 1
        text = self.s[start:self.i].strip()
        m = re.match(r"^jsonencode\((.*)\)$", text, re.S)
        if m:
            try:
                return _HCL(m.group(1)).value()
            except (IndexError, AssertionError, ValueError):
                pass
        return Expr(text)

    def value(self):
        self.ws()
        if self.i >= self.n:
            return None
        c = self.s[self.i]
        if c == '"':
            v = self.string()
        elif self.s.startswith("<<", self.i):
            v = self.heredoc()
        elif c == "[":
            self.i += 1
            v = []
            while True:
                self.ws()
                if self.i >= self.n or self.s[self.i] == "]":
                    self.i += 1
                    break
                v.append(self.value())
                self.ws()
                if self.i < self.n and self.s[self.i] == ",":
                    self.i += 1
        elif c == "{":
            self.i += 1
            v = {}
            while True:
                self.ws()
                if self.i >= self.n or self.s[self.i] == "}":
                    self.i += 1
                    break
                if self.s[self.i] == '"':
                    k = self.string()
                else:
                    k = self.ident()
                    if k is None:                     # (expr) keys or junk: skip to the end of the object entry
                        self.raw_expr()
                        if self.i < self.n and self.s[self.i] in ",\n":
                            self.i += 1
                        continue
                self.ws()
                if self.i < self.n and self.s[self.i] in "=:":
                    self.i += 1
                v[str(k)] = self.value()
                self.ws()
                if self.i < self.n and self.s[self.i] == ",":
                    self.i += 1
        else:
            m = re.compile(r"(-?\d+(?:\.\d+)?)(?=\s*[,\n\]})])").match(self.s, self.i)
            if m:
                self.i = m.end()
                v = float(m.group(1)) if "." in m.group(1) else int(m.group(1))
            else:
                m = re.compile(r"(true|false|null)(?=\s*[,\n\]})#/])").match(self.s, self.i)
                if m:
                    self.i = m.end()
                    v = {"true": True, "false": False, "null": None}[m.group(1)]
                else:
                    return self.raw_expr()
        # a literal followed by an operator is an expression (e.g. "a" == var.b ? 1 : 2)
        save = self.i
        self.ws(newlines=False)
        if self.i < self.n and self.s[self.i] in "?=!<>&|+*-/%" and not self.s.startswith("=>", self.i):
            self.i = save
            rest = self.raw_expr()
            return Expr(f"{v!r} {rest}")
        self.i = save
        return v

    def body(self, until_brace=True):
        attrs = {}
        while True:
            self.ws()
            if self.i >= self.n:
                return attrs
            if self.s[self.i] == "}":
                self.i += 1
                return attrs
            start = self.i
            name = self.ident()
            if name is None:
                self.i += 1
                continue
            self.ws(newlines=False)
            if self.i < self.n and self.s[self.i] == "=" and not self.s.startswith("==", self.i):
                self.i += 1
                attrs[name] = self.value()
                continue
            labels = []
            while self.i < self.n and self.s[self.i] in '"' or (self.i < self.n and re.match(r"[A-Za-z_]", self.s[self.i])):
                labels.append(self.string() if self.s[self.i] == '"' else self.ident())
                self.ws(newlines=False)
            if self.i < self.n and self.s[self.i] == "{":
                line = self.line(start)
                self.i += 1
                inner = self.body()
                inner["__labels__"] = labels
                inner["__line__"] = line
                attrs.setdefault(name, []).append(inner)
            else:
                self.raw_expr()


def parse_hcl(text: str) -> dict:
    try:
        return _HCL(text).body(until_brace=False)
    except (IndexError, AssertionError, RecursionError, AttributeError):
        return {}


def _terraform(text, rel):
    doc = parse_hcl(text)
    out = []
    for kind in ("resource", "data"):
        for b in doc.get(kind, []):
            labels = b.get("__labels__") or []
            if len(labels) >= 2:
                out.append({"fmt": "tf", "kind": kind, "type": labels[0], "name": labels[1], "file": rel,
                            "line": b.get("__line__"), "attrs": b})
    for b in doc.get("module", []):
        labels = b.get("__labels__") or []
        out.append({"fmt": "tf", "kind": "module", "type": "module", "name": labels[0] if labels else "", "file": rel,
                    "line": b.get("__line__"), "attrs": b})
    return out


# ------------------------------------------------------------------------------------------ CloudFormation
def _cfn_loader():
    import yaml

    class Loader(yaml.SafeLoader):
        pass

    def intrinsic(loader, tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            val = loader.construct_scalar(node)
        elif isinstance(node, yaml.SequenceNode):
            val = loader.construct_sequence(node, deep=True)
        else:
            val = loader.construct_mapping(node, deep=True)
        return Expr(json.dumps({"Fn::" + tag_suffix if tag_suffix != "Ref" else "Ref": val}, default=str))

    Loader.add_multi_constructor("!", intrinsic)
    return Loader


def _resolve_cfn(v):
    """Intrinsic functions (Ref, Fn::Sub, ...) are plan-time values: keep them as Expr."""
    if isinstance(v, dict):
        if len(v) == 1 and next(iter(v)) in ("Ref",) or (len(v) == 1 and str(next(iter(v))).startswith("Fn::")):
            return Expr(json.dumps(v, default=str))
        return {k: _resolve_cfn(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_resolve_cfn(x) for x in v]
    return v


def _cloudformation(text, rel):
    try:
        if rel.endswith(".json"):
            doc = json.loads(text)
        else:
            import yaml
            doc = yaml.load(text, Loader=_cfn_loader())  # noqa: S506  # myelin:ignore[NM-SAST-006] -- SafeLoader subclass, intrinsic tags only
    except Exception:  # noqa: BLE001 - not a template
        return []
    if not isinstance(doc, dict) or not isinstance(doc.get("Resources"), dict):
        return []
    out = []
    for name, res in doc["Resources"].items():
        if not isinstance(res, dict) or not str(res.get("Type", "")).startswith(("AWS::", "Alexa::")):
            continue
        m = re.search(rf"(?m)^\s*{re.escape(str(name))}\s*:", text) or re.search(rf'"{re.escape(str(name))}"\s*:', text)
        out.append({"fmt": "cfn", "type": res["Type"], "name": name, "file": rel,
                    "line": text.count("\n", 0, m.start()) + 1 if m else None,
                    "attrs": _resolve_cfn(res.get("Properties") or {})})
    return out


# ------------------------------------------------------------------------------------------ ARM / Bicep
def _arm(text, rel):
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict) or "deploymentTemplate" not in str(doc.get("$schema", "")):
        return []
    out = []

    def walk(resources, parent=""):
        for r in resources or []:
            if not isinstance(r, dict):
                continue
            t = str(r.get("type", ""))
            full = f"{parent}/{t}" if parent and "/" not in t.split("/", 1)[0] and not t.startswith("Microsoft.") else t
            name = str(r.get("name", ""))
            m = re.search(re.escape(f'"{name}"'), text) if name else None
            out.append({"fmt": "arm", "type": full.lower(), "name": name, "file": rel,
                        "line": text.count("\n", 0, m.start()) + 1 if m else None,
                        "attrs": _arm_vals(r)})
            walk(r.get("resources"), full)
    walk(doc.get("resources"))
    return out


def _arm_vals(v):
    if isinstance(v, str) and v.startswith("[") and v.endswith("]"):
        return Expr(v)                                  # ARM template expression
    if isinstance(v, dict):
        return {k: _arm_vals(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_arm_vals(x) for x in v]
    return v


_BICEP_RES = re.compile(r"(?m)^\s*resource\s+(\w+)\s+'([\w.\-/]+)@[\w.\-]+'\s*(?:existing\s*)?=\s*(?:\[[^\]]*\]\s*)?(?:if\s*\([^)]*\)\s*)?\{")


def _bicep_obj(s: str, i: int):
    """Parse a Bicep object/array literal starting at s[i] in '{['; returns (value, next index)."""
    def skip(i):
        while i < len(s):
            if s[i] in " \t\r\n,":
                i += 1
            elif s.startswith("//", i):
                j = s.find("\n", i)
                i = len(s) if j < 0 else j
            elif s.startswith("/*", i):
                j = s.find("*/", i)
                i = len(s) if j < 0 else j + 2
            else:
                break
        return i

    def val(i):
        i = skip(i)
        c = s[i]
        if c == "{":
            i += 1
            obj = {}
            while True:
                i = skip(i)
                if s[i] == "}":
                    return obj, i + 1
                m = re.compile(r"'([^']*)'|([A-Za-z_$][\w$]*)").match(s, i)
                if not m:
                    j = s.find("\n", i)
                    i = len(s) if j < 0 else j
                    continue
                key = m.group(1) if m.group(1) is not None else m.group(2)
                i = skip(m.end())
                if s[i] == ":":
                    i += 1
                obj[key], i = val(i)
        if c == "[":
            i += 1
            arr = []
            while True:
                i = skip(i)
                if s[i] == "]":
                    return arr, i + 1
                x, i = val(i)
                arr.append(x)
        if c == "'":
            j = i + 1
            while j < len(s) and s[j] != "'":
                j += 2 if s[j] == "\\" else 1
            lit = s[i + 1:j]
            return (Expr(lit) if "${" in lit else lit), j + 1
        m = re.compile(r"(true|false|null|-?\d+(?:\.\d+)?)\b").match(s, i)
        if m and re.match(r"\s*(?:\n|\}|\]|,|//)", s[m.end():m.end() + 3] or "\n"):
            t = m.group(1)
            if t in ("true", "false", "null"):
                return {"true": True, "false": False, "null": None}[t], m.end()
            return (int(t) if t.lstrip("-").isdigit() else float(t)), m.end()
        # expression: up to end of line at depth 0
        j, depth = i, 0
        while j < len(s):
            ch = s[j]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif ch == "\n" and depth == 0:
                break
            j += 1
        return Expr(s[i:j].strip()), j

    return val(i)


def _bicep(text, rel):
    out = []
    for m in _BICEP_RES.finditer(text):
        try:
            body, _ = _bicep_obj(text, m.end() - 1)
        except (IndexError, ValueError, RecursionError):
            body = {}
        out.append({"fmt": "arm", "type": m.group(2).lower(), "name": m.group(1), "file": rel,
                    "line": text.count("\n", 0, m.start()) + 1, "attrs": body if isinstance(body, dict) else {}})
    return out


# ------------------------------------------------------------------------------------------ walk
def resources(root: str) -> list[dict]:
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP]
        for fn in files:
            low = fn.lower()
            if not low.endswith((".tf", ".json", ".yaml", ".yml", ".template", ".bicep")):
                continue
            p = os.path.join(d, fn)
            try:
                if os.path.getsize(p) > MAX:
                    continue
                text = open(p, encoding="utf-8-sig", errors="replace").read()
            except OSError:
                continue
            rel = os.path.relpath(p, root).replace("\\", "/")
            if low.endswith(".tf"):
                out += _terraform(text, rel)
            elif low.endswith(".bicep"):
                out += _bicep(text, rel)
            elif low.endswith(".json") and "deploymentTemplate" in text[:2000]:
                out += _arm(text, rel)
            elif "Resources" in text and ("AWS::" in text or "AWSTemplateFormatVersion" in text):
                out += _cloudformation(text, rel)
    return out
