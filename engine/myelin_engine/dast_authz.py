# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Multi-user authorisation testing for APIs (OWASP API Security Top 10 2023: API1, API3, API5, API2).

Given an OpenAPI spec and two or more test identities, NERvvE:
  1. calls each parameter-free GET operation as every identity and harvests object ids each user can see;
  2. for every GET operation with path parameters, fills them with ids owned by user A, confirms A can read the
     object, then requests the same object as every other user and anonymously
       → API1 Broken Object Level Authorisation (another user reads A's object)
       → API2 Broken Authentication (anyone reads it without credentials);
  3. calls privileged operations (configured, tagged "admin", or under /admin/) as non-privileged identities
       → API5 Broken Function Level Authorisation;
  4. inspects every successful response for sensitive properties (password hashes, secrets, card/ID numbers)
       → API3 Broken Object Property Level Authorisation (excessive data exposure).

Read-only: GET requests only, within the shared request budget and host scope of the DAST client.
Identities file (YAML/JSON):
  identities: [{name, role, headers: {Header: value}}]   value = literal | env:VAR | (online) vault reference
  cross_user_roles: [admin]          roles legitimately allowed to read other users' objects
  privileged: [{path: /api/admin/*, roles: [admin]}]
  seeds: {alice: {accountId: [ACC-1]}}   optional ids known to belong to an identity
"""
import fnmatch
import json
import os
import re
import urllib.parse

from .dast import _f

ID_KEY = re.compile(r"^(id|uuid|guid|key|.*(_id|Id|ID|_uuid|Uuid|_key|Key|_no|No|Number|_number))$")
SENSITIVE = re.compile(r"^(password|passwd|pwd|password_?hash|pass_?hash|hash|secret|client_?secret|api_?key|access_?token|"
                       r"refresh_?token|private_?key|ssn|social_?security.*|pan|pan_?number|aadhaar.*|card_?number|cc_?number|"
                       r"cvv|cvc|pin|otp|mfa_?secret|totp_?secret|dob|date_?of_?birth)$", re.I)
MAX_VALUES_PER_PARAM = 3


class IdentityError(ValueError):
    pass


def load_identities(source, resolve=None):
    """Load identities from a path or dict. resolve(value) maps env:/vault references to secrets."""
    if isinstance(source, (str, os.PathLike)):
        text = open(source, encoding="utf-8").read()
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            import yaml
            doc = yaml.safe_load(text)
    else:
        doc = source
    ids = doc.get("identities") or []
    if len(ids) < 2:
        raise IdentityError("authorisation testing needs at least two identities (e.g. two customers, or a customer and an admin)")

    def default_resolve(v):
        if isinstance(v, str) and v.startswith("env:"):
            val = os.environ.get(v[4:])
            if not val:
                raise IdentityError(f"environment variable {v[4:]} is not set")
            return val
        return v
    resolve = resolve or default_resolve
    out = []
    for i in ids:
        if not i.get("name") or not i.get("headers"):
            raise IdentityError("each identity needs a name and headers")
        out.append({"name": str(i["name"]), "role": str(i.get("role", "user")),
                    "headers": {k: resolve(v) for k, v in i["headers"].items()}})
    return {"identities": out, "cross_user_roles": set(doc.get("cross_user_roles") or ["admin"]),
            "privileged": doc.get("privileged") or [], "seeds": doc.get("seeds") or {}}


def _norm(k):
    return re.sub(r"[^a-z0-9]", "", k.lower())


def _walk(obj, cb, depth=0):
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            cb(k, v)
            _walk(v, cb, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:200]:
            _walk(v, cb, depth + 1)


def _json(body):
    try:
        return json.loads(body.decode("utf-8", "ignore"))
    except (ValueError, AttributeError):
        return None


def _singular(seg):
    seg = seg.lower()
    return seg[:-3] + "y" if seg.endswith("ies") else seg[:-1] if seg.endswith("s") else seg


def _operations(spec):
    server = ""
    if spec.get("servers"):
        server = urllib.parse.urlsplit(spec["servers"][0].get("url", "")).path.rstrip("/")
    elif spec.get("basePath"):
        server = spec["basePath"].rstrip("/")
    ops = []
    for path, item in (spec.get("paths") or {}).items():
        g = (item or {}).get("get")
        if not g:
            continue
        ops.append({"path": server + path, "params": re.findall(r"{([^}]+)}", path), "tags": [t.lower() for t in g.get("tags", [])],
                    "roles": g.get("x-myelin-roles"), "id": g.get("operationId") or path})
    return ops


def _privileged_roles(op, cfg):
    for rule in cfg["privileged"]:
        if fnmatch.fnmatch(op["path"], rule["path"]):
            return set(rule.get("roles") or ["admin"])
    if op["roles"]:
        return set(op["roles"])
    if "admin" in op["tags"] or "/admin/" in op["path"] + "/":
        return set(cfg["cross_user_roles"]) or {"admin"}
    return None


def _same_object(a_body, b_body, value):
    if a_body and b_body and a_body == b_body:
        return True
    return str(value) in b_body.decode("utf-8", "ignore") if b_body else False


def authz_scan(client, base, spec, cfg):
    if not spec:
        raise IdentityError("authorisation testing needs an OpenAPI spec (--openapi)")
    base = base.rstrip("/")
    ops = _operations(spec)
    idents = cfg["identities"]
    findings, harvested, exposure_seen = [], {i["name"]: {} for i in idents}, set()
    reported = set()

    def add(f, op_path):
        """One finding per rule and endpoint template; the concrete URL stays in f['url'] as evidence."""
        if (f["rule_id"], op_path) in reported:
            return
        reported.add((f["rule_id"], op_path))
        f["file"] = f"GET {op_path}"
        findings.append(f)
    stats = {"operations": len(ops), "object_checks": 0, "function_checks": 0, "identities": [i["name"] for i in idents]}

    def call(url, ident=None, anonymous=False):
        try:
            return client.request("GET", url, auth=not anonymous, identity=(ident["name"], ident["headers"]) if ident else None)
        except (OSError, RuntimeError) as e:
            if "budget" in str(e) or "out of scope" in str(e):
                raise
            return (0, {}, [], b"")

    def exposure(op_path, url, body, ident):
        doc = _json(body)
        if doc is None or op_path in exposure_seen:
            return
        hits = set()
        _walk(doc, lambda k, v: hits.add(k) if isinstance(k, str) and SENSITIVE.match(k) and v not in (None, "", [], {}) else None)
        if hits:
            exposure_seen.add(op_path)
            add(_f("NM-DAST-022", f"Sensitive properties returned by {op_path}", "medium", url, "API3",
                               "Return only the properties the client needs; never return password hashes, secrets or full identity/card numbers. "
                               "Use explicit response schemas (allow-lists) rather than serialising whole objects.",
                               f"as {ident['name']}: fields {', '.join(sorted(hits))}", "CWE-213"), op_path)

    # 1. harvest ids from parameter-free operations, per identity
    for op in [o for o in ops if not o["params"]]:
        if _privileged_roles(op, cfg):
            continue
        for ident in idents:
            st, _, _, body = call(base + op["path"], ident)
            if not 200 <= st < 300:
                continue
            exposure(op["path"], base + op["path"], body, ident)
            segs = [s for s in op["path"].split("/") if s and not s.startswith("{")]
            last = _singular(segs[-1]) if segs else ""

            def collect(k, v, ident=ident, last=last):
                if isinstance(k, str) and isinstance(v, (str, int)) and not isinstance(v, bool) and ID_KEY.match(k):
                    bucket = harvested[ident["name"]]
                    bucket.setdefault(_norm(k), set()).add(str(v))
                    if _norm(k) in ("id", "uuid", "guid", "key") and last:      # generic "id" from /accounts → accountid
                        bucket.setdefault(_norm(last + "id"), set()).add(str(v))
            _walk(_json(body), collect)
    for name, params in (cfg["seeds"] or {}).items():
        for p, vals in params.items():
            harvested.setdefault(name, {}).setdefault(_norm(p), set()).update(map(str, vals))

    # 2. object-level authorisation (BOLA) and unauthenticated object access
    for op in [o for o in ops if o["params"] and not _privileged_roles(o, cfg)]:
        segs = [s for s in op["path"].split("/") if s]
        for owner in idents:
            pools = []
            for p in op["params"]:
                pool = harvested[owner["name"]].get(_norm(p))
                if not pool and _norm(p) in ("id", "uuid", "guid", "key"):
                    i = segs.index("{" + p + "}")
                    prev = _singular(segs[i - 1]) if i > 0 else ""
                    pool = harvested[owner["name"]].get(_norm(prev + "id"))
                if not pool:
                    break
                pools.append(sorted(pool)[:MAX_VALUES_PER_PARAM])
            if len(pools) != len(op["params"]):
                continue
            for k in range(min(len(x) for x in pools)):
                vals = [x[k] for x in pools]
                path = op["path"]
                for p, v in zip(op["params"], vals):
                    path = path.replace("{" + p + "}", urllib.parse.quote(v, safe=""))
                url = base + path
                ast, _, _, abody = call(url, owner)
                if not 200 <= ast < 300:
                    continue                                            # owner cannot read it: no baseline
                exposure(op["path"], url, abody, owner)
                stats["object_checks"] += 1
                for other in idents:
                    if other is owner or other["role"] in cfg["cross_user_roles"]:
                        continue
                    bst, _, _, bbody = call(url, other)
                    if 200 <= bst < 300 and _same_object(abody, bbody, vals[-1]):
                        add(_f("NM-DAST-020", f"{other['name']} can read {owner['name']}'s object via {op['path']}", "critical", url, "API1",
                                           "Check on every request that the authenticated user owns or may access the requested object "
                                           "(e.g. WHERE owner_id = :current_user); return 404 otherwise. Add an automated cross-user test.",
                                           f"{owner['name']} → HTTP {ast}; {other['name']} → HTTP {bst} with the same object", "CWE-639"), op["path"])
                        break
                nst, _, _, nbody = call(url, anonymous=True)
                if 200 <= nst < 300 and _same_object(abody, nbody, vals[-1]):
                    add(_f("NM-DAST-021", f"Object readable without authentication via {op['path']}", "critical", url, "API2",
                                       "Require authentication on this operation in the gateway and the service.",
                                       f"anonymous → HTTP {nst} with {owner['name']}'s object", "CWE-306"), op["path"])
                break                                                   # one confirmed object per owner per operation

    # 3. function-level authorisation (BFLA)
    for op in ops:
        allowed = _privileged_roles(op, cfg)
        if not allowed or op["params"]:
            continue
        url = base + op["path"]
        for ident in [i for i in idents if i["role"] not in allowed]:
            stats["function_checks"] += 1
            st, _, _, body = call(url, ident)
            if 200 <= st < 300:
                add(_f("NM-DAST-023", f"Privileged operation {op['path']} callable by role '{ident['role']}'", "high", url, "API5",
                                   f"Enforce role checks server-side: only {', '.join(sorted(allowed))} may call this operation. "
                                   "Deny by default and centralise authorisation policy.",
                                   f"{ident['name']} ({ident['role']}) → HTTP {st}", "CWE-285"), op["path"])
                break
    return findings, stats
