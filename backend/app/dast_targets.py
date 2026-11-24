# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Online live-application assessment: targets registered in the platform and scanned server-side.

Safety controls for hosted scanning:
  * ownership verification — the target must serve /.well-known/myelin-verification.txt containing the target's token
    (MYELIN_DAST_REQUIRE_VERIFICATION, default on; demo mode off);
  * network guard — targets resolving to loopback, link-local, metadata or (unless MYELIN_DAST_ALLOW_PRIVATE) private
    addresses are refused, checked before every request;
  * read-only safe mode and a request budget (MYELIN_DAST_MAX_REQUESTS);
  * identity credentials are secret references (vault/Key Vault/Secrets Manager paths containing the tenant id),
    resolved only at run time and never stored or reported.
"""
import copy
import secrets as _rand
import sys
import threading
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "engine") not in sys.path:
    sys.path.insert(0, str(ROOT / "engine"))

from myelin_engine import assessment, dast, dast_authz  # noqa: E402

WELL_KNOWN = "/.well-known/myelin-verification.txt"
PUBLIC_FIELDS = ("id", "name", "base_url", "spec_url", "config", "verification_token", "verified_at", "status",
                 "last_run_at", "last_scan_id", "last_error", "created_by", "created_at")


class TargetError(ValueError):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def now():
    return datetime.now(timezone.utc)


RUN_STALE_AFTER = 1800      # seconds: a run still "running" after this was interrupted (e.g. platform restart)


def is_stale(t: dict) -> bool:
    started = t.get("last_run_at")
    if isinstance(started, str):
        started = datetime.fromisoformat(started)
    if started is not None and started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return started is None or (now() - started).total_seconds() > RUN_STALE_AFTER


def public(t: dict) -> dict:
    out = {k: (v.isoformat() if isinstance(v, datetime) else str(v) if isinstance(v, uuid.UUID) else v)
           for k, v in t.items() if k in PUBLIC_FIELDS}
    if t.get("status") == "running" and is_stale(t):
        out["status"], out["last_error"] = "failed", "the run was interrupted (platform restart or an internal error) - run it again"
    out["identities"] = [{"name": i["name"], "role": i.get("role", "user"), "headers": sorted(i.get("headers", {}))}
                         for i in t.get("identities") or []]                         # header names only, never values
    out["has_spec"] = bool(t.get("spec") or t.get("spec_url"))
    r = t.get("last_result") or {}
    if r:
        out["summary"] = {"decision": (r.get("decision") or {}).get("decision"), "findings": len(r.get("findings", [])),
                          "by_severity": _count(r.get("findings", [])), "requests": r.get("requests"), "mode": r.get("mode"),
                          "duration_s": r.get("duration_s")}
    return out


def _count(fs):
    c = {}
    for f in fs:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


def validate(body: dict, tenant_id, enterprise: bool):
    from urllib.parse import urlsplit
    u = urlsplit(body.get("base_url", ""))
    if u.scheme not in ("http", "https") or not u.hostname:
        raise TargetError("base_url must be an http(s) URL")
    if enterprise and u.scheme != "https":
        raise TargetError("online targets must use https")
    if body.get("spec_url") and urlsplit(body["spec_url"]).scheme not in ("http", "https"):
        raise TargetError("spec_url must be an http(s) URL")
    ids = body.get("identities") or []
    if ids and len(ids) < 2:
        raise TargetError("authorisation testing needs at least two identities")
    if enterprise:
        from .connectors.base import ConnectorError, validate_credential_ref
        for i in ids:
            for h, ref in (i.get("headers") or {}).items():
                try:
                    validate_credential_ref(ref, tenant_id)
                except ConnectorError as e:
                    raise TargetError(f"identity '{i.get('name')}' header {h}: {e}") from None


def new_target(body: dict, actor: str) -> dict:
    return {"id": uuid.uuid4(), "name": body["name"], "base_url": body["base_url"].rstrip("/"), "spec_url": body.get("spec_url"),
            "spec": body.get("spec"), "identities": body.get("identities") or [],
            "config": {k: body[k] for k in ("criticality", "privileged", "cross_user_roles", "max_requests", "crawl", "active_checks") if k in body},
            "verification_token": "myelin-verify-" + _rand.token_urlsafe(24), "verified_at": None, "status": "new",
            "last_run_at": None, "last_scan_id": None, "last_result": None, "last_error": None,
            "created_by": actor, "created_at": now()}


# ------------------------------------------------------------------ repositories
class MemoryTargets:
    """Demo mode: in-process registry (lost on restart)."""

    def __init__(self):
        self._t: dict[str, dict] = {}
        self._lock = threading.Lock()

    def list(self, tenant_id):
        return [copy.deepcopy(t) for t in self._t.values() if t["tenant_id"] == str(tenant_id)]

    def get(self, tenant_id, tid):
        t = self._t.get(str(tid))
        if not t or t["tenant_id"] != str(tenant_id):
            raise TargetError("target not found", 404)
        return copy.deepcopy(t)

    def add(self, tenant_id, t):
        with self._lock:
            if any(x["name"] == t["name"] and x["tenant_id"] == str(tenant_id) for x in self._t.values()):
                raise TargetError("a target with this name exists", 409)
            self._t[str(t["id"])] = {**t, "tenant_id": str(tenant_id)}
        return t

    def update(self, tenant_id, tid, **fields):
        with self._lock:
            self.get(tenant_id, tid)
            self._t[str(tid)].update(fields)

    def delete(self, tenant_id, tid):
        self.get(tenant_id, tid)
        self._t.pop(str(tid))


class PgTargets:
    """Enterprise mode: PostgreSQL with row-level security (every call runs in the caller's tenant context)."""

    def __init__(self, db_url):
        self.db_url = db_url

    def _row(self, r):
        return {c: getattr(r, c) for c in ("id", "name", "base_url", "spec_url", "spec", "identities", "config", "verification_token",
                                           "verified_at", "status", "last_run_at", "last_scan_id", "last_result", "last_error",
                                           "created_by", "created_at")}

    def list(self, tenant_id):
        from sqlalchemy import select
        from .db.models import DastTarget
        from .db.session import tenant_tx
        with tenant_tx(self.db_url, tenant_id) as s:
            return [self._row(r) for r in s.scalars(select(DastTarget).order_by(DastTarget.created_at))]

    def get(self, tenant_id, tid):
        from .db.models import DastTarget
        from .db.session import tenant_tx
        try:
            tid = uuid.UUID(str(tid))
        except ValueError:
            raise TargetError("target not found", 404) from None
        with tenant_tx(self.db_url, tenant_id) as s:
            r = s.get(DastTarget, tid)
            if not r:
                raise TargetError("target not found", 404)
            return self._row(r)

    def add(self, tenant_id, t):
        from sqlalchemy import select
        from .db.models import DastTarget
        from .db.session import tenant_tx
        with tenant_tx(self.db_url, tenant_id) as s:
            if s.scalars(select(DastTarget).where(DastTarget.name == t["name"])).first():
                raise TargetError("a target with this name exists", 409)
            s.add(DastTarget(tenant_id=uuid.UUID(str(tenant_id)), **t))
        return t

    def update(self, tenant_id, tid, **fields):
        from .db.models import DastTarget
        from .db.session import tenant_tx
        with tenant_tx(self.db_url, tenant_id) as s:
            r = s.get(DastTarget, uuid.UUID(str(tid)))
            if not r:
                raise TargetError("target not found", 404)
            for k, v in fields.items():
                setattr(r, k, v)

    def delete(self, tenant_id, tid):
        from .db.models import DastTarget
        from .db.session import tenant_tx
        with tenant_tx(self.db_url, tenant_id) as s:
            r = s.get(DastTarget, uuid.UUID(str(tid)))
            if not r:
                raise TargetError("target not found", 404)
            s.delete(r)


# ------------------------------------------------------------------ verification and runs
def verify_ownership(t: dict, guard=None) -> bool:
    from urllib.parse import urlsplit
    c = dast.Client(delay=0, max_requests=2, scope_host=urlsplit(t["base_url"]).hostname, guard=guard)
    try:
        st, _, _, body = c.request("GET", t["base_url"] + WELL_KNOWN, auth=False)
    except (OSError, RuntimeError) as e:
        raise TargetError(f"verification request failed: {e}") from None
    return st == 200 and t["verification_token"] in body.decode("utf-8", "ignore")


def _resolve_identities(t, resolver):
    if not t.get("identities"):
        return None
    cfg = {"identities": t["identities"], "cross_user_roles": t["config"].get("cross_user_roles") or ["admin"],
           "privileged": t["config"].get("privileged") or [], "seeds": {}}
    return dast_authz.load_identities(cfg, resolve=resolver)


def execute(t: dict, *, resolver, guard, max_requests, policy_doc=None) -> dict:
    """Run one assessment synchronously and return the stored result (request log trimmed, no secrets)."""
    ids = _resolve_identities(t, resolver)
    res = assessment.run(t["base_url"], t.get("spec") or t.get("spec_url"), None, ids, t["name"],
                         t["config"].get("criticality", "medium"),
                         min(int(t["config"].get("max_requests", max_requests)), max_requests), 0.2, True,
                         policy_doc=policy_doc, guard=guard, crawl=t["config"].get("crawl", True) is not False,
                         probe=bool(t["config"].get("active_checks")) and bool(t.get("verified_at")))   # active checks only on verified targets
    res["request_log"] = res["request_log"][-500:]
    return res


def start_run(repo, store_factory, tenant_id, t, actor, *, resolver, guard, max_requests, require_verification,
              synchronous=False, on_scanned=None):
    if require_verification and not t.get("verified_at"):
        raise TargetError(f"verify ownership first: serve {WELL_KNOWN} containing the target's verification token", 409)
    if t["status"] == "running" and not is_stale(t):
        raise TargetError("a run is already in progress", 409)
    repo.update(tenant_id, t["id"], status="running", last_error=None, last_run_at=now())

    def work():
        try:
            res = execute(t, resolver=resolver, guard=guard, max_requests=max_requests)
            store = store_factory()
            sid, _ = store.add_scan(t["name"], "runtime", "", res["findings"], None, res["decision"], actor, scanned_engines=("dast",))
            if on_scanned:
                on_scanned(store, getattr(store, "last_delta", None))
            repo.update(tenant_id, t["id"], status="done", last_run_at=now(), last_scan_id=sid, last_result=_jsonable(res))
        except (Exception, SystemExit) as e:                     # record, never crash the API (the engine exits on bad input)
            msg = str(e) if isinstance(e, (RuntimeError, SystemExit, TargetError, dast_authz.IdentityError)) else \
                f"{type(e).__name__}: {e}"
            repo.update(tenant_id, t["id"], status="failed", last_run_at=now(), last_error=msg[:1000])
            traceback.print_exc()
    if synchronous:
        work()
    else:
        threading.Thread(target=work, name=f"dast-{t['id']}", daemon=True).start()


def _jsonable(res):
    import json
    return json.loads(json.dumps(res, default=str))


def render_report(t: dict, customer: str, *, audience="internal", prepared_for="", classification="", title="") -> str:
    if not t.get("last_result"):
        raise TargetError("no completed run yet", 404)
    from myelin_engine import report_enterprise
    res = dict(t["last_result"], repo=t.get("name"))
    return report_enterprise.render(
        res, issuer=customer, prepared_for=prepared_for, source_url=t.get("base_url") or res.get("target") or "", kind="dast",
        audience="external" if audience == "external" else "internal",
        classification=classification or ("Confidential — for authorised recipients" if audience == "external" else "Confidential — internal"),
        title=title or "Application & API Security Assessment")
