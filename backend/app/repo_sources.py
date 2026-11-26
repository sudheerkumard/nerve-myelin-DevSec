# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Repositories scanned from the console: paste a URL, the platform fetches a snapshot and runs every engine.

  * Providers (see scm.py): GitHub, GitLab, Bitbucket, Azure DevOps Repos, AWS CodeCommit, Google Cloud Source
    Repositories / Secure Source Manager and any HTTPS Git server. Internal addresses are refused unless allowed.
  * Private repositories: the access token is written to the secret vault under the tenant's path and only the
    reference is stored; it is resolved at fetch time and never returned, logged or reported.
  * The snapshot is downloaded as an archive (size-capped), extracted with path-traversal, link and device
    protection into a private temporary directory, scanned, and deleted.
"""
import copy
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "engine") not in sys.path:
    sys.path.insert(0, str(ROOT / "engine"))

from myelin_engine import orchestrator, report_enterprise  # noqa: E402

from . import scm  # noqa: E402

RUN_STALE_AFTER = 3600
PUBLIC_FIELDS = ("id", "name", "url", "provider", "branch", "config", "status", "last_run_at", "last_scan_id",
                 "last_commit", "last_error", "created_by", "created_at")
class SourceError(ValueError):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def now():
    return datetime.now(timezone.utc)


QUEUE_STALE_AFTER = 6 * 3600
_SLOTS = threading.BoundedSemaphore(max(1, int(os.environ.get("MYELIN_SCAN_CONCURRENCY", "2"))))   # scans running at once


def is_stale(s: dict) -> bool:
    limit = QUEUE_STALE_AFTER if s.get("status") == "queued" else RUN_STALE_AFTER
    started = s.get("last_run_at")
    if isinstance(started, str):
        started = datetime.fromisoformat(started)
    if started is not None and started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return started is None or (now() - started).total_seconds() > limit


def public(s: dict) -> dict:
    out = {k: (v.isoformat() if isinstance(v, datetime) else str(v) if isinstance(v, uuid.UUID) else v)
           for k, v in s.items() if k in PUBLIC_FIELDS}
    out["private"] = bool(s.get("credential_ref"))
    if s.get("status") in ("running", "queued") and is_stale(s):
        out["status"], out["last_error"] = "failed", "the scan was interrupted (platform restart or an internal error) - scan again"
    r = s.get("last_result") or {}
    if r:
        out["summary"] = r.get("summary")
    return out


def new_source(body: dict, actor: str) -> dict:
    try:
        info = scm.detect(body.get("url"), body.get("provider"))
    except scm.ScmError as e:
        raise SourceError(str(e)) from None
    name = (body.get("name") or (info.get("repo") or info["path"].split("/")[-1])).strip()[:200]
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,199}$", name):
        raise SourceError("name may contain letters, digits, spaces, '.', '_' and '-'")
    branch = (body.get("branch") or "").strip()
    if branch and not re.match(r"^[A-Za-z0-9._/-]{1,200}$", branch):
        raise SourceError("invalid branch name")
    crit = body.get("criticality") or "medium"
    if crit not in ("low", "medium", "high", "critical"):
        raise SourceError("criticality must be low, medium, high or critical")
    return {"id": uuid.uuid4(), "name": name, "url": info["url"], "provider": info["provider"], "branch": branch or None, "credential_ref": None, "config": {"criticality": crit},
            "status": "new", "last_run_at": None, "last_scan_id": None, "last_commit": None, "last_result": None,
            "last_error": None, "created_by": actor, "created_at": now()}


def token_ref(tenant_id, source_id) -> str:
    return f"vault://secret/myelin/tenants/{tenant_id}/repos/{source_id}#token"


# ------------------------------------------------------------------ storage
class MemorySources:
    """Demo mode: in-process registry (lost on restart). Tokens are kept in memory only."""

    def __init__(self):
        self._s: dict[str, dict] = {}
        self._tokens: dict[str, str] = {}
        self._lock = threading.Lock()

    def list(self, tenant_id):
        return [copy.deepcopy(s) for s in self._s.values() if s["tenant_id"] == str(tenant_id)]

    def get(self, tenant_id, sid):
        s = self._s.get(str(sid))
        if not s or s["tenant_id"] != str(tenant_id):
            raise SourceError("repository not found", 404)
        return copy.deepcopy(s)

    def add(self, tenant_id, s):
        with self._lock:
            if any(x["name"] == s["name"] and x["tenant_id"] == str(tenant_id) for x in self._s.values()):
                raise SourceError("a repository with this name exists", 409)
            self._s[str(s["id"])] = {**s, "tenant_id": str(tenant_id)}
        return s

    def update(self, tenant_id, sid, **fields):
        with self._lock:
            self.get(tenant_id, sid)
            self._s[str(sid)].update(fields)

    def delete(self, tenant_id, sid):
        self.get(tenant_id, sid)
        self._s.pop(str(sid))
        self._tokens.pop(str(sid), None)


class PgSources:
    """Enterprise mode: PostgreSQL with row-level security (every call runs in the caller's tenant context)."""
    COLS = ("id", "name", "url", "provider", "branch", "credential_ref", "config", "status", "last_run_at", "last_scan_id",
            "last_commit", "last_result", "last_error", "created_by", "created_at")

    def __init__(self, db_url):
        self.db_url = db_url

    def _tx(self, tenant_id):
        from .db.session import tenant_tx
        return tenant_tx(self.db_url, tenant_id)

    def list(self, tenant_id):
        from sqlalchemy import select
        from .db.models import RepoSource
        with self._tx(tenant_id) as s:
            return [{c: getattr(r, c) for c in self.COLS} for r in s.scalars(select(RepoSource).order_by(RepoSource.created_at))]

    def _get(self, s, sid):
        from .db.models import RepoSource
        try:
            r = s.get(RepoSource, uuid.UUID(str(sid)))
        except ValueError:
            r = None
        if not r:
            raise SourceError("repository not found", 404)
        return r

    def get(self, tenant_id, sid):
        with self._tx(tenant_id) as s:
            r = self._get(s, sid)
            return {c: getattr(r, c) for c in self.COLS}

    def add(self, tenant_id, src):
        from sqlalchemy import select
        from .db.models import RepoSource
        with self._tx(tenant_id) as s:
            if s.scalars(select(RepoSource).where(RepoSource.name == src["name"])).first():
                raise SourceError("a repository with this name exists", 409)
            s.add(RepoSource(tenant_id=uuid.UUID(str(tenant_id)), **src))
        return src

    def update(self, tenant_id, sid, **fields):
        with self._tx(tenant_id) as s:
            r = self._get(s, sid)
            for k, v in fields.items():
                setattr(r, k, v)

    def delete(self, tenant_id, sid):
        with self._tx(tenant_id) as s:
            s.delete(self._get(s, sid))


# ------------------------------------------------------------------ scan
def _summary(res: dict, decision: dict) -> dict:
    by_engine, by_sev = {}, {}
    for f in res["findings"]:
        if f.get("engine") == "meta":
            continue
        by_engine[f["engine"]] = by_engine.get(f["engine"], 0) + 1
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {"by_engine": by_engine, "by_severity": by_sev, "components": res.get("components", 0),
            "decision": decision.get("decision"), "duration_s": res.get("duration_s")}


def execute(src: dict, token: str | None, decide) -> dict:
    tmp = tempfile.mkdtemp(prefix="myelin-repo-")
    try:
        try:
            root, commit = scm.fetch(src["url"], src["provider"], src.get("branch"), token, tmp)
        except scm.ScmError as e:
            raise SourceError(str(e)) from None
        crit = {"low": 0.6, "medium": 1.0, "high": 1.3, "critical": 1.5}.get((src.get("config") or {}).get("criticality"), 1.0)
        res = orchestrator.scan(root, repo=src["name"], criticality=crit)
        res["path"] = src["url"]
        decision = decide([f for f in res["findings"] if f.get("engine") != "meta"])
        res["decision"], res["commit"], res["branch"] = decision, commit, src.get("branch") or "default"
        res["summary"] = _summary(res, decision)
        res["engines"] = res.get("engines") or list(CODE_ENGINES)     # domains actually assessed (see engine coverage)
        return res
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


CODE_ENGINES = ("sca", "license", "sast", "secrets", "iac", "cicd", "aibom", "supply")


def start_scan(repo, store_factory, tenant_id, src, actor, *, token_resolver, decide, synchronous=False, on_scanned=None):
    if src["status"] in ("running", "queued") and not is_stale(src):
        raise SourceError("a scan is already queued or in progress", 409)
    repo.update(tenant_id, src["id"], status="queued", last_error=None, last_run_at=now())

    def work():
        with _SLOTS:
            repo.update(tenant_id, src["id"], status="running", last_run_at=now())
            _work()

    def _work():
        try:
            token = token_resolver(src) if src.get("credential_ref") else None
            res = execute(src, token, decide)
            fs = [f for f in res["findings"] if f.get("engine") != "meta"]
            for f in fs:
                if f.get("file") and f.get("engine") not in ("sca", "license", "aibom", "container"):
                    link = scm.blob_url(src["provider"], src["url"], res["commit"], f["file"], f.get("line"))
                    if link:
                        f["code_url"] = link
            store = store_factory()
            sid, _ = store.add_scan(src["name"], res["branch"], res["commit"], fs, res["sbom"], res["decision"], actor,
                                    scanned_engines=CODE_ENGINES, stats=res.get("stats"))   # engines run: absent findings are fixed
            if on_scanned:
                on_scanned(store, getattr(store, "last_delta", None))
            keep = {**res, "findings": res["findings"][:3000]}
            repo.update(tenant_id, src["id"], status="done", last_run_at=now(), last_scan_id=sid,
                        last_commit=res["commit"] or None, last_result=json.loads(json.dumps(keep, default=str)))
        except (Exception, SystemExit) as e:
            msg = str(e) if isinstance(e, (SourceError, SystemExit, RuntimeError)) else f"{type(e).__name__}: {e}"
            repo.update(tenant_id, src["id"], status="failed", last_run_at=now(), last_error=msg[:1000])
            traceback.print_exc()
    if synchronous:
        work()
    else:
        threading.Thread(target=work, name=f"repo-{src['id']}", daemon=True).start()


def render_report(src: dict, customer: str, *, audience="internal", prepared_for="", classification="", title="") -> str:
    if not src.get("last_result"):
        raise SourceError("no completed scan yet", 404)
    return report_enterprise.render(
        src["last_result"], issuer=customer, prepared_for=prepared_for, source_url=src["url"],
        audience="external" if audience == "external" else "internal",
        classification=classification or ("Confidential — for authorised recipients" if audience == "external" else "Confidential — internal"),
        title=title or "Application Security Assessment")
