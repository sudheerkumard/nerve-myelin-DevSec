# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""RAT Flea DevSec Platform API.

MYELIN_MODE=demo        in-memory sample tenant; demo API key / open read access (customer demos only)
MYELIN_MODE=enterprise  PostgreSQL with row-level security; OIDC (Keycloak or any OIDC IdP), MFA, RBAC,
                        tenant from validated identity only; connectors; evidence integrity; audit hash chain
Every route declares the permission it needs; the tenant is never taken from the request.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))

from myelin_engine import __version__, orchestrator, policy as pol  # noqa: E402
from myelin_engine.scoring import enrich  # noqa: E402

from . import advisory_feeds, plans, seed  # noqa: E402
from .auth.rbac import ROLES, Principal  # noqa: E402
from .auth.service import demo_principal  # noqa: E402
from .config import settings  # noqa: E402
from .ops import observability  # noqa: E402
from .store import DemoStore, PgStore  # noqa: E402

ENTERPRISE = settings.mode == "enterprise"
app = FastAPI(title="RAT Flea DevSec Platform API", version=__version__,
              description="Unified CI/CD security: SCA, SAST, secrets, IaC, container, pipeline posture, provenance, DAST, AI-BOM.",
              docs_url=None if ENTERPRISE and not settings.demo_open else "/docs", redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=ENTERPRISE,
                   allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-CSRF-Token"])
observability.install(app, settings)

DEMO_TENANT = uuid.UUID("00000000-0000-4000-8000-00000000d3d0")
API_KEYS = set(settings.api_keys)
POLICY = pol.load(os.path.join(ROOT, settings.policy_file)) if settings.policy_file else {**pol.DEFAULT_POLICY, "exceptions": [
    {"id": "EXC-1042", "match": {"rule_id": "CVE-2022-42003", "repo": "trade-capture"}, "expires": "2026-12-31",
     "approved_by": "r.iyer (CISO)", "reason": "Not reachable — jackson used only for internal batch export; upgrade in Q1 release train"}]}

if ENTERPRISE:
    from . import secrets as sm
    from .auth.service import AuthService
    from .licensing import BLOCKED_WHEN_RESTRICTED, LicenseManager
    LICENSE = LicenseManager(settings.license_ref, settings.deployment_id)
    AUTH = AuthService(settings)
    DB_URL = AUTH.db
    app.include_router(AUTH.router())
    from .connectors.api import router as connectors_router
    from .evidence.audit_api import router as audit_router
    app.include_router(connectors_router(lambda r, perm: _principal_for(r, perm), DB_URL))
    app.include_router(audit_router(lambda r, perm: _principal_for(r, perm), DB_URL))   # before /{eid}/... routes
    try:   # optional module; not part of every edition
        from .evidence.api import router as evidence_router
    except ImportError:
        evidence_router = None
    if evidence_router:
        app.include_router(evidence_router(lambda r, perm: _principal_for(r, perm), DB_URL, settings))
    observability.register_readiness(app, settings, DB_URL, AUTH)
else:
    DEMO = DemoStore(seed.build() if settings.seed_demo_data else seed.empty())
    DEMO.tenant().update({"name": settings.tenant_name, "plan": settings.tenant_plan, "devs": settings.tenant_devs,
                          "region": settings.tenant_region, "sso": settings.tenant_sso})
    observability.register_readiness(app, settings, None, None)


if ENTERPRISE:
    @app.middleware("http")
    async def license_signal(request: Request, call_next):
        resp = await call_next(request)
        st = LICENSE.status()
        if st.state not in ("valid", "community"):
            resp.headers["X-Myelin-License"] = f"{st.state}; {st.reason}"[:200]
        if observability.LIC_USABLE is not None:
            observability.LIC_USABLE.set(1 if st.usable else 0)
            if st.days_remaining is not None:
                observability.LIC_DAYS.set(st.days_remaining)
        return resp


@dataclass
class Ctx:
    p: Principal
    store: object


def _principal_for(request: Request, perm: str) -> Principal:
    if ENTERPRISE:
        p = AUTH.authenticate(request)
    else:
        key = request.headers.get("x-api-key")
        if key in API_KEYS:
            p = demo_principal(DEMO_TENANT, admin=True)
        elif settings.demo_open:
            p = demo_principal(DEMO_TENANT, admin=True)
        else:
            raise HTTPException(401, "Missing or invalid X-API-Key")
    if not p.can(perm):
        raise HTTPException(403, f"permission '{perm}' required")
    if ENTERPRISE and perm in BLOCKED_WHEN_RESTRICTED:
        lic = LICENSE.status()
        if not lic.usable:
            raise HTTPException(402, f"Licence restricted ({lic.reason}). Existing data remains available; "
                                     "contact the RAT Flea DevSec product owner to renew or install a licence.")
    request.state.principal = p
    return p


def _effective_policy(store, repo: str | None = None, project: str | None = None) -> dict:
    """Resolve organisation → project → repository policy layers; the most-specific binding wins per gate ID."""
    bindings = store.policy_bindings() if hasattr(store, "policy_bindings") else []
    if repo:
        mapped_project = store.get_repo_project(repo) if hasattr(store, "get_repo_project") else None
        if project and mapped_project != project:
            raise HTTPException(409, "supplied project does not match the trusted repository-to-project mapping")
        if not mapped_project and any(b["scope_type"] == "project" for b in bindings):
            raise HTTPException(409, "repository must be mapped to a project before policy evaluation")
        project = mapped_project or project
    wanted = [("organisation", "*")]
    if project:
        wanted.append(("project", project))
    if repo:
        wanted.append(("repository", repo))
    selected = []
    versions = {x["id"]: x for x in store.policy_versions()} if hasattr(store, "policy_versions") else {}
    for scope_type, scope_key in wanted:
        binding = next((b for b in bindings if b["scope_type"] == scope_type and b["scope_key"] == scope_key), None)
        version = versions.get(binding["policy_version_id"]) if binding else None
        if version and version.get("status") == "published":
            selected.append({"scope_type": scope_type, "scope_key": scope_key, "version": version})
    merged = dict(POLICY)
    gates = {g["id"]: dict(g) for g in merged.get("gates", [])}
    exceptions = {str(ex.get("id") or "default:" + str(i)): dict(ex) for i, ex in enumerate(merged.get("exceptions", []))}
    for layer_index, layer in enumerate(selected):
        content = layer["version"]["content"]
        for gate in content.get("gates", []):
            gates[gate["id"]] = dict(gate)
        # More-specific exception IDs replace inherited definitions; exception matching still
        # cannot bypass required-scanner-failure safeguards in the policy evaluator.
        for exception_index, exception in enumerate(content.get("exceptions", [])):
            exception_key = str(exception.get("id") or f"scope:{layer_index}:{exception_index}")
            exceptions[exception_key] = dict(exception)
        merged.update({k: content[k] for k in ("mode", "block_open_p0", "licence_policy") if k in content})
    merged["gates"] = list(gates.values())
    merged["exceptions"] = list(exceptions.values())
    today = datetime.now(timezone.utc).date()
    project_key = project
    for exception in (store.policy_exceptions() if hasattr(store, "policy_exceptions") else []):
        if exception.get("status") != "approved":
            continue
        try:
            expiry = datetime.fromisoformat(exception["expires_at"].replace("Z", "+00:00")).date()
        except (ValueError, TypeError, KeyError):
            continue
        if expiry < today:
            continue
        scope_type, scope_key = exception.get("scope_type"), exception.get("scope_key")
        in_scope = (scope_type == "organisation" and scope_key == "*") or (scope_type == "repository" and repo == scope_key) or (scope_type == "project" and project_key == scope_key)
        if in_scope:
            exceptions[str(exception["id"])] = {"id": str(exception["id"]), "match": exception["match"],
                "expires": exception["expires_at"][:10], "approved_by": exception.get("reviewed_by"),
                "reason": exception.get("reason")}
    merged["exceptions"] = list(exceptions.values())
    merged["_governance"] = {"layers": [{"scope_type": x["scope_type"], "scope_key": x["scope_key"],
        "policy_version_id": x["version"]["id"], "version": x["version"]["version"],
        "content_sha256": x["version"]["content_sha256"]} for x in selected]}
    return merged


def ctx(perm: str):
    def dep(request: Request) -> Ctx:
        p = _principal_for(request, perm)
        return Ctx(p, PgStore(DB_URL, p.tenant_id) if ENTERPRISE else DEMO)
    return dep


def feature(name: str):
    def dep(request: Request):
        c = ctx("plans:read")(request)
        plan = c.store.tenant()["plan"]
        if not plans.entitled(plan, name):
            raise HTTPException(402, f"Feature '{name}' is not included in the {plan} plan")
        if ENTERPRISE:
            granted = LICENSE.status().features
            if granted is not None and name not in granted:
                raise HTTPException(402, f"Feature '{name}' is not included in this installation's licence")
    return dep


def _open(c: Ctx):
    return [f for f in c.store.findings() if f["status"] == "open"]


# ─── health / tenant ──────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__, "mode": settings.mode, "time": datetime.now(timezone.utc).isoformat()}


def _license_summary() -> dict:
    if not ENTERPRISE:
        return {"state": "demo"}
    st = LICENSE.status()
    return {"state": st.state, "reason": st.reason, "days_remaining": st.days_remaining}


@app.get("/api/v1/license")
def license_status(c: Ctx = Depends(ctx("plans:read"))):
    """Licence state for the console banner and administrators. Usage counts users active in 90 days."""
    if not ENTERPRISE:
        return {"state": "demo", "reason": "demonstration mode — no licence required"}
    from datetime import timedelta
    from sqlalchemy import func, select
    from .db.models import User
    from .db.session import tenant_tx
    with tenant_tx(DB_URL, c.p.tenant_id) as s:
        active = s.scalar(select(func.count()).select_from(User).where(
            User.last_login_at > datetime.now(timezone.utc) - timedelta(days=90))) or 0
    out = LICENSE.status().public({"developers": active, "scope": "this tenant, active in last 90 days"})
    if "settings:manage" not in c.p.permissions:          # limits and ids for administrators only
        out = {k: out[k] for k in ("state", "reason", "days_remaining", "plan", "expires_at")}
    return out


@app.get("/api/tenant")
def tenant(c: Ctx = Depends(ctx("plans:read"))):
    t = c.store.tenant()
    p = plans.plan(t["plan"])
    return {**t, "plan_detail": p, "entitlements": {k: k in p["features"] for k in plans.FEATURES}, "license": _license_summary(),
            "you": {"roles": sorted(c.p.roles), "permissions": sorted(c.p.permissions), "method": c.p.method, "mfa": c.p.mfa}}


@app.get("/api/plans")
def get_plans():
    return {"plans": plans.PLANS, "addons": plans.ADDONS, "features": plans.FEATURES}


@app.get("/api/plans/quote")
def get_quote(plan: str, devs: int = Query(ge=1), annual: bool = True):
    try:
        return plans.quote(plan, devs, annual)
    except StopIteration:
        raise HTTPException(404, "unknown plan")


# ─── dashboard ────────────────────────────────────────────────────────────────
@app.get("/api/summary")
def summary(c: Ctx = Depends(ctx("findings:read"))):
    _expire(c)
    fs = c.store.findings()
    o = [f for f in fs if f["status"] == "open"]
    sev, pri, eng = Counter(f["severity"] for f in o), Counter(f["priority"] for f in o), Counter(f["engine"] for f in o)
    crit_high, actionable = sev["critical"] + sev["high"], pri["P0"] + pri["P1"]
    t, repos, pl = c.store.trend(), c.store.repos(), c.store.pipelines()
    return {
        "kpis": {
            "open_findings": len(o), "p0": pri["P0"], "p1": pri["P1"], "critical_high": crit_high,
            "noise_reduction_pct": round(100 * (1 - actionable / max(crit_high, 1)), 1),
            "mttr_days": t[-1]["mttr_days"], "mttr_days_90d_ago": t[0]["mttr_days"],
            "fixed_30d": sum(d["fixed"] for d in t[-30:]), "autofix_merged_30d": sum(d["autofix_merged"] for d in t[-30:]),
            "repos": len(repos), "repos_slsa3": sum(r["slsa_level"] >= 3 for r in repos),
            "signed_pct": round(100 * sum(r["signed"] for r in repos) / max(len(repos), 1)),
            "pipelines_24h": len(pl), "blocked_24h": sum(p["decision"] == "block" for p in pl),
            "kev_open": sum(1 for f in o if f.get("kev")), "secrets_open": eng["secrets"],
            "posture_score": _posture_score(o, repos), "sla_breaches": sum(1 for f in o if f.get("age_days", 0) > f.get("sla_days", 999)),
            "fixed_total": sum(f["status"] == "fixed" for f in fs),
            **_advanced_kpis(c, o, repos),
        },
        "by_severity": sev, "by_priority": pri, "by_engine": eng,
        "by_bu": _group(o, "business_unit"), "trend": t, "top_risks": o[:10],
        "funnel": {"raw_alerts": _raw_alerts(pl, fs), "deduplicated": len(fs), "open": len(o),
                   "reachable_or_exposed": sum(1 for f in o if f.get("reachable") or f.get("exposure") == "internet"), "p0_p1": actionable},
        **_dashboard(fs, o, repos, pl, t),
    }


def _advanced_kpis(c: Ctx, o: list[dict], repos: list[dict]) -> dict:
    """Supply-chain, SSVC, posture, post-quantum and CRA headline figures (all from stored evidence)."""
    from myelin_engine import crypto_inventory as CI
    from myelin_engine.scoring import ssvc as _ssvc
    crit = {r.get("name"): float(r.get("criticality") or 1.0) for r in repos}
    dec = Counter(_ssvc(f, crit.get(f.get("repo"), 1.0))["decision"] for f in o)
    scores, crypto = [], []
    for r in repos:
        try:
            ext = _ext(c, r["name"])
        except Exception:  # noqa: BLE001 - a malformed stored SBOM must not break the dashboard
            continue
        if ext["posture"]:
            scores.append(ext["posture"]["score"])
        crypto += ext["crypto"] or []
    pq = CI.readiness(crypto) if crypto else None
    return {"ssvc": {k: dec.get(k, 0) for k in ("Act", "Attend", "Track*", "Track")},
            "supply_chain_open": sum(1 for f in o if f["engine"] == "supply"),
            "malicious_open": sum(1 for f in o if f.get("malicious")),
            "posture_avg": round(sum(scores) / len(scores), 1) if scores else None, "posture_repos": len(scores),
            "pqc_score": pq["score"] if pq else None, "pqc_quantum_vulnerable": pq["by_class"]["quantum-vulnerable"] if pq else 0,
            "crypto_broken": pq["by_class"]["broken"] if pq else 0,
            "cra_reportable": sum(1 for f in o if f.get("kev") or f.get("malicious"))}


def _raw_alerts(pl, fs):
    """Raw tool results before de-duplication, from the latest scan of each repository (or the stored count)."""
    latest = {}
    for p in pl:
        if p.get("stats") and p["repo"] not in latest:
            latest[p["repo"]] = p["stats"].get("raw", 0)
    raw = sum(latest.values())
    return max(raw, len(fs)) if latest else len(fs)


SLA_DAYS = {"P0": 2, "P1": 7, "P2": 30, "P3": 90}


def _expire(c):
    try:
        c.store.expire_acceptances()
    except Exception:  # noqa: BLE001  (read-only licence mode etc.: never break a read)
        pass


def _vmax(vs):
    from myelin_engine.report_enterprise import vmax
    return vmax(vs)


def _dashboard(fs, o, repos, pl, trend=None):
    """Role-based dashboard data computed from stored findings and scans (nothing estimated)."""
    from myelin_engine import frameworks as FW
    from myelin_engine.report_enterprise import vuln_id, vuln_url
    now = datetime.now(timezone.utc)
    if trend:                                   # the demo dataset is dated relative to its own "today"
        try:
            now = min(now, datetime.fromisoformat(trend[-1]["date"]).replace(tzinfo=timezone.utc) + timedelta(hours=23))
        except (KeyError, ValueError):
            pass
    buckets = [("0–7 days", 0, 7), ("8–30 days", 8, 30), ("31–90 days", 31, 90), ("> 90 days", 91, 10 ** 6)]
    aging = [{"bucket": b, **{sv: sum(1 for f in o if lo <= f.get("age_days", 0) <= hi and f["severity"] == sv)
                              for sv in ("critical", "high", "medium", "low")}} for b, lo, hi in buckets]
    sla_by = {p: {"open": sum(f["priority"] == p for f in o),
                  "breached": sum(1 for f in o if f["priority"] == p and f.get("age_days", 0) > (f.get("sla_days") or SLA_DAYS[p]))}
              for p in SLA_DAYS}
    breached = sum(v["breached"] for v in sla_by.values())
    fixed = [f for f in fs if f["status"] == "fixed"]
    mttr_sev = {sv: round(sum(f.get("age_days", 0) for f in fixed if f["severity"] == sv) / max(1, sum(f["severity"] == sv for f in fixed)), 1)
                for sv in ("critical", "high", "medium", "low")}
    # gate decisions per day, last 30 days
    days = [(now - timedelta(days=i)).date().isoformat() for i in range(29, -1, -1)]
    gate = {d: {"date": d, "pass": 0, "warn": 0, "block": 0} for d in days}
    for p in pl:
        d = str(p.get("started", ""))[:10]
        if d in gate and p.get("decision") in ("pass", "warn", "block"):
            gate[d][p["decision"]] += 1
    g30 = [gate[d] for d in days]
    runs = sum(x["pass"] + x["warn"] + x["block"] for x in g30)
    # repositories ranked by risk
    last_dec = {}
    for p in pl:
        last_dec.setdefault(p["repo"], {"decision": p.get("decision"), "at": p.get("started")})
    by_repo = []
    for r in repos:
        mine = [f for f in o if f.get("repo") == r["name"]]
        by_repo.append({"repo": r["name"], "open": len(mine), "p0": sum(f["priority"] == "P0" for f in mine),
                        "p1": sum(f["priority"] == "P1" for f in mine),
                        **{sv: sum(f["severity"] == sv for f in mine) for sv in ("critical", "high", "medium", "low")},
                        "risk": max([f.get("mrs", 0) for f in mine] or [0]), "gate": (last_dec.get(r["name"]) or {}).get("decision"),
                        "last_scan": (last_dec.get(r["name"]) or {}).get("at") or r.get("last_scan"),
                        "business_unit": r.get("business_unit") or ""})
    by_repo.sort(key=lambda x: (-x["p0"], -x["risk"], -x["open"]))
    # vulnerabilities and upgrades
    cves = {}
    ups = defaultdict(lambda: {"findings": 0, "repos": set(), "to": set()})
    for f in o:
        if f.get("engine") != "sca":
            continue
        vid = vuln_id(f)
        if vid:
            c = cves.setdefault(vid, {"id": vid, "url": vuln_url(vid), "package": f.get("package"), "severity": f["severity"],
                                      "cvss": f.get("cvss"), "epss": f.get("epss"), "kev": bool(f.get("kev")), "repos": set()})
            c["repos"].add(f.get("repo"))
            c["kev"] = c["kev"] or bool(f.get("kev"))
        if f.get("package") and f.get("fixed_version"):
            u = ups[(f["package"], f.get("version"))]
            u["findings"] += 1
            u["repos"].add(f.get("repo"))
            u["to"].add(str(f["fixed_version"]))
    top_cves = sorted(cves.values(), key=lambda c: (not c["kev"], -(float(c["cvss"] or 0)), -len(c["repos"])))[:15]
    for c in top_cves:
        c["repos"] = len(c["repos"])
    upgrades = sorted(({"package": k[0], "from": k[1], "to": _vmax(v["to"]), "closes": v["findings"], "repos": len(v["repos"])}
                       for k, v in ups.items()), key=lambda u: -u["closes"])[:10]
    # framework posture across everything that is open
    matrix = FW.matrix(o, sorted({f.get("engine") for f in fs} | {"sast", "sca", "secrets", "iac", "cicd", "license"}))
    frameworks = [{"id": m["id"], "name": m["name"], "version": m["version"], "gaps": m["gaps"], "observations": m["observations"],
                   "clear": m["clear"], "not_tested": m["not_tested"], "controls": len(m["controls"])} for m in matrix if m["id"] != "cwe25"]
    return {"aging": aging, "sla": {"compliance_pct": round(100 * (len(o) - breached) / max(len(o), 1), 1), "by_priority": sla_by,
                                    "breached": breached},
            "mttr_by_severity": mttr_sev, "gates_30d": g30,
            "gate_pass_rate": round(100 * sum(x["pass"] + x["warn"] for x in g30) / runs, 1) if runs else None, "runs_30d": runs,
            "by_repo": by_repo[:25], "top_cves": top_cves,
            "recent_blocks": [{"repo": p["repo"], "branch": p.get("branch"), "commit": p.get("commit"), "at": p.get("started"),
                               "blocking": (p.get("gate") or {}).get("blocking", 0)} for p in pl if p.get("decision") == "block"][:5], "upgrades": upgrades, "frameworks": frameworks,
            "kev_open": sum(1 for f in o if f.get("kev")), "epss_high": sum(1 for f in o if float(f.get("epss") or 0) >= 0.1),
            "reachable_open": sum(1 for f in o if f.get("reachable")), "secrets_open": sum(1 for f in o if f.get("engine") == "secrets")}


def _posture_score(o, repos):
    s = 100 - min(40, sum(f["priority"] == "P0" for f in o) * 1.5) - min(20, sum(f["priority"] == "P1" for f in o) * 0.25)
    s -= 15 * (1 - sum(r["signed"] for r in repos) / max(len(repos), 1)) if repos else 0
    return max(0, round(s))


def _group(o, key):
    g = defaultdict(lambda: {"open": 0, "p0": 0, "p1": 0, "critical": 0})
    for f in o:
        x = g[f.get(key) or "—"]
        x["open"] += 1
        x["p0"] += f["priority"] == "P0"
        x["p1"] += f["priority"] == "P1"
        x["critical"] += f["severity"] == "critical"
    return g


# ─── findings ─────────────────────────────────────────────────────────────────
@app.get("/api/findings")
def findings(engine: str | None = None, severity: str | None = None, priority: str | None = None, repo: str | None = None,
             status: str | None = "open", q: str | None = None, kev: bool | None = None, limit: int = Query(200, ge=1, le=1000),
             offset: int = Query(0, ge=0), ssvc: str | None = Query(None, max_length=60), c: Ctx = Depends(ctx("findings:read"))):
    _expire(c)
    fs = _with_ssvc(c, c.store.findings())
    if status and status != "all":
        fs = [f for f in fs if f["status"] == status]
    for k, v in (("engine", engine), ("severity", severity), ("priority", priority), ("repo", repo)):
        if v:
            vals = set(v.split(","))
            fs = [f for f in fs if f.get(k) in vals]
    if kev is not None:
        fs = [f for f in fs if bool(f.get("kev")) == kev]
    if ssvc:
        want = {x.strip().lower() for x in ssvc.split(",")}
        fs = [f for f in fs if (f.get("ssvc") or {}).get("decision", "").lower() in want]
    if q:
        ql = q.lower()
        fs = [f for f in fs if ql in " ".join(str(f.get(k, "")) for k in ("title", "cve", "package", "file", "repo", "rule_id")).lower()]
    return {"total": len(fs), "items": fs[offset: offset + limit]}


def _with_ssvc(c: Ctx, fs: list[dict]) -> list[dict]:
    """CISA SSVC decision on every finding, recomputed from current intelligence (KEV/EPSS can change after a scan)."""
    from myelin_engine.scoring import ssvc as _ssvc
    crit = {r.get("name"): float(r.get("criticality") or 1.0) for r in c.store.repos()}
    for f in fs:
        f["ssvc"] = _ssvc(f, crit.get(f.get("repo"), 1.0))
    return fs


def _get(c: Ctx, fid: str) -> dict:
    f = c.store.get_finding(fid)
    if not f:
        raise HTTPException(404, "finding not found")
    return f


@app.get("/api/findings/{fid}")
def finding(fid: str, c: Ctx = Depends(ctx("findings:read"))):
    f = _with_ssvc(c, [dict(_get(c, fid))])[0]
    same = [x["repo"] for x in c.store.findings() if x.get("rule_id") == f.get("rule_id") and x["status"] == "open"]
    from myelin_engine import frameworks as FW
    from myelin_engine import mitigation as MIT
    return {**f, "mitigation": MIT.guidance(f), "blast_radius": {"repos": sorted(set(same)), "count": len(same)}, "compliance": _controls_for(f),
            "frameworks": FW.short(f)}


class StatusIn(BaseModel):
    status: str
    reason: str | None = Field(default=None, max_length=1000)
    expires: str | None = None


def _mitigation_cells(g: dict, f: dict) -> list:
    locs = [f"{x.get('file')}:{x.get('line')}" + (f" @{x['commit']}" if x.get("commit") else "")
            for x in (f.get("locations") or [])[1:]]
    return [g["summary"], "\n".join(f"{i}. {s}" for i, s in enumerate(g["steps"], 1)), g["verify"], g["reference"],
            f.get("occurrences") or 1, "; ".join(locs)[:2000]]


@app.get("/api/v1/findings/export")
def findings_export(status: str = "open", repo: str | None = None, c: Ctx = Depends(ctx("findings:read"))):
    """Findings as CSV (opens in Excel), with CVE links and triage decisions."""
    import csv
    import io
    from fastapi.responses import Response
    from myelin_engine.report_enterprise import vuln_id, vuln_url
    _expire(c)
    fs = [f for f in c.store.findings() if (status == "all" or f.get("status") == status) and (not repo or f.get("repo") == repo)]
    buf = io.StringIO()
    buf.write("\ufeff")                                                    # Excel reads UTF-8 correctly with a BOM
    w = csv.writer(buf)
    w.writerow(["id", "priority", "severity", "risk_score", "status", "engine", "repository", "title", "rule", "cve_or_advisory", "link",
                "cwe", "cvss", "epss", "kev", "package", "version", "fixed_version", "file", "line", "first_seen", "age_days", "sla_days",
                "ticket", "triage_reason", "accepted_until", "how_to_fix", "mitigation_steps", "how_to_verify", "reference",
                "occurrences", "other_locations"])
    from myelin_engine import mitigation as MIT
    for f in fs:
        vid = vuln_id(f) if f.get("engine") in ("sca", "container") else ""
        t = f.get("triage") or {}
        cell = lambda v: ("'" + v) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v  # noqa: E731  (no CSV formula injection)
        w.writerow([cell(x) for x in [f.get("id"), f.get("priority"), f.get("severity"), f.get("mrs"), f.get("status"), f.get("engine"),
                    f.get("repo"), f.get("title"), f.get("rule_id"), vid, vuln_url(vid) if vid else f.get("code_url", ""), f.get("cwe"),
                    f.get("cvss"), f.get("epss"), "yes" if f.get("kev") else "", f.get("package"), f.get("version"), f.get("fixed_version"),
                    f.get("file"), f.get("line"), f.get("first_seen"), f.get("age_days"), f.get("sla_days"),
                    (f.get("ticket") or {}).get("key", ""), t.get("reason", ""), t.get("expires", "")]]
                   + [cell(x) for x in _mitigation_cells(MIT.guidance(f), f)])
    c.store.audit_event("findings.exported", c.p.actor, {"text": f"{len(fs)} findings exported as CSV", "status": status})
    return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="myelin-findings-{status}.csv"'})


@app.post("/api/findings/{fid}/status")
def set_status(fid: str, body: StatusIn, c: Ctx = Depends(ctx("findings:triage"))):
    if body.status not in ("open", "fixed", "suppressed", "risk_accepted"):
        raise HTTPException(400, "invalid status")
    expires = None
    if body.status in ("suppressed", "risk_accepted") and len((body.reason or "").strip()) < 5:
        raise HTTPException(400, "a reason of at least 5 characters is required")
    if body.status == "risk_accepted":
        try:
            exp = datetime.fromisoformat(body.expires or "").date()
        except ValueError:
            raise HTTPException(400, "accepted risk needs an expiry date (YYYY-MM-DD)") from None
        today = datetime.now(timezone.utc).date()
        if not today < exp <= today + timedelta(days=366):
            raise HTTPException(400, "the expiry date must be in the future and at most one year away")
        expires = exp.isoformat()
    f = c.store.set_status(fid, body.status, c.p.actor, body.reason, expires)
    if not f:
        raise HTTPException(404, "finding not found")
    return f


@app.post("/api/findings/{fid}/autofix", dependencies=[Depends(feature("autofix"))])
def autofix(fid: str, c: Ctx = Depends(ctx("findings:fix"))):
    """A fix computed from the repository's own file at the scanned commit (or guidance when no safe change exists)."""
    f = _get(c, fid)
    prop, src = _autofix_proposal(c, f)
    c.store.audit_event("autofix.proposed", c.p.actor, f"{f.get('rule_id')} in {f['repo']}: {'patch' if prop['changes'] else 'guidance'}")
    return {"proposed": bool(prop["changes"]), "title": prop.get("title"), "diff": prop.get("diff", ""), "explanation": prop.get("explanation", ""),
            "review": prop.get("review", False), "guidance": prop.get("guidance"), "repo": f["repo"],
            "branch": f"myelin/fix-{f['id'].lower()}",
            "can_open_pr": bool(prop["changes"] and src and src.get("provider") in ("github", "gitlab", "azure") and
                                (src.get("credential_ref") or (not ENTERPRISE and SOURCES._tokens.get(str(src["id"])))))}


def _autofix_proposal(c: Ctx, f: dict):
    """Fetch the repository (connected source, or the bundled sample in the demo) and compute the fix."""
    import tempfile
    from . import autofix as AF, scm
    src = next((s for s in _safe_list(lambda: SOURCES.list(c.p.tenant_id)) if s.get("name") == f.get("repo")), None)
    root, tmp, token, info = None, None, None, None
    try:
        if src:
            token = _source_token(src) if src.get("credential_ref") or not ENTERPRISE else None
            tmp = tempfile.mkdtemp(prefix="myelin-fix-")
            try:
                root, _ = scm.fetch(src["url"], src["provider"], src.get("last_commit") or src.get("branch"), token, tmp)
            except scm.ScmError:
                root, _ = scm.fetch(src["url"], src["provider"], src.get("branch"), token, tmp)
            info = scm.detect(src["url"], src["provider"])
        elif not ENTERPRISE and f.get("repo") == "payments-web":
            root = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "demo", "vulnerable-app")

        def read(path):
            if not root:
                return None
            p = os.path.realpath(os.path.join(root, path))
            if not p.startswith(os.path.realpath(root) + os.sep) or not os.path.isfile(p):
                return None
            return open(p, encoding="utf-8", errors="replace").read()
        resolver = AF.github_resolver(info, token) if f.get("rule_id") == "NM-CICD-001" and not os.environ.get("MYELIN_OFFLINE") else None
        prop = AF.propose(f, read, resolver)
        prop["_info"], prop["_token"] = info, token
        return prop, src
    except scm.ScmError as e:
        return {"changes": [], "guidance": f"Could not read the repository to compute a fix: {e}"}, src
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def _safe_list(fn):
    try:
        return fn() or []
    except Exception:  # noqa: BLE001
        return []


@app.post("/api/findings/{fid}/autofix/pull-request")
def autofix_pull_request(fid: str, c: Ctx = Depends(ctx("findings:fix"))):
    """Open a pull request (GitHub), merge request (GitLab) or pull request (Azure DevOps) with the computed fix."""
    from . import autofix as AF
    f = _get(c, fid)
    prop, src = _autofix_proposal(c, f)
    if not prop["changes"]:
        raise HTTPException(422, prop.get("guidance") or "no automatic change exists for this finding")
    if not src:
        raise HTTPException(409, "connect this repository under Repositories to open pull requests")
    try:
        pr = AF.open_pull_request(prop["_info"], prop["_token"], src.get("branch"), f"myelin/fix-{f['id'].lower()}", prop, AF.pr_body(f, prop))
    except AF.AutofixError as e:
        raise HTTPException(502, str(e)) from None
    c.store.record_finding_event(fid, "autofix.pull_request", c.p.actor, pr)
    c.store.audit_event("autofix.pull_request", c.p.actor, f"{prop['title']} → {pr.get('url')}")
    return {**pr, "title": prop["title"], "diff": prop["diff"]}


@app.post("/api/findings/{fid}/explain", dependencies=[Depends(feature("ai_remediation"))])
def explain(fid: str, c: Ctx = Depends(ctx("findings:read"))):
    """AI remediation assistant: what it is, why it matters here, step-by-step fix, verification and references.
    Built-in knowledge always; the tenant's configured model (Anthropic, OpenAI, Azure OpenAI) when set up."""
    from . import ai
    r = ai.explain(_get(c, fid))
    c.store.audit_event("ai.explain", c.p.actor, {"finding": fid, "source": r["source"]})
    return r


class AskIn(BaseModel):
    question: str = Field(min_length=3, max_length=500)


@app.get("/api/v1/ai/status")
def ai_status(c: Ctx = Depends(ctx("findings:read"))):
    from . import ai
    return ai.status()


@app.post("/api/v1/ai/triage/{fid}", dependencies=[Depends(feature("ai_remediation"))])
def ai_triage(fid: str, c: Ctx = Depends(ctx("findings:read"))):
    """Evidence-based triage suggestion (likely real / likely false positive / needs review). Changes nothing."""
    from . import ai
    r = ai.triage(_get(c, fid))
    c.store.audit_event("ai.triage", c.p.actor, {"finding": fid, "verdict": r["verdict"], "source": r["source"]})
    return r


@app.post("/api/v1/ai/ask", dependencies=[Depends(feature("ai_remediation"))])
def ai_ask(body: AskIn, c: Ctx = Depends(ctx("findings:read"))):
    """Ask questions about your findings in plain language."""
    from . import ai
    _expire(c)
    r = ai.ask(body.question, _with_ssvc(c, c.store.findings()), sorted({x["name"] for x in c.store.repos()}))
    c.store.audit_event("ai.ask", c.p.actor, {"question": ai.redact(body.question)[:200], "results": r["count"], "source": r["source"]})
    return r


@app.get("/api/v1/ai/briefing", dependencies=[Depends(feature("ai_remediation"))])
def ai_briefing(c: Ctx = Depends(ctx("findings:read"))):
    """Executive narrative of the current posture, written only from stored figures."""
    from . import ai
    r = ai.briefing(summary(c))
    c.store.audit_event("ai.briefing", c.p.actor, {"source": r["source"]})
    return r


@app.get("/api/v1/gate")
def deployment_gate(repo: str = Query(min_length=1, max_length=300), commit: str = Query("", max_length=64),
                    environment: str = Query("", max_length=100), scope: str = Query("all", pattern="^(all|new)$"),
                    require: str = Query("", max_length=200), c: Ctx = Depends(ctx("findings:read"))):
    """CD deployment gate: the policy decision of the latest scan of `repo` (at `commit` when given) plus open P0s.
    404 when there is no matching scan, so pipelines fail closed on unscanned code."""
    scans = [p for p in c.store.pipelines() if p.get("repo") == repo and p.get("branch") != "runtime"]
    if commit:
        scans = [p for p in scans if p.get("commit") and (commit.startswith(p["commit"]) or str(p["commit"]).startswith(commit[:7]))]
    if not scans:
        raise HTTPException(404, f"no scan of {repo}" + (f" at commit {commit[:12]}" if commit else "") + ": scan it before deploying")
    last = max(scans, key=lambda p: p.get("started") or "")
    open_p0 = sum(1 for f in c.store.findings() if f.get("repo") == repo and f.get("status") == "open" and f.get("priority") == "P0")
    decision = "block" if open_p0 and last["decision"] != "block" and POLICY.get("block_open_p0", False) else last["decision"]
    gate = last.get("gate") or {}
    new_only = None
    if scope == "new":
        # only findings this commit introduced decide (existing debt is reported, not blocking)
        sha = (commit or last.get("commit") or "")[:7]
        intro = [f for f in c.store.findings() if f.get("repo") == repo and f.get("status") == "open"
                 and sha and str(f.get("introduced_in") or "").startswith(sha)]
        ev = pol.evaluate(intro, _effective_policy(c.store, repo=repo))
        decision, gate = ev["decision"], {"blocking": ev["blocking"], "warnings": ev["warnings"]}
        new_only = len(intro)
    missing = []
    if require:
        ran = set(last.get("engines") or [])
        missing = [e for e in (x.strip() for x in require.split(",")) if e and ran and e not in ran] if ran else \
            [e.strip() for e in require.split(",") if e.strip()]
        if missing:
            decision = "block"                     # incomplete coverage fails closed: a green gate means every check ran
    c.store.audit_event("deploy.gate", c.p.actor, {"text": f"deployment gate {decision} for {repo}@{(commit or last.get('commit') or '')[:12]}"
                                                           + (f" → {environment}" if environment else "")})
    return {"repo": repo, "commit": last.get("commit"), "scan_id": last.get("id"), "scanned_at": last.get("started"),
            "decision": decision, "blocking": gate.get("blocking", 0), "warnings": gate.get("warnings", 0), "open_p0": open_p0,
            "environment": environment or None, "scope": scope, "new_findings": new_only, "missing_engines": missing,
            "engines": last.get("engines")}


@app.get("/api/repos")
def repos(c: Ctx = Depends(ctx("findings:read"))):
    return sorted(c.store.repos(), key=lambda r: -r["risk"])


@app.get("/api/pipelines")
def pipelines(repo: str | None = None, decision: str | None = None, c: Ctx = Depends(ctx("findings:read"))):
    p = c.store.pipelines()
    if repo:
        p = [x for x in p if x["repo"] == repo]
    if decision:
        p = [x for x in p if x["decision"] == decision]
    return p


OWASP_CICD = {"CICD-SEC-1": "Insufficient Flow Control", "CICD-SEC-2": "Inadequate Identity & Access Mgmt", "CICD-SEC-3": "Dependency Chain Abuse",
              "CICD-SEC-4": "Poisoned Pipeline Execution", "CICD-SEC-5": "Insufficient PBAC", "CICD-SEC-6": "Insufficient Credential Hygiene",
              "CICD-SEC-7": "Insecure System Configuration", "CICD-SEC-8": "Ungoverned 3rd-Party Services",
              "CICD-SEC-9": "Improper Artifact Integrity Validation", "CICD-SEC-10": "Insufficient Logging & Visibility"}


@app.get("/api/posture/cicd")
def cicd_posture(c: Ctx = Depends(ctx("findings:read"))):
    o = [f for f in _open(c) if f["engine"] == "cicd"]
    by = defaultdict(lambda: {"open": 0, "repos": set()})
    for f in o:
        by[f.get("owasp_cicd", "—")]["open"] += 1
        by[f.get("owasp_cicd", "—")]["repos"].add(f["repo"])
    return [{"id": k, "name": v, "open": by[k]["open"] if k in by else 0, "repos": sorted(by[k]["repos"]) if k in by else []}
            for k, v in OWASP_CICD.items()]


@app.get("/api/supply-chain")
def supply_chain(c: Ctx = Depends(ctx("findings:read"))):
    """Return recorded build metadata without presenting it as verified admission telemetry."""
    rs = c.store.repos()
    artifacts = [{
        "repo": r["name"], "image": r.get("image_ref") or r.get("artifact_ref"),
        "slsa_level": int(r.get("slsa_level") or 0), "signed": bool(r.get("signed")),
        "signature_verified": bool(r.get("signature_verified")),
        "sbom_attested": bool(r.get("sbom_attested")), "provenance": r.get("provenance_uri"),
        "admission": "observed" if r.get("admission_decision") else "not_observed",
        "admission_decision": r.get("admission_decision"),
        "metadata_source": "demo_fixture" if not ENTERPRISE else "tenant_repository_record",
    } for r in rs]
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    ev = _safe_list(lambda: c.store.admission_events(since))
    det = [e.get("detail") if isinstance(e.get("detail"), dict) else {} for e in ev]
    blocked = [d for d in det if d.get("result") in ("fail", "error")]
    adm = {"available": bool(ev), "allowed": sum(1 for d in det if d.get("result") == "pass"),
           "blocked_unsigned": sum(1 for d in blocked if re.search(r"signature|provenance|attest|verify", str(d.get("rule", "")), re.I)),
           "blocked_policy": sum(1 for d in blocked if not re.search(r"signature|provenance|attest|verify", str(d.get("rule", "")), re.I)),
           "recent": det[:20],
           "note": "From Kyverno policy reports forwarded to POST /api/v1/admission/reports." if ev else
                   "Admission is enforced in the cluster by the Kyverno policy (deploy/k8s). Forward its policy reports to "
                   "POST /api/v1/admission/reports to see decisions here."}
    return {
        "slsa_distribution": Counter(str(a["slsa_level"]) for a in artifacts),
        "artifacts": artifacts,
        "admission_events_24h": adm,
    }


class AdmissionReportsIn(BaseModel):
    reports: list[dict] = Field(min_length=1, max_length=500)
    cluster: str = Field("default", max_length=120)


@app.post("/api/v1/admission/reports")
def admission_reports(body: AdmissionReportsIn, c: Ctx = Depends(ctx("scans:write"))):
    """Ingest Kubernetes policy reports (wgpolicyk8s.io PolicyReport / ClusterPolicyReport, as written by Kyverno) for the
    RAT Flea DevSec admission policies, so deployment decisions are visible next to build and scan evidence."""
    n = 0
    for rep in body.reports:
        if rep.get("kind") not in ("PolicyReport", "ClusterPolicyReport"):
            raise HTTPException(422, "each report must be a PolicyReport or ClusterPolicyReport")
        ns = (rep.get("metadata") or {}).get("namespace", "")
        for r in rep.get("results") or []:
            if not str(r.get("policy", "")).startswith("myelin-"):
                continue
            res = str(r.get("result", "")).lower()
            if res not in ("pass", "fail", "warn", "error", "skip"):
                continue
            for obj in (r.get("resources") or [{}])[:50]:
                c.store.audit_event(f"admission.{res}", f"kyverno:{body.cluster}"[:120], {
                    "text": f"{res}: {obj.get('kind', '')}/{obj.get('namespace', ns)}/{obj.get('name', '')} ({r.get('rule')})",
                    "cluster": body.cluster, "namespace": obj.get("namespace", ns), "kind": obj.get("kind"), "name": obj.get("name"),
                    "policy": r.get("policy"), "rule": r.get("rule"), "result": res, "message": str(r.get("message", ""))[:500]})
                n += 1
    return {"recorded": n}


def _supply_graph_id(kind: str, *parts: str) -> str:
    import hashlib
    raw = "|".join([kind, *(str(p) for p in parts)])
    return kind + ":" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


@app.get("/api/supply-chain/graph")
def supply_chain_graph(c: Ctx = Depends(ctx("findings:read"))):
    """Evidence-backed repository/build/SBOM/dependency/finding graph. Runtime links are never inferred."""
    repos, findings, pipelines = c.store.repos(), c.store.findings(), c.store.pipelines()
    nodes, edges, node_ids, edge_ids = [], [], set(), set()
    component_by_key = {}

    def add_node(kind, key, label, **data):
        nid = _supply_graph_id(kind, key)
        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append({"id": nid, "type": kind, "label": str(label)[:300], **data})
        return nid

    def add_edge(source, target, relationship, evidence, linkage="observed", **data):
        if not source or not target or source == target:
            return
        eid = _supply_graph_id("edge", source, target, relationship)
        if eid not in edge_ids:
            edge_ids.add(eid)
            edges.append({"id": eid, "source": source, "target": target,
                          "relationship": relationship, "evidence": evidence,
                          "linkage": linkage, **data})

    repo_nodes = {r["name"]: add_node("repository", r["name"], r["name"],
        repository=r["name"], business_unit=r.get("business_unit", ""),
        internet_facing=bool(r.get("internet_facing")), evidence_source="repository inventory") for r in repos}

    sbom_repos, component_count = set(), 0
    for r in repos:
        repo = r["name"]
        doc = c.store.sbom(repo)
        if not isinstance(doc, dict):
            continue
        sbom_repos.add(repo)
        sbom_id = add_node("sbom", repo, repo + " CycloneDX SBOM", repository=repo,
            bom_format=doc.get("bomFormat", "CycloneDX"), spec_version=doc.get("specVersion"),
            serial_number=doc.get("serialNumber"), evidence_source="stored SBOM document")
        add_edge(repo_nodes.get(repo), sbom_id, "has_sbom", "Stored CycloneDX document")
        refs = {}

        def walk_components(items):
            nonlocal component_count
            for comp in items if isinstance(items, list) else []:
                if not isinstance(comp, dict):
                    continue
                name, version = str(comp.get("name") or comp.get("purl") or "unnamed"), str(comp.get("version") or "")
                purl = str(comp.get("purl") or "")
                ref = str(comp.get("bom-ref") or purl or (name + "@" + version))
                cid = add_node("component", repo + "|" + ref, name, repository=repo,
                    version=version, purl=purl, scope=comp.get("scope"), licenses=comp.get("licenses", []), supplier=comp.get("supplier"), evidence_source=doc.get("source_format", "CycloneDX SBOM"))
                refs[ref] = cid
                component_by_key.setdefault((repo, name.casefold(), version.casefold()), []).append(cid)
                component_count += 1
                add_edge(repo_nodes.get(repo), cid, "declares_dependency", "CycloneDX component inventory")
                walk_components(comp.get("components", []))

        walk_components(doc.get("components", []))
        for dep in doc.get("dependencies", []) if isinstance(doc.get("dependencies"), list) else []:
            if not isinstance(dep, dict):
                continue
            src = refs.get(str(dep.get("ref") or ""))
            for target_ref in dep.get("dependsOn", []) if isinstance(dep.get("dependsOn"), list) else []:
                dst = refs.get(str(target_ref))
                if src and dst:
                    add_edge(src, dst, "depends_on", "CycloneDX dependency graph")

    for p in pipelines[:200]:
        repo = p.get("repo")
        if repo not in repo_nodes:
            continue
        pid = str(p.get("id") or p.get("commit") or p.get("started") or "unknown")
        pn = add_node("pipeline_run", repo + "|" + pid, repo + " · " + str(p.get("branch") or "branch unknown"),
            repository=repo, branch=p.get("branch"), commit=p.get("commit"),
            decision=p.get("decision"), started=p.get("started"), evidence_source="stored pipeline scan record")
        add_edge(repo_nodes[repo], pn, "has_pipeline_run", "Stored pipeline scan record")

    selected = sorted(findings, key=lambda f: float(f.get("mrs") or 0), reverse=True)[:500]
    linked = 0
    for f in selected:
        repo = f.get("repo")
        if repo not in repo_nodes:
            continue
        fid = str(f.get("id") or f.get("fingerprint") or f.get("rule_id") or "finding")
        fn = add_node("finding", repo + "|" + fid, f.get("title") or f.get("cve") or f.get("rule_id") or fid,
            repository=repo, finding_id=f.get("id"), cve=f.get("cve"), rule_id=f.get("rule_id"),
            package=f.get("package"), version=f.get("version"), severity=f.get("severity"),
            priority=f.get("priority"), mrs=f.get("mrs"), status=f.get("status"),
            evidence_source="scanner finding")
        package, version = str(f.get("package") or "").casefold(), str(f.get("version") or "").casefold()
        matches = component_by_key.get((repo, package, version), []) if package else []
        if matches and len(set(matches)) == 1:
            add_edge(matches[0], fn, "affected_by", "Scanner finding matched to SBOM component",
                      linkage="component_match", finding_id=f.get("id"))
            linked += 1
        else:
            add_edge(repo_nodes[repo], fn, "reports_finding", "Scanner finding repository attribution",
                      linkage="repository_only", finding_id=f.get("id"))

    return {
        "data_source": "demo_seed" if not ENTERPRISE else "tenant_database",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "repositories": len(repo_nodes),
            "pipeline_runs": sum(n["type"] == "pipeline_run" for n in nodes),
            "sbom_repositories": len(sbom_repos), "components": component_count,
            "findings": sum(n["type"] == "finding" for n in nodes),
            "component_linked_findings": linked,
            "repository_only_findings": sum(e["relationship"] == "reports_finding" for e in edges),
            "truncated_findings": max(0, len(findings) - len(selected)),
        },
        "nodes": nodes, "edges": edges,
        "scope_notes": [
            "Component-to-finding links require a package identity match against a stored SBOM.",
            "Repository-only findings are not presented as dependency reachability.",
            "Runtime workloads, registries, clusters and cloud resources are not inferred without corresponding inventory evidence.",
            "Demo mode contains representative seeded records; production mode reads the authenticated tenant database.",
        ],
    }


@app.get("/api/sbom/{repo}")
def sbom(repo: str, c: Ctx = Depends(ctx("findings:read"))):
    doc = c.store.sbom(repo)
    if not doc:
        raise HTTPException(404, "no SBOM for this repository yet; it is generated on the next scan")
    return _public_sbom(doc)


@app.get("/api/v1/licenses/report", dependencies=[Depends(feature("license"))])
def licence_policy_report(repo: str | None = None, c: Ctx = Depends(ctx("findings:read"))):
    """Evaluate retained tenant SBOM licence evidence against the platform default policy.

    This is a triage report, not legal advice. Unknown or malformed expressions require review.
    """
    from myelin_engine.license_policy import evaluate_components

    repositories = c.store.repos()
    selected = [repo] if repo else [str(x.get("name")) for x in repositories if x.get("name")]
    rows = []
    missing_sboms = []
    for repository in selected:
        document = c.store.sbom(repository)
        if not document:
            missing_sboms.append(repository)
            continue
        components = []
        for component in document.get("components") or []:
            # CycloneDX uses licenses[].license.id/name or licenses[].expression;
            # SPDX-derived inventory may expose a normalized top-level license field.
            licences = component.get("licenses") or []
            first = licences[0] if licences else {}
            license_object = first.get("license") or {}
            expression = (component.get("license") or component.get("licence")
                          or first.get("expression") or license_object.get("id")
                          or license_object.get("name") or "unknown")
            components.append({**component, "license": expression})
        effective_policy = _effective_policy(c.store, repo=repository)
        licence_policy = effective_policy.get("licence_policy")
        for item in evaluate_components(components, licence_policy):
            rows.append({**item, "repo": repository,
                         "policy_version": (licence_policy or {}).get("version", "default-1")})
    counts = {key: sum(1 for item in rows if item["decision"] == key)
              for key in ("allow", "review", "deny")}
    policy_versions = sorted({str(item.get("policy_version") or "default-1") for item in rows})
    return {"policy_version": policy_versions[0] if len(policy_versions) == 1 else "mixed",
            "policy_versions": policy_versions or ["default-1"], "legal_advice": False, "repositories": selected,
            "components_evaluated": len(rows), "counts": counts,
            "missing_sbom_repositories": missing_sboms, "items": rows[:5000]}

# ─── supply-chain defence, repository posture, cryptography (CBOM / PQC), EU CRA ──────────────────────────────────
CI_HARDENING = {"NM-CICD-001", "NM-CICD-013", "NM-CICD-014", "NM-CICD-015", "NM-CICD-016", "NM-CICD-017", "NM-CICD-018",
                "NM-CICD-019", "NM-CICD-020", "NM-CICD-021", "NM-AI-023", "NM-AI-031"}


def _public_sbom(doc):
    """The stored SBOM without RAT Flea DevSec's internal extension properties (posture, cryptography inventory)."""
    if not isinstance(doc, dict):
        return doc
    out = dict(doc)
    meta = dict(out.get("metadata") or {})
    meta["properties"] = [p for p in meta.get("properties") or [] if p.get("name") not in ("myelin:posture-detail", "myelin:crypto")]
    out["metadata"] = meta
    return out


def _ext(c: Ctx, repo: str) -> dict:
    ext = orchestrator.extensions(c.store.sbom(repo))
    if ext["posture"] is None and hasattr(c.store, "demo_extensions"):
        ext = c.store.demo_extensions(repo) or ext
    return ext


@app.get("/api/v1/supply-chain/defence")
def supply_chain_defence(c: Ctx = Depends(ctx("findings:read"))):
    """Malicious releases, typosquats, hallucinated names, dependency confusion, install scripts, worm indicators and the
    CI hardening that stops token theft, from stored scan results."""
    from myelin_engine import cicd_posture as CP, supply_chain as SC
    o = _open(c)
    sup = [f for f in o if f["engine"] == "supply"]
    hard = [f for f in o if f.get("rule_id") in CI_HARDENING]
    titles = {**{k: v[0] for k, v in SC.RULES.items()}, **{k: v[0] for k, v in CP.RULES.items()},
              "NM-AI-023": "MCP server runs an unpinned package", "NM-AI-031": "AI agent in CI acts on untrusted text"}
    rules = Counter(f["rule_id"] for f in sup + hard)
    repos = defaultdict(lambda: {"supply": 0, "hardening": 0, "critical": 0})
    for f in sup + hard:
        r = repos[f["repo"]]
        r["supply" if f["engine"] == "supply" else "hardening"] += 1
        r["critical"] += f["severity"] == "critical"

    def brief(f):
        return {k: f.get(k) for k in ("id", "rule_id", "title", "severity", "repo", "file", "line", "package", "version",
                                      "lookalike_of", "evidence", "priority", "mrs", "code_url", "advisory")}
    return {
        "counts": {"supply_findings": len(sup), "hardening_findings": len(hard),
                   "malicious": rules["NM-SUP-001"], "typosquats": rules["NM-SUP-002"], "hallucinated": rules["NM-SUP-003"],
                   "indicators": rules["NM-SUP-010"], "install_scripts": rules["NM-SUP-007"],
                   "unlocked": rules["NM-SUP-005"], "no_cooldown": rules["NM-SUP-008"],
                   "secret_exposure_in_ci": sum(rules[r] for r in ("NM-CICD-013", "NM-CICD-014", "NM-CICD-015", "NM-CICD-017"))},
        "by_rule": [{"rule": k, "title": titles.get(k, k), "open": v} for k, v in rules.most_common()],
        "malicious": [brief(f) for f in sup if f["rule_id"] == "NM-SUP-001"],
        "typosquats": [brief(f) for f in sup if f["rule_id"] in ("NM-SUP-002", "NM-SUP-003")],
        "indicators": [brief(f) for f in sup if f["rule_id"] == "NM-SUP-010"],
        "hardening": [brief(f) for f in sorted(hard, key=lambda f: -f.get("mrs", 0))[:50]],
        "other": [brief(f) for f in sup if f["rule_id"] not in ("NM-SUP-001", "NM-SUP-002", "NM-SUP-003", "NM-SUP-010")][:50],
        "repos": [{"repo": k, **v} for k, v in sorted(repos.items(), key=lambda kv: (-kv[1]["critical"], -kv[1]["supply"]))],
    }


@app.get("/api/v1/posture")
def posture_overview(c: Ctx = Depends(ctx("findings:read"))):
    """Repository security posture (19 checks) and OpenSSF OSPS Baseline coverage for every scanned repository."""
    rows, checks = [], defaultdict(lambda: {"pass": 0, "partial": 0, "fail": 0, "n/a": 0, "name": "", "risk": ""})
    levels = {lvl: {"met": 0, "controls": 0} for lvl in ("1", "2", "3")}
    for r in c.store.repos():
        pst = _ext(c, r["name"])["posture"]
        if not pst:
            continue
        lv = {str(k): v for k, v in pst["osps"]["levels"].items()}
        for k in levels:
            levels[k]["met"] += lv.get(k, {}).get("met", 0)
            levels[k]["controls"] += lv.get(k, {}).get("controls", 0)
        for ch in pst["checks"]:
            cc = checks[ch["id"]]
            cc[ch["status"]] += 1
            cc["name"], cc["risk"] = ch["name"], ch["risk"]
        rows.append({"repo": r["name"], "score": pst["score"], "grade": pst["grade"], "osps": lv,
                     "failing": [ch["name"] for ch in pst["checks"] if ch["status"] == "fail"]})
    rows.sort(key=lambda x: x["score"])
    return {"repos": rows, "average": round(sum(x["score"] for x in rows) / len(rows), 1) if rows else None,
            "checks": [{"id": k, **v} for k, v in checks.items()], "osps_levels": levels,
            "osps_version": __import__("myelin_engine.repo_posture", fromlist=["x"]).OSPS_VERSION}


@app.get("/api/v1/posture/{repo}")
def posture_repo(repo: str, c: Ctx = Depends(ctx("findings:read"))):
    pst = _ext(c, repo)["posture"]
    if not pst:
        raise HTTPException(404, "no posture assessment for this repository yet; it is produced by the next scan")
    return {"repo": repo, **pst}


@app.get("/api/v1/cbom/{repo}")
def cbom_export(repo: str, c: Ctx = Depends(ctx("findings:read"))):
    """CycloneDX 1.6 Cryptography Bill of Materials for one repository."""
    from fastapi.responses import JSONResponse
    from myelin_engine import crypto_inventory as CI
    crypto = _ext(c, repo)["crypto"]
    if crypto is None:
        raise HTTPException(404, "no cryptography inventory for this repository yet; it is produced by the next scan")
    return JSONResponse(CI.cbom(crypto, repo), headers={"Content-Disposition": f'attachment; filename="{repo}.cbom.json"'})


@app.get("/api/v1/pqc")
def pqc_readiness(c: Ctx = Depends(ctx("findings:read"))):
    """Post-quantum readiness: where quantum-vulnerable and broken cryptography is used, across repositories."""
    from myelin_engine import crypto_inventory as CI
    algs, repos, combined = {}, [], []
    for r in c.store.repos():
        crypto = _ext(c, r["name"])["crypto"]
        if crypto is None:
            continue
        combined += crypto
        rd = CI.readiness(crypto)
        repos.append({"repo": r["name"], **rd, "algorithms": [a["algorithm"] for a in crypto]})
        for a in crypto:
            g = algs.setdefault(a["algorithm"], {k: a[k] for k in ("algorithm", "family", "primitive", "classification",
                                                                    "nist_quantum_level", "advice")} | {"uses": 0, "repos": [], "examples": []})
            g["uses"] += a.get("count", len(a["occurrences"]))
            g["repos"].append(r["name"])
            g["examples"] += [{"repo": r["name"], **o} for o in a["occurrences"][:3]]
    order = {"broken": 0, "quantum-vulnerable": 1, "review": 2, "quantum-safe": 3}
    return {"overall": CI.readiness(combined), "repos": sorted(repos, key=lambda x: x["score"]),
            "algorithms": sorted(algs.values(), key=lambda a: (order[a["classification"]], -a["uses"])),
            "guidance": "Quantum-vulnerable public-key cryptography is a migration item, not an open vulnerability: plan ML-KEM "
                        "(FIPS 203) and ML-DSA (FIPS 204), starting with hybrid key exchange for long-lived confidential data."}


CRA_START = datetime(2026, 9, 11, tzinfo=timezone.utc)
CRA_STAGES = (("early_warning", 24, "Early warning to the CSIRT coordinator and ENISA"),
              ("notification", 72, "Vulnerability notification with general information and mitigations"),
              ("final_report", None, "Final report no later than 14 days after a corrective measure is available"))


def _parse_ts(v):
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


@app.get("/api/v1/cra")
def cra_tracker(c: Ctx = Depends(ctx("findings:read"))):
    """EU Cyber Resilience Act readiness: Article 14 reporting clocks for actively exploited vulnerabilities, and the
    Annex I evidence RAT Flea DevSec holds per product (repository). A planning aid, not legal advice."""
    from myelin_engine import frameworks as FW
    now = datetime.now(timezone.utc)
    fs = c.store.findings()
    reportable = []
    for f in fs:
        if not (f.get("kev") or f.get("malicious")) or f.get("status") not in ("open", "fixed"):
            continue
        fixed_at = _parse_ts(f.get("fixed_at") or f.get("closed_at")) if f.get("status") == "fixed" else None
        if f.get("status") == "fixed" and (fixed_at is None or fixed_at < CRA_START):
            continue                                   # fixed before the obligations applied, or no fix date recorded
        rec = ((f.get("regulatory") or {}).get("cra") or {})
        aware = _parse_ts((rec.get("aware") or {}).get("at")) or _parse_ts(f.get("first_seen")) or now
        aware = max(aware, CRA_START)
        stages = []
        for key, hours, label in CRA_STAGES:
            due = aware + timedelta(hours=hours) if hours else (fixed_at + timedelta(days=14) if fixed_at else None)
            done = rec.get(key)
            stages.append({"stage": key, "label": label, "due": due.isoformat() if due else None,
                           "submitted": done, "status": "submitted" if done else "waiting_for_fix" if due is None
                           else "overdue" if now > due else "due"})
        reportable.append({"id": f["id"], "title": f["title"], "repo": f["repo"], "cve": f.get("cve"), "kev": bool(f.get("kev")),
                           "malicious": bool(f.get("malicious")), "status": f["status"], "aware_at": aware.isoformat(),
                           "stages": stages, "overdue": sum(st["status"] == "overdue" for st in stages)})
    reportable.sort(key=lambda x: (-x["overdue"], x["aware_at"]))
    o = [f for f in fs if f["status"] == "open"]
    products = []
    for r in c.store.repos():
        ro = [f for f in o if f["repo"] == r["name"]]
        ext = _ext(c, r["name"])
        pst = ext["posture"] or {}
        chk = {ch["id"]: ch["status"] for ch in pst.get("checks", [])}
        cra = next((m for m in FW.matrix(ro, ["sca", "sast", "secrets", "iac", "cicd", "supply"]) if m["id"] == "cra"), None)
        items = {
            "sbom": bool(c.store.sbom(r["name"])),
            "no_known_exploited": not any(f.get("kev") or f.get("malicious") for f in ro),
            "vulnerability_handling_within_sla": not any(f.get("age_days", 0) > f.get("sla_days", 999) and f["severity"] in ("critical", "high") for f in ro),
            "coordinated_disclosure_policy": chk.get("security-policy") == "pass",
            "secure_update_distribution": chk.get("signed-releases") == "pass",
            "secrets_protected": chk.get("no-committed-secrets", "pass") == "pass",
        }
        products.append({"repo": r["name"], "checks": items, "met": sum(items.values()), "total": len(items),
                         "annex_i_gaps": cra["gaps"] if cra else None, "posture_score": pst.get("score")})
    products.sort(key=lambda x: x["met"])
    return {"in_force_since": CRA_START.date().isoformat(), "full_application": "2027-12-11", "reportable": reportable,
            "summary": {"reportable": len(reportable), "overdue": sum(1 for x in reportable if x["overdue"]),
                        "products": len(products), "products_ready": sum(1 for p in products if p["met"] == p["total"])},
            "products": products, "legal_advice": False,
            "note": "Clocks start when the manufacturer becomes aware of active exploitation; RAT Flea DevSec uses the time the "
                    "finding was first seen (or the awareness time you record) and CISA KEV / malicious-release evidence. "
                    "Submit notifications through the ENISA Single Reporting Platform."}


class CraRecordIn(BaseModel):
    stage: str = Field(pattern="^(aware|early_warning|notification|final_report)$")
    reference: str = Field("", max_length=200)
    note: str = Field("", max_length=1000)
    at: str | None = Field(None, max_length=40)


@app.post("/api/v1/cra/{fid}")
def cra_record(fid: str, body: CraRecordIn, c: Ctx = Depends(ctx("findings:triage"))):
    """Record a CRA reporting milestone (or the time the organisation became aware of exploitation) on a finding."""
    _get(c, fid)
    at = _parse_ts(body.at) if body.at else datetime.now(timezone.utc)
    if body.at and at is None:
        raise HTTPException(422, "at: use an ISO 8601 timestamp")
    rec = {body.stage: {"at": at.isoformat(), "by": c.p.actor, "reference": body.reference, "note": body.note}}
    c.store.set_regulatory(fid, rec, c.p.actor)
    return {"id": fid, "recorded": rec}


# ─── compliance ───────────────────────────────────────────────────────────────
CONTROLS = [
    ("PCI DSS 4.0", "6.2.4", "Software engineering techniques prevent common attacks", {"sast", "dast"}),
    ("PCI DSS 4.0", "6.3.2", "Inventory of bespoke and third-party software (SBOM)", {"sca", "license"}),
    ("PCI DSS 4.0", "6.3.3", "Known vulnerabilities patched (critical within 1 month)", {"sca", "container"}),
    ("PCI DSS 4.0", "8.6.2", "No hard-coded passwords in scripts/config", {"secrets"}),
    ("ISO 27001:2022", "A.8.25", "Secure development life cycle", {"sast", "cicd"}),
    ("ISO 27001:2022", "A.8.28", "Secure coding", {"sast"}),
    ("ISO 27001:2022", "A.8.9", "Configuration management", {"iac"}),
    ("SOC 2", "CC8.1", "Change management — authorised, tested changes", {"cicd"}),
    ("SOC 2", "CC7.1", "Vulnerability detection & monitoring", {"sca", "container", "dast"}),
    ("NIST SSDF", "PS.2/PS.3", "Protect & archive software integrity (provenance)", {"cicd"}),
    ("NIST SSDF", "PW.4", "Reuse well-secured third-party software", {"sca", "license"}),
    ("EU CRA", "Annex I §2", "No known exploitable vulnerabilities; SBOM", {"sca", "container", "supply"}),
    ("OWASP Top 10:2025", "A03", "Software Supply Chain Failures", {"sca", "supply", "cicd"}),
    ("DORA", "Art. 9", "ICT security tools & change controls", {"cicd", "iac"}),
    ("RBI / SEBI CSCRF", "AppSec", "Secure SDLC, source code review, VAPT", {"sast", "dast", "sca"}),
    ("OWASP LLM Top 10 (2025)", "LLM01-10", "AI application risks", {"aibom"}),
    ("OWASP Agentic Top 10 (2026)", "ASI01-10", "Autonomous agent risks", {"aibom"}),
    ("PCI DSS 4.0", "1.3.1", "Inbound traffic to the cardholder environment restricted", {"cspm", "kspm", "paths"}),
    ("PCI DSS 4.0", "7.2.1", "Access assigned by job need (least privilege)", {"ciem", "kspm"}),
    ("PCI DSS 4.0", "11.5.1", "Intrusion detection monitors critical systems", {"runtime"}),
    ("ISO 27001:2022", "A.8.20", "Network security", {"cspm", "kspm"}),
    ("ISO 27001:2022", "A.8.2", "Privileged access rights", {"ciem", "kspm"}),
    ("ISO 27001:2022", "A.8.16", "Monitoring activities", {"runtime", "cspm"}),
    ("SOC 2", "CC6.1", "Logical access security", {"ciem", "cspm"}),
    ("SOC 2", "CC7.2", "Monitoring of system components for anomalies", {"runtime"}),
    ("NIST SP 800-53", "AC-6", "Least privilege", {"ciem", "kspm"}),
    ("NIST SP 800-53", "SC-7", "Boundary protection", {"cspm", "kspm", "paths"}),
    ("CIS Benchmarks", "Cloud & Kubernetes", "CIS foundations benchmarks for Azure, AWS, Google Cloud and Kubernetes", {"cspm", "kspm", "ciem"}),
    ("DORA", "Art. 10", "Detection of anomalous activities", {"runtime", "paths"}),
]


def _controls_for(f):
    out = []
    for fw, cid, _, eng in CONTROLS:
        if f["engine"] not in eng:
            continue
        if cid == "ASI01-10":
            if f.get("owasp_agentic"):
                from myelin_engine.frameworks import OWASP_AGENTIC_NAMES
                key = str(f["owasp_agentic"]).split(":")[0] + ":2026"
                if key in OWASP_AGENTIC_NAMES:
                    out.append(f"OWASP {key} {OWASP_AGENTIC_NAMES[key]}")
            continue
        if cid == "LLM01-10" and f.get("owasp_llm"):         # the exact LLM risk, not the whole list
            from myelin_engine.frameworks import OWASP_LLM_NAMES
            for part in str(f["owasp_llm"]).replace(",", "/").split("/"):
                key = part.strip().split(":")[0] + ":2025"
                if key in OWASP_LLM_NAMES:
                    out.append(f"OWASP {key} {OWASP_LLM_NAMES[key]}")
            continue
        out.append(f"{fw} {cid}")
    return out


@app.get("/api/compliance", dependencies=[Depends(feature("compliance"))])
def compliance(c: Ctx = Depends(ctx("findings:read"))):
    o = _open(c)
    out = []
    for fw, cid, name, eng in CONTROLS:
        rel = [f for f in o if f["engine"] in eng]
        p0 = sum(f["priority"] in ("P0", "P1") for f in rel)
        out.append({"framework": fw, "control": cid, "name": name, "open": len(rel), "blocking": p0,
                    "status": "pass" if p0 == 0 and len(rel) < 10 else "at_risk" if p0 < 5 else "fail"})
    return out


# ─── policy & scans ───────────────────────────────────────────────────────────
@app.get("/api/policies")
def get_policy(c: Ctx = Depends(ctx("policies:read"))):
    return _effective_policy(c.store)


class PolicyExceptionCreateIn(BaseModel):
    scope_type: str = Field(pattern="^(organisation|project|repository)$")
    scope_key: str = Field(min_length=1, max_length=300)
    match: dict
    reason: str = Field(min_length=10, max_length=3000)
    expires_at: datetime


@app.get("/api/policies/exceptions")
def list_policy_exceptions(c: Ctx = Depends(ctx("policies:read"))):
    return {"items": c.store.policy_exceptions() if hasattr(c.store, "policy_exceptions") else []}


@app.post("/api/policies/exceptions", status_code=201)
def create_policy_exception(body: PolicyExceptionCreateIn, c: Ctx = Depends(ctx("policies:write"))):
    allowed = {"fingerprint", "cve", "rule_id", "repo", "engine", "package"}
    if not body.match or set(body.match) - allowed:
        raise HTTPException(422, "exception match must contain supported exact finding fields")
    if body.scope_type == "organisation" and body.scope_key != "*":
        raise HTTPException(422, "organisation scope key must be *")
    if body.scope_type != "organisation" and body.scope_key == "*":
        raise HTTPException(422, "project/repository exceptions require an explicit scope key")
    expires = body.expires_at
    if expires.tzinfo is None: expires = expires.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        raise HTTPException(422, "exception expiry must be in the future")
    item = {"id": str(uuid.uuid4()), "scope_type": body.scope_type, "scope_key": body.scope_key,
        "match": body.match, "reason": body.reason, "status": "pending", "expires_at": expires.isoformat(),
        "requested_by": c.p.actor, "reviewed_by": None, "review_note": "",
        "created_at": datetime.now(timezone.utc).isoformat(), "reviewed_at": None}
    return {"exception": c.store.create_policy_exception(item),
        "note": "Exception is pending independent approval and is not active in policy evaluation."}


class PolicyExceptionReviewIn(BaseModel):
    decision: str = Field(pattern="^(approved|rejected)$")
    note: str = Field(min_length=5, max_length=2000)


@app.post("/api/policies/exceptions/{exception_id}/review")
def review_policy_exception(exception_id: str, body: PolicyExceptionReviewIn,
                            c: Ctx = Depends(ctx("policies:approve"))):
    if c.p.method not in {"oidc", "session"} or not c.p.mfa:
        raise HTTPException(403, "Exception decisions require an interactive MFA-authenticated identity")
    try: uuid.UUID(exception_id)
    except ValueError: raise HTTPException(422, "invalid exception ID") from None
    try:
        result = c.store.review_policy_exception(exception_id, c.p.actor, body.decision, body.note,
            datetime.now(timezone.utc).isoformat())
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    if not result: raise HTTPException(404, "pending exception request not found")
    return {"exception": result, "note": "Approved exception is now eligible for exact-match policy evaluation." if body.decision == "approved" else "Exception rejected and retained for audit."}


@app.get("/api/policies/versions")
def list_policy_versions(c: Ctx = Depends(ctx("policies:read"))):
    return {"items": c.store.policy_versions()}


class PolicyVersionIn(BaseModel):
    name: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    content: dict


@app.post("/api/policies/versions", status_code=201)
def create_policy_version(body: PolicyVersionIn, c: Ctx = Depends(ctx("policies:write"))):
    content = dict(body.content)
    if len(json.dumps(content, separators=(",", ":")).encode("utf-8")) > 1_000_000:
        raise HTTPException(413, "Policy definition exceeds the 1 MB limit")
    content["name"] = body.name
    content.pop("version", None)
    try:
        pol.evaluate([], content)
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(422, f"Invalid policy definition: {str(exc)[:250]}") from None
    if not isinstance(content.get("gates"), list) or len(content["gates"]) > 500:
        raise HTTPException(422, "Policy gates must be an array of at most 500 entries")
    for gate in content["gates"]:
        if not isinstance(gate, dict) or not isinstance(gate.get("when"), dict) or gate.get("action") not in {"block", "warn", "monitor"}:
            raise HTTPException(422, "Each policy gate needs a condition object and action block, warn or monitor")
        if not isinstance(gate.get("description", ""), str) or len(gate.get("description", "")) > 1000:
            raise HTTPException(422, "Policy gate descriptions must be strings of at most 1000 characters")
    exceptions = content.get("exceptions", [])
    if not isinstance(exceptions, list) or len(exceptions) > 500 or any(not isinstance(x, dict) or not isinstance(x.get("match", {}), dict) for x in exceptions):
        raise HTTPException(422, "Policy exceptions must be an array of at most 500 objects with match objects")
    gate_ids = [g.get("id") for g in content["gates"] if isinstance(g, dict)]
    if len(gate_ids) != len(content["gates"]) or any(not isinstance(x, str) or not x for x in gate_ids) or len(set(gate_ids)) != len(gate_ids):
        raise HTTPException(422, "Every policy gate needs a unique non-empty ID")
    versions = [x for x in c.store.policy_versions() if x["name"] == body.name]
    version = max((x["version"] for x in versions), default=0) + 1
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    item = {"id": str(uuid.uuid4()), "name": body.name, "version": version, "content_sha256": digest,
        "content": content, "status": "draft", "created_by": c.p.actor,
        "created_at": datetime.now(timezone.utc).isoformat(), "published_by": None, "published_at": None}
    try:
        c.store.create_policy_version(item)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    return {"version": item, "note": "Immutable draft created. Submit it for independent approval before binding."}



@app.post("/api/policies/versions/{version_id}/rollback", status_code=201)
def rollback_policy_version(version_id: str, c: Ctx = Depends(ctx("policies:write"))):
    """Create a new immutable draft using a prior published version's content; never mutate history."""
    try:
        uuid.UUID(version_id)
    except ValueError:
        raise HTTPException(422, "invalid policy version ID") from None
    source = c.store.get_policy_version(version_id)
    if not source or source["status"] not in {"published", "superseded"}:
        raise HTTPException(404, "published source policy version not found")
    versions = [x for x in c.store.policy_versions() if x["name"] == source["name"]]
    next_version = max((x["version"] for x in versions), default=0) + 1
    content = dict(source["content"])
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    item = {"id": str(uuid.uuid4()), "name": source["name"], "version": next_version,
        "content_sha256": digest, "content": content, "status": "draft", "created_by": c.p.actor,
        "created_at": datetime.now(timezone.utc).isoformat(), "published_by": None, "published_at": None}
    c.store.create_policy_version(item, event="policy.version.rollback_draft_created", detail={"source_policy_version_id": version_id, "new_policy_version_id": item["id"], "version": next_version})
    return {"version": item, "source_policy_version_id": version_id,
        "note": "Rollback is staged as a new immutable draft and requires independent approval before activation."}


@app.post("/api/policies/versions/{version_id}/request-approval", status_code=201)
def request_policy_approval(version_id: str, c: Ctx = Depends(ctx("policies:write"))):
    try:
        uuid.UUID(version_id)
    except ValueError:
        raise HTTPException(422, "invalid policy version ID") from None
    version = c.store.get_policy_version(version_id)
    if not version:
        raise HTTPException(404, "policy version not found")
    if version["status"] != "draft":
        raise HTTPException(409, "only a draft policy version can be submitted")
    item = {"id": str(uuid.uuid4()), "policy_version_id": version_id, "requested_by": c.p.actor,
        "status": "pending", "reviewed_by": None, "review_note": "",
        "created_at": datetime.now(timezone.utc).isoformat(), "reviewed_at": None}
    try:
        c.store.create_policy_approval(item)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    return {"approval": item}


@app.get("/api/policies/approvals")
def list_policy_approvals(c: Ctx = Depends(ctx("policies:read"))):
    if not hasattr(c.store, "policy_approval_requests"):
        return {"items": []}
    return {"items": list(c.store.policy_approval_requests())}


class PolicyApprovalReviewIn(BaseModel):
    decision: str = Field(pattern="^(approved|rejected)$")
    note: str = Field(min_length=5, max_length=2000)


@app.post("/api/policies/approvals/{request_id}/review")
def review_policy_approval(request_id: str, body: PolicyApprovalReviewIn, c: Ctx = Depends(ctx("policies:approve"))):
    if c.p.method not in {"oidc", "session"} or not c.p.mfa:
        raise HTTPException(403, "Policy publication decisions require an interactive MFA-authenticated identity")
    try:
        uuid.UUID(request_id)
    except ValueError:
        raise HTTPException(422, "invalid approval request ID") from None
    try:
        result = c.store.review_policy_approval(request_id, c.p.actor, body.decision, body.note,
            datetime.now(timezone.utc).isoformat())
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from None
    if not result:
        raise HTTPException(404, "pending approval request not found")
    return {"approval": result, "note": "Approved versions are now eligible for scoped binding." if body.decision == "approved" else "Version rejected; immutable content retained for audit."}


class PolicyBindingIn(BaseModel):
    policy_version_id: str
    scope_type: str = Field(pattern="^(organisation|project|repository)$")
    scope_key: str = Field(min_length=1, max_length=300)


@app.put("/api/policies/bindings")
def bind_policy(body: PolicyBindingIn, c: Ctx = Depends(ctx("policies:write"))):
    if body.scope_type == "organisation" and body.scope_key != "*":
        raise HTTPException(422, "organisation scope key must be '*'")
    if body.scope_type != "organisation" and body.scope_key.strip() in {"", "*"}:
        raise HTTPException(422, "project and repository scopes require an explicit key")
    try:
        uuid.UUID(body.policy_version_id)
    except ValueError:
        raise HTTPException(422, "invalid policy version ID") from None
    version = c.store.get_policy_version(body.policy_version_id)
    if not version:
        raise HTTPException(404, "policy version not found")
    if version["status"] != "published":
        raise HTTPException(409, "only an independently approved and published version can be bound")
    item = {"id": str(uuid.uuid4()), "scope_type": body.scope_type, "scope_key": body.scope_key,
        "policy_version_id": body.policy_version_id, "updated_by": c.p.actor,
        "updated_at": datetime.now(timezone.utc).isoformat()}
    try:
        c.store.bind_policy(item)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    return {"binding": item}


@app.get("/api/policies/bindings")
def list_policy_bindings(c: Ctx = Depends(ctx("policies:read"))):
    return {"items": c.store.policy_bindings()}



class RepositoryProjectMappingIn(BaseModel):
    repo: str = Field(min_length=1, max_length=300)
    project: str = Field(min_length=1, max_length=300)


@app.put("/api/policies/repository-projects")
def map_repository_project(body: RepositoryProjectMappingIn, c: Ctx = Depends(ctx("policies:write"))):
    result = c.store.set_repo_project(body.repo, body.project, c.p.actor)
    return {"mapping": result}


@app.get("/api/policies/repository-projects")
def list_repository_projects(c: Ctx = Depends(ctx("policies:read"))):
    repos = c.store.repos()
    return {"items": [{"repo": x["name"], "project": x.get("project")} for x in repos if x.get("project")]}


@app.get("/api/policies/effective")
def effective_policy(repo: str | None = Query(default=None, max_length=300),
                     project: str | None = Query(default=None, max_length=300),
                     c: Ctx = Depends(ctx("policies:read"))):
    return _effective_policy(c.store, repo=repo, project=project)


@app.post("/api/policies/evaluate")
def evaluate(repo: str | None = None, project: str | None = None, c: Ctx = Depends(ctx("findings:read"))):
    fs = [f for f in c.store.findings() if not repo or f["repo"] == repo]
    return pol.evaluate(fs, _effective_policy(c.store, repo=repo, project=project if not repo else None))


class ScanUpload(BaseModel):
    repo: str = Field(min_length=1, max_length=300)
    branch: str = Field("main", max_length=300)
    commit: str = Field("", max_length=64)
    findings: list[dict] = Field(max_length=50000)
    sbom: dict | None = None
    engines: list[str] | None = Field(default=None, max_length=20)   # engines with completed coverage
    reconcile_engines: list[str] | None = Field(default=None, max_length=20)  # includes areas with confirmed removed inputs
    stats: dict | None = None                                         # {"raw", "after_dedup", "reported"} from the CLI


@app.post("/api/scans")
def upload_scan(body: ScanUpload, c: Ctx = Depends(ctx("scans:write"))):
    """Ingest results from `myelin scan --server` (any CI)."""
    fs = [enrich(dict(f)) for f in body.findings if f.get("engine") != "meta"]
    for f in fs:
        f.setdefault("first_seen", datetime.now(timezone.utc).isoformat())
        f.setdefault("age_days", 0)
        f["repo"] = body.repo
    errors = [enrich(dict(f)) for f in body.findings
              if f.get("engine") == "meta" and f.get("scanner_status") == "required_error"]
    decision = pol.evaluate(fs + errors, _effective_policy(c.store, repo=body.repo))
    sid, new = c.store.add_scan(body.repo, body.branch, body.commit, fs, body.sbom, decision, c.p.actor, scanned_engines=body.engines,
                                  reconcile_engines=body.reconcile_engines,
                                  stats=body.stats if isinstance(body.stats, dict) else None)
    tickets = after_scan(c.store, getattr(c.store, "last_delta", None), c.p.tenant_id)
    if not ENTERPRISE:
        c.store.audit_event("scan.uploaded", c.p.actor, f"{body.repo}@{body.branch}: {len(fs)} findings, {new} new, gate={decision['decision']}")
    return {"scan_id": sid, "received": len(fs), "new": new, "decision": decision, "tickets": tickets}


class ScanImportIn(BaseModel):
    repo: str = Field(min_length=1, max_length=300)
    branch: str = Field("main", max_length=300)
    commit: str = Field("", max_length=64)
    filename: str = Field("", max_length=300)
    format: str = Field("auto", max_length=20)
    content_base64: str = Field(min_length=4, max_length=40_000_000)


@app.post("/api/v1/scans/import")
def import_scan(body: ScanImportIn, c: Ctx = Depends(ctx("scans:write"))):
    """Bring your own scanner: SARIF, CycloneDX, Trivy, Grype, Semgrep, Gitleaks, Checkov, Bandit or ZAP results become
    RAT Flea DevSec findings (de-duplicated, risk-scored, gated, ticketed, reported). Imports never auto-close other findings."""
    from myelin_engine import importers
    try:
        raw = base64.b64decode(body.content_base64, validate=False)
        fmt, found = importers.parse(raw, body.repo, body.filename, body.format)
    except (importers.ImportError_, ValueError) as e:
        raise HTTPException(400, f"could not import {body.filename or 'the file'}: {e}") from None
    if len(found) > 50000:
        raise HTTPException(413, "more than 50,000 results in one file")
    res = upload_scan(ScanUpload(repo=body.repo, branch=body.branch, commit=body.commit, findings=found, engines=[],
                                 stats={"raw": len(found), "after_dedup": len(found), "reported": len(found)}), c)
    c.store.audit_event("scan.imported", c.p.actor, {"text": f"{fmt} import into {body.repo}: {len(found)} results", "format": fmt})
    return {**res, "format": fmt}


@app.get("/api/v1/vex")
def vex_export(repo: str = Query(min_length=1, max_length=300), format: str = Query("openvex", pattern="^(openvex|cyclonedx)$"),
               c: Ctx = Depends(ctx("findings:read"))):
    """VEX document for a repository built from triage decisions (fixed, false positive, accepted risk, open)."""
    from fastapi.responses import JSONResponse
    from myelin_engine import vex
    fs = [f for f in c.store.findings() if f.get("repo") == repo]
    if not fs:
        raise HTTPException(404, f"no findings for {repo}")
    product = f"pkg:generic/{repo}"
    doc = vex.openvex(fs, product, author=c.store.tenant().get("name") or "RAT Flea DevSec") if format == "openvex" else vex.cyclonedx_vex(fs, product)
    c.store.audit_event("vex.exported", c.p.actor, {"text": f"{format} VEX for {repo}", "statements": len(doc.get("statements") or doc.get("vulnerabilities") or [])})
    name = f"{repo}.{'openvex' if format == 'openvex' else 'vex.cdx'}.json"
    return JSONResponse(doc, headers={"Content-Disposition": f'attachment; filename="{name}"'})


class VexIn(BaseModel):
    content_base64: str = Field(min_length=4, max_length=20_000_000)
    repo: str | None = Field(default=None, max_length=300)
    dry_run: bool = True        # VEX never changes a finding by itself: preview, then an analyst applies with dry_run=false


@app.post("/api/v1/vex/import")
def vex_import(body: VexIn, c: Ctx = Depends(ctx("findings:triage"))):
    """Apply a supplier's or your own VEX (OpenVEX, CycloneDX VEX or CSAF 2.0). Only exact vulnerability + component
    matches apply: not_affected -> false positive (with the justification), fixed -> fixed. Conflicting statements are
    ambiguous and ignored; under-investigation and affected never close anything."""
    import json as _json
    from myelin_engine import vex
    try:
        doc = _json.loads(base64.b64decode(body.content_base64).decode("utf-8-sig"))
        matches, ambiguous = vex.match_statements(
            [f for f in c.store.findings() if f.get("status") in ("open", "risk_accepted") and (not body.repo or f.get("repo") == body.repo)], [doc])
        statements = len(vex.normalize_document(doc))
    except (ValueError, UnicodeDecodeError) as e:
        raise HTTPException(400, f"not a usable VEX document: {e}") from None
    applied = []
    for f, st in matches:
        target = {"not_affected": "suppressed", "fixed": "fixed"}.get(st["state"])
        if not target or f.get("status") == target:
            continue
        applied.append({"finding": f["id"], "vulnerability": st["vulnerability"], "status": target, "source": st.get("source")})
        if not body.dry_run:
            why = " ".join(x for x in [st.get("justification"), st.get("detail")] if x) or "no justification given"
            c.store.set_status(f["id"], target, c.p.actor, f"VEX {st['state']} ({st.get('source')}): {why}"[:1000])
    c.store.audit_event("vex.imported", c.p.actor, {"text": f"VEX import: {statements} statements, {len(applied)} findings updated, "
                                                        f"{ambiguous} ambiguous" + (" (dry run)" if body.dry_run else ""), "statements": statements})
    return {"statements": statements, "matched": len(applied), "ambiguous": ambiguous, "applied": [] if body.dry_run else applied,
            "would_apply": applied if body.dry_run else None}


class LiveScan(BaseModel):
    path: str = "demo/vulnerable-app"
    repo: str = "payments-web"


@app.post("/api/scans/live")
def live_scan(body: LiveScan, c: Ctx = Depends(ctx("scans:run"))):
    """Run the engine server-side against a path inside the deployment (used for the live demo)."""
    base = os.path.abspath(settings.live_scan_root)
    p = os.path.abspath(os.path.join(ROOT, body.path))
    if os.path.commonpath([p, base]) != base or not os.path.isdir(p):
        raise HTTPException(400, "path must be a directory inside the RAT Flea DevSec workspace")
    res = orchestrator.scan(p, repo=body.repo, criticality=1.4, advisory_lookup=c.store.advisories_for)
    decision = pol.evaluate(res["findings"], _effective_policy(c.store, repo=body.repo))
    c.store.audit_event("scan.completed", c.p.actor, f"live scan {body.repo}: {len(res['findings'])} findings, gate={decision['decision']}")
    return {**{k: res[k] for k in ("repo", "duration_s", "tools", "components", "coverage", "engines")},
            "findings": res["findings"], "decision": decision}


# ─── API keys (enterprise) ────────────────────────────────────────────────────
class ApiKeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    roles: list[str] = ["integration"]
    days: int = Field(90, ge=1, le=365)


@app.post("/api/v1/api-keys")
def create_api_key(body: ApiKeyIn, c: Ctx = Depends(ctx("apikeys:manage"))):
    if not ENTERPRISE:
        raise HTTPException(400, "API keys are managed in enterprise mode")
    bad = set(body.roles) - ROLES
    if bad or {"tenant_admin", "policy_approver"} & set(body.roles):
        raise HTTPException(400, "invalid roles for an API key")
    key = AUTH.create_api_key(c.p, body.name, body.roles, body.days)
    c.store.audit_event("apikey.created", c.p.actor, {"text": f"API key '{body.name}' created", "roles": body.roles})
    return {"api_key": key, "note": "Shown once. Store it in your CI secret store."}


# ─── live application testing (online) ───────────────────────────────────────
from . import dast_targets as DT  # noqa: E402

TARGETS = DT.PgTargets(DB_URL) if ENTERPRISE else DT.MemoryTargets()


class IdentityIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    role: str = Field(default="user", max_length=60)
    headers: dict[str, str] = Field(min_length=1, max_length=5)     # enterprise: secret references only


class TargetIn(BaseModel):
    name: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9 ._-]+$")
    base_url: str = Field(max_length=2048)
    spec_url: str | None = Field(default=None, max_length=2048)
    spec: dict | None = None
    identities: list[IdentityIn] = Field(default_factory=list, max_length=10)
    criticality: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    privileged: list[dict] = Field(default_factory=list, max_length=50)
    cross_user_roles: list[str] = Field(default_factory=lambda: ["admin"], max_length=10)
    max_requests: int = Field(default=600, ge=50, le=5000)
    crawl: bool = True                    # discover pages, forms and query parameters (read-only)
    active_checks: bool = False           # authorised active checks; runs only after ownership is verified


class TargetPatch(BaseModel):
    spec_url: str | None = Field(default=None, max_length=2048)          # "" or null clears the spec
    crawl: bool | None = None
    active_checks: bool | None = None
    identities: list[IdentityIn] | None = None
    criticality: str | None = Field(default=None, pattern="^(low|medium|high|critical)$")


def _dast_runtime():
    if ENTERPRISE:
        from myelin_engine.dast import host_guard
        return {"resolver": lambda ref: sm.resolve(ref), "guard": host_guard(settings.dast_allow_private),
                "require_verification": settings.dast_require_verification, "max_requests": settings.dast_max_requests}
    return {"resolver": None, "guard": None, "require_verification": False, "max_requests": 1500}   # demo: local targets allowed


def _dast(fn):
    try:
        return fn()
    except DT.TargetError as e:
        raise HTTPException(e.status, str(e)) from None


@app.get("/api/v1/dast/targets", dependencies=[Depends(feature("dast"))])
def dast_list(c: Ctx = Depends(ctx("dast:read"))):
    return [DT.public(t) for t in TARGETS.list(c.p.tenant_id)]


@app.post("/api/v1/dast/targets", status_code=201, dependencies=[Depends(feature("dast"))])
def dast_create(body: TargetIn, c: Ctx = Depends(ctx("dast:manage"))):
    data = body.model_dump()
    if data["max_requests"] > settings.dast_max_requests:
        raise HTTPException(400, f"max_requests above the platform limit ({settings.dast_max_requests})")
    _dast(lambda: DT.validate(data, c.p.tenant_id, ENTERPRISE))
    if ENTERPRISE:
        from urllib.parse import urlsplit
        guard = _dast_runtime()["guard"]
        try:
            if guard:
                guard(urlsplit(data["base_url"]).hostname)
        except RuntimeError as e:
            raise HTTPException(400, str(e)) from None
    t = DT.new_target(data, c.p.actor)
    _dast(lambda: TARGETS.add(c.p.tenant_id, t))
    c.store.audit_event("dast.target.created", c.p.actor, {"text": f"Live-application target '{t['name']}' registered ({t['base_url']})"})
    return DT.public(t)


@app.get("/api/v1/dast/targets/{tid}", dependencies=[Depends(feature("dast"))])
def dast_get(tid: str, c: Ctx = Depends(ctx("dast:read"))):
    return DT.public(_dast(lambda: TARGETS.get(c.p.tenant_id, tid)))


@app.patch("/api/v1/dast/targets/{tid}", dependencies=[Depends(feature("dast"))])
def dast_update(tid: str, body: TargetPatch, c: Ctx = Depends(ctx("dast:manage"))):
    """Change the spec, identities or criticality. The address cannot change, so verified ownership is kept."""
    t = _dast(lambda: TARGETS.get(c.p.tenant_id, tid))
    if t["status"] == "running" and not DT.is_stale(t):
        raise HTTPException(409, "a run is in progress; edit the target when it has finished")
    sent, fields = body.model_fields_set, {}
    if "spec_url" in sent:
        fields["spec_url"], fields["spec"] = (body.spec_url or "").strip() or None, None
    if "identities" in sent and body.identities is not None:
        fields["identities"] = [i.model_dump() for i in body.identities]
    if "criticality" in sent and body.criticality:
        fields["config"] = {**(t.get("config") or {}), "criticality": body.criticality}
    for k in ("crawl", "active_checks"):
        if k in sent and getattr(body, k) is not None:
            fields["config"] = {**(fields.get("config") or t.get("config") or {}), k: getattr(body, k)}
    merged = {**t, **fields}
    _dast(lambda: DT.validate(merged, c.p.tenant_id, ENTERPRISE))
    if fields:
        _dast(lambda: TARGETS.update(c.p.tenant_id, tid, **fields))
        c.store.audit_event("dast.target.updated", c.p.actor,
                            {"text": f"Live-application target '{t['name']}' updated ({', '.join(sorted(k for k in fields if k != 'spec'))})"})
    return DT.public(_dast(lambda: TARGETS.get(c.p.tenant_id, tid)))


@app.delete("/api/v1/dast/targets/{tid}", dependencies=[Depends(feature("dast"))])
def dast_delete(tid: str, c: Ctx = Depends(ctx("dast:manage"))):
    t = _dast(lambda: TARGETS.get(c.p.tenant_id, tid))
    _dast(lambda: TARGETS.delete(c.p.tenant_id, tid))
    c.store.audit_event("dast.target.deleted", c.p.actor, {"text": f"Live-application target '{t['name']}' deleted"})
    return {"deleted": tid}


@app.post("/api/v1/dast/targets/{tid}/verify", dependencies=[Depends(feature("dast"))])
def dast_verify(tid: str, c: Ctx = Depends(ctx("dast:manage"))):
    t = _dast(lambda: TARGETS.get(c.p.tenant_id, tid))
    ok = _dast(lambda: DT.verify_ownership(t, _dast_runtime()["guard"]))
    if not ok:
        raise HTTPException(409, f"token not found at {t['base_url']}{DT.WELL_KNOWN}")
    TARGETS.update(c.p.tenant_id, tid, verified_at=DT.now())
    c.store.audit_event("dast.target.verified", c.p.actor, {"text": f"Ownership of '{t['name']}' verified"})
    return {"verified": True}


@app.post("/api/v1/dast/targets/{tid}/run", status_code=202, dependencies=[Depends(feature("dast"))])
def dast_run(tid: str, request: Request, c: Ctx = Depends(ctx("dast:run"))):
    t = _dast(lambda: TARGETS.get(c.p.tenant_id, tid))
    rt = _dast_runtime()
    tenant = c.p.tenant_id
    factory = (lambda: PgStore(DB_URL, tenant)) if ENTERPRISE else (lambda: DEMO)
    sync = request.query_params.get("wait") == "true"
    _dast(lambda: DT.start_run(TARGETS, factory, tenant, t, c.p.actor, resolver=rt["resolver"], guard=rt["guard"],
                               max_requests=rt["max_requests"], require_verification=rt["require_verification"], synchronous=sync,
                               on_scanned=lambda store, delta: after_scan(store, delta, tenant)))
    c.store.audit_event("dast.run.started", c.p.actor, {"text": f"Live-application assessment of '{t['name']}' started"})
    return DT.public(TARGETS.get(tenant, tid))


@app.get("/api/v1/dast/targets/{tid}/result", dependencies=[Depends(feature("dast"))])
def dast_result(tid: str, c: Ctx = Depends(ctx("dast:read"))):
    t = _dast(lambda: TARGETS.get(c.p.tenant_id, tid))
    if not t.get("last_result"):
        raise HTTPException(404, "no completed run yet")
    return t["last_result"]


@app.get("/api/v1/dast/targets/{tid}/report", dependencies=[Depends(feature("dast"))])
def dast_report(tid: str, request: Request, c: Ctx = Depends(ctx("dast:read"))):
    from fastapi.responses import HTMLResponse
    t = _dast(lambda: TARGETS.get(c.p.tenant_id, tid))
    q = request.query_params
    html = _dast(lambda: DT.render_report(t, c.store.tenant().get("name", ""), audience=q.get("audience", "internal"),
                                          prepared_for=q.get("prepared_for", "")[:120], classification=q.get("classification", "")[:80],
                                          title=q.get("title", "")[:120]))
    return HTMLResponse(html, headers={"Content-Disposition": f'inline; filename="myelin-assessment-{t["name"]}.html"',
                                       "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"})


# ─── repositories scanned from the console ────────────────────────────────────
from . import repo_sources as RS  # noqa: E402
from . import secrets as sm  # noqa: E402,F811

SOURCES = RS.PgSources(DB_URL) if ENTERPRISE else RS.MemorySources()


class SourceIn(BaseModel):
    url: str = Field(min_length=10, max_length=2048)
    provider: str = Field(default="auto", pattern="^(auto|github|gitlab|bitbucket|azure|codecommit|gcp|git)$")
    name: str | None = Field(default=None, max_length=200)
    branch: str | None = Field(default=None, max_length=200)
    token: str | None = Field(default=None, max_length=4096)            # pasted once; stored in the vault, never in the database
    criticality: str = Field(default="medium", pattern="^(low|medium|high|critical)$")


def _rs(fn):
    try:
        return fn()
    except RS.SourceError as e:
        raise HTTPException(e.status, str(e)) from None
    except sm.SecretError as e:
        raise HTTPException(400, str(e)) from None


def _source_token(src):
    if not ENTERPRISE:
        return SOURCES._tokens.get(str(src["id"]))
    return sm.resolve(src["credential_ref"])


@app.get("/api/v1/repos/providers")
def sources_providers(c: Ctx = Depends(ctx("findings:read"))):
    from . import scm
    return [{"id": k, "name": v, "token_help": scm.TOKEN_HELP[k]} for k, v in scm.PROVIDERS.items()]


@app.get("/api/v1/repos/sources")
def sources_list(c: Ctx = Depends(ctx("findings:read"))):
    return [RS.public(s) for s in SOURCES.list(c.p.tenant_id)]


@app.post("/api/v1/repos/sources", status_code=201)
def sources_create(body: SourceIn, request: Request, c: Ctx = Depends(ctx("scans:run"))):
    """Add a repository and start its first scan. A pasted token goes straight to the vault."""
    src = _rs(lambda: RS.new_source(body.model_dump(), c.p.actor))
    token = (body.token or "").strip()
    if token:
        if ENTERPRISE:
            if not sm.vault_available():
                raise HTTPException(400, "private repositories need a secret vault (VAULT_ADDR) to hold the access token")
            src["credential_ref"] = RS.token_ref(c.p.tenant_id, src["id"])
            _rs(lambda: sm.store(src["credential_ref"], token))
        else:
            src["credential_ref"] = "memory"
    try:
        _rs(lambda: SOURCES.add(c.p.tenant_id, src))
    except HTTPException:
        if ENTERPRISE and src["credential_ref"]:
            sm.forget(src["credential_ref"])
        raise
    if token and not ENTERPRISE:
        SOURCES._tokens[str(src["id"])] = token
    c.store.audit_event("repo.source.added", c.p.actor,
                        {"text": f"Repository '{src['name']}' added ({src['url']}{', private' if token else ''})"})
    if request.query_params.get("scan", "true") == "true":
        return sources_scan(str(src["id"]), request, c)
    return RS.public(SOURCES.get(c.p.tenant_id, src["id"]))


from . import repo_import as RI  # noqa: E402


class FileImportIn(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content_base64: str = Field(min_length=1, max_length=14_000_000)


class DiscoverIn(BaseModel):
    provider: str = Field(pattern="^(github|gitlab|azure|bitbucket)$")
    target: str = Field(min_length=1, max_length=500)
    token: str | None = Field(default=None, max_length=8192)
    include_archived: bool = False


class ImportItem(BaseModel):
    url: str = Field(min_length=10, max_length=2048)
    provider: str = Field(default="auto", pattern="^(auto|github|gitlab|bitbucket|azure|codecommit|gcp|git)$")
    name: str | None = Field(default=None, max_length=200)
    branch: str | None = Field(default=None, max_length=200)
    criticality: str | None = Field(default=None, pattern="^(low|medium|high|critical)$")


class ImportIn(BaseModel):
    items: list[ImportItem] = Field(min_length=1, max_length=1000)
    tokens: dict[str, str] = Field(default={}, max_length=8)            # provider -> credential, stored once per repository
    criticality: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    scan: bool = True


def _ri(fn):
    try:
        return fn()
    except RI.ImportError_ as e:
        raise HTTPException(e.status, str(e)) from None
    except scm_mod.ScmError as e:
        raise HTTPException(e.status, str(e)) from None


from . import scm as scm_mod  # noqa: E402


def _mark_existing(tenant, repos):
    have = {s["url"].lower() for s in SOURCES.list(tenant)}
    for r in repos:
        r["already_added"] = r["url"].lower() in have
    return repos


@app.post("/api/v1/repos/import/file")
def import_file(body: FileImportIn, c: Ctx = Depends(ctx("scans:run"))):
    """Preview: repository addresses found in an uploaded file. Nothing is created."""
    try:
        data = base64.b64decode(body.content_base64, validate=True)
    except ValueError:
        raise HTTPException(400, "the file content is not valid base64") from None
    res = _ri(lambda: RI.extract_file(body.filename, data))
    res["repositories"] = _mark_existing(c.p.tenant_id, res["repositories"])
    return res


@app.post("/api/v1/repos/import/discover")
def import_discover(body: DiscoverIn, c: Ctx = Depends(ctx("scans:run"))):
    """Preview: repositories in an organisation / group / project / workspace. Nothing is created."""
    res = _ri(lambda: RI.discover(body.provider, body.target, body.token, body.include_archived))
    res["repositories"] = _mark_existing(c.p.tenant_id, res["repositories"])
    return res


@app.post("/api/v1/repos/import")
def import_many(body: ImportIn, c: Ctx = Depends(ctx("scans:run"))):
    """Add the selected repositories (skipping ones already added) and queue their scans."""
    added, skipped = [], []
    have = {s["url"].lower() for s in SOURCES.list(c.p.tenant_id)}
    names = {s["name"].lower() for s in SOURCES.list(c.p.tenant_id)}
    tenant = c.p.tenant_id
    factory = (lambda: PgStore(DB_URL, tenant)) if ENTERPRISE else (lambda: DEMO)
    for it in body.items:
        try:
            src = RS.new_source({"url": it.url, "provider": it.provider, "branch": it.branch, "name": it.name,
                                 "criticality": it.criticality or body.criticality}, c.p.actor)
        except RS.SourceError as e:
            skipped.append({"url": it.url, "reason": str(e)})
            continue
        if src["url"].lower() in have:
            skipped.append({"url": src["url"], "reason": "already added"})
            continue
        base, n = src["name"], 2
        while src["name"].lower() in names:                       # same repository name in two organisations
            src["name"] = f"{base}-{n}"
            n += 1
        token = (body.tokens.get(src["provider"]) or body.tokens.get("*") or "").strip()
        if token:
            if ENTERPRISE:
                if not sm.vault_available():
                    raise HTTPException(400, "private repositories need a secret vault (VAULT_ADDR) to hold the access token")
                src["credential_ref"] = RS.token_ref(tenant, src["id"])
                _rs(lambda: sm.store(src["credential_ref"], token))
            else:
                src["credential_ref"] = "memory"
        try:
            _rs(lambda: SOURCES.add(tenant, src))
        except HTTPException as e:
            skipped.append({"url": src["url"], "reason": str(e.detail)})
            continue
        if token and not ENTERPRISE:
            SOURCES._tokens[str(src["id"])] = token
        have.add(src["url"].lower()); names.add(src["name"].lower())
        if body.scan:
            RS.start_scan(SOURCES, factory, tenant, SOURCES.get(tenant, src["id"]), c.p.actor, token_resolver=_source_token,
                          decide=lambda fs: pol.evaluate(fs, _effective_policy(factory(), repo=src["name"])), on_scanned=lambda store, delta: after_scan(store, delta, tenant))
        added.append({"id": str(src["id"]), "name": src["name"], "url": src["url"], "provider": src["provider"]})
    c.store.audit_event("repo.import", c.p.actor, {"text": f"Imported {len(added)} repositories ({len(skipped)} skipped)"
                                                           + (", scans queued" if body.scan and added else "")})
    return {"added": added, "skipped": skipped, "queued": len(added) if body.scan else 0}


@app.post("/api/v1/repos/sources/{sid}/scan")
def sources_scan(sid: str, request: Request, c: Ctx = Depends(ctx("scans:run"))):
    src = _rs(lambda: SOURCES.get(c.p.tenant_id, sid))
    tenant = c.p.tenant_id
    factory = (lambda: PgStore(DB_URL, tenant)) if ENTERPRISE else (lambda: DEMO)
    _rs(lambda: RS.start_scan(SOURCES, factory, tenant, src, c.p.actor, token_resolver=_source_token,
                              decide=lambda fs: pol.evaluate(fs, _effective_policy(factory(), repo=src["name"])), synchronous=request.query_params.get("wait") == "true",
                              on_scanned=lambda store, delta: after_scan(store, delta, tenant)))
    c.store.audit_event("repo.scan.started", c.p.actor, {"text": f"Scan of repository '{src['name']}' started"})
    return RS.public(SOURCES.get(tenant, sid))


@app.get("/api/v1/repos/sources/{sid}/report")
def sources_report(sid: str, request: Request, c: Ctx = Depends(ctx("findings:read"))):
    from fastapi.responses import HTMLResponse
    src = _rs(lambda: SOURCES.get(c.p.tenant_id, sid))
    q = request.query_params
    html = _rs(lambda: RS.render_report(src, c.store.tenant().get("name", ""), audience=q.get("audience", "internal"),
                                        prepared_for=q.get("prepared_for", "")[:120], classification=q.get("classification", "")[:80],
                                        title=q.get("title", "")[:120]))
    return HTMLResponse(html, headers={"Content-Disposition": f'inline; filename="myelin-code-report-{src["name"]}.html"',
                                       "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"})


@app.get("/api/v1/repos/sources/{sid}/sbom")
def sources_sbom(sid: str, c: Ctx = Depends(ctx("findings:read"))):
    src = _rs(lambda: SOURCES.get(c.p.tenant_id, sid))
    if not (src.get("last_result") or {}).get("sbom"):
        raise HTTPException(404, "no completed scan yet")
    return JSONResponse(_public_sbom(src["last_result"]["sbom"]), headers={"Content-Disposition": f'attachment; filename="{src["name"]}.cdx.json"'})


@app.delete("/api/v1/repos/sources/{sid}", status_code=204)
def sources_delete(sid: str, c: Ctx = Depends(ctx("scans:run"))):
    src = _rs(lambda: SOURCES.get(c.p.tenant_id, sid))
    if src["status"] == "running" and not RS.is_stale(src):
        raise HTTPException(409, "a scan is in progress")
    _rs(lambda: SOURCES.delete(c.p.tenant_id, sid))
    if ENTERPRISE and src.get("credential_ref"):
        sm.forget(src["credential_ref"])
    c.store.audit_event("repo.source.removed", c.p.actor, {"text": f"Repository '{src['name']}' removed (findings history kept)"})


# ─── ticketing (Jira, ServiceNow, Azure Boards, webhooks) ─────────────────────
from . import itsm  # noqa: E402

TICKETING = itsm.PgIntegrations(DB_URL) if ENTERPRISE else itsm.MemoryIntegrations()
ITSM_TRANSPORT = None          # test hook: an httpx transport for the ticketing clients


class IntegrationIn(BaseModel):
    kind: str = Field(pattern="^(jira|servicenow|azure_boards|webhook)$")
    name: str | None = Field(default=None, max_length=200)
    config: dict = {}
    routing: list[dict] = Field(default=[], max_length=100)
    auto: dict = {}
    token: str | None = Field(default=None, max_length=8192)            # pasted once; stored in the vault


class IntegrationPatch(BaseModel):
    enabled: bool | None = None
    routing: list[dict] | None = Field(default=None, max_length=100)
    auto: dict | None = None
    config: dict | None = None


def _it(fn):
    try:
        return fn()
    except itsm.ItsmError as e:
        raise HTTPException(e.status, str(e)) from None
    except sm.SecretError as e:
        raise HTTPException(400, str(e)) from None


def _itsm_client(tenant):
    def make(integ):
        if ENTERPRISE:
            cred = sm.resolve(integ["credential_ref"]) if integ.get("credential_ref") else None
        else:
            cred = TICKETING._cred.get(str(integ["id"]))
        return itsm.Client(integ, cred, transport=ITSM_TRANSPORT)
    return make


def _console_url():
    return os.environ.get("MYELIN_PUBLIC_URL", "")


def after_scan(store, delta, tenant, actor="nerve-myelin"):
    """Hook run after every stored scan: raise and update tickets. Never fails the scan."""
    try:
        integrations = TICKETING.list(tenant)
        if not integrations or not delta:
            return None
        res = itsm.process_delta(store, integrations, delta, _itsm_client(tenant), actor, _console_url())
        if res["created"] or res["updated"] or res["errors"]:
            store.audit_event("tickets.synced", actor, {"text": f"tickets: {res['created']} created, {res['updated']} updated"
                                                                + (f"; {len(res['errors'])} problems: {res['errors'][0]}" if res["errors"] else "")})
        return res
    except Exception as e:  # noqa: BLE001 - ticketing must never break scanning
        import traceback
        traceback.print_exc()
        return {"created": 0, "updated": 0, "errors": [f"{type(e).__name__}: {e}"]}


@app.get("/api/v1/ticketing/kinds")
def ticketing_kinds(c: Ctx = Depends(ctx("findings:read"))):
    return [{"kind": k, **v} for k, v in itsm.KINDS.items()]


@app.get("/api/v1/ticketing/integrations")
def ticketing_list(c: Ctx = Depends(ctx("findings:read"))):
    return [itsm.public(i) for i in TICKETING.list(c.p.tenant_id)]


@app.post("/api/v1/ticketing/integrations", status_code=201)
def ticketing_create(body: IntegrationIn, c: Ctx = Depends(ctx("connectors:manage"))):
    integ = _it(lambda: itsm.new_integration(body.model_dump(), c.p.actor))
    token = (body.token or "").strip()
    if token:
        if ENTERPRISE:
            if not sm.vault_available():
                raise HTTPException(400, "a secret vault (VAULT_ADDR) is required to hold the ticketing credential")
            integ["credential_ref"] = itsm.credential_ref(c.p.tenant_id, integ["id"])
            _it(lambda: sm.store(integ["credential_ref"], token))
        else:
            integ["credential_ref"] = "memory"
            TICKETING._cred[str(integ["id"])] = token
    elif body.kind != "webhook":
        raise HTTPException(400, "a credential is required: " + itsm.KINDS[body.kind]["credential"])
    _it(lambda: TICKETING.add(c.p.tenant_id, integ))
    c.store.audit_event("ticketing.added", c.p.actor, {"text": f"Ticketing integration '{integ['name']}' ({integ['kind']}) added"})
    return itsm.public(TICKETING.get(c.p.tenant_id, integ["id"]))


@app.patch("/api/v1/ticketing/integrations/{iid}")
def ticketing_update(iid: str, body: IntegrationPatch, c: Ctx = Depends(ctx("connectors:manage"))):
    cur = _it(lambda: TICKETING.get(c.p.tenant_id, iid))
    merged = {"kind": cur["kind"], "name": cur["name"], "config": {**cur["config"], **(body.config or {})},
              "routing": body.routing if body.routing is not None else cur["config"].get("routing"),
              "auto": body.auto if body.auto is not None else cur["config"].get("auto")}
    cfg = _it(lambda: itsm.new_integration(merged, c.p.actor))["config"]
    fields = {"config": cfg}
    if body.enabled is not None:
        fields["enabled"] = body.enabled
    _it(lambda: TICKETING.update(c.p.tenant_id, iid, **fields))
    c.store.audit_event("ticketing.updated", c.p.actor, {"text": f"Ticketing integration '{cur['name']}' updated"})
    return itsm.public(TICKETING.get(c.p.tenant_id, iid))


@app.post("/api/v1/ticketing/integrations/{iid}/test")
def ticketing_test(iid: str, c: Ctx = Depends(ctx("connectors:manage"))):
    integ = _it(lambda: TICKETING.get(c.p.tenant_id, iid))
    try:
        msg = _it(lambda: _itsm_client(c.p.tenant_id)(integ).check())
        TICKETING.update(c.p.tenant_id, iid, last_error=None)
        return {"ok": True, "message": msg}
    except HTTPException as e:
        TICKETING.update(c.p.tenant_id, iid, last_error=str(e.detail)[:1000])
        return {"ok": False, "message": e.detail}


@app.delete("/api/v1/ticketing/integrations/{iid}", status_code=204)
def ticketing_delete(iid: str, c: Ctx = Depends(ctx("connectors:manage"))):
    integ = _it(lambda: TICKETING.get(c.p.tenant_id, iid))
    _it(lambda: TICKETING.delete(c.p.tenant_id, iid))
    if ENTERPRISE and integ.get("credential_ref"):
        sm.forget(integ["credential_ref"])
    c.store.audit_event("ticketing.removed", c.p.actor, {"text": f"Ticketing integration '{integ['name']}' removed"})


class TicketIn(BaseModel):
    integration_id: str | None = None
    finding_ids: list[str] = Field(min_length=1, max_length=200)


@app.post("/api/v1/ticketing/tickets")
def ticketing_raise(body: TicketIn, c: Ctx = Depends(ctx("findings:triage"))):
    """Raise tickets for selected findings (skips findings that already have one)."""
    integrations = [i for i in TICKETING.list(c.p.tenant_id) if i.get("enabled", True)]
    if body.integration_id:
        integrations = [i for i in integrations if str(i["id"]) == body.integration_id]
    if not integrations:
        raise HTTPException(400, "no ticketing integration is configured: add one under Integrations → Ticketing")
    integ = integrations[0]
    client = _itsm_client(c.p.tenant_id)(integ)
    out = []
    for fid in body.finding_ids:
        f = c.store.get_finding(fid)
        if not f:
            out.append({"finding": fid, "error": "not found"})
            continue
        try:
            t = itsm.raise_ticket(c.store, client, integ, f, c.p.actor, _console_url())
            out.append({"finding": fid, "ticket": t})
        except itsm.ItsmError as e:
            out.append({"finding": fid, "error": str(e)})
    return {"integration": integ["name"], "results": out}


# ─── integrations & audit ─────────────────────────────────────────────────────
@app.get("/api/integrations")
def integrations(c: Ctx = Depends(ctx("findings:read"))):
    """Integration catalogue with real status: connected (configured for this tenant) or available (supported, not set
    up). Only shipped integrations are listed; nothing is reported as connected unless it is actually configured."""
    tenant = c.p.tenant_id
    providers, kinds = set(), set()
    try:
        providers = {x.get("provider") for x in SOURCES.list(tenant)}
    except Exception:  # noqa: BLE001
        pass
    try:
        for t in TICKETING.list(tenant):
            kinds.add(t.get("kind"))
    except Exception:  # noqa: BLE001
        pass
    sso = ENTERPRISE                                            # enterprise mode always signs in through OIDC
    admission = bool(_safe_list(lambda: c.store.admission_events((datetime.now(timezone.utc) - timedelta(days=7)).isoformat())))
    cloud_p = {i["summary"].get("provider") for i in _safe_list(lambda: CLOUD.list_inventories(c.p.tenant_id))}
    runtime_on = bool(_safe_list(lambda: CLOUD.list_events(c.p.tenant_id, (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(), limit=1)))
    I = [
        ("GitHub / GitHub Enterprise", "Source code", "github" in providers, True),
        ("GitLab", "Source code", "gitlab" in providers, True),
        ("Azure DevOps Repos", "Source code", "azure" in providers, True),
        ("Bitbucket", "Source code", "bitbucket" in providers, True),
        ("AWS CodeCommit", "Source code", "codecommit" in providers, True),
        ("Google Cloud Source", "Source code", "gcp" in providers, True),
        ("GitHub Actions · Azure Pipelines · GitLab CI · Bitbucket · Jenkins", "CI templates", False, True),
        ("Argo CD · Flux · deployment gate", "CD / GitOps", False, True),
        ("Jira Cloud / Data Center", "Ticketing", "jira" in kinds, True),
        ("ServiceNow", "ITSM", "servicenow" in kinds, True),
        ("Azure Boards", "Ticketing", "azure_boards" in kinds, True),
        ("Microsoft Teams / Slack / webhook", "ChatOps", "webhook" in kinds, True),
        ("SIEM (Sentinel, Splunk, Wazuh, Elastic) — audit export API, JSON lines / CSV", "SIEM", False, True),
        ("Keycloak / Entra ID / Okta (OIDC + MFA)", "SSO", sso, True),
        ("OpenBao / HashiCorp Vault", "Secrets", sm.vault_available(), True),
        ("SARIF · CycloneDX · Trivy · Grype · Semgrep · Gitleaks · ZAP import", "Scanner import", False, True),
        ("OpenVEX · CycloneDX VEX · CSAF 2.0", "VEX", False, True),
        ("Container images — myelin scan --image (Trivy / Grype)", "Images", False, True),
        ("Kubernetes admission — Kyverno policy + policy-report ingestion", "Admission", admission, True),
        ("AI coding assistants — myelin mcp (MCP server)", "Developer", False, True),
        ("Git pre-commit hook — myelin precommit", "Developer", False, True),
        ("Microsoft Azure — cloud posture & identities (Resource Graph, read-only)", "Cloud", "azure" in cloud_p, True),
        ("Amazon Web Services — cloud posture & IAM (read-only APIs)", "Cloud", "aws" in cloud_p, True),
        ("Google Cloud — cloud posture & IAM (Cloud Asset Inventory, read-only)", "Cloud", "gcp" in cloud_p, True),
        ("Kubernetes — posture & RBAC (read-only ClusterRole)", "Cloud", "kubernetes" in cloud_p, True),
        ("Falco / Tetragon — runtime detections", "Runtime", runtime_on, True),
    ]
    return [{"name": n, "category": cat, "connected": on, "status": "connected" if on else "available"}
            for n, cat, on, ok in I]


@app.get("/api/audit")
def audit(c: Ctx = Depends(ctx("audit:read"))):
    return c.store.audit()


@app.get("/api/v1/audit/export")
def audit_export(format: str = "jsonl", c: Ctx = Depends(ctx("audit:read"))):
    """The tenant's audit trail for a SIEM: JSON lines (one event per line) or CSV."""
    import csv
    import io
    import json as _json
    from fastapi.responses import Response
    rows = c.store.audit()
    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ts", "event", "actor", "detail", "hash"])
        for e in rows:
            d = e.get("detail")
            w.writerow([e.get("ts"), e.get("event"), e.get("actor"), d if isinstance(d, str) else _json.dumps(d, default=str), e.get("hash", "")])
        body, mt, ext = buf.getvalue(), "text/csv", "csv"
    else:
        body, mt, ext = "".join(_json.dumps(e, default=str) + "\n" for e in rows), "application/x-ndjson", "jsonl"
    c.store.audit_event("audit.export", c.p.actor, {"format": ext, "events": len(rows)})
    return Response(body, media_type=mt, headers={"Content-Disposition": f'attachment; filename="myelin-audit.{ext}"'})


# ─── console ──────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
def console():
    if os.path.exists(settings.console_path):
        return FileResponse(settings.console_path, headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        })
    return JSONResponse({"msg": "console not built"}, status_code=503)


# ─── comparison-led vulnerability intelligence and remediation campaigns ──────
def _feed_store(tenant_id):
    return PgStore(DB_URL, tenant_id) if ENTERPRISE else DEMO


def _run_advisory_feed_sync(job_id, source, tenant_id, purls, cves, actor, *, scope=None):
    """Fixed-host, bounded advisory synchronization. No user-supplied URLs are fetched."""
    import httpx, time
    store = _feed_store(tenant_id)
    scope = scope or {}
    requested = scope.get("limit", 0) if scope.get("window_start") else len(purls if source == "OSV" else cves)
    store.update_import_job(job_id, "running", {"requested": requested, "processed": 0, "stored": 0})
    budget = time.monotonic() + min(600, max(1, scope.get("lease_seconds", 900) - 30))
    records, processed = [], 0
    timeout = httpx.Timeout(20.0, connect=5.0)
    def request(client, method, url, **kwargs):
        last = None
        for attempt in range(3):
            if time.monotonic() >= budget:
                raise advisory_feeds.WindowTooLarge("job exceeded its feed time budget; reduce the window or target limit")
            response = client.request(method, url, **kwargs)
            if response.status_code not in {429, 500, 502, 503, 504}:
                response.raise_for_status()
                return response
            last = response
            if attempt < 2:
                retry_after = response.headers.get("Retry-After", "")
                try: delay = min(10, max(1, int(retry_after)))
                except ValueError: delay = 2 ** attempt
                time.sleep(delay)
        last.raise_for_status()
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, headers={"User-Agent": "RAT-FLEA-DEVSEC/2.1 advisory-sync"}) as client:
            if source in advisory_feeds.NORMALIZED:
                records = advisory_feeds.collect(source, lambda method, url, **kw: request(client, method, url, **kw),
                                                purls=purls, cves=cves, scope=scope)
                processed = len(records) if scope.get("window_start") else requested
            elif source == "KEV":
                response = request(client, "GET", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
                if len(response.content) > 25000000: raise ValueError("CISA KEV feed exceeded 25 MB limit")
                catalog = response.json()
                for vuln in catalog.get("vulnerabilities", []):
                    cve = str(vuln.get("cveID") or "")
                    if cve:
                        records.append({"advisory_id": cve, "modified_at": catalog.get("dateReleased"),
                            "payload": {"cve": cve, "vendor": vuln.get("vendorProject"), "product": vuln.get("product"),
                                "name": vuln.get("vulnerabilityName"), "date_added": vuln.get("dateAdded"),
                                "due_date": vuln.get("dueDate"), "known_ransomware_use": vuln.get("knownRansomwareCampaignUse"),
                                "required_action": vuln.get("requiredAction"), "notes": vuln.get("notes")}})
                processed = len(catalog.get("vulnerabilities", []))
            elif source == "EPSS":
                for offset in range(0, len(cves), 100):
                    chunk = cves[offset:offset + 100]
                    response = request(client, "GET", "https://api.first.org/data/v1/epss", params={"cve": ",".join(chunk)})
                    payload = response.json()
                    for item in payload.get("data", []):
                        cve = str(item.get("cve") or "")
                        if cve:
                            records.append({"advisory_id": cve, "modified_at": None,
                                "payload": {"cve": cve, "epss": item.get("epss"), "percentile": item.get("percentile"), "date": item.get("date")}})
                    processed += len(chunk)
            else:
                raise ValueError("unsupported advisory feed")
            if records:
                store.upsert_advisories(source, records)
            store.update_import_job(job_id, "succeeded", {"requested": requested, "processed": processed, "stored": len(records)})
    except advisory_feeds.WindowTooLarge as exc:
        store.update_import_job(job_id, "partial", {"requested": requested, "processed": processed, "stored": 0}, str(exc))
    except Exception as exc:
        store.update_import_job(job_id, "failed", {"requested": requested, "processed": processed, "stored": 0},
                                f"{type(exc).__name__}: {str(exc)[:500]}")


class AdvisorySyncIn(BaseModel):
    limit: int = Field(default=500, ge=1, le=5000)
    mode: Literal["inventory", "changes"] = "inventory"
    since: datetime | None = None
    until: datetime | None = None
    ecosystems: list[str] = Field(default_factory=list, max_length=5)


@app.post("/api/v1/intelligence/feeds/{source}/sync", status_code=202)
def start_advisory_sync(source: str, body: AdvisorySyncIn = AdvisorySyncIn(),
                        c: Ctx = Depends(ctx("scans:write"))):
    source = source.upper()
    if source not in advisory_feeds.SOURCES:
        raise HTTPException(422, "Supported feeds: OSV, KEV, EPSS, NVD, GitHub and Red Hat CSAF.")
    scope = {}
    targets = []
    changes = body.mode == "changes" or source == "REDHAT"
    if changes:
        if source not in advisory_feeds.NORMALIZED:
            raise HTTPException(422, "This source does not support a change window.")
        ecosystems = sorted(set(body.ecosystems))
        if source == "OSV" and (not ecosystems or set(ecosystems) - advisory_feeds.OSV_ECOSYSTEM.keys()):
            raise HTTPException(422, "Supply one to five supported OSV ecosystems for a changes job.")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        # Bulk feeds can publish records after their upstream modified time.
        stable_end = now - (timedelta(hours=2) if source == "OSV" else timedelta(minutes=15))
        prior = c.store.advisory_watermark(source, ecosystems) if body.since is None else None
        if any(stamp is not None and stamp.utcoffset() is None for stamp in (body.since, body.until)):
            raise HTTPException(422, "Change window timestamps must include a timezone.")
        start = (body.since.astimezone(timezone.utc) if body.since else
                 advisory_feeds.parse_time(prior) - timedelta(minutes=5) if prior else stable_end - timedelta(hours=1))
        end = body.until.astimezone(timezone.utc) if body.until else min(stable_end, start + timedelta(days=1))
        if start >= end or end > now or end - start > timedelta(days=1):
            raise HTTPException(422, "Use an ordered UTC change window of at most one day ending in the past.")
        scope = {"window_start": start.isoformat(), "window_end": end.isoformat(), "ecosystems": ecosystems,
                 "limit": body.limit, "rolling": body.since is None}
    elif body.since or body.until or body.ecosystems:
        raise HTTPException(422, "since, until and ecosystems apply only to changes jobs.")
    purls = set()
    if not changes and source == "OSV":
        for repo in c.store.repos():
            name = repo.get("name") if isinstance(repo, dict) else None
            sbom = c.store.sbom(name) if name else None
            def walk(items):
                for item in items if isinstance(items, list) else []:
                    if not isinstance(item, dict): continue
                    if item.get("purl"): purls.add(str(item["purl"]))
                    walk(item.get("components"))
            if isinstance(sbom, dict): walk(sbom.get("components"))
        if not purls:
            raise HTTPException(409, "No package URLs found in stored SBOMs. Import CycloneDX or SPDX JSON first.")
        targets = sorted(purls)[:body.limit]
    elif not changes:
        targets = sorted({str(f["cve"]) for f in c.store.findings()
                          if re.fullmatch(r"CVE-\d{4}-\d{4,}", str(f.get("cve") or ""))})[:body.limit]
        if source == "NVD" and not os.getenv("NVD_API_KEY"): targets = targets[:10]
        if source == "GITHUB" and not os.getenv("GITHUB_ADVISORY_TOKEN"): targets = targets[:20]
        if not targets and source in {"EPSS", "NVD", "GITHUB"}: raise HTTPException(409, "No CVE identifiers found in tenant findings.")
    item = {"id": str(uuid.uuid4()), "kind": "advisory_sync", "source": source, "status": "queued",
        "requested_by": c.p.actor, "counters": {"targets": targets, "requested": body.limit if changes else len(targets), **scope}, "error": "", "created_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None, "finished_at": None}
    c.store.create_import_job(item)
    return {"job": item, "note": "Job persisted to the tenant queue. A separately deployed MYELIN worker claims it using a database lease, retries after worker interruption and records the outcome. Configure MYELIN_WORKER_TENANT_IDS, NVD_API_KEY and GITHUB_ADVISORY_TOKEN in the worker environment."}


@app.post("/api/v1/intelligence/feeds/jobs/{job_id}/retry", status_code=202)
def retry_advisory_sync(job_id: str, c: Ctx = Depends(ctx("scans:write"))):
    try: uuid.UUID(job_id)
    except ValueError: raise HTTPException(422, "invalid import job ID") from None
    job = next((x for x in c.store.import_jobs() if x.get("id") == job_id), None)
    if not job: raise HTTPException(404, "import job not found")
    if job.get("status") not in {"failed", "queued"}:
        raise HTTPException(409, "only failed or queued jobs can be requeued; stale running jobs are recovered by the worker lease")
    source = job["source"]
    if source not in advisory_feeds.SOURCES: raise HTTPException(422, "unsupported retry source")
    try:
        c.store.requeue_import_job(job_id, c.p.actor)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    return {"job_id": job_id, "status": "queued", "note": "The durable worker will claim this job."}


@app.get("/api/v1/intelligence/feeds/jobs")
def list_advisory_sync_jobs(c: Ctx = Depends(ctx("findings:read"))):
    return {"items": c.store.import_jobs()}


@app.get("/api/v1/intelligence/feeds/{source}")
def get_advisory_feed(source: str, c: Ctx = Depends(ctx("findings:read"))):
    source = source.upper()
    if source not in advisory_feeds.SOURCES: raise HTTPException(404, "Feed not found")
    items = c.store.advisory_records(source, limit=5000)
    jobs = [x for x in c.store.import_jobs() if x.get("source") == source]
    latest_success = next((x for x in jobs if x.get("status") == "succeeded"), None)
    state = "synced" if items else ("synced_empty" if latest_success else ("failed" if jobs and jobs[0].get("status") == "failed" else "not_synced"))
    return {"source": source, "state": state, "records": len(items),
        "last_successful_sync": latest_success.get("finished_at") if latest_success else None,
        "coverage_through": (latest_success.get("counters") or {}).get("window_end") if latest_success else None,
        "last_job": jobs[0] if jobs else None, "items": items[:500]}


@app.get("/api/v1/intelligence/vulnerabilities")
def vulnerability_intelligence(c: Ctx = Depends(ctx("findings:read"))):
    """Correlate tenant findings with successfully synchronized advisory intelligence."""
    fs = c.store.findings()
    kev_records = c.store.advisory_records("KEV", limit=5000)
    epss_records = c.store.advisory_records("EPSS", limit=5000)
    osv_records = c.store.advisory_records("OSV", limit=5000)
    nvd_records = c.store.advisory_records("NVD", limit=5000)
    github_records = c.store.advisory_records("GITHUB", limit=5000)
    kev_cves = {x["advisory_id"] for x in kev_records}
    epss_by_cve = {x["advisory_id"]: x["payload"] for x in epss_records}
    nvd_by_cve = {x["advisory_id"]: x["payload"] for x in nvd_records}
    github_by_cve = {}
    for record in github_records:
        cve_id = (record.get("payload") or {}).get("cve")
        if cve_id: github_by_cve.setdefault(str(cve_id), []).append(record.get("payload") or {})
    osv_by_alias = {}
    for record in osv_records:
        payload = record.get("payload") or {}
        for alias in [record["advisory_id"], *(payload.get("aliases") or [])]:
            osv_by_alias.setdefault(str(alias), []).append(payload)
    open_fs = [f for f in fs if f.get("status") == "open"]
    cves = {}
    for f in fs:
        cve = f.get("cve")
        if not cve:
            continue
        item = cves.setdefault(cve, {"cve": cve, "severity": f.get("severity"), "cvss": f.get("cvss"),
            "epss": f.get("epss"), "kev": bool(f.get("kev")), "instances": 0, "open_instances": 0,
            "repositories": set(), "packages": set(), "fixed_versions": set()})
        item["instances"] += 1
        item["open_instances"] += f.get("status") == "open"
        item["repositories"].add(f.get("repo"))
        if f.get("package"): item["packages"].add(f.get("package"))
        if f.get("fixed_version"): item["fixed_versions"].add(f.get("fixed_version"))
        if f.get("kev"): item["kev"] = True
        if f.get("epss") is not None: item["epss"] = max(item["epss"] or 0, f["epss"])
        if f.get("cvss") is not None: item["cvss"] = max(item["cvss"] or 0, f["cvss"])
        if cve in kev_cves: item["kev"] = True
        epss_record = epss_by_cve.get(cve) or {}
        try: synced_epss = float(epss_record.get("epss")) if epss_record.get("epss") is not None else None
        except (TypeError, ValueError): synced_epss = None
        if synced_epss is not None: item["epss"] = max(item["epss"] or 0, synced_epss)
        nvd = nvd_by_cve.get(cve) or {}
        if isinstance(nvd.get("cvss"), (int, float)): item["cvss"] = max(item["cvss"] or 0, nvd["cvss"])
        if nvd.get("severity"): item["nvd_severity"] = nvd["severity"]
        gh_advisories = github_by_cve.get(cve, [])
        if gh_advisories: item["github_advisories"] = sorted({str(x.get("id")) for x in gh_advisories if x.get("id")})
        matched_advisories = osv_by_alias.get(cve, [])
        if matched_advisories:
            item["advisories"] = sorted({str(a.get("id")) for a in matched_advisories if a.get("id")})
            ranges = []
            for advisory in matched_advisories:
                for affected in advisory.get("affected", []) if isinstance(advisory.get("affected"), list) else []:
                    for version_range in affected.get("ranges", []) if isinstance(affected, dict) and isinstance(affected.get("ranges"), list) else []:
                        events = version_range.get("events", []) if isinstance(version_range, dict) else []
                        ranges.append({"type": version_range.get("type"), "events": events})
                        for event in events:
                            if isinstance(event, dict) and event.get("fixed"):
                                item["fixed_versions"].add(str(event["fixed"]))
            item["osv_affected_ranges"] = ranges
    items = []
    for x in cves.values():
        x["repositories"] = sorted(v for v in x["repositories"] if v)
        x["packages"] = sorted(x["packages"])
        x["fixed_versions"] = sorted(x["fixed_versions"])
        items.append(x)
    items.sort(key=lambda x: (not x["kev"], -(x["epss"] or 0), -(x["cvss"] or 0), x["cve"]))
    jobs = c.store.import_jobs()
    feeds = []
    for name, source, records in (("OSV", "OSV", osv_records), ("CISA KEV", "KEV", kev_records), ("EPSS", "EPSS", epss_records),
                                  ("NVD", "NVD", c.store.advisory_records("NVD", limit=5000)), ("GitHub Advisory Database", "GITHUB", github_records),
                                  ("Red Hat CSAF", "REDHAT", c.store.advisory_records("REDHAT", limit=5000))):
        latest = next((j for j in jobs if j.get("source") == source and j.get("status") == "succeeded"), None)
        feeds.append({"name": name, "state": "synced" if records else ("synced_empty" if latest else ("failed" if any(j.get("source") == source and j.get("status") == "failed" for j in jobs) else "not_configured")),
            "records": len(records), "last_successful_sync": latest.get("finished_at") if latest else None})
    feeds.append({"name": "CSAF/VEX", "state": "source_documents", "records": len(c.store.intelligence_documents()), "last_successful_sync": None})
    return {"source": "tenant_findings", "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"unique_cves": len(items), "open_cves": sum(x["open_instances"] > 0 for x in items),
            "kev_open": sum(x["kev"] and x["open_instances"] > 0 for x in items),
            "open_instances": len(open_fs), "fix_available": sum(x["open_instances"] > 0 and bool(x["fixed_versions"]) for x in items)},
        "advisory_feeds": feeds, "items": items,
        "limitations": ["Inventory jobs use stored packages or CVEs. Change jobs retrieve bounded upstream windows; the latest job records its scope.",
            "NVD rate limits apply without NVD_API_KEY and GitHub rate limits apply without GITHUB_ADVISORY_TOKEN; unauthenticated batches are capped.",
            "A missing advisory or feed is not evidence that a component is safe."]}


CAMPAIGN_STATES = ("proposed", "planned", "approved", "in_progress", "fix_submitted", "verified", "rejected")


def _campaign_groups(c, include_closed=True):
    groups = {}
    for f in c.store.findings():
        st = f.get("status")
        if st != "open" and not (include_closed and st == "fixed" and (f.get("campaign") or {}).get("id")):
            continue
        key = "|".join((str(f.get("repo") or "unassigned"), str(f.get("package") or f.get("engine") or "general"),
                        str(f.get("fixed_version") or "manual")))
        cid = "campaign-" + _supply_graph_id("campaign", key).split(":")[1]
        g = groups.setdefault(cid, {"id": cid, "repository": f.get("repo"), "target": f.get("package") or f.get("engine"),
                                    "engine": f.get("engine"), "recommended_version": f.get("fixed_version"), "findings": [],
                                    "owners": set(), "priority": f.get("priority"), "kev": False, "max_mrs": 0, "_camp": []})
        g["findings"].append({"id": f.get("id"), "title": f.get("title"), "severity": f.get("severity"), "status": st,
                              "priority": f.get("priority"), "mrs": f.get("mrs"), "cve": f.get("cve"), "ticket": f.get("ticket")})
        if f.get("assignee"):
            g["owners"].add(f["assignee"])
        if (f.get("assessment") or {}).get("owner"):
            g["owners"].add(f["assessment"]["owner"])
        g["kev"] = g["kev"] or bool(f.get("kev"))
        g["max_mrs"] = max(g["max_mrs"], f.get("mrs") or 0)
        if (f.get("priority") or "P3") < (g.get("priority") or "P3"):
            g["priority"] = f.get("priority")
        g["_camp"].append(f.get("campaign") or {})
    return groups


def _campaign_view(g):
    camps = [x for x in g.pop("_camp") if x]
    latest = max(camps, key=lambda x: x.get("updated_at") or "") if camps else {}
    open_n = sum(1 for f in g["findings"] if f["status"] == "open")
    state = latest.get("state", "proposed")
    if g["findings"] and open_n == 0:
        state = "verified"                    # every member finding closed by a later scan of the same engine
    g.update(owners=sorted(g["owners"] | ({latest["owner"]} if latest.get("owner") else set())), finding_count=len(g["findings"]),
             open_count=open_n, state=state, due_date=latest.get("due_date"), planned_by=latest.get("planned_by"),
             approved_by=latest.get("approved_by"), note=latest.get("note"), updated_at=latest.get("updated_at"),
             tickets=sum(1 for f in g["findings"] if f.get("ticket")),
             overdue=bool(latest.get("due_date") and open_n and latest["due_date"] < datetime.now(timezone.utc).date().isoformat()))
    # backwards-compatible fields
    g.update(approval_state="approved" if state in ("approved", "in_progress", "fix_submitted", "verified") else "not_requested",
             execution_state="proposal_only" if state == "proposed" else state,
             verification_state="verified" if state == "verified" else "not_started")
    if g["engine"] in ("sca", "container") and g["recommended_version"]:
        g["action"] = f"Upgrade {g['target']} to {g['recommended_version']} in {g['repository']}"
    else:
        g["action"] = f"Fix {open_n} {g['engine'] or ''} finding(s) in {g['repository']}"
    return g


@app.get("/api/v1/remediation/campaigns")
def remediation_campaigns(c: Ctx = Depends(ctx("findings:read"))):
    """Remediation campaigns: open findings grouped by repository + component/engine + fix, with a persisted workflow
    (planned → approved by a second person → in progress → fix submitted → verified by a re-scan)."""
    items = [_campaign_view(g) for g in _campaign_groups(c).values()]
    items.sort(key=lambda x: (x["state"] == "verified", not x["kev"], x["priority"] or "P3", -x["max_mrs"]))
    by_state = Counter(x["state"] for x in items)
    return {"source": "tenant_findings", "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {"campaigns": len(items), "findings": sum(x["open_count"] for x in items),
                        "kev_campaigns": sum(1 for x in items if x["kev"] and x["state"] != "verified"),
                        "proposal_only": by_state.get("proposed", 0), "by_state": dict(by_state),
                        "overdue": sum(1 for x in items if x["overdue"]), "verified": by_state.get("verified", 0)},
            "items": items,
            "limitations": ["Campaign state is stored on each member finding; new findings that join a campaign start as proposed.",
                            "RAT Flea DevSec never changes code by itself: fixes are proposed, applied by your team and verified by a re-scan."]}


class CampaignActionIn(BaseModel):
    action: str = Field(pattern="^(plan|approve|reject|start|submit_fix|ticket|reopen)$")
    owner: str | None = Field(default=None, max_length=200)
    due_date: str | None = Field(default=None, max_length=10)
    note: str | None = Field(default=None, max_length=1000)


@app.post("/api/v1/remediation/campaigns/{cid}")
def campaign_action(cid: str, body: CampaignActionIn, c: Ctx = Depends(ctx("findings:triage"))):
    g = _campaign_groups(c).get(cid)
    if not g:
        raise HTTPException(404, "campaign not found (it may have been verified and closed)")
    cur = _campaign_view(dict(g, _camp=list(g["_camp"])))
    now = datetime.now(timezone.utc).isoformat()
    upd = {"id": cid, "updated_at": now, "updated_by": c.p.actor}
    a = body.action
    if a == "plan":
        if not body.owner:
            raise HTTPException(400, "a plan needs an owner")
        if body.due_date:
            try:
                datetime.fromisoformat(body.due_date)
            except ValueError:
                raise HTTPException(400, "due date must be YYYY-MM-DD") from None
        upd.update(state="planned", owner=body.owner, due_date=body.due_date, planned_by=c.p.actor, note=body.note)
    elif a in ("approve", "reject"):
        if cur["state"] != "planned":
            raise HTTPException(409, "only a planned campaign can be approved or rejected")
        if cur.get("planned_by") == c.p.actor:
            raise HTTPException(403, "four-eyes rule: the person who planned a campaign cannot approve it")
        upd.update(state="approved" if a == "approve" else "rejected", approved_by=c.p.actor, note=body.note or cur.get("note"))
    elif a == "start":
        if cur["state"] not in ("approved",):
            raise HTTPException(409, "approve the campaign before starting it")
        upd.update(state="in_progress")
    elif a == "submit_fix":
        if cur["state"] not in ("approved", "in_progress"):
            raise HTTPException(409, "the campaign must be approved or in progress")
        upd.update(state="fix_submitted", note=body.note or "Fix submitted; awaiting verification scan")
    elif a == "reopen":
        upd.update(state="proposed")
    elif a == "ticket":
        ids = [f["id"] for f in g["findings"] if f["status"] == "open" and not f.get("ticket")]
        if not ids:
            raise HTTPException(409, "every open finding in this campaign already has a ticket")
        res = ticketing_raise(TicketIn(finding_ids=ids[:200]), c)
        if cur["state"] == "approved":
            upd.update(state="in_progress")
        for f in g["findings"]:
            c.store.set_campaign(f["id"], upd, c.p.actor)
        return {"campaign": cid, "tickets": res["results"]}
    for f in g["findings"]:
        c.store.set_campaign(f["id"], upd, c.p.actor)
    c.store.audit_event("campaign." + a, c.p.actor, {"text": f"campaign {cid} ({cur['target']} in {cur['repository']}) → {upd.get('state')}",
                                                    "campaign": cid})
    out = _campaign_groups(c).get(cid)
    return _campaign_view(out) if out else {"id": cid, "state": upd.get("state")}


class VexParseIn(BaseModel):
    document: dict
    format: str = Field(default="auto", pattern="^(auto|openvex|csaf)$")


@app.post("/api/v1/intelligence/vex/parse")
def parse_vex_document(body: VexParseIn, c: Ctx = Depends(ctx("findings:read"))):
    """Validate and normalize OpenVEX or CSAF product-status statements without applying suppression."""
    import json
    raw = json.dumps(body.document, separators=(",", ":"))
    if len(raw.encode("utf-8")) > 1_500_000:
        raise HTTPException(413, "VEX/CSAF document exceeds the 1.5 MB preview limit")
    doc = body.document
    is_openvex = body.format == "openvex" or (body.format == "auto" and isinstance(doc.get("statements"), list))
    is_csaf = body.format == "csaf" or (body.format == "auto" and isinstance(doc.get("vulnerabilities"), list))
    if is_openvex == is_csaf:
        raise HTTPException(422, "Unable to determine format. Supply format=openvex or format=csaf.")
    statements = []
    if is_openvex:
        if not isinstance(doc.get("statements"), list):
            raise HTTPException(422, "OpenVEX statements must be an array")
        for index, item in enumerate(doc.get("statements", [])):
            if not isinstance(item, dict):
                raise HTTPException(422, f"OpenVEX statement {index} must be an object")
            status = item.get("status")
            if status not in {"affected", "not_affected", "fixed", "under_investigation"}:
                raise HTTPException(422, f"OpenVEX statement {index} has unsupported status")
            vuln = item.get("vulnerability") or {}
            vuln_id = vuln.get("name") or vuln.get("@id") if isinstance(vuln, dict) else None
            products = item.get("products") or []
            if not isinstance(products, list):
                raise HTTPException(422, f"OpenVEX statement {index} products must be an array")
            statements.append({"vulnerability": vuln_id, "status": status, "products": products,
                "justification": item.get("justification"), "impact_statement": item.get("impact_statement"),
                "action_statement": item.get("action_statement"), "source_index": index})
        fmt = "openvex"
        document_id = doc.get("@id")
    else:
        vulnerabilities = doc.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise HTTPException(422, "CSAF vulnerabilities must be an array")
        status_map = {"known_affected": "affected", "known_not_affected": "not_affected",
                      "fixed": "fixed", "under_investigation": "under_investigation"}
        for index, item in enumerate(vulnerabilities):
            if not isinstance(item, dict):
                raise HTTPException(422, f"CSAF vulnerability {index} must be an object")
            product_status = item.get("product_status") or {}
            if not isinstance(product_status, dict):
                raise HTTPException(422, f"CSAF vulnerability {index} product_status must be an object")
            for csaf_status, normalized in status_map.items():
                products = product_status.get(csaf_status, [])
                if not isinstance(products, list):
                    raise HTTPException(422, f"CSAF {csaf_status} must be an array")
                if products:
                    statements.append({"vulnerability": item.get("cve") or item.get("title"),
                        "status": normalized, "products": products, "justification": None,
                        "impact_statement": None, "action_statement": None, "source_index": index})
        fmt = "csaf"
        document_id = doc.get("document", {}).get("tracking", {}).get("id") if isinstance(doc.get("document"), dict) else None
    if not statements:
        raise HTTPException(422, "No supported vulnerability product-status statements were found")
    return {"format": fmt, "document_id": document_id, "statement_count": len(statements),
        "statements": statements, "applied": False,
        "note": "Preview only. Statements are not persisted and do not suppress or close findings. Apply only after schema, product identity, issuer trust and policy approval checks."}




@app.get("/api/v1/intelligence/vex/documents")
def list_vex_documents(c: Ctx = Depends(ctx("findings:read"))):
    return {"items": c.store.intelligence_documents()}


class VexRecordIn(BaseModel):
    document: dict


@app.post("/api/v1/intelligence/vex/documents")
def record_vex_document(body: VexRecordIn, c: Ctx = Depends(ctx("findings:triage"))):
    import json
    from myelin_engine.vex import normalize_document
    from uuid import uuid4
    raw = json.dumps(body.document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(raw.encode("utf-8")) > 1_500_000:
        raise HTTPException(413, "VEX/CSAF document exceeds the 1.5 MB limit")
    try:
        statements = normalize_document(body.document)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise HTTPException(422, f"Invalid VEX/CSAF document: {str(exc)[:300]}") from None
    if not statements:
        raise HTTPException(422, "No product-specific vulnerability statements with exact PURL identity were found")
    first = statements[0]
    fmt = "openvex" if isinstance(body.document.get("statements"), list) else ("cyclonedx-vex" if body.document.get("bomFormat") == "CycloneDX" else "csaf-2.0")
    item = {"id": str(uuid4()), "format": fmt,
        "document_id": first.get("source_id") or "", "issuer": first.get("issuer") or "",
        "sha256": first["source_digest"].removeprefix("sha256:"), "document": body.document,
        "imported_by": c.p.actor, "created_at": datetime.now(timezone.utc).isoformat()}
    stored, created = c.store.save_intelligence_document(item)
    matched = 0
    findings = c.store.findings()
    for statement in statements:
        for finding in findings:
            ids = {str(finding.get("cve") or "").upper(), str(finding.get("rule_id") or "").upper()}
            if str(statement.get("vulnerability") or "").upper() not in ids:
                continue
            if not statement.get("purl") or statement.get("purl") != finding.get("purl"):
                continue
            annotation = {k: statement.get(k) for k in ("state", "justification", "detail", "source",
                "source_id", "source_digest", "issuer", "timestamp", "purl", "vulnerability")}
            c.store.annotate_finding_vex(finding["id"], annotation, c.p.actor)
            matched += 1
    return {"document": stored, "created": created, "statements": len(statements),
        "matched_findings": matched, "applied": False,
        "note": "Original document and exact-PURL statements are retained as provenance. VEX does not suppress findings, change MRS, or alter policy gates. Trust validation and policy approval remain separate."}

class ScannerImportIn(BaseModel):
    repo: str = Field(min_length=1, max_length=300)
    branch: str = Field(default="main", max_length=300)
    commit: str = Field(default="", max_length=64)
    format: str = Field(pattern="^(sarif|trivy|grype|dependency-check|semgrep|cyclonedx|spdx)$")
    document: dict


def _scanner_severity(value):
    v = str(value or "").lower()
    return v if v in {"critical", "high", "medium", "low", "info"} else "medium"


def _normalize_spdx_document(doc):
    """Convert SPDX 2.x JSON SBOM inventory and relationships into MYELIN's graph shape."""
    version = str(doc.get("spdxVersion") or "")
    if not version.startswith("SPDX-2."):
        raise ValueError("SPDX JSON must declare a supported SPDX-2.x spdxVersion")
    packages = doc.get("packages")
    if not isinstance(packages, list):
        raise ValueError("SPDX packages must be an array")
    components, refs, dependencies = [], {}, []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        spdx_id = str(pkg.get("SPDXID") or "")
        name = str(pkg.get("name") or "").strip()
        if not spdx_id or not name:
            continue
        external_refs = pkg.get("externalRefs") if isinstance(pkg.get("externalRefs"), list) else []
        purl = next((str(x.get("referenceLocator")) for x in external_refs
                     if isinstance(x, dict) and str(x.get("referenceType", "")).lower() == "purl"
                     and x.get("referenceLocator")), "")
        component = {"type": "library", "bom-ref": spdx_id, "name": name,
            "version": str(pkg.get("versionInfo") or ""), "purl": purl,
            "licenses": [{"license": {"id": pkg.get("licenseConcluded") or pkg.get("licenseDeclared") or "NOASSERTION"}}],
            "scope": "required", "supplier": pkg.get("supplier"),
            "downloadLocation": pkg.get("downloadLocation")}
        components.append(component)
        refs[spdx_id] = component
    for rel in doc.get("relationships", []) if isinstance(doc.get("relationships"), list) else []:
        if not isinstance(rel, dict) or rel.get("relationshipType") != "DEPENDS_ON":
            continue
        src, dst = str(rel.get("spdxElementId") or ""), str(rel.get("relatedSpdxElement") or "")
        if src in refs and dst in refs:
            dependencies.append({"ref": src, "dependsOn": [dst]})
    if not components:
        raise ValueError("SPDX document contains no packages with valid SPDXID and name")
    return {"bomFormat": "SPDX", "specVersion": version, "name": doc.get("name"),
        "documentNamespace": doc.get("documentNamespace"), "creationInfo": doc.get("creationInfo"),
        "components": components, "dependencies": dependencies,
        "source_format": "SPDX-JSON", "source_sha256": hashlib.sha256(
            json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()}


def _parse_scanner_document(fmt, doc):
    """Normalize common scanner export formats. Preserve source identifiers and locations."""
    import re
    out = []
    def add(engine, rule, title, severity, file=None, line=None, cve=None, package=None,
            version=None, fixed=None, cvss=None, description=None, url=None):
        sev = _scanner_severity(severity)
        out.append({"engine": engine, "rule_id": str(rule or cve or "SCANNER-FINDING"),
            "title": str(title or rule or cve or "Scanner finding")[:1000], "severity": sev,
            "file": str(file)[:1000] if file else None, "line": line if isinstance(line, int) else None,
            "cve": cve, "package": package, "version": version, "fixed_version": fixed,
            "cvss": cvss, "description": str(description or "")[:4000],
            "reference": url, "source_format": fmt})
    if fmt == "sarif":
        runs = doc.get("runs")
        if not isinstance(runs, list): raise ValueError("SARIF runs must be an array")
        for run in runs:
            driver = (run.get("tool") or {}).get("driver") or {}
            engine_name = str(driver.get("name") or "").lower()
            engine = "secrets" if "secret" in engine_name or "gitleaks" in engine_name else "sast"
            rules = {r.get("id"): r for r in driver.get("rules", []) if isinstance(r, dict)}
            for result in run.get("results", []):
                rule = result.get("ruleId") or "SARIF-FINDING"
                level = result.get("level") or "warning"
                severity = {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level, "medium")
                rule_meta = rules.get(rule, {})
                loc = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
                artifact = loc.get("artifactLocation") or {}
                region = loc.get("region") or {}
                msg = result.get("message") or {}
                text = msg.get("text") or msg.get("markdown") or rule
                tags = (rule_meta.get("properties") or {}).get("tags") or []
                cves = [x for x in tags if re.fullmatch(r"CVE-\\d{4}-\\d+", str(x), re.I)]
                add(engine, rule, text, severity, artifact.get("uri"), region.get("startLine"),
                    cves[0] if cves else None, description=text)
    elif fmt == "trivy":
        results = doc.get("Results")
        if not isinstance(results, list): raise ValueError("Trivy Results must be an array")
        for result in results:
            for v in result.get("Vulnerabilities") or []:
                cvss_data = v.get("CVSS") or {}
                score = None
                for source in cvss_data.values():
                    if isinstance(source, dict) and isinstance(source.get("V3Score"), (int, float)):
                        score = max(score or 0, source["V3Score"])
                add("container" if result.get("Type") in {"os-pkgs", "library"} else "sca",
                    v.get("VulnerabilityID"), v.get("Title") or v.get("VulnerabilityID"), v.get("Severity"),
                    result.get("Target"), cve=v.get("VulnerabilityID") if str(v.get("VulnerabilityID", "")).startswith("CVE-") else None,
                    package=v.get("PkgName"), version=v.get("InstalledVersion"), fixed=v.get("FixedVersion"),
                    cvss=score, description=v.get("Description"), url=v.get("PrimaryURL"))
    elif fmt == "grype":
        matches = doc.get("matches")
        if not isinstance(matches, list): raise ValueError("Grype matches must be an array")
        for match in matches:
            vuln = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            fix = vuln.get("fix") or {}
            locations = artifact.get("locations") or [{}]
            add("container" if artifact.get("type") in {"deb", "rpm", "apk"} else "sca",
                vuln.get("id"), artifact.get("name") or vuln.get("id"), vuln.get("severity"),
                locations[0].get("path"), cve=vuln.get("id") if str(vuln.get("id", "")).startswith("CVE-") else None,
                package=artifact.get("name"), version=artifact.get("version"),
                fixed=", ".join(fix.get("versions") or []) or None, description=vuln.get("description"))
    elif fmt == "dependency-check":
        dependencies = doc.get("dependencies")
        if not isinstance(dependencies, list): raise ValueError("Dependency-Check dependencies must be an array")
        for dep in dependencies:
            file_name = dep.get("fileName")
            for pkg in dep.get("packages") or []:
                for vuln in pkg.get("vulnerabilities") or []:
                    score = (vuln.get("cvssv3") or {}).get("baseScore")
                    add("sca", vuln.get("name"), vuln.get("description") or vuln.get("name"),
                        vuln.get("severity"), file_name,
                        cve=vuln.get("name") if str(vuln.get("name", "")).startswith("CVE-") else None,
                        package=pkg.get("id") or pkg.get("name"), version=pkg.get("version"),
                        cvss=score, description=vuln.get("description"))
    elif fmt == "semgrep":
        results = doc.get("results")
        if not isinstance(results, list): raise ValueError("Semgrep results must be an array")
        for result in results:
            extra = result.get("extra") or {}
            metadata = extra.get("metadata") or {}
            severity_raw = str(metadata.get("severity") or extra.get("severity") or "medium").lower()
            severity = {"error": "high", "warning": "medium", "info": "low"}.get(severity_raw, severity_raw)
            add("sast", result.get("check_id"), extra.get("message") or result.get("check_id"), severity,
                result.get("path"), (result.get("start") or {}).get("line"),
                description=extra.get("message"), url=(metadata.get("references") or [None])[0])
            if out:
                out[-1]["cwe"] = metadata.get("cwe")
                out[-1]["semgrep_metadata"] = {k: metadata.get(k) for k in ("category", "technology", "confidence", "likelihood", "impact") if metadata.get(k) is not None}
    elif fmt == "spdx":
        _normalize_spdx_document(doc)
    elif fmt == "cyclonedx":
        if doc.get("bomFormat") != "CycloneDX": raise ValueError("CycloneDX report must declare bomFormat=CycloneDX")
        components = {x.get("bom-ref"): x for x in doc.get("components") or [] if isinstance(x, dict) and x.get("bom-ref")}
        for vuln in doc.get("vulnerabilities") or []:
            ratings = vuln.get("ratings") or []
            rating = max((x.get("score", 0) for x in ratings if isinstance(x.get("score"), (int, float))), default=None)
            severity = next((x.get("severity") for x in ratings if x.get("severity")), "medium")
            for affect in vuln.get("affects") or []:
                component = components.get(affect.get("ref"), {})
                purl = component.get("purl") or affect.get("purl")
                add("sca", vuln.get("id"), vuln.get("detail") or vuln.get("id"), severity,
                    package=component.get("name"), version=component.get("version"), cvss=rating,
                    cve=vuln.get("id") if str(vuln.get("id", "")).startswith("CVE-") else None,
                    description=vuln.get("detail"))
                if out and purl: out[-1]["purl"] = purl
    return out


@app.post("/api/v1/scanners/import")
def import_scanner_report(body: ScannerImportIn, c: Ctx = Depends(ctx("scans:write"))):
    """Parse and ingest a supported scanner report into the canonical finding lifecycle."""
    import json
    raw = json.dumps(body.document, separators=(",", ":"))
    if len(raw.encode("utf-8")) > 10_000_000:
        raise HTTPException(413, "Scanner report exceeds the 10 MB import limit")
    try:
        parsed = _parse_scanner_document(body.format, body.document)
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(422, f"Invalid {body.format} report: {str(exc)[:300]}") from None
    sbom = None
    if body.format == "spdx":
        try:
            sbom = _normalize_spdx_document(body.document)
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(422, f"Invalid SPDX report: {str(exc)[:300]}") from None
    if not parsed and sbom is None:
        raise HTTPException(422, "No supported findings were found in the scanner report")
    fs = [enrich(dict(f)) for f in parsed]
    now = datetime.now(timezone.utc).isoformat()
    for f in fs:
        f.setdefault("first_seen", now)
        f.setdefault("age_days", 0)
        f["repo"] = body.repo
    decision = pol.evaluate(fs, _effective_policy(c.store, repo=body.repo))
    # an external report never closes findings from RAT Flea DevSec's own engines (or other tools) that it did not cover
    sid, new = c.store.add_scan(body.repo, body.branch, body.commit, fs, sbom, decision,
                                c.p.actor, scanned_engines=())
    tickets = after_scan(c.store, getattr(c.store, "last_delta", None), c.p.tenant_id)
    c.store.audit_event("scanner.imported", c.p.actor,
        {"text": f"{body.format} import into {body.repo}: {len(fs)} findings, {new} new, gate={decision['decision']}",
         "scan": sid, "format": body.format})
    return {"scan_id": sid, "format": body.format, "received": len(fs), "new": new,
        "components": len((sbom or {}).get("components", [])), "decision": decision, "tickets": tickets,
        "source": "scanner_report", "note": "SPDX inventory is stored as SBOM evidence and does not imply a vulnerability scan. Empty SBOM-only imports do not close existing findings."}



class FindingAssessmentIn(BaseModel):
    assessment: str = Field(pattern="^(not_assessed|needs_review|exploitable|not_exploitable)$")
    business_impact: str | None = Field(default=None, max_length=2000)
    rationale: str = Field(min_length=5, max_length=3000)
    owner: str | None = Field(default=None, max_length=200)
    due_date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")


@app.patch("/api/findings/{fid}/assessment")
def update_finding_assessment(fid: str, body: FindingAssessmentIn,
                              c: Ctx = Depends(ctx("findings:triage"))):
    """Persist analyst assessment and ownership; this does not itself suppress or close a finding."""
    _get(c, fid)                                   # 404 when the finding does not exist
    data = body.model_dump()
    if data.get("due_date"):
        from datetime import date
        try:
            date.fromisoformat(data["due_date"])
        except ValueError:
            raise HTTPException(422, "due_date must be a valid calendar date") from None
    updated = c.store.set_assessment(fid, data, c.p.actor)
    if not updated:
        raise HTTPException(404, "finding not found")
    return {"finding": updated, "note": "Assessment saved. Finding status and policy decisions are unchanged."}




@app.get("/api/findings/{fid}/events")
def finding_events(fid: str, c: Ctx = Depends(ctx("findings:read"))):
    f = _get(c, fid)
    return {"finding_id": fid, "events": f.get("events", []),
            "remediation_verifications": f.get("remediation_verifications", [])}


class RemediationVerificationIn(BaseModel):
    verification_scan_id: str = Field(min_length=1, max_length=100)
    remediation_commit: str = Field(min_length=7, max_length=64)
    notes: str = Field(min_length=5, max_length=2000)


@app.post("/api/v1/findings/{fid}/verify-remediation")
def verify_remediation(fid: str, body: RemediationVerificationIn,
                       c: Ctx = Depends(ctx("findings:triage"))):
    finding = _get(c, fid)
    scan = next((x for x in c.store.pipelines() if x.get("id") == body.verification_scan_id), None)
    if not scan or scan.get("repo") != finding.get("repo"):
        raise HTTPException(404, "verification scan was not found for this finding repository")
    if str(scan.get("commit") or "").lower() != body.remediation_commit.lower()[:7]:
        raise HTTPException(409, "verification commit does not match the recorded scan commit")
    engines = set(scan.get("scanned_engines") or [])
    if finding.get("engine") not in engines:
        raise HTTPException(409, "verification scan did not run the finding originating engine")
    present = finding.get("fingerprint") in set(scan.get("finding_fingerprints") or [])
    verification = {"scan_id": scan["id"], "commit": scan.get("commit"), "engine": finding["engine"],
        "result": "failed" if present else "passed", "notes": body.notes,
        "finding_fingerprint": finding["fingerprint"], "scanner_coverage": sorted(engines)}
    item = c.store.record_remediation_verification(fid, verification, c.p.actor)
    if not item:
        raise HTTPException(404, "finding not found")
    c.store.record_finding_event(fid, "remediation_verification", c.p.actor, verification)
    return {"verification": item, "finding_status": "open" if present else "fixed",
        "note": "Originating engine still reports this finding." if present else
        "Finding closed only after the originating engine ran in the recorded scan and did not report this fingerprint."}

@app.get("/api/v1/policies/baseline-delta")
def policy_baseline_delta(repo: str = Query(min_length=1, max_length=300),
                          project: str | None = Query(default=None, max_length=300),
                          base_scan_id: str = Query(min_length=1, max_length=100),
                          head_scan_id: str = Query(min_length=1, max_length=100),
                          c: Ctx = Depends(ctx("findings:read"))):
    """Compare two recorded scan snapshots and evaluate only introduced findings against the active policy."""
    if base_scan_id == head_scan_id:
        raise HTTPException(422, "base and head scan IDs must be different")
    scans = [x for x in c.store.pipelines() if x.get("repo") == repo]
    by_id = {x.get("id"): x for x in scans}
    base, head = by_id.get(base_scan_id), by_id.get(head_scan_id)
    if not base or not head:
        raise HTTPException(404, "one or both scan snapshots were not found for this repository")
    if (base.get("started") or "") >= (head.get("started") or ""):
        raise HTTPException(422, "baseline scan must be older than the head scan")
    base_fp, head_fp = base.get("finding_fingerprints"), head.get("finding_fingerprints")
    if not isinstance(base_fp, list) or not isinstance(head_fp, list):
        raise HTTPException(409, "scan snapshots predate fingerprint retention; run fresh baseline and head scans")
    base_set, head_set = set(base_fp), set(head_fp)
    introduced, resolved, unchanged = head_set - base_set, base_set - head_set, base_set & head_set
    by_fingerprint = {f.get("fingerprint"): f for f in c.store.findings() if f.get("repo") == repo}
    introduced_findings = [by_fingerprint[x] for x in sorted(introduced) if x in by_fingerprint]
    decision = pol.evaluate(introduced_findings, _effective_policy(c.store, repo=repo, project=project if not repo else None))
    return {"repo": repo, "base_scan_id": base_scan_id, "head_scan_id": head_scan_id,
        "baseline": {"findings": len(base_set)}, "head": {"findings": len(head_set)},
        "delta": {"introduced": len(introduced), "resolved": len(resolved), "unchanged": len(unchanged)},
        "introduced_findings": introduced_findings[:500], "decision": decision,
        "note": "Only introduced findings are evaluated for the delta decision. Existing findings remain visible in the full finding inventory."}



# ─── cloud-native application protection (CSPM, KSPM, CIEM, CWPP, attack paths) ────────────
from . import cnapp  # noqa: E402

CLOUD = cnapp.PgCloud(DB_URL) if ENTERPRISE else cnapp.MemoryCloud()


def _cl(fn):
    try:
        return fn()
    except cnapp.CloudError as e:
        raise HTTPException(e.status, str(e)) from None
    except sm.SecretError as e:
        raise HTTPException(400, str(e)) from None


def _any_feature(*names):
    def dep(request: Request):
        last = None
        for n in names:
            try:
                feature(n)(request)
                return
            except HTTPException as e:
                last = e
        raise last
    return dep


def store_findings(c: Ctx, repo: str, findings: list[dict], engines: list[str] | None, refresh=(), branch="cloud", commit="", actor=None):
    """Enrich, gate, store and ticket findings produced on the platform (cloud, cluster and runtime analysis)."""
    crit = {r["name"]: r.get("criticality", 1.0) for r in c.store.repos()}
    fs = []
    for f in findings:
        linked = [crit[x] for x in f.get("linked_repos") or ([f["source"]["repo"]] if f.get("source") else []) if x in crit]
        g = enrich(dict(f), max(linked) if linked else 1.0)
        g.setdefault("first_seen", datetime.now(timezone.utc).isoformat())
        g.setdefault("age_days", 0)
        g["repo"] = repo
        fs.append(g)
    try:
        effective = _effective_policy(c.store, repo=repo)
    except HTTPException:            # cloud accounts and clusters are not mapped to projects: organisation policy applies
        effective = _effective_policy(c.store)
    decision = pol.evaluate(fs, effective)
    sid, new = c.store.add_scan(repo, branch, commit, fs, None, decision, actor or c.p.actor, scanned_engines=engines,
                                stats={"raw": len(fs), "after_dedup": len(fs), "reported": len(fs)}, refresh=refresh)
    tickets = after_scan(c.store, getattr(c.store, "last_delta", None), c.p.tenant_id)
    return {"scan_id": sid, "received": len(fs), "new": new, "decision": decision, "tickets": tickets}


def _ingest_inventory(c: Ctx, inv: dict, actor: str) -> dict:
    CLOUD.save_inventory(c.p.tenant_id, inv, actor)
    all_inv = CLOUD.inventory_docs(c.p.tenant_id)
    repos = [r["name"] for r in c.store.repos()]
    found = cnapp.analyse(inv, all_inv, c.store.findings(), repos)
    from myelin_engine.cloud import ENGINES
    from myelin_engine.cloud.rules import repo_key
    res = store_findings(c, repo_key(inv), found, ENGINES[inv["provider"]] + ["paths"], refresh=cnapp.REFRESH, actor=actor)
    c.store.audit_event("cloud.inventory.analysed", actor, {"text": f"{inv['provider']} {inv['account']}: {len(inv.get('resources') or [])} resources, "
                                                                  f"{len(found)} findings ({res['new']} new)", "key": repo_key(inv)})
    from myelin_engine import cloud as ce
    return {**res, "key": repo_key(inv), "summary": ce.summary(inv),
            "attack_paths": sum(1 for f in found if f["engine"] == "paths")}


class CloudInventoryIn(BaseModel):
    content_base64: str = Field(min_length=4, max_length=60_000_000)
    provider: str = Field("", max_length=16)
    account: str = Field("", max_length=300)
    filename: str = Field("", max_length=300)


@app.get("/api/v1/cloud/rules")
def cloud_rules(c: Ctx = Depends(ctx("findings:read"))):
    from myelin_engine import cloud as ce
    return ce.catalogue()


@app.post("/api/v1/cloud/inventory")
def cloud_inventory_upload(body: CloudInventoryIn, request: Request, c: Ctx = Depends(ctx("scans:write"))):
    """Analyse an inventory: a RAT Flea inventory (`myelin cloud collect`), Azure Resource Graph rows, a Google Cloud Asset
    Inventory export or `kubectl get ... -o json`. Re-uploading the same account closes what was fixed."""
    try:
        raw = base64.b64decode(body.content_base64, validate=False)
    except ValueError:
        raise HTTPException(400, "content_base64 is not base64") from None
    inv = _cl(lambda: cnapp.load_upload(raw, body.provider, body.account))
    feature("kspm" if inv["provider"] == "kubernetes" else "cspm")(request)
    return _ingest_inventory(c, inv, c.p.actor)


@app.get("/api/v1/cloud/inventories")
def cloud_inventories(c: Ctx = Depends(ctx("findings:read"))):
    return CLOUD.list_inventories(c.p.tenant_id)


@app.delete("/api/v1/cloud/inventories", status_code=204)
def cloud_inventory_delete(key: str = Query(min_length=3, max_length=300), c: Ctx = Depends(ctx("connectors:manage"))):
    _cl(lambda: CLOUD.delete_inventory(c.p.tenant_id, key))
    c.store.audit_event("cloud.inventory.deleted", c.p.actor, {"text": f"inventory {key} deleted"})


class CloudAccountIn(BaseModel):
    provider: str = Field(pattern="^(azure|aws|gcp|kubernetes)$")
    name: str | None = Field(default=None, max_length=200)
    config: dict = {}
    credential: str | None = Field(default=None, max_length=32768)   # JSON, pasted once; stored in the vault


@app.get("/api/v1/cloud/accounts")
def cloud_accounts(c: Ctx = Depends(ctx("findings:read"))):
    return [cnapp.public(a) for a in CLOUD.list_accounts(c.p.tenant_id)]


@app.post("/api/v1/cloud/accounts", status_code=201)
def cloud_account_create(body: CloudAccountIn, request: Request, c: Ctx = Depends(ctx("connectors:manage"))):
    feature("kspm" if body.provider == "kubernetes" else "cspm")(request)
    acc = _cl(lambda: cnapp.new_account(body.model_dump(), c.p.actor))
    cred = (body.credential or "").strip()
    if cred:
        try:
            json.loads(cred)
        except ValueError:
            raise HTTPException(400, "credential must be JSON (see the connection guide for each provider)") from None
        if ENTERPRISE:
            if not sm.vault_available():
                raise HTTPException(400, "a secret vault (VAULT_ADDR) is required to hold the cloud credential")
            acc["credential_ref"] = cnapp.credential_ref(c.p.tenant_id, acc["id"])
            _cl(lambda: sm.store(acc["credential_ref"], cred))
        else:
            acc["credential_ref"] = "memory"
            CLOUD._cred[str(acc["id"])] = cred
    elif body.provider != "aws":
        raise HTTPException(400, "a read-only credential is required for this provider")
    _cl(lambda: CLOUD.add_account(c.p.tenant_id, acc))
    c.store.audit_event("cloud.account.added", c.p.actor, {"text": f"{acc['provider']} account '{acc['name']}' added"})
    return cnapp.public(CLOUD.get_account(c.p.tenant_id, acc["id"]))


@app.post("/api/v1/cloud/accounts/{aid}/collect")
def cloud_account_collect(aid: str, c: Ctx = Depends(ctx("scans:run"))):
    """Collect the account now (read-only APIs), analyse it and store the findings."""
    acc = _cl(lambda: CLOUD.get_account(c.p.tenant_id, aid))
    raw = None
    if acc.get("credential_ref"):
        raw = sm.resolve(acc["credential_ref"]) if ENTERPRISE else CLOUD._cred.get(str(acc["id"]))
    try:
        inv = cnapp.collect(acc, json.loads(raw) if raw else None)
    except cnapp.CloudError as e:
        CLOUD.update_account(c.p.tenant_id, aid, last_error=str(e)[:1000])
        c.store.audit_event("cloud.collect.failed", c.p.actor, {"text": f"{acc['provider']} '{acc['name']}': {e}"[:500]})
        raise HTTPException(e.status, str(e)) from None
    CLOUD.update_account(c.p.tenant_id, aid, last_error=None, last_collected_at=datetime.now(timezone.utc))
    return _ingest_inventory(c, inv, c.p.actor)


@app.delete("/api/v1/cloud/accounts/{aid}", status_code=204)
def cloud_account_delete(aid: str, c: Ctx = Depends(ctx("connectors:manage"))):
    acc = _cl(lambda: CLOUD.get_account(c.p.tenant_id, aid))
    _cl(lambda: CLOUD.delete_account(c.p.tenant_id, aid))
    if ENTERPRISE and acc.get("credential_ref"):
        sm.forget(acc["credential_ref"])
    c.store.audit_event("cloud.account.deleted", c.p.actor, {"text": f"{acc['provider']} account '{acc['name']}' deleted"})


@app.post("/api/v1/runtime/events", dependencies=[Depends(feature("cwpp"))])
async def runtime_events_in(request: Request, cluster: str = Query("", max_length=200), c: Ctx = Depends(ctx("scans:write"))):
    """Runtime detections from Falco (Falcosidekick webhook), Tetragon (JSON export) or a compatible sensor. Accepts one
    event, a list, or {"cluster", "events": [...]}. Authenticate with an integration API key (X-API-Key)."""
    raw = await request.body()
    if len(raw) > 20_000_000:
        raise HTTPException(413, "request body too large")
    try:
        payload = json.loads(raw or b"null")
    except ValueError:
        try:
            payload = [json.loads(x) for x in raw.decode("utf-8", "replace").splitlines() if x.strip()]   # JSON lines (Tetragon export)
        except ValueError:
            raise HTTPException(400, "body must be JSON or JSON lines") from None
    events, found = _cl(lambda: cnapp.runtime_ingest(CLOUD, c.p.tenant_id, payload, cluster))
    if not events:
        return {"received": 0, "findings": 0}
    found = cnapp.link_runtime(found, CLOUD.inventory_docs(c.p.tenant_id), [r["name"] for r in c.store.repos()])
    by_cluster = {}
    for f in found:
        by_cluster.setdefault(f["repo"], []).append(f)
    new = 0
    for repo, fs in by_cluster.items():
        new += store_findings(c, repo, fs, [], refresh=cnapp.REFRESH, branch="runtime")["new"]
    c.store.audit_event("runtime.events", c.p.actor, {"text": f"{len(events)} runtime events, {len(found)} findings updated, {new} new"})
    return {"received": len(events), "findings": len(found), "new": new}


@app.get("/api/v1/runtime/events")
def runtime_events_list(hours: int = Query(24, ge=1, le=720), cluster: str | None = Query(None, max_length=200),
                        c: Ctx = Depends(ctx("findings:read"))):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    return CLOUD.list_events(c.p.tenant_id, since, cluster, limit=2000)[::-1]


@app.get("/api/v1/cloud/identities")
def cloud_identities(provider: str | None = Query(None, max_length=16), c: Ctx = Depends(ctx("findings:read"))):
    from myelin_engine.cloud import ciem
    return [i for inv in CLOUD.inventory_docs(c.p.tenant_id) if not provider or inv["provider"] == provider for i in ciem.identities(inv)][:2000]


@app.get("/api/v1/cloud/attack-paths")
def cloud_attack_paths(c: Ctx = Depends(ctx("findings:read"))):
    from myelin_engine.cloud import graph
    return graph.attack_paths(CLOUD.inventory_docs(c.p.tenant_id), c.store.findings(), [r["name"] for r in c.store.repos()])


@app.get("/api/v1/cnapp", dependencies=[Depends(_any_feature("cspm", "kspm", "cwpp"))])
def cnapp_overview(c: Ctx = Depends(ctx("findings:read"))):
    """Cloud and runtime overview: coverage, findings by engine, attack paths, identities, code-to-cloud links, runtime."""
    since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    return cnapp.overview(CLOUD.inventory_docs(c.p.tenant_id), c.store.findings(), [r["name"] for r in c.store.repos()],
                          CLOUD.list_events(c.p.tenant_id, since, limit=5000), [cnapp.public(a) for a in CLOUD.list_accounts(c.p.tenant_id)])


def seed_cloud_demo():
    """Demo mode: analyse the bundled sample cloud accounts, cluster and runtime events (demo/cloud) through the same
    code path a customer upload takes, so the console shows real engine output."""
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "demo", "cloud")
    if ENTERPRISE or not os.path.isdir(root):
        return
    c = Ctx(demo_principal(DEMO_TENANT, admin=True), DEMO)
    actor = "demo:cloud-collector"
    files = [("aws-inventory.json", "", ""), ("azure-resource-graph.json", "azure", ""), ("gcp-cloud-asset-export.jsonl", "gcp", "acme-risk-analytics"),
             ("aks-prod-cin.kubectl.json", "kubernetes", "aks-prod-cin")]
    for name, prov, acct in files:
        with open(os.path.join(root, name), "rb") as fh:
            _ingest_inventory(c, cnapp.load_upload(fh.read(), prov, acct), actor)
    with open(os.path.join(root, "runtime-events.json")) as fh:
        events = json.load(fh)
    shift = datetime.now(timezone.utc) - timedelta(hours=2)
    for i, e in enumerate(events):     # keep the sample detections inside the last 24 hours
        t = (shift + timedelta(minutes=7 * i)).isoformat().replace("+00:00", "Z")
        e["time"] = t
    _, found = cnapp.runtime_ingest(CLOUD, c.p.tenant_id, events, "aks-prod-cin")
    found = cnapp.link_runtime(found, CLOUD.inventory_docs(c.p.tenant_id), [r["name"] for r in c.store.repos()])
    store_findings(c, "k8s:aks-prod-cin", found, [], refresh=cnapp.REFRESH, branch="runtime", actor="falco")
    with open(os.path.join(root, "aks-prod-cin.kubectl.json"), "rb") as fh:     # attack paths now see the runtime detections
        _ingest_inventory(c, cnapp.load_upload(fh.read(), "kubernetes", "aks-prod-cin"), actor)
    for acct in (("azure", "Production subscription", {"subscriptions": ["8c1f4e2a-55d0-4b7e-9a31-6f20c7d1b9e4"]}),
                 ("aws", "Retail banking (ap-south-1)", {"regions": ["ap-south-1"]}),
                 ("gcp", "Risk analytics", {"parent": "projects/acme-risk-analytics"}),
                 ("kubernetes", "aks-prod-cin", {"server": "https://aks-prod-cin.hcp.centralindia.azmk8s.io:443"})):
        a = cnapp.new_account({"provider": acct[0], "name": acct[1], "config": acct[2]}, actor)
        a["last_collected_at"] = datetime.now(timezone.utc)
        CLOUD.add_account(c.p.tenant_id, a)


seed_cloud_demo()
