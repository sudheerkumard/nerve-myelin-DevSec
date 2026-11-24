# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Cloud-native application protection on the platform: cloud accounts and clusters (read-only collection),
normalised inventories, runtime events, and the analysis that ties them to repositories.

Storage follows the ticketing pattern: MemoryCloud for demo mode, PgCloud (row-level security per tenant) for
enterprise mode. Credentials are written to the vault and referenced, never stored in the database."""
import copy
import uuid
from datetime import datetime, timedelta, timezone

from myelin_engine import cloud as engine
from myelin_engine.cloud import ciem, graph, inventory, runtime
from myelin_engine.cloud.rules import repo_key

PROVIDERS = ("azure", "aws", "gcp", "kubernetes")
CONFIG_FIELDS = {"azure": ("subscriptions",), "aws": ("regions",), "gcp": ("parent",), "kubernetes": ("server",)}
REFRESH = ("title", "severity", "mrs", "priority", "sla_days", "ssvc", "evidence", "event_count", "last_event", "first_event", "nodes",
           "tactics", "techniques", "command", "path", "path_id", "linked_repos", "resource", "source", "exposure")
RUNTIME_WINDOW_DAYS = 30
MAX_EVENTS_PER_CALL = 5000


class CloudError(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def new_account(body: dict, actor: str) -> dict:
    p = str(body.get("provider", "")).lower()
    if p not in PROVIDERS:
        raise CloudError("provider must be azure, aws, gcp or kubernetes")
    cfg = dict(body.get("config") or {})
    for k in CONFIG_FIELDS[p]:
        if not cfg.get(k):
            raise CloudError(f"config.{k} is required for {p}")
    if p == "azure" and isinstance(cfg["subscriptions"], str):
        cfg["subscriptions"] = [x.strip() for x in cfg["subscriptions"].split(",") if x.strip()]
    if p == "aws" and isinstance(cfg["regions"], str):
        cfg["regions"] = [x.strip() for x in cfg["regions"].split(",") if x.strip()]
    if p == "kubernetes" and not str(cfg["server"]).startswith("https://"):
        raise CloudError("config.server must be the https URL of the Kubernetes API server")
    if p == "gcp" and str(cfg["parent"]).split("/")[0] not in ("projects", "folders", "organizations"):
        raise CloudError("config.parent must be projects/<id>, folders/<id> or organizations/<id>")
    return {"id": uuid.uuid4(), "provider": p, "name": (body.get("name") or f"{p} account")[:200], "config": cfg,
            "credential_ref": None, "enabled": True, "last_collected_at": None, "last_error": None, "created_by": actor,
            "created_at": datetime.now(timezone.utc)}


def public(a: dict) -> dict:
    return {k: (str(v) if k == "id" else v.isoformat() if isinstance(v, datetime) else v) for k, v in a.items()
            if k not in ("credential_ref", "tenant_id")} | {"has_credential": bool(a.get("credential_ref"))}


def credential_ref(tenant_id, aid) -> str:
    return f"vault://secret/myelin/tenants/{tenant_id}/cloud/{aid}#credential"


# ------------------------------------------------------------------ storage
class MemoryCloud:
    """Demo mode: in-process storage (lost on restart); credentials kept in memory only."""

    def __init__(self):
        self.accounts, self.inventories, self.events, self._cred = {}, {}, {}, {}

    def list_accounts(self, t):
        return [copy.deepcopy(a) for a in self.accounts.values() if a["tenant_id"] == str(t)]

    def get_account(self, t, aid):
        a = self.accounts.get(str(aid))
        if not a or a["tenant_id"] != str(t):
            raise CloudError("cloud account not found", 404)
        return copy.deepcopy(a)

    def add_account(self, t, a):
        self.accounts[str(a["id"])] = {**a, "tenant_id": str(t)}

    def update_account(self, t, aid, **f):
        self.get_account(t, aid)
        self.accounts[str(aid)].update(f)

    def delete_account(self, t, aid):
        self.get_account(t, aid)
        self.accounts.pop(str(aid))
        self._cred.pop(str(aid), None)

    def save_inventory(self, t, inv, actor):
        self.inventories.setdefault(str(t), {})[repo_key(inv)] = {"doc": copy.deepcopy(inv), "summary": engine.summary(inv),
                                                                   "collected_by": actor, "collected_at": datetime.now(timezone.utc).isoformat()}

    def list_inventories(self, t):
        return [{"key": k, **{x: v[x] for x in ("summary", "collected_by", "collected_at")}} for k, v in self.inventories.get(str(t), {}).items()]

    def inventory_docs(self, t):
        return [copy.deepcopy(v["doc"]) for v in self.inventories.get(str(t), {}).values()]

    def delete_inventory(self, t, key):
        if key not in self.inventories.get(str(t), {}):
            raise CloudError("inventory not found", 404)
        self.inventories[str(t)].pop(key)

    def add_events(self, t, events):
        self.events.setdefault(str(t), []).extend(copy.deepcopy(events))
        cut = (datetime.now(timezone.utc) - timedelta(days=RUNTIME_WINDOW_DAYS)).isoformat()
        self.events[str(t)] = [e for e in self.events[str(t)] if e["ts"] >= cut][-50000:]

    def list_events(self, t, since_iso, cluster=None, limit=5000):
        return [copy.deepcopy(e) for e in self.events.get(str(t), []) if e["ts"] >= since_iso and (not cluster or e["cluster"] == cluster)][-limit:]


class PgCloud:
    ACOLS = ("id", "provider", "name", "config", "credential_ref", "enabled", "last_collected_at", "last_error", "created_by", "created_at")

    def __init__(self, db_url):
        self.db_url = db_url

    def _tx(self, t):
        from .db.session import tenant_tx
        return tenant_tx(self.db_url, t)

    def _acc(self, s, aid):
        from .db.models import CloudAccount
        try:
            r = s.get(CloudAccount, uuid.UUID(str(aid)))
        except ValueError:
            r = None
        if not r:
            raise CloudError("cloud account not found", 404)
        return r

    def list_accounts(self, t):
        from sqlalchemy import select
        from .db.models import CloudAccount
        with self._tx(t) as s:
            return [{c: getattr(r, c) for c in self.ACOLS} for r in s.scalars(select(CloudAccount).order_by(CloudAccount.created_at))]

    def get_account(self, t, aid):
        with self._tx(t) as s:
            r = self._acc(s, aid)
            return {c: getattr(r, c) for c in self.ACOLS}

    def add_account(self, t, a):
        from .db.models import CloudAccount
        with self._tx(t) as s:
            s.add(CloudAccount(tenant_id=uuid.UUID(str(t)), **a))

    def update_account(self, t, aid, **f):
        with self._tx(t) as s:
            r = self._acc(s, aid)
            for k, v in f.items():
                setattr(r, k, v)

    def delete_account(self, t, aid):
        with self._tx(t) as s:
            s.delete(self._acc(s, aid))

    def save_inventory(self, t, inv, actor):
        from sqlalchemy import select
        from .db.models import CloudInventory
        key = repo_key(inv)
        with self._tx(t) as s:
            r = s.scalars(select(CloudInventory).where(CloudInventory.key == key)).first()
            if r is None:
                r = CloudInventory(tenant_id=uuid.UUID(str(t)), key=key, provider=inv["provider"], account=inv["account"], doc={}, collected_by=actor)
                s.add(r)
            r.doc, r.summary, r.collected_by, r.collected_at = inv, engine.summary(inv), actor, datetime.now(timezone.utc)

    def list_inventories(self, t):
        from sqlalchemy import select
        from .db.models import CloudInventory
        with self._tx(t) as s:
            return [{"key": r.key, "summary": r.summary, "collected_by": r.collected_by, "collected_at": r.collected_at.isoformat()}
                    for r in s.scalars(select(CloudInventory).order_by(CloudInventory.key))]

    def inventory_docs(self, t):
        from sqlalchemy import select
        from .db.models import CloudInventory
        with self._tx(t) as s:
            return [r.doc for r in s.scalars(select(CloudInventory))]

    def delete_inventory(self, t, key):
        from sqlalchemy import select
        from .db.models import CloudInventory
        with self._tx(t) as s:
            r = s.scalars(select(CloudInventory).where(CloudInventory.key == key)).first()
            if not r:
                raise CloudError("inventory not found", 404)
            s.delete(r)

    def add_events(self, t, events):
        from .db.models import RuntimeEvent
        with self._tx(t) as s:
            for e in events:
                s.add(RuntimeEvent(tenant_id=uuid.UUID(str(t)), cluster=e["cluster"][:200], ts=datetime.fromisoformat(e["ts"]),
                                   rule=e["rule"][:300], severity=e["severity"], namespace=e["namespace"][:200], workload=e["workload"][:300], event=e))

    def list_events(self, t, since_iso, cluster=None, limit=5000):
        from sqlalchemy import select
        from .db.models import RuntimeEvent
        with self._tx(t) as s:
            q = select(RuntimeEvent).where(RuntimeEvent.ts >= datetime.fromisoformat(since_iso))
            if cluster:
                q = q.where(RuntimeEvent.cluster == cluster)
            return [r.event for r in s.scalars(q.order_by(RuntimeEvent.ts.desc()).limit(limit))][::-1]


# ------------------------------------------------------------------ live collection
COLLECT_TRANSPORT = None        # test hook for the AWS client factory (callable(service, region) -> client)


def collect(account: dict, cred: dict | None) -> dict:
    """Run the read-only collector for one account. Raises CloudError with a readable message."""
    from myelin_engine.cloud import collect_aws, collect_azure, collect_gcp, collect_k8s, http
    p, cfg = account["provider"], account["config"]
    try:
        if p == "azure":
            return collect_azure.collect(cred or {}, cfg["subscriptions"], account=cfg.get("account", ""))
        if p == "aws":
            return collect_aws.collect(cfg["regions"], cred, client=COLLECT_TRANSPORT, account=cfg.get("account", ""))
        if p == "gcp":
            return collect_gcp.collect(cred or {}, cfg["parent"], account=cfg.get("account", ""))
        return collect_k8s.collect({**(cred or {}), "server": cfg["server"], **({"ca_data": cfg["ca_data"]} if cfg.get("ca_data") else {})},
                                   cluster=cfg.get("cluster") or account["name"])
    except http.CollectorError as e:
        raise CloudError(str(e), 502) from None
    except ImportError as e:
        raise CloudError(f"collector dependency missing: {e.name} (install requirements-cloud.txt)", 501) from None
    except (KeyError, TypeError, ValueError) as e:
        raise CloudError(f"credential or configuration is incomplete: {e}") from None


# ------------------------------------------------------------------ analysis
def analyse(inv: dict, all_inventories: list[dict], findings: list[dict], repos: list[str]) -> list[dict]:
    """Posture + identity findings for one inventory, plus attack paths that start in it."""
    out = engine.evaluate(inv)
    others = [i for i in all_inventories if repo_key(i) != repo_key(inv)] + [inv]
    current = [f for f in findings if f.get("repo") != repo_key(inv) or f.get("engine") not in ("cspm", "kspm", "ciem", "paths")] + out
    paths = [p for p in graph.attack_paths(others, current, repos) if p["repo"] == repo_key(inv)]
    return out + graph.path_findings(paths)


def runtime_ingest(cloud, tenant, payload, cluster: str = "") -> tuple[list[dict], list[dict]]:
    """Normalise and store events; return (events, findings recomputed over the window for the affected groups)."""
    if isinstance(payload, dict) and isinstance(payload.get("events"), list):
        cluster = cluster or payload.get("cluster") or ""
        payload = payload["events"]
    events = runtime.normalise(payload, cluster)
    if len(events) > MAX_EVENTS_PER_CALL:
        raise CloudError(f"more than {MAX_EVENTS_PER_CALL} events in one call", 413)
    if not events:
        return [], []
    cloud.add_events(tenant, events)
    since = (datetime.now(timezone.utc) - timedelta(days=RUNTIME_WINDOW_DAYS)).isoformat()
    keys = {(e["cluster"], e["namespace"], e["workload"] or e["pod"] or e["node"], e["rule"], e["image"]) for e in events}
    window = [e for c in {e["cluster"] for e in events} for e in cloud.list_events(tenant, since, c, limit=50000)
              if (e["cluster"], e["namespace"], e["workload"] or e["pod"] or e["node"], e["rule"], e["image"]) in keys]
    return events, runtime.findings(window)


def link_runtime(findings: list[dict], inventories: list[dict], repos: list[str]) -> list[dict]:
    """Code-to-runtime: attach the repository (from the image) and internet exposure (from the cluster inventory)."""
    exposed = set()
    for inv in inventories:
        if inv["provider"] != "kubernetes":
            continue
        for w in graph._workloads(inv, inventories, set(repos)):
            if w["exposure"]:
                exposed.add((inv["account"], w["res"]["props"].get("namespace"), w["res"]["name"]))
    for f in findings:
        r = graph.image_repo(f.get("image") or "", set(repos))
        if r:
            f["linked_repos"] = [r]
        if (f.get("account"), f.get("namespace"), f.get("workload")) in exposed:
            f["exposure"] = "internet"
    return findings


def overview(inventories, findings, repos, events, accounts) -> dict:
    """Everything the CNAPP console needs in one call."""
    eng = ("cspm", "kspm", "ciem", "runtime", "paths")
    open_f = [f for f in findings if f.get("status") == "open" and f.get("engine") in eng]
    by_eng = {e: {"open": 0, "critical": 0, "high": 0} for e in eng}
    by_cat, by_acct = {}, {}
    for f in open_f:
        b = by_eng[f["engine"]]
        b["open"] += 1
        if f.get("severity") in ("critical", "high"):
            b[f["severity"]] += 1
        by_cat[f.get("category") or "other"] = by_cat.get(f.get("category") or "other", 0) + 1
        a = by_acct.setdefault(f.get("repo"), {"open": 0, "critical": 0, "high": 0})
        a["open"] += 1
        if f.get("severity") in ("critical", "high"):
            a[f["severity"]] += 1
    paths = graph.attack_paths(inventories, findings, repos)
    idents = [i for inv in inventories for i in ciem.identities(inv)]
    links = graph.code_to_cloud(inventories, repos)
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    ev24 = [e for e in events if e["ts"] >= since]
    tactics = {}
    for e in ev24:
        for t in e.get("tactics") or ["Unclassified"]:
            tactics[t] = tactics.get(t, 0) + 1
    invs = []
    for inv in inventories:
        s = engine.summary(inv)
        s["key"] = repo_key(inv)
        s.update(by_acct.get(s["key"], {"open": 0, "critical": 0, "high": 0}))
        invs.append(s)
    return {
        "inventories": invs, "accounts": accounts, "engines": by_eng, "categories": by_cat,
        "attack_paths": paths[:50], "attack_path_count": len(paths),
        "identities": {"total": len(idents), "admin": sum(i["privilege"] == "admin" for i in idents),
                       "risky": sum(bool(i["flags"]) for i in idents), "top": idents[:25]},
        "code_to_cloud": links[:200], "linked_repos": sorted({x["repo"] for x in links}),
        "runtime": {"events_24h": len(ev24), "tactics_24h": tactics, "latest": ev24[-20:][::-1],
                    "clusters": sorted({e["cluster"] for e in events})},
        "coverage": {"providers": sorted({i["provider"] for i in inventories}), "resources": sum(len(i.get("resources") or []) for i in inventories),
                     "rules": len(engine.catalogue()) + 1},
    }


def load_upload(raw: bytes, provider: str = "", account: str = "") -> dict:
    try:
        return inventory.load(raw, provider, account)
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise CloudError(f"not a usable inventory: {e}") from None
