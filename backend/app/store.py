# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Data access behind the API routes.

DemoStore  in-memory sample tenant (customer demos, offline console).
PgStore    PostgreSQL. Every method opens a transaction bound to the caller's tenant (from the validated
           identity), so row-level security applies to every statement. Routes never see a tenant id
           from the request itself.
"""
import uuid
from collections import Counter
from datetime import datetime, timezone

from sqlalchemy import cast, func, literal_column, or_, select, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, insert

from .db.models import Finding, Repo, Scan, Tenant
from .db.session import tenant_tx
from .evidence import audit as audit_log


def _advisory_timestamp(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class DemoStore:
    def __init__(self, db: dict):
        self.db = db

    def tenant(self):
        return self.db["tenant"]

    def findings(self):
        return self.db["findings"]

    REPO_DEFAULTS = {"slsa_level": 0, "signed": False, "sbom": False, "branch_protection": False, "criticality": 1.0,
                     "internet_facing": False, "business_unit": "", "language": "", "scm": "", "ci": "", "owner": "",
                     "components": 0, "open": 0, "p0": 0, "p1": 0, "risk": 0}

    def repos(self):
        """Repository records with every field the API reads (records added by integrations may be partial)."""
        repos = self.db.setdefault("repos", [])
        for r in repos:
            for k, v in self.REPO_DEFAULTS.items():
                r.setdefault(k, v)
        return repos

    def pipelines(self):
        return self.db["pipelines"]

    def trend(self):
        return self.db["trend"]

    def audit(self):
        return self.db["audit"]

    def sbom(self, repo):
        stored = self.db.setdefault("sboms", {}).get(repo)
        if isinstance(stored, dict): return stored
        return self.db["sbom_payments_web"] if repo == "payments-web" else None

    def admission_events(self, since_iso):
        return [e for e in self.db.get("audit", []) if str(e.get("event", "")).startswith("admission.") and str(e.get("ts", "")) >= since_iso]

    def demo_extensions(self, repo):
        """Posture / cryptography records of generated demo repositories (no SBOM document is stored for them)."""
        return (self.db.get("repo_ext") or {}).get(repo)

    def get_finding(self, fid):
        return next((f for f in self.db["findings"] if f["id"] == fid), None)

    def save_intelligence_document(self, item):
        docs = self.db.setdefault("intelligence_documents", [])
        existing = next((x for x in docs if x.get("sha256") == item["sha256"]), None)
        if existing: return existing, False
        docs.insert(0, item)
        self.audit_event("intelligence.document.imported", item["imported_by"],
                         {"document_id": item["id"], "sha256": item["sha256"], "format": item["format"]})
        return item, True

    def intelligence_documents(self):
        return list(self.db.setdefault("intelligence_documents", []))
    def create_import_job(self, item):
        jobs = self.db.setdefault("import_jobs", [])
        jobs.insert(0, item)
        self.audit_event("import.job.queued", item["requested_by"], {"job_id": item["id"], "source": item["source"], "kind": item["kind"]})
        return item

    def update_import_job(self, job_id, status, counters=None, error=""):
        item = next((x for x in self.db.setdefault("import_jobs", []) if x["id"] == str(job_id)), None)
        if not item: return None
        now = datetime.now(timezone.utc).isoformat()
        if status == "running": item["started_at"] = now
        if status in {"succeeded", "partial", "failed"}: item["finished_at"] = now
        item.update(status=status, counters={**(item.get("counters") or {}), **(counters or {})}, error=error[:2000])
        self.audit_event("import.job." + status, item["requested_by"], {"job_id": item["id"], "counters": item["counters"], "error": item["error"]})
        return item

    def import_jobs(self):
        return list(self.db.setdefault("import_jobs", []))[:100]

    def requeue_import_job(self, job_id, actor):
        item = next((x for x in self.db.setdefault("import_jobs", []) if x["id"] == str(job_id)), None)
        if not item: return None
        if item.get("status") not in {"failed", "queued"}:
            raise ValueError("only failed or queued jobs can be requeued")
        item.update(status="queued", error="", finished_at=None)
        self.audit_event("import.job.requeued", actor, {"job_id": str(job_id)})
        return item

    def claim_import_job(self, worker_id, lease_seconds=900, max_attempts=5):
        now = datetime.now(timezone.utc)
        for item in self.db.setdefault("import_jobs", []):
            counters = item.get("counters") or {}
            stale = item.get("status") == "running" and item.get("started_at") and (
                now - datetime.fromisoformat(item["started_at"].replace("Z", "+00:00"))
            ).total_seconds() >= lease_seconds
            if item.get("status") != "queued" and not stale: continue
            attempts = int(counters.get("attempts", 0))
            if attempts >= max_attempts:
                item.update(status="failed", error="maximum worker attempts exceeded",
                            finished_at=now.isoformat())
                continue
            item.update(status="running", started_at=now.isoformat(),
                        counters={**counters, "attempts": attempts + 1, "worker_id": worker_id,
                                  "lease_seconds": lease_seconds})
            return dict(item)
        return None

    def advisory_watermark(self, source, ecosystems):
        return max((row["counters"]["window_end"] for row in self.db.get("import_jobs", [])
                    if row["source"] == source and row["status"] == "succeeded"
                    and row["counters"].get("rolling") and row["counters"].get("ecosystems") == ecosystems
                    and row["counters"].get("window_end")), default=None)

    def advisories_for(self, keys, cves=()):
        keys, cves = set(keys), set(cves)
        records = list(self.db.get("advisory_records", {}).items())
        matching = [row for _, row in records if keys.intersection(row["payload"].get("package_keys") or [])]
        cves.update(cve for row in matching for cve in row["payload"].get("cve_ids") or [])
        matching_ids = {id(row) for row in matching}
        matching.extend(row for (source, _), row in records if source in {"NVD", "REDHAT"} and id(row) not in matching_ids
                        and cves.intersection(row["payload"].get("cve_ids") or []))
        return matching

    def upsert_advisories(self, source, items):
        records = self.db.setdefault("advisory_records", {})
        for item in items:
            import hashlib, json
            item = {**item, "sha256": hashlib.sha256(json.dumps(item["payload"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
            key = (source, item["advisory_id"])
            previous = records.get(key)
            old = _advisory_timestamp(previous.get("modified_at")) if previous else None
            new = _advisory_timestamp(item.get("modified_at"))
            if old is None or (new is not None and new >= old):
                records[key] = item
        return len(items)

    def advisory_records(self, source=None, limit=5000):
        records = self.db.setdefault("advisory_records", {})
        values = [v for (src, _), v in records.items() if source is None or src == source]
        return values[-limit:]


    def annotate_finding_vex(self, fid, annotation, actor):
        f = self.get_finding(fid)
        if not f: return None
        f["vex_documents"] = [*f.get("vex_documents", []), annotation]
        self.record_finding_event(fid, "vex_statement_recorded", actor, annotation)
        return f
    def record_finding_event(self, fid, event, actor, detail):
        f = self.get_finding(fid)
        if not f:
            return None
        item = {"id": "evt-" + uuid.uuid4().hex[:12], "event": event, "actor": actor,
                "detail": detail, "created_at": datetime.now(timezone.utc).isoformat()}
        f["events"] = [*f.get("events", []), item]
        self.audit_event("finding." + event, actor, {"finding": fid, "event_id": item["id"], "detail": detail})
        return item

    def record_remediation_verification(self, fid, verification, actor):
        f = self.get_finding(fid)
        if not f:
            return None
        item = {"id": "ver-" + uuid.uuid4().hex[:12], **verification,
                "verified_by": actor, "created_at": datetime.now(timezone.utc).isoformat()}
        f["remediation_verifications"] = [*f.get("remediation_verifications", []), item]
        if item.get("result") == "passed":
            f.update(status="fixed", fixed_at=item["created_at"], verification_id=item["id"])
        else:
            f.update(status="open", reopened_at=item["created_at"])
        self.audit_event("finding.remediation_verified", actor,
                         {"finding": fid, "verification_id": item["id"], "result": item["result"]})
        return item

    def set_assessment(self, fid, assessment, actor):
        f = self.get_finding(fid)
        if f:
            f["assessment"] = {**(f.get("assessment") or {}), **assessment,
                               "updated_at": datetime.now(timezone.utc).isoformat(), "updated_by": actor}
            self.record_finding_event(fid, "assessed", actor, assessment)
            self.audit_event("finding.assessed", actor, f"Assessment updated for {fid}")
        return f

    def set_regulatory(self, fid, record, actor):
        """EU CRA (Article 14) reporting milestones kept on the finding: early warning, notification, final report."""
        f = self.get_finding(fid)
        if f:
            reg = dict(f.get("regulatory") or {})
            reg.setdefault("cra", {}).update(record)
            f["regulatory"] = reg
            self.record_finding_event(fid, "regulatory", actor, record)
            self.audit_event("finding.regulatory", actor, f"CRA reporting record for {fid}: {', '.join(record)}")
        return f

    def set_campaign(self, fid, campaign, actor):
        """Campaign workflow state kept on each member finding (survives re-grouping and re-scans)."""
        f = self.get_finding(fid)
        if f:
            f["campaign"] = {**(f.get("campaign") or {}), **campaign}
            self.record_finding_event(fid, "campaign", actor, campaign)
        return f

    def set_ticket(self, fid, ticket, actor):
        f = self.get_finding(fid)
        if f:
            first = not f.get("ticket")
            f["ticket"] = ticket
            if first:
                self.audit_event("finding.ticket", actor, f"{fid} → {ticket.get('system')} {ticket.get('key')}")
        return f

    def set_status(self, fid, status, actor, reason, expires=None):
        f = self.get_finding(fid)
        if f:
            f.update(_triage(status, actor, reason, expires))
            self.record_finding_event(fid, "status_changed", actor, {"status": status, "reason": reason, **({"expires": expires} if expires else {})})
            self.audit_event("finding.status", actor, f"{fid} → {status} ({reason or 'no reason'})" + (f" until {expires}" if expires else ""))
        return f

    def expire_acceptances(self):
        """Risk acceptances past their expiry date reopen automatically."""
        today = datetime.now(timezone.utc).date().isoformat()
        n = 0
        for f in self.db["findings"]:
            if f.get("status") == "risk_accepted" and f.get("triage", {}).get("expires") and f["triage"]["expires"] < today:
                f["status"], n = "open", n + 1
                f["reopened_reason"] = f"risk acceptance expired on {f['triage']['expires']}"
        if n:
            self.audit_event("finding.acceptance_expired", "system", f"{n} risk acceptance(s) expired and reopened")
        return n

    def add_scan(self, repo, branch, commit, findings, sbom, decision, actor, scanned_engines=None, stats=None, refresh=(), reconcile_engines=None):
        known = {f["fingerprint"]: f for f in self.db["findings"]}
        new = [f for f in findings if f["fingerprint"] not in known]
        for f in findings:      # refresh live fields (evidence, event counts, attack-path steps) of findings already stored
            old = known.get(f["fingerprint"])
            if old is not None and refresh:
                old.update({k: f[k] for k in refresh if k in f})
        for f in new:
            f.setdefault("introduced_in", (commit or "")[:12] or None)
        seen = {f["fingerprint"] for f in findings}
        engines = set(scanned_engines) if scanned_engines is not None else {f["engine"] for f in findings}
        reconcile = engines if reconcile_engines is None else set(reconcile_engines)
        now = datetime.now(timezone.utc).isoformat()
        fixed, reopened = [], []
        for f in self.db["findings"]:
            if f.get("repo") != repo or (f.get("engine") not in reconcile and f["fingerprint"] not in seen):
                continue
            if f["fingerprint"] not in seen and f.get("status") == "open":
                f.update(status="fixed", fixed_at=now, fixed_in=commit[:12] or None)
                fixed.append(f)
            elif f["fingerprint"] in seen and f.get("status") == "fixed":
                f.update(status="open", reopened_at=now)
                reopened.append(f)
        self.db["findings"] = new + self.db["findings"]
        self.last_delta = {"new": new, "fixed": fixed, "reopened": reopened, "repo": repo, "commit": commit}
        if not any(x.get("name") == repo for x in self.db["repos"]):
            self.db["repos"].append({"name": repo, "project": None, "business_unit": "External assessment", "risk": 0,
                "slsa_level": 0, "signed": False, "sbom": bool(sbom), "branch_protection": False,
                "criticality": 1.0, "internet_facing": False, "language": "", "scm": "", "ci": "external",
                "owner": "", "components": len((sbom or {}).get("components", [])), "open": len(new),
                "p0": sum(x.get("priority") == "P0" for x in new), "p1": sum(x.get("priority") == "P1" for x in new),
                "last_scan": datetime.now(timezone.utc).isoformat()})
        sid = "scan-" + uuid.uuid4().hex[:10]
        if isinstance(sbom, dict): self.db.setdefault("sboms", {})[repo] = sbom
        self.db["pipelines"].insert(0, {"id": sid, "repo": repo, "ci": "nerve-myelin", "branch": branch, "commit": commit[:7],
                                        "author": actor, "started": datetime.now(timezone.utc).isoformat(), "duration_s": 0,
                                        "decision": decision["decision"], "stages": [],
                                        "gate": {"blocking": decision["blocking"], "warnings": decision["warnings"]},
                                        "stats": stats or {"raw": len(findings), "after_dedup": len(findings), "reported": len(findings)},
                                        "finding_fingerprints": sorted({f["fingerprint"] for f in findings}), "scanned_engines": sorted(engines),
                                        "engines": sorted(engines)})
        return sid, len(new)

    def get_repo_project(self, repo):
        item = next((x for x in self.db["repos"] if x.get("name") == repo), None)
        return item.get("project") if item else None

    def set_repo_project(self, repo, project, actor):
        item = next((x for x in self.db["repos"] if x.get("name") == repo), None)
        if item is None:
            item = {"name": repo, "project": project}
            self.db["repos"].append(item)
        else:
            item["project"] = project
        self.audit_event("policy.repository_project.mapped", actor, {"repository": repo, "project": project})
        return {"repo": repo, "project": project}

    def policy_exceptions(self):
        return list(self.db.setdefault("policy_exceptions", []))

    def create_policy_exception(self, item):
        self.db.setdefault("policy_exceptions", []).insert(0, item)
        self.audit_event("policy.exception.requested", item["requested_by"], {"exception_id": item["id"], "scope": item["scope_key"], "match": item["match"]})
        return item

    def review_policy_exception(self, exception_id, reviewer, decision, note, now):
        item = next((x for x in self.policy_exceptions() if x["id"] == str(exception_id)), None)
        if not item or item["status"] != "pending": return None
        if item["requested_by"] == reviewer: raise PermissionError("requester cannot approve or reject their own exception")
        if item["expires_at"] <= now and decision == "approved": raise ValueError("exception expiry must be in the future")
        item.update(status=decision, reviewed_by=reviewer, review_note=note, reviewed_at=now)
        self.audit_event("policy.exception." + decision, reviewer, {"exception_id": item["id"], "requested_by": item["requested_by"], "note": note})
        return item
    def policy_versions(self):
        return list(self.db.setdefault("policy_versions", []))

    def get_policy_version(self, version_id):
        return next((x for x in self.policy_versions() if x["id"] == str(version_id)), None)

    def create_policy_version(self, item, event="policy.version.created", detail=None):
        self.db["policy_versions"].append(item)
        self.audit_event(event, item["created_by"], detail or {"policy_version_id": item["id"], "version": item["version"], "sha256": item["content_sha256"]})
        return item

    def create_policy_approval(self, item):
        requests = self.db.setdefault("policy_approval_requests", [])
        if any(x["policy_version_id"] == item["policy_version_id"] for x in requests):
            raise ValueError("an approval request already exists for this policy version")
        requests.append(item)
        version = self.get_policy_version(item["policy_version_id"])
        if version: version["status"] = "pending"
        self.audit_event("policy.approval.requested", item["requested_by"], {"request_id": item["id"], "policy_version_id": item["policy_version_id"]})
        return item

    def get_policy_approval(self, request_id):
        return next((x for x in self.db.setdefault("policy_approval_requests", []) if x["id"] == str(request_id)), None)

    def policy_approval_requests(self):
        return list(self.db.setdefault("policy_approval_requests", []))

    def review_policy_approval(self, request_id, reviewer, decision, note, now):
        item = self.get_policy_approval(request_id)
        if not item or item["status"] != "pending":
            return None
        if item["requested_by"] == reviewer:
            raise PermissionError("requester cannot approve or reject their own policy")
        item.update(status=decision, reviewed_by=reviewer, review_note=note, reviewed_at=now)
        version = self.get_policy_version(item["policy_version_id"])
        if version:
            version["status"] = "published" if decision == "approved" else "rejected"
            if decision == "approved":
                version["published_by"] = reviewer
                version["published_at"] = now
        self.audit_event("policy.approval." + decision, reviewer, {"request_id": item["id"], "policy_version_id": item["policy_version_id"], "requested_by": item["requested_by"], "note": note})
        return item

    def bind_policy(self, item):
        bindings = self.db.setdefault("policy_bindings", [])
        existing = next((x for x in bindings if x["scope_type"] == item["scope_type"] and x["scope_key"] == item["scope_key"]), None)
        if existing:
            existing.update(item)
            result = existing
        else:
            bindings.append(item)
            result = item
        self.audit_event("policy.binding.updated", item["updated_by"], {"scope_type": item["scope_type"], "scope_key": item["scope_key"], "policy_version_id": item["policy_version_id"]})
        return result

    def policy_bindings(self):
        return list(self.db.setdefault("policy_bindings", []))

    def audit_event(self, event, actor, detail):
        self.db.setdefault("audit", []).insert(0, {"ts": datetime.now(timezone.utc).isoformat(), "event": event, "actor": actor, "detail": detail})


def _age(d: datetime, end: datetime | None = None) -> int:
    """Days open: until it was fixed/closed for closed findings (time to remediate), until now for open ones."""
    return max(0, ((end or datetime.now(timezone.utc)) - d).days)


def _closed_at(r) -> datetime | None:
    if r.status == "open":
        return None
    v = (r.data or {}).get("fixed_at") if r.status == "fixed" else None
    try:
        return datetime.fromisoformat(v) if v else r.updated_at
    except (TypeError, ValueError):
        return r.updated_at


def _triage(status, actor, reason, expires):
    """Triage record kept on the finding: who decided, why, when, and (for accepted risk) until when."""
    d = {"status": status}
    if status in ("suppressed", "risk_accepted", "fixed"):
        d["triage"] = {"status": status, "by": actor, "reason": reason or "", "at": datetime.now(timezone.utc).isoformat(),
                       **({"expires": expires} if expires and status == "risk_accepted" else {})}
    return d


def build_trend(findings: list[dict], days: int = 90) -> list[dict]:
    """Daily history reconstructed from first-seen and closed timestamps: open, open P0, introduced, fixed, MTTR."""
    from datetime import timedelta
    today = datetime.now(timezone.utc).date()
    rows = []
    for f in findings:
        try:
            fs = datetime.fromisoformat(f["first_seen"]).date()
        except (KeyError, TypeError, ValueError):
            continue
        ca = f.get("closed_at")
        ce = datetime.fromisoformat(ca).date() if ca else None
        rows.append((fs, ce, f.get("status"), f.get("priority")))
    out = []
    for i in range(days - 1, -1, -1):
        d = today - timedelta(days=i)
        op = [r for r in rows if r[0] <= d and (r[1] is None or r[1] > d)]
        fixed_window = [(r[1] - r[0]).days for r in rows if r[2] == "fixed" and r[1] and d - timedelta(days=30) < r[1] <= d]
        out.append({"date": d.isoformat(), "open": len(op), "p0": sum(r[3] == "P0" for r in op),
                    "introduced": sum(r[0] == d for r in rows), "fixed": sum(r[2] == "fixed" and r[1] == d for r in rows),
                    "mttr_days": round(sum(fixed_window) / len(fixed_window), 1) if fixed_window else 0, "autofix_merged": 0})
    return out


class PgStore:
    def __init__(self, url: str, tenant_id: uuid.UUID):
        self.url, self.tid = url, tenant_id

    def _tx(self):
        return tenant_tx(self.url, self.tid)

    @staticmethod
    def _finding(r: Finding) -> dict:
        end = _closed_at(r)
        return {**r.data, "id": r.id, "fingerprint": r.fingerprint, "repo": r.repo, "engine": r.engine, "severity": r.severity,
                "priority": r.priority, "mrs": r.mrs, "status": r.status, "first_seen": r.first_seen.isoformat(),
                "age_days": _age(r.first_seen, end), "closed_at": end.isoformat() if end else None}

    def tenant(self):
        with self._tx() as s:
            t = s.scalars(select(Tenant)).one()
            return {"id": str(t.id), "name": t.name, "plan": t.plan, "devs": t.devs, "region": t.region,
                    "sso": t.settings.get("sso", "OIDC"), "created": t.created_at.date().isoformat()}

    def findings(self):
        with self._tx() as s:
            return [self._finding(r) for r in s.scalars(select(Finding).order_by(Finding.mrs.desc()))]

    def get_finding(self, fid):
        with self._tx() as s:
            r = s.get(Finding, fid)
            return self._finding(r) if r else None

    def repos(self):
        fs = [f for f in self.findings() if f["status"] == "open"]
        with self._tx() as s:
            out = []
            for r in s.scalars(select(Repo)):
                mine = [f for f in fs if f["repo"] == r.name]
                d = {"slsa_level": 0, "signed": False, "sbom": False, "branch_protection": False, "criticality": 1.0,
                     "internet_facing": False, "business_unit": "", "language": "", "scm": "", "ci": "", "owner": "", "components": 0,
                     "last_scan": r.updated_at.isoformat(), **r.data}
                d.update({"name": r.name, "open": len(mine), "p0": sum(f["priority"] == "P0" for f in mine),
                          "p1": sum(f["priority"] == "P1" for f in mine), "risk": max([f["mrs"] for f in mine] or [0])})
                out.append(d)
            return out

    def pipelines(self):
        with self._tx() as s:
            return [{"id": r.id, "repo": r.repo, "decision": r.decision, "started": r.started_at.isoformat(), **r.data}
                    for r in s.scalars(select(Scan).order_by(Scan.started_at.desc()).limit(200))]

    def trend(self):
        return build_trend(self.findings())

    def admission_events(self, since_iso):
        from .db.models import AuditEvent
        since = datetime.fromisoformat(since_iso)
        with self._tx() as s:
            rows = s.scalars(select(AuditEvent).where(AuditEvent.event.like("admission.%"), AuditEvent.ts >= since)
                             .order_by(AuditEvent.id.desc()).limit(5000))
            return [{"ts": e.ts.isoformat(), "event": e.event, "actor": e.actor, "detail": e.detail} for e in rows]

    def audit(self):
        from .db.models import AuditEvent
        with self._tx() as s:
            return [{"ts": e.ts.isoformat(), "event": e.event, "actor": e.actor,
                     "detail": e.detail.get("text") if isinstance(e.detail, dict) and "text" in e.detail else e.detail, "hash": e.hash}
                    for e in s.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(500))]

    def sbom(self, repo):
        with self._tx() as s:
            r = s.scalars(select(Scan).where(Scan.repo == repo, Scan.sbom.is_not(None)).order_by(Scan.started_at.desc()).limit(1)).first()
            return r.sbom if r else None

    def save_intelligence_document(self, item):
        from .db.models import IntelligenceDocument
        import uuid as _uuid
        with self._tx() as s:
            existing = s.scalars(select(IntelligenceDocument).where(IntelligenceDocument.sha256 == item["sha256"])).first()
            if existing:
                return {"id": str(existing.id), "format": existing.format, "document_id": existing.document_id,
                    "issuer": existing.issuer, "sha256": existing.sha256, "imported_by": existing.imported_by,
                    "created_at": existing.created_at.isoformat()}, False
            row = IntelligenceDocument(id=_uuid.UUID(item["id"]), tenant_id=self.tid, format=item["format"],
                document_id=item.get("document_id") or "", issuer=item.get("issuer") or "", sha256=item["sha256"],
                document=item["document"], imported_by=item["imported_by"])
            s.add(row)
            audit_log.append(s, self.tid, item["imported_by"], "intelligence.document.imported",
                {"document_id": item["id"], "sha256": item["sha256"], "format": item["format"]})
            return item, True

    def intelligence_documents(self):
        from .db.models import IntelligenceDocument
        with self._tx() as s:
            return [{"id": str(x.id), "format": x.format, "document_id": x.document_id, "issuer": x.issuer,
                "sha256": x.sha256, "imported_by": x.imported_by, "created_at": x.created_at.isoformat()}
                for x in s.scalars(select(IntelligenceDocument).order_by(IntelligenceDocument.created_at.desc()))]
    def create_import_job(self, item):
        from .db.models import ImportJob
        with self._tx() as s:
            row = ImportJob(id=uuid.UUID(item["id"]), tenant_id=self.tid, kind=item["kind"], source=item["source"],
                status="queued", requested_by=item["requested_by"], counters=item.get("counters") or {}, error="")
            s.add(row)
            audit_log.append(s, self.tid, item["requested_by"], "import.job.queued",
                {"job_id": item["id"], "source": item["source"], "kind": item["kind"]})
            return item

    def update_import_job(self, job_id, status, counters=None, error=""):
        from .db.models import ImportJob
        with self._tx() as s:
            row = s.get(ImportJob, uuid.UUID(str(job_id)))
            if not row: return None
            now = datetime.now(timezone.utc)
            row.status, row.counters, row.error = status, {**(row.counters or {}), **(counters or {})}, error[:2000]
            if status == "running": row.started_at = now
            if status in {"succeeded", "partial", "failed"}: row.finished_at = now
            audit_log.append(s, self.tid, row.requested_by, "import.job." + status,
                {"job_id": str(row.id), "counters": row.counters, "error": row.error})
            return {"id": str(row.id), "kind": row.kind, "source": row.source, "status": row.status,
                "requested_by": row.requested_by, "counters": row.counters, "error": row.error,
                "created_at": row.created_at.isoformat(), "started_at": row.started_at.isoformat() if row.started_at else None,
                "finished_at": row.finished_at.isoformat() if row.finished_at else None}

    def import_jobs(self):
        from .db.models import ImportJob
        with self._tx() as s:
            return [{"id": str(x.id), "kind": x.kind, "source": x.source, "status": x.status,
                "requested_by": x.requested_by, "counters": x.counters, "error": x.error,
                "created_at": x.created_at.isoformat(), "started_at": x.started_at.isoformat() if x.started_at else None,
                "finished_at": x.finished_at.isoformat() if x.finished_at else None}
                for x in s.scalars(select(ImportJob).order_by(ImportJob.created_at.desc()).limit(100))]

    def requeue_import_job(self, job_id, actor):
        from .db.models import ImportJob
        with self._tx() as s:
            row = s.get(ImportJob, uuid.UUID(str(job_id)))
            if not row: return None
            if row.status not in {"failed", "queued"}:
                raise ValueError("only failed or queued jobs can be requeued")
            row.status, row.error, row.finished_at = "queued", "", None
            audit_log.append(s, self.tid, actor, "import.job.requeued", {"job_id": str(row.id)})
            return {"id": str(row.id), "status": row.status, "source": row.source}

    def claim_import_job(self, worker_id, lease_seconds=900, max_attempts=5):
        from sqlalchemy import and_, or_
        from .db.models import ImportJob
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        stale_before = now - timedelta(seconds=lease_seconds)
        with self._tx() as s:
            eligible = or_(ImportJob.status == "queued",
                           and_(ImportJob.status == "running", ImportJob.started_at < stale_before))
            row = s.scalars(select(ImportJob).where(eligible)
                .order_by(ImportJob.created_at.asc()).with_for_update(skip_locked=True).limit(1)).first()
            if not row: return None
            counters = dict(row.counters or {})
            attempts = int(counters.get("attempts", 0))
            if attempts >= max_attempts:
                row.status, row.error, row.finished_at = "failed", "maximum worker attempts exceeded", now
                return None
            counters.update(attempts=attempts + 1, worker_id=worker_id, lease_seconds=lease_seconds)
            row.status, row.started_at, row.finished_at = "running", now, None
            row.counters = counters
            return {"id": str(row.id), "kind": row.kind, "source": row.source, "status": row.status,
                "requested_by": row.requested_by, "counters": counters, "error": row.error,
                "created_at": row.created_at.isoformat(), "started_at": now.isoformat()}

    def advisory_watermark(self, source, ecosystems):
        from .db.models import ImportJob
        with self._tx() as s:
            return s.scalar(select(func.max(ImportJob.counters["window_end"].astext)).where(
                ImportJob.source == source, ImportJob.status == "succeeded",
                ImportJob.counters["rolling"].as_boolean().is_(True), ImportJob.counters["ecosystems"] == ecosystems))

    def advisories_for(self, keys, cves=()):
        from .db.models import AdvisoryRecord as A
        package_keys = A.payload.op("->", return_type=JSONB)(literal_column("'package_keys'"))
        cve_ids = A.payload.op("->", return_type=JSONB)(literal_column("'cve_ids'"))
        with self._tx() as s:
            matching = list(s.scalars(select(A).where(package_keys.has_any(cast(list(keys), ARRAY(Text)))))) if keys else []
            aliases = set(cves) | {cve for row in matching for cve in row.payload.get("cve_ids", [])}
            if aliases:
                extra = s.scalars(select(A).where(A.source.in_(("NVD", "REDHAT")), or_(
                    cve_ids.has_any(cast(sorted(aliases), ARRAY(Text))),
                    (A.source == "NVD") & A.advisory_id.in_(sorted(aliases)))))
                matching = list({x.id: x for x in [*matching, *extra]}.values())
            return [{"source": x.source, "advisory_id": x.advisory_id, "payload": x.payload} for x in matching]

    def upsert_advisories(self, source, items):
        from .db.models import AdvisoryRecord as A
        import hashlib, json

        rows = {}
        for item in items:
            key = item["advisory_id"]
            modified = _advisory_timestamp(item.get("modified_at"))
            previous = rows.get(key)
            if previous and previous["modified_at"] is not None and (modified is None or modified < previous["modified_at"]):
                continue
            rows[key] = {"id": uuid.uuid4(), "tenant_id": self.tid, "source": source, "advisory_id": key,
                         "modified_at": modified, "payload": item["payload"], "sha256": hashlib.sha256(
                             json.dumps(item["payload"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        values = list(rows.values())
        with self._tx() as s:
            for offset in range(0, len(values), 500):
                incoming = insert(A).values(values[offset:offset + 500])
                s.execute(incoming.on_conflict_do_update(
                    index_elements=[A.tenant_id, A.source, A.advisory_id],
                    set_={k: getattr(incoming.excluded, k) for k in ("payload", "sha256", "modified_at")},
                    where=(A.sha256 != incoming.excluded.sha256) & or_(
                        A.modified_at.is_(None), incoming.excluded.modified_at >= A.modified_at)))
            audit_log.append(s, self.tid, "myelin-advisory-sync", "advisory.feed.upserted",
                             {"source": source, "records": len(values)})
        return len(values)

    def advisory_records(self, source=None, limit=5000):
        from .db.models import AdvisoryRecord
        with self._tx() as s:
            q = select(AdvisoryRecord).order_by(AdvisoryRecord.modified_at.desc().nullslast()).limit(limit)
            if source: q = q.where(AdvisoryRecord.source == source)
            return [{"source": x.source, "advisory_id": x.advisory_id, "modified_at": x.modified_at.isoformat() if x.modified_at else None,
                "sha256": x.sha256, "payload": x.payload} for x in s.scalars(q)]


    def annotate_finding_vex(self, fid, annotation, actor):
        with self._tx() as s:
            r = s.get(Finding, fid)
            if not r: return None
            r.data = {**(r.data or {}), "vex_documents": [*((r.data or {}).get("vex_documents") or []), annotation]}
            r.updated_at = datetime.now(timezone.utc)
            item = {"id": "evt-" + uuid.uuid4().hex[:12], "event": "vex_statement_recorded", "actor": actor,
                "detail": annotation, "created_at": datetime.now(timezone.utc).isoformat()}
            r.data = {**r.data, "events": [*((r.data or {}).get("events") or []), item]}
            audit_log.append(s, self.tid, actor, "finding.vex_statement_recorded",
                {"finding": fid, "source_digest": annotation.get("source_digest"), "state": annotation.get("state")})
            return self._finding(r)
    def record_finding_event(self, fid, event, actor, detail):
        with self._tx() as s:
            r = s.get(Finding, fid)
            if not r:
                return None
            item = {"id": "evt-" + uuid.uuid4().hex[:12], "event": event, "actor": actor,
                    "detail": detail, "created_at": datetime.now(timezone.utc).isoformat()}
            r.data = {**(r.data or {}), "events": [*((r.data or {}).get("events") or []), item]}
            r.updated_at = datetime.now(timezone.utc)
            audit_log.append(s, self.tid, actor, "finding." + event,
                             {"finding": fid, "event_id": item["id"], "detail": detail})
            return item

    def record_remediation_verification(self, fid, verification, actor):
        with self._tx() as s:
            r = s.get(Finding, fid)
            if not r:
                return None
            created = datetime.now(timezone.utc).isoformat()
            item = {"id": "ver-" + uuid.uuid4().hex[:12], **verification,
                    "verified_by": actor, "created_at": created}
            data = r.data or {}
            r.data = {**data, "remediation_verifications": [*((data.get("remediation_verifications") or [])), item]}
            if item.get("result") == "passed":
                r.status = "fixed"
                r.data = {**r.data, "status": "fixed", "fixed_at": created, "verification_id": item["id"]}
            else:
                r.status = "open"
                r.data = {**r.data, "status": "open", "reopened_at": created}
            r.updated_at = datetime.now(timezone.utc)
            audit_log.append(s, self.tid, actor, "finding.remediation_verified",
                             {"finding": fid, "verification_id": item["id"], "result": item["result"]})
            return item

    def set_assessment(self, fid, assessment, actor):
        with self._tx() as s:
            r = s.get(Finding, fid)
            if not r:
                return None
            data = {**(r.data or {}), "assessment": {**((r.data or {}).get("assessment") or {}),
                **assessment, "updated_at": datetime.now(timezone.utc).isoformat(), "updated_by": actor}}
            r.data, r.updated_at = data, datetime.now(timezone.utc)
            audit_log.append(s, self.tid, actor, "finding.assessed", {"text": f"Assessment updated for {fid}"})
            return self._finding(r)

    def set_regulatory(self, fid, record, actor):
        with self._tx() as s:
            r = s.get(Finding, fid)
            if not r:
                return None
            item = {"id": "evt-" + uuid.uuid4().hex[:12], "event": "regulatory", "actor": actor, "detail": record,
                    "created_at": datetime.now(timezone.utc).isoformat()}
            reg = dict((r.data or {}).get("regulatory") or {})
            reg["cra"] = {**(reg.get("cra") or {}), **record}
            r.data = {**(r.data or {}), "regulatory": reg, "events": [*((r.data or {}).get("events") or []), item]}
            r.updated_at = datetime.now(timezone.utc)
            audit_log.append(s, self.tid, actor, "finding.regulatory", {"finding": fid, "event_id": item["id"], "detail": record})
            return self._finding(r)

    def set_campaign(self, fid, campaign, actor):
        with self._tx() as s:
            r = s.get(Finding, fid)
            if not r:
                return None
            item = {"id": "evt-" + uuid.uuid4().hex[:12], "event": "campaign", "actor": actor, "detail": campaign,
                    "created_at": datetime.now(timezone.utc).isoformat()}
            r.data = {**(r.data or {}), "campaign": {**((r.data or {}).get("campaign") or {}), **campaign},
                      "events": [*((r.data or {}).get("events") or []), item]}
            r.updated_at = datetime.now(timezone.utc)
            audit_log.append(s, self.tid, actor, "finding.campaign", {"finding": fid, "event_id": item["id"], "detail": campaign})
            return self._finding(r)

    def set_ticket(self, fid, ticket, actor):
        with self._tx() as s:
            r = s.get(Finding, fid)
            if not r:
                return None
            first = not (r.data or {}).get("ticket")
            r.data, r.updated_at = {**r.data, "ticket": ticket}, datetime.now(timezone.utc)
            if first:
                audit_log.append(s, self.tid, actor, "finding.ticket",
                                 {"text": f"{fid} → {ticket.get('system')} {ticket.get('key')}", "finding": fid, "url": ticket.get("url")})
            return self._finding(r)

    def set_status(self, fid, status, actor, reason, expires=None):
        with self._tx() as s:
            r = s.get(Finding, fid)
            if not r:
                return None
            r.status, r.updated_at = status, datetime.now(timezone.utc)
            r.data = {**r.data, **_triage(status, actor, reason, expires)}
            item = {"id": "evt-" + uuid.uuid4().hex[:12], "event": "status_changed", "actor": actor,
                    "detail": {"status": status, "reason": reason, **({"expires": expires} if expires else {})},
                    "created_at": datetime.now(timezone.utc).isoformat()}
            r.data = {**r.data, "events": [*((r.data or {}).get("events") or []), item]}
            audit_log.append(s, self.tid, actor, "finding.status",
                             {"text": f"{fid} → {status} ({reason or 'no reason'})" + (f" until {expires}" if expires else ""),
                              "finding": fid, "event_id": item["id"]})
            return self._finding(r)

    def expire_acceptances(self):
        today = datetime.now(timezone.utc).date().isoformat()
        n = 0
        with self._tx() as s:
            for r in s.scalars(select(Finding).where(Finding.status == "risk_accepted")):
                exp = ((r.data or {}).get("triage") or {}).get("expires")
                if exp and exp < today:
                    r.status, r.updated_at, n = "open", datetime.now(timezone.utc), n + 1
                    r.data = {**r.data, "status": "open", "reopened_reason": f"risk acceptance expired on {exp}"}
            if n:
                audit_log.append(s, self.tid, "system", "finding.acceptance_expired", {"text": f"{n} risk acceptance(s) expired and reopened"})
        return n

    def add_scan(self, repo, branch, commit, findings, sbom, decision, actor, scanned_engines=None, stats=None, refresh=(), reconcile_engines=None):
        """Store a scan. Within this repository and the engines that ran, open findings that are no longer reported
        become `fixed`. A fixed finding that is observed again is reopened even with partial coverage. Suppressed / risk-accepted /
        false-positive decisions stay attached to the fingerprint across scans."""
        sid = "scan-" + uuid.uuid4().hex[:10]
        seen = {f["fingerprint"] for f in findings}
        engines = set(scanned_engines) if scanned_engines is not None else {f["engine"] for f in findings}
        reconcile = engines if reconcile_engines is None else set(reconcile_engines)
        now = datetime.now(timezone.utc)
        with self._tx() as s:
            known = set(s.scalars(select(Finding.fingerprint)))
            new = [f for f in findings if f["fingerprint"] not in known]
            if refresh:
                incoming = {f["fingerprint"]: f for f in findings if f["fingerprint"] in known}
                if incoming:
                    for r in s.scalars(select(Finding).where(Finding.fingerprint.in_(list(incoming)))):
                        f = incoming[r.fingerprint]
                        r.data = {**r.data, **{k: f[k] for k in refresh if k in f}}
                        if "severity" in refresh:
                            r.severity, r.mrs, r.priority = f["severity"], f["mrs"], f["priority"]
                        r.updated_at = now
            for f in new:
                f.setdefault("introduced_in", (commit or "")[:12] or None)
            fixed, reopened = [], []
            observed_engines = {f["engine"] for f in findings}
            if reconcile or observed_engines:
                for r in s.scalars(select(Finding).where(Finding.repo == repo, Finding.engine.in_(reconcile | observed_engines),
                                                         Finding.status.in_(("open", "fixed")))):
                    if r.engine in reconcile and r.fingerprint not in seen and r.status == "open":
                        r.status, r.updated_at = "fixed", now
                        r.data = {**r.data, "status": "fixed", "fixed_at": now.isoformat(), "fixed_in": commit[:12] or None}
                        fixed.append(self._finding(r))
                    elif r.fingerprint in seen and r.status == "fixed":
                        r.status, r.updated_at = "open", now
                        r.data = {**r.data, "status": "open", "reopened_at": now.isoformat()}
                        reopened.append(self._finding(r))
            for f in new:
                s.add(Finding(id=f["id"] + "-" + uuid.uuid4().hex[:4] if s.get(Finding, f["id"]) else f["id"], tenant_id=self.tid,
                              fingerprint=f["fingerprint"], repo=repo, engine=f["engine"], severity=f["severity"], priority=f["priority"],
                              mrs=f["mrs"], status=f.get("status", "open"), data=f))
            if not s.scalars(select(Repo).where(Repo.name == repo)).first():
                s.add(Repo(tenant_id=self.tid, name=repo, data={"sbom": bool(sbom)}))
            s.add(Scan(id=sid, tenant_id=self.tid, repo=repo, decision=decision["decision"], sbom=sbom,
                       data={"ci": "nerve-myelin", "branch": branch, "commit": commit[:7], "author": actor, "duration_s": 0, "stages": [],
                             "gate": {"blocking": decision["blocking"], "warnings": decision["warnings"]},
                             "stats": stats or {"raw": len(findings), "after_dedup": len(findings), "reported": len(findings)},
                             "finding_fingerprints": sorted(seen), "scanned_engines": sorted(engines), "engines": sorted(engines)}))
            audit_log.append(s, self.tid, actor, "scan.uploaded",
                             {"text": f"{repo}@{branch}: {len(findings)} findings, {len(new)} new, {len(fixed)} fixed, "
                                      f"{len(reopened)} reopened, gate={decision['decision']}", "scan": sid})
            self.last_delta = {"new": new, "fixed": fixed, "reopened": reopened, "repo": repo, "commit": commit}
            return sid, len(new)

    def get_repo_project(self, repo):
        with self._tx() as s:
            r = s.scalars(select(Repo).where(Repo.name == repo)).first()
            return (r.data or {}).get("project") if r else None

    def set_repo_project(self, repo, project, actor):
        with self._tx() as s:
            r = s.scalars(select(Repo).where(Repo.name == repo)).first()
            if not r:
                r = Repo(tenant_id=self.tid, name=repo, data={"project": project})
                s.add(r)
            else:
                r.data = {**(r.data or {}), "project": project}
                r.updated_at = datetime.now(timezone.utc)
            audit_log.append(s, self.tid, actor, "policy.repository_project.mapped",
                {"repository": repo, "project": project})
        return {"repo": repo, "project": project}

    def policy_exceptions(self):
        from .db.models import PolicyException
        with self._tx() as s:
            return [{"id": str(x.id), "scope_type": x.scope_type, "scope_key": x.scope_key, "match": x.match,
                "reason": x.reason, "status": x.status, "expires_at": x.expires_at.isoformat(),
                "requested_by": x.requested_by, "reviewed_by": x.reviewed_by, "review_note": x.review_note,
                "created_at": x.created_at.isoformat(), "reviewed_at": x.reviewed_at.isoformat() if x.reviewed_at else None}
                for x in s.scalars(select(PolicyException).order_by(PolicyException.created_at.desc()))]

    def create_policy_exception(self, item):
        from .db.models import PolicyException
        with self._tx() as s:
            row = PolicyException(id=uuid.UUID(item["id"]), tenant_id=self.tid, scope_type=item["scope_type"],
                scope_key=item["scope_key"], match=item["match"], reason=item["reason"], status="pending",
                expires_at=datetime.fromisoformat(item["expires_at"]), requested_by=item["requested_by"])
            s.add(row)
            audit_log.append(s, self.tid, item["requested_by"], "policy.exception.requested",
                {"exception_id": item["id"], "scope": item["scope_key"], "match": item["match"]})
            return item

    def review_policy_exception(self, exception_id, reviewer, decision, note, now):
        from .db.models import PolicyException
        with self._tx() as s:
            row = s.get(PolicyException, uuid.UUID(str(exception_id)))
            if not row or row.status != "pending": return None
            if row.requested_by == reviewer: raise PermissionError("requester cannot approve or reject their own exception")
            if row.expires_at <= datetime.fromisoformat(now) and decision == "approved": raise ValueError("exception expiry must be in the future")
            row.status, row.reviewed_by, row.review_note = decision, reviewer, note
            row.reviewed_at = datetime.fromisoformat(now)
            audit_log.append(s, self.tid, reviewer, "policy.exception." + decision,
                {"exception_id": str(row.id), "requested_by": row.requested_by, "note": note})
            return {"id": str(row.id), "status": row.status, "reviewed_by": row.reviewed_by,
                "review_note": row.review_note, "reviewed_at": row.reviewed_at.isoformat()}
    def policy_versions(self):
        from .db.models import PolicyVersion
        with self._tx() as s:
            return [{"id": str(x.id), "name": x.name, "version": x.version, "content_sha256": x.content_sha256,
                "content": x.content, "status": x.status, "created_by": x.created_by,
                "created_at": x.created_at.isoformat(), "published_by": x.published_by,
                "published_at": x.published_at.isoformat() if x.published_at else None}
                for x in s.scalars(select(PolicyVersion).order_by(PolicyVersion.version.desc()))]

    def get_policy_version(self, version_id):
        from .db.models import PolicyVersion
        with self._tx() as s:
            x = s.get(PolicyVersion, uuid.UUID(str(version_id)))
            return ({"id": str(x.id), "name": x.name, "version": x.version, "content_sha256": x.content_sha256,
                "content": x.content, "status": x.status, "created_by": x.created_by,
                "created_at": x.created_at.isoformat(), "published_by": x.published_by,
                "published_at": x.published_at.isoformat() if x.published_at else None} if x else None)

    def create_policy_version(self, item, event="policy.version.created", detail=None):
        from .db.models import PolicyVersion
        with self._tx() as s:
            x = PolicyVersion(id=uuid.UUID(item["id"]), tenant_id=self.tid, name=item["name"], version=item["version"],
                content_sha256=item["content_sha256"], content=item["content"], status="draft",
                created_by=item["created_by"])
            s.add(x)
            audit_log.append(s, self.tid, item["created_by"], event, detail or {"policy_version_id": item["id"], "version": item["version"], "sha256": item["content_sha256"]})
            return item

    def create_policy_approval(self, item):
        from .db.models import PolicyApprovalRequest, PolicyVersion
        with self._tx() as s:
            v = s.get(PolicyVersion, uuid.UUID(item["policy_version_id"]))
            if not v or v.status != "draft":
                raise ValueError("only a draft policy version can be submitted")
            v.status = "pending"
            s.add(PolicyApprovalRequest(id=uuid.UUID(item["id"]), tenant_id=self.tid,
                policy_version_id=v.id, requested_by=item["requested_by"], status="pending"))
            audit_log.append(s, self.tid, item["requested_by"], "policy.approval.requested", {"request_id": item["id"], "policy_version_id": item["policy_version_id"]})
        return item

    def policy_approval_requests(self):
        from .db.models import PolicyApprovalRequest
        with self._tx() as s:
            return [{"id": str(x.id), "policy_version_id": str(x.policy_version_id), "requested_by": x.requested_by,
                "status": x.status, "reviewed_by": x.reviewed_by, "review_note": x.review_note,
                "created_at": x.created_at.isoformat(), "reviewed_at": x.reviewed_at.isoformat() if x.reviewed_at else None}
                for x in s.scalars(select(PolicyApprovalRequest).order_by(PolicyApprovalRequest.created_at.desc()))]

    def get_policy_approval(self, request_id):
        from .db.models import PolicyApprovalRequest
        with self._tx() as s:
            x = s.get(PolicyApprovalRequest, uuid.UUID(str(request_id)))
            return ({"id": str(x.id), "policy_version_id": str(x.policy_version_id), "requested_by": x.requested_by,
                "status": x.status, "reviewed_by": x.reviewed_by, "review_note": x.review_note,
                "created_at": x.created_at.isoformat(), "reviewed_at": x.reviewed_at.isoformat() if x.reviewed_at else None} if x else None)

    def review_policy_approval(self, request_id, reviewer, decision, note, now):
        from .db.models import PolicyApprovalRequest, PolicyVersion
        with self._tx() as s:
            x = s.get(PolicyApprovalRequest, uuid.UUID(str(request_id)))
            if not x or x.status != "pending":
                return None
            if x.requested_by == reviewer:
                raise PermissionError("requester cannot approve or reject their own policy")
            x.status, x.reviewed_by, x.review_note, x.reviewed_at = decision, reviewer, note, datetime.fromisoformat(now)
            v = s.get(PolicyVersion, x.policy_version_id)
            if decision == "approved":
                v.status, v.published_by, v.published_at = "published", reviewer, datetime.fromisoformat(now)
            else:
                v.status = "rejected"
            audit_log.append(s, self.tid, reviewer, "policy.approval." + decision,
                {"request_id": str(x.id), "policy_version_id": str(v.id), "requested_by": x.requested_by, "note": note})
            return {"id": str(x.id), "policy_version_id": str(x.policy_version_id), "requested_by": x.requested_by,
                "status": x.status, "reviewed_by": x.reviewed_by, "review_note": x.review_note,
                "created_at": x.created_at.isoformat(), "reviewed_at": x.reviewed_at.isoformat()}

    def bind_policy(self, item):
        from .db.models import PolicyBinding, PolicyVersion
        with self._tx() as s:
            v = s.get(PolicyVersion, uuid.UUID(item["policy_version_id"]))
            if not v or v.status != "published":
                raise ValueError("only a published policy version can be bound")
            x = s.scalars(select(PolicyBinding).where(PolicyBinding.scope_type == item["scope_type"],
                PolicyBinding.scope_key == item["scope_key"])).first()
            if x:
                x.policy_version_id, x.updated_by, x.updated_at = v.id, item["updated_by"], datetime.now(timezone.utc)
            else:
                x = PolicyBinding(id=uuid.UUID(item["id"]), tenant_id=self.tid, scope_type=item["scope_type"],
                    scope_key=item["scope_key"], policy_version_id=v.id, updated_by=item["updated_by"])
                s.add(x)
            audit_log.append(s, self.tid, item["updated_by"], "policy.binding.updated",
                {"scope_type": item["scope_type"], "scope_key": item["scope_key"], "policy_version_id": item["policy_version_id"]})
        return item

    def policy_bindings(self):
        from .db.models import PolicyBinding
        with self._tx() as s:
            return [{"id": str(x.id), "scope_type": x.scope_type, "scope_key": x.scope_key,
                "policy_version_id": str(x.policy_version_id), "updated_by": x.updated_by, "updated_at": x.updated_at.isoformat()}
                for x in s.scalars(select(PolicyBinding))]

    def audit_event(self, event, actor, detail):
        with self._tx() as s:
            audit_log.append(s, self.tid, actor, event, {"text": detail} if isinstance(detail, str) else detail)


def counter_dict(c: Counter) -> dict:
    return dict(c)
