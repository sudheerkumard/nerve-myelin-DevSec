# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Platform operator CLI. Runs with the migrations (owner) connection and acts through the myelin_admin role.

  python -m app.admin_cli tenant-create --slug acme --name "Acme Bank" --plan enterprise --devs 400 --region in-south \
         --bind https://auth.example.com/realms/myelin=acme
  python -m app.admin_cli bind --tenant acme --issuer https://login.microsoftonline.com/<tid>/v2.0 --value <entra tid>
  python -m app.admin_cli tenants
  python -m app.admin_cli purge-evidence [--dry-run]
  python -m app.admin_cli verify-audit --tenant acme

Connection: MYELIN_MIGRATIONS_DATABASE_URL (a secret reference such as env://, file:// or vault:// is also accepted).
"""
import argparse
import json
import os
import sys

from sqlalchemy import select

from . import secrets as sm
from .db import admin
from .db.models import Evidence, Tenant


def _owner_url() -> str:
    ref = os.environ.get("MYELIN_MIGRATIONS_DATABASE_URL")
    if not ref:
        sys.exit("MYELIN_MIGRATIONS_DATABASE_URL is not set")
    return sm.resolve(ref, allow_plain=True)


def _license():
    from .config import settings
    from .licensing import LicenseManager
    return LicenseManager(settings.license_ref, settings.deployment_id).status()


def _tenant_id(url: str, slug: str):
    with admin.admin_tx(url) as s:
        t = s.scalars(select(Tenant).where(Tenant.slug == slug)).first()
        if not t:
            sys.exit(f"unknown tenant: {slug}")
        return t.id


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="myelin-admin", description="RAT Flea DevSec platform administration")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("tenant-create")
    c.add_argument("--slug", required=True)
    c.add_argument("--name", required=True)
    c.add_argument("--plan", default="business", choices=["community", "team", "business", "enterprise", "sovereign"])
    c.add_argument("--devs", type=int, default=0)
    c.add_argument("--region", default="")
    c.add_argument("--bind", action="append", default=[], metavar="ISSUER=CLAIM_VALUE")
    b = sub.add_parser("bind")
    b.add_argument("--tenant", required=True)
    b.add_argument("--issuer", required=True)
    b.add_argument("--value", required=True)
    sub.add_parser("tenants")
    sub.add_parser("license-status", help="licence state and deployment-wide usage")
    p = sub.add_parser("purge-evidence")
    p.add_argument("--dry-run", action="store_true")
    g = sub.add_parser("grant-app-login", help="attach an API login role to myelin_app (NOBYPASSRLS)")
    g.add_argument("--login", required=True)
    v = sub.add_parser("verify-audit")
    v.add_argument("--tenant", required=True)
    a = ap.parse_args(argv)
    url = _owner_url()

    if a.cmd == "tenant-create":
        lic = _license()
        if not lic.usable:
            sys.exit(f"cannot create tenants: licence {lic.state} ({lic.reason})")
        max_t = lic.payload.get("max_tenants")
        if max_t and len(admin.list_tenants(url)) >= int(max_t):
            sys.exit(f"licence allows {max_t} tenant(s); contact the RAT Flea DevSec product owner to extend it")
        binds = []
        for item in a.bind:
            issuer, sep, value = item.rpartition("=")
            if not sep or not issuer.startswith("https://"):
                sys.exit(f"--bind must be ISSUER=VALUE with an https issuer: {item}")
            binds.append((issuer, value))
        tid = admin.create_tenant(url, a.slug, a.name, plan=a.plan, devs=a.devs, region=a.region, bindings=binds)
        print(json.dumps({"tenant_id": str(tid), "slug": a.slug, "bindings": len(binds)}))
    elif a.cmd == "bind":
        admin.bind_identity(url, _tenant_id(url, a.tenant), a.issuer, a.value)
        print(json.dumps({"bound": a.tenant, "issuer": a.issuer}))
    elif a.cmd == "license-status":
        from datetime import datetime, timedelta, timezone
        from sqlalchemy import func
        from .db.models import User
        lic = _license()
        with admin.admin_tx(url) as s:
            devs = s.scalar(select(func.count()).select_from(User).where(
                User.last_login_at > datetime.now(timezone.utc) - timedelta(days=90))) or 0
            tenants = s.scalar(select(func.count()).select_from(Tenant)) or 0
        print(json.dumps(lic.public({"developers": devs, "tenants": tenants, "scope": "deployment, active in last 90 days"}), indent=2))
        return 0 if lic.usable else 3
    elif a.cmd == "tenants":
        print(json.dumps(admin.list_tenants(url), indent=2))
    elif a.cmd == "purge-evidence":
        from datetime import datetime, timezone
        from .config import settings
        try:
            from .evidence.storage import open_store
        except ImportError:
            sys.exit("purge-evidence is not available in this edition (no evidence store)")
        if a.dry_run:
            with admin.admin_tx(url) as s:
                rows = s.scalars(select(Evidence).where(Evidence.retention_until < datetime.now(timezone.utc),
                                                        Evidence.legal_hold.is_(False))).all()
                print(json.dumps({"would_purge": [str(e.id) for e in rows]}))
        else:
            store = open_store(settings.evidence_store)
            print(json.dumps({"purged": admin.purge_expired_evidence(url, store.delete)}))
    elif a.cmd == "grant-app-login":
        import re
        from sqlalchemy import create_engine, text
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", a.login):
            sys.exit("invalid role name")
        with create_engine(url).begin() as c:
            r = c.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = :n"), {"n": a.login}).first()
            if not r:
                sys.exit(f"login role {a.login} does not exist")
            if r.rolsuper or r.rolbypassrls:
                sys.exit(f"refusing: {a.login} is SUPERUSER or BYPASSRLS, which would defeat tenant isolation")
            c.execute(text(f'GRANT myelin_app TO "{a.login}"'))
        print(json.dumps({"granted": "myelin_app", "to": a.login}))
    elif a.cmd == "verify-audit":
        from .evidence import audit
        tid = _tenant_id(url, a.tenant)
        with admin.admin_tx(url) as s:
            res = audit.verify_chain(s, tid)
        print(json.dumps(res))
        return 0 if res["valid"] else 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
