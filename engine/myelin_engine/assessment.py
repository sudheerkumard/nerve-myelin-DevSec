# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""One live-application assessment run, shared by the offline CLI and the online platform so both behave identically.

    result = run(target, spec=..., headers=..., identities=cfg, zap=False, active=False)
    result["findings"] are scored (MRS, priority) and de-duplicated; result["decision"] is the policy gate.
"""
import time
import urllib.parse
from datetime import datetime, timezone

from . import __version__, dast, dast_authz, policy
from .scoring import enrich

CRIT = {"low": 0.6, "medium": 1.0, "high": 1.2, "critical": 1.4}


def run(target, spec=None, headers=None, identities=None, name=None, criticality="medium", max_requests=600,
        delay=0.2, verify_tls=True, zap=False, active=False, policy_doc=None, progress=None, guard=None, crawl=False, probe=False):
    started = datetime.now(timezone.utc)
    t0 = time.time()
    say = progress or (lambda m: None)
    say("baseline checks")
    t = dast.safe_scan(target, spec, headers, max_requests, delay, verify_tls, guard)
    findings, tools, stats = list(t["findings"]), ["myelin-dast"], {"baseline_auth_checks": t["auth_checks"]}
    if identities:
        say("multi-user authorisation tests")
        u = urllib.parse.urlsplit(target)
        af, astats = dast_authz.authz_scan(t["client"], f"{u.scheme}://{u.netloc}", t["spec"], identities)
        findings += af
        stats.update(astats)
        tools.append("myelin-authz")
    if crawl or probe:
        from . import dast_active
        u = urllib.parse.urlsplit(target)
        say("crawling")
        eps = dast_active.crawl(t["client"], f"{u.scheme}://{u.netloc}", target, t["spec"])
        stats["crawled_endpoints"] = len(eps)
        tools.append("myelin-crawler")
        if probe:
            say("active checks")
            af, astats = dast_active.active_checks(t["client"], eps)
            findings += af
            stats.update(astats)
            tools.append("myelin-active")
    if zap:
        from . import zap_api
        say("OWASP ZAP " + ("active scan" if active else "spider + passive scan"))
        if zap_api.configured():                      # platform: ZAP daemon service
            hdrs = dict(headers or {})
            if identities and not hdrs:
                first = (identities.get("identities") or [{}])[0]
                hdrs = dict(first.get("headers") or {})
            z = zap_api.Zap().scan(target, active=active, headers=hdrs,
                                   spec_url=spec if isinstance(spec, str) and spec.startswith(("http://", "https://")) else None, say=say)
            findings += zap_api.normalize(z["alerts"], dast._f)
            stats["zap"] = {"urls": z["urls"], "mode": z["mode"], "complete": z["complete"], "version": z["version"]}
        else:                                         # CLI: ZAP in Docker
            findings += dast.zap_scan(target, spec, headers, active=active)
        tools.append("zap")
    name = name or urllib.parse.urlsplit(target).hostname
    seen, uniq = set(), []
    for f in findings:
        f["repo"] = name
        enrich(f, CRIT.get(criticality, 1.0))
        if f["fingerprint"] not in seen:
            seen.add(f["fingerprint"])
            uniq.append(f)
    uniq.sort(key=lambda f: -f["mrs"])
    decision = policy.evaluate(uniq, policy_doc or policy.load(None))
    mode = "zap-active" if (zap and active) else "active checks (authorised)" if probe else \
        "safe (read-only) with OWASP ZAP passive scan" if zap else "safe (read-only) with crawling" if crawl else "safe (read-only)"
    return {"repo": name, "target": target, "spec": spec if isinstance(spec, str) else None, "mode": mode,
            "identities": [i["name"] + f" ({i['role']})" for i in (identities or {}).get("identities", [])],
            "started_at": started.isoformat(timespec="seconds"), "duration_s": round(time.time() - t0, 2),
            "requests": t["client"].count, "spec_operations": len(dast_authz._operations(t["spec"])) if t["spec"] else 0,
            "stats": stats, "tools": tools, "components": 0, "scanner_version": __version__,
            "request_log": t["client"].log, "findings": uniq, "decision": decision}
