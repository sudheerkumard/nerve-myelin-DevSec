# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""myelin — the NERvvE DevSecOps pipeline CLI.

  myelin scan   [PATH] [--repo NAME] [--engines sca,sast,...] [--policy FILE] [--server URL]
               [--sarif out.sarif] [--sbom out.cdx.json] [--json out.json] [--fail-on block|warn|never]
  myelin dast   --target https://api.example.com [--openapi spec.json|URL] [--identities users.yaml] [--report r.html]
               [--zap [--active --authorized]] [--sarif ..] [--json ..] [--server URL]   test a running web API
  myelin gate   --results out.json [--policy FILE]              re-evaluate saved results
  myelin attest --image REF [--provenance slsa.json] [--sbom sbom.cdx.json]   cosign sign + SLSA / SBOM attestations
  myelin precommit [--policy FILE]                     scan staged files (secrets, code, config, agent files) before a commit
  myelin mcp                                           MCP server for AI coding assistants (stdio)
  myelin advisories download DIR [--ecosystems PyPI,npm]   OSV exports for air-gapped scans (MYELIN_OSV_EXPORT_DIR=DIR)

Exit codes: 0 pass, 1 policy block (or warn with --fail-on warn), 2 usage/error.
Env: MYELIN_SERVER, MYELIN_API_KEY, MYELIN_CA_FILE (extra CA for a self-hosted console), MYELIN_PROJECT, MYELIN_DAST_AUTH (Authorization header value for dast).
"""
import argparse
import json
import os
import shutil
import subprocess
import urllib.parse
import sys
import urllib.request

from . import __version__, orchestrator, policy

try:   # optional extension; not part of every edition
    from . import attest_cli as _ext
except ImportError:
    _ext = None

C = {"critical": "\033[91m", "high": "\033[33m", "medium": "\033[93m", "low": "\033[36m", "info": "\033[37m", "end": "\033[0m", "b": "\033[1m"}
if not sys.stdout.isatty() and not os.getenv("FORCE_COLOR"):
    C = {k: "" for k in C}


def to_sarif(findings):
    rules, results = {}, []
    lvl = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    for f in findings:
        rid = f.get("rule_id") or f["engine"]
        rules.setdefault(rid, {"id": rid, "name": rid, "shortDescription": {"text": f.get("title", rid)[:120]},
                               "properties": {"security-severity": str(f.get("cvss") or {"critical": 9.5, "high": 7.5, "medium": 5, "low": 2.5}.get(f["severity"], 1)),
                                              "tags": ["security", f["engine"]]}})
        res = {"ruleId": rid, "level": lvl.get(f["severity"], "note"),
               "message": {"text": f"[{f['priority']} | MRS {f['mrs']}] {f.get('title')}. {f.get('remediation', '')}"},
               "partialFingerprints": {"myelin/v1": f["fingerprint"]}}
        if f.get("file"):
            res["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                                      "region": {"startLine": int(f.get("line") or 1)}}}]
        if f.get("status") == "suppressed":
            suppression = f.get("suppression") or {}
            res["suppressions"] = [{
                "kind": "inSource",
                "status": "accepted",
                "justification": suppression.get("reason") or "Suppressed by NERVVE DEVSECOPS governance",
            }]
        results.append(res)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "NERvvE DevSecOps", "version": __version__, "informationUri": "https://github.com/sudheerkumard/nervve-devsecops", "rules": list(rules.values())}},
                      "results": results}]}


def upload(server, key, payload, path="/api/scans"):
    req = urllib.request.Request(server.rstrip("/") + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "X-API-Key": key or ""}, method="POST")
    import ssl
    ctx = ssl.create_default_context()
    if os.getenv("MYELIN_CA_FILE"):              # extra CA for a private/self-hosted console (system CAs stay trusted)
        ctx.load_verify_locations(os.environ["MYELIN_CA_FILE"])
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:  # myelin:ignore[NM-SAST-010] -- URL is the operator-configured MYELIN_SERVER (https), not user input
        return json.loads(r.read())


def print_report(res, decision):
    fs = [f for f in res["findings"] if f["engine"] != "meta" and f.get("status") != "suppressed"]
    by = {}
    for f in fs:
        by.setdefault(f["engine"], {}).setdefault(f["severity"], 0)
        by[f["engine"]][f["severity"]] += 1
    print(f"\n{C['b']}NERvvE DevSecOps scan · {res['repo']}{C['end']}  ({res['duration_s']}s, {res['components']} components, tools: {', '.join(res['tools'])})")
    cov = res.get("coverage") or {}
    if cov:
        done = [k for k, c in cov.items() if c.get("assessed")]
        print("  Assessed: " + ", ".join(done) if done else "  Assessed: nothing applicable was found")
        for k in done:
            c = cov[k]
            tools = ", ".join(t["name"] + (f" {t['version']}" if t.get("version") else "") + (" (FAILED)" if t.get("error") else "")
                              for t in c.get("tools") or [])
            state = " (partial)" if c.get("status") == "partial" else ""
            print(f"    {k:<8} {c.get('examined', '')[:52]:<52} {tools}{state}")
            if state:
                for note in [*c.get("limitations", []), *c.get("errors", [])]:
                    print(f"             {note}")
        skipped = [f"{k} ({c.get('reason')})" for k, c in cov.items() if not c.get("assessed")]
        if skipped:
            print("  Not assessed: " + "; ".join(skipped))
    print("─" * 78)
    for eng, sev in sorted(by.items()):
        parts = "  ".join(f"{C[s]}{s[:4]}:{n}{C['end']}" for s, n in sorted(sev.items(), key=lambda x: -"info low medium high critical".split().index(x[0])))
        print(f"  {eng:<10} {parts}")
    print("─" * 78)
    for f in fs[:12]:
        loc = f"{f.get('file', '')}:{f.get('line') or ''}".rstrip(":")
        print(f"  {f['priority']} {C[f['severity']]}{f['severity']:<8}{C['end']} MRS {f['mrs']:>5}  {f['title'][:52]:<52} {loc}")
    if len(fs) > 12:
        print(f"  … {len(fs) - 12} more (see JSON/SARIF output)")
    col = {"pass": "\033[92m", "warn": "\033[93m", "block": "\033[91m"}.get(decision["decision"], "") if C["end"] else ""
    print(f"\n  Policy '{decision['policy']}': {col}{C['b']}{decision['decision'].upper()}{C['end']}  "
          f"(blocking {decision['blocking']}, warnings {decision['warnings']}, excepted {decision['excepted']})")
    suppressed = [f for f in res["findings"] if f.get("status") == "suppressed"]
    if suppressed:
        print(f"  Suppressed with inline/path evidence: {len(suppressed)}")
    for violation in [v for v in decision.get("violations", []) if v.get("action") == "block"][:20]:
        print(f"  BLOCK {violation['gate']} · {violation.get('finding') or 'finding'} · {violation.get('title') or ''}")
    print()


def cmd_scan(a):
    from . import coverage
    engines = a.engines.split(",") if a.engines else None
    if a.image:
        if a.report:
            print("--report is available for repository scans.", file=sys.stderr)
            return 2
        res = orchestrator.scan_image(a.image)
        decision = policy.evaluate(res["findings"], policy.load(a.policy))
        print_report(res, decision)
        if a.json:
            json.dump({**res, "decision": decision}, open(a.json, "w"), indent=2)
        return 1 if decision["decision"] == "block" and a.fail_on != "never" else 0
    if not os.path.isdir(a.path):
        print(f"Repository folder does not exist: {a.path}", file=sys.stderr)
        return 2
    res = orchestrator.scan(a.path, repo=a.repo or os.path.basename(os.path.abspath(a.path)), engines=engines,
                            use_external=not a.builtin_only)
    pol = policy.load(a.policy)
    decision = policy.evaluate(res["findings"], pol)
    print_report(res, decision)
    if a.report:
        from . import report_enterprise
        with open(a.report, "w", encoding="utf-8") as report_file:
            report_file.write(report_enterprise.render({**res, "decision": decision}))
        print(f"  Report written to {a.report}")
    if a.json:
        json.dump({**res, "decision": decision}, open(a.json, "w"), indent=2)
    if a.sarif:
        json.dump(to_sarif(res["findings"]), open(a.sarif, "w"), indent=2)
    if a.sbom:
        json.dump(res["sbom"], open(a.sbom, "w"), indent=2)
    server = a.server or os.getenv("MYELIN_SERVER")
    if server:
        try:
            r = upload(server, os.getenv("MYELIN_API_KEY"), {"repo": res["repo"], "branch": os.getenv("GITHUB_REF_NAME") or os.getenv("CI_COMMIT_REF_NAME") or os.getenv("BUILD_SOURCEBRANCHNAME") or "local",
                                                             "commit": os.getenv("GITHUB_SHA") or os.getenv("CI_COMMIT_SHA") or "", "findings": res["findings"], "sbom": res["sbom"],
                                                             "engines": coverage.completed(res["coverage"]),
                                                             "reconcile_engines": coverage.reconciled(res["coverage"], engines or orchestrator.DEFAULT_ENGINES),
                                                             "stats": res.get("stats")})
            print(f"  Uploaded → {server}  scan_id={r.get('scan_id')}  server decision={r.get('decision', {}).get('decision')}")
        except Exception as e:
            print(f"  ! upload failed: {e}", file=sys.stderr)
    fail = {"block": decision["decision"] == "block", "warn": decision["decision"] in ("block", "warn"), "never": False}[a.fail_on]
    return 1 if fail else 0


def _outputs_and_upload(a, res, decision):
    if a.json:
        json.dump({**res, "decision": decision}, open(a.json, "w"), indent=2)
    if a.sarif:
        json.dump(to_sarif(res["findings"]), open(a.sarif, "w"), indent=2)
    server = a.server or os.getenv("MYELIN_SERVER")
    if server:
        try:
            r = upload(server, os.getenv("MYELIN_API_KEY"), {"repo": res["repo"], "branch": "runtime", "commit": "",
                                                             "findings": res["findings"], "sbom": res.get("sbom"), "engines": ["dast"]})
            print(f"  Uploaded → {server}  scan_id={r.get('scan_id')}  server decision={r.get('decision', {}).get('decision')}")
        except Exception as e:
            print(f"  ! upload failed: {e}", file=sys.stderr)


def cmd_dast(a):
    from . import assessment, dast_authz, report
    headers = {}
    for hv in a.header or []:
        k, sep, v = hv.partition(":")
        if not sep:
            print(f"--header must look like 'Name: value' (got {hv!r})", file=sys.stderr)
            return 2
        headers[k.strip()] = v.strip()
    if os.getenv("MYELIN_DAST_AUTH") and "Authorization" not in headers:
        headers["Authorization"] = os.environ["MYELIN_DAST_AUTH"]
    if a.active and not a.authorized:
        print("--active sends attack payloads. Re-run with --authorized to confirm you have written permission to test "
              "this target, preferably a non-production environment.", file=sys.stderr)
        return 2
    ids = None
    if a.identities:
        try:
            ids = dast_authz.load_identities(a.identities)
        except (dast_authz.IdentityError, OSError) as e:
            print(f"identities: {e}", file=sys.stderr)
            return 2
        if not a.openapi:
            print("--identities needs --openapi so NERvvE knows which operations to test", file=sys.stderr)
            return 2
    mode = "zap-active + active checks" if (a.active and a.zap) else "active checks" if a.active else "zap-baseline" if a.zap else \
        "safe, read-only, crawling" if a.crawl else "safe, read-only"
    print(f"{C['b']}NERvvE DevSecOps live application assessment{C['end']} · {a.target}  (mode: {mode}"
          f"{', authorisation tests with ' + str(len(ids['identities'])) + ' identities' if ids else ''})")
    print("  Only scan systems you own or are authorised in writing to test.")
    res = assessment.run(a.target, a.openapi, headers, ids, a.name, a.criticality, a.max_requests, a.delay, not a.insecure,
                         a.zap, a.active, policy.load(a.policy), progress=lambda m: print(f"  … {m}"), crawl=a.crawl or a.active, probe=a.active)
    decision = res["decision"]
    print_report(res, decision)
    st = res["stats"]
    print(f"  {res['requests']} requests · {res['spec_operations']} GET operations in spec"
          + (f" · {st.get('object_checks', 0)} cross-user object checks · {st.get('function_checks', 0)} privileged-function checks" if ids else "") + "\n")
    if a.report:
        open(a.report, "w", encoding="utf-8").write(report.render(res, a.customer or "", a.assessor or ""))
        print(f"  Report written to {a.report}")
    _outputs_and_upload(a, res, decision)
    fail = {"block": decision["decision"] == "block", "warn": decision["decision"] in ("block", "warn"), "never": False}[a.fail_on]
    return 1 if fail else 0


def cmd_vex(a):
    """Apply supplier VEX/CSAF evidence to a saved scan without silently clearing policy gates."""
    from . import vex
    with open(a.results, encoding="utf-8") as fh:
        result = json.load(fh)
    documents = []
    for path in a.document:
        with open(path, encoding="utf-8") as fh:
            documents.append(json.load(fh))
    summary = vex.apply(result.get("findings") or [], documents)
    result["vex"] = summary
    result["decision"] = policy.evaluate(result["findings"], policy.load(a.policy))
    output = a.output or a.results
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(json.dumps({"vex": summary, "decision": result["decision"]["decision"],
                      "blocking": result["decision"]["blocking"], "warnings": result["decision"]["warnings"]}))
    return 1 if result["decision"]["decision"] == "block" else 0


def cmd_gate(a):
    """Gate a deployment. Local mode: evaluate a results file. Platform mode (--repo): ask NERvvE DevSecOps for the
    decision on the commit being deployed — fails closed when the commit was never scanned (unless --allow-unscanned)."""
    if a.results:
        res = json.load(open(a.results))
        d = policy.evaluate(res["findings"], policy.load(a.policy))
        print(json.dumps({k: d[k] for k in ("policy", "decision", "blocking", "warnings", "excepted")}))
        return 1 if d["decision"] == "block" else 0
    server = a.server or os.getenv("MYELIN_SERVER")
    if not (a.repo and server):
        print("myelin gate: give --results FILE, or --repo NAME with --server URL / MYELIN_SERVER", file=sys.stderr)
        return 2
    import ssl
    import urllib.error
    q = urllib.parse.urlencode({k: v for k, v in (("repo", a.repo), ("commit", a.commit or os.getenv("GITHUB_SHA") or
                                                                       os.getenv("CI_COMMIT_SHA") or os.getenv("BUILD_SOURCEVERSION") or ""),
                                                   ("environment", a.environment or ""), ("scope", a.scope if a.scope != "all" else ""),
                                                   ("require", a.require or "")) if v})
    req = urllib.request.Request(f"{server.rstrip('/')}/api/v1/gate?{q}", headers={"X-API-Key": os.getenv("MYELIN_API_KEY") or ""})
    ctx = ssl.create_default_context()
    if os.getenv("MYELIN_CA_FILE"):
        ctx.load_verify_locations(os.environ["MYELIN_CA_FILE"])
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:  # myelin:ignore[NM-SAST-010] -- operator-configured MYELIN_SERVER
            d = json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404 and a.allow_unscanned:
            print(f"myelin gate: {a.repo} has no scan for this commit; allowed by --allow-unscanned")
            return 0
        print(f"myelin gate: BLOCK — {json.loads(e.read() or b'{}').get('detail', e.reason)}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError) as e:
        print(f"myelin gate: cannot reach {server}: {getattr(e, 'reason', e)} (failing closed)", file=sys.stderr)
        return 1
    blocked = d["decision"] == "block" or (a.fail_on == "warn" and d["decision"] == "warn")
    print(f"myelin gate: {d['decision'].upper()} — {a.repo}@{d.get('commit') or '?'} scanned {d.get('scanned_at', '?')}: "
          f"{d.get('blocking', 0)} blocking, {d.get('warnings', 0)} warnings, {d.get('open_p0', 0)} open P0"
          + (f", {d['new_findings']} introduced by this commit" if d.get("new_findings") is not None else "")
          + (f"; missing checks: {', '.join(d['missing_engines'])}" if d.get("missing_engines") else ""))
    return 1 if blocked else 0


def cmd_import(a):
    """Import another scanner's results (SARIF, CycloneDX, Trivy, Grype, Semgrep, Gitleaks, Checkov, Bandit, ZAP)."""
    from . import importers
    raw = open(a.file, "rb").read()
    try:
        fmt, found = importers.parse(raw, a.repo, os.path.basename(a.file), a.format)
    except importers.ImportError_ as e:
        print(f"myelin import: {e}", file=sys.stderr)
        return 2
    server = a.server or os.getenv("MYELIN_SERVER")
    print(f"myelin import: {len(found)} results read from {a.file} ({fmt})")
    if not server:
        from .scoring import enrich
        for f in found:
            enrich(f)
        d = policy.evaluate(found, policy.load(a.policy))
        print(f"  local gate: {d['decision'].upper()} — {d['blocking']} blocking, {d['warnings']} warnings (use --server to upload)")
        return 1 if d["decision"] == "block" and a.fail_on == "block" else 0
    import base64
    body = {"repo": a.repo, "branch": a.branch or os.getenv("GITHUB_REF_NAME") or "main", "commit": a.commit or os.getenv("GITHUB_SHA") or "",
            "filename": os.path.basename(a.file), "format": a.format, "content_base64": base64.b64encode(raw).decode()}
    r = upload(server, os.getenv("MYELIN_API_KEY"), body, path="/api/v1/scans/import")
    print(f"  Uploaded → {server}  scan_id={r.get('scan_id')}  new={r.get('new')}  server decision={r.get('decision', {}).get('decision')}")
    return 1 if r.get("decision", {}).get("decision") == "block" and a.fail_on == "block" else 0


def cmd_precommit(a):
    """Copy the staged version of each file into a temporary tree and scan it: what is about to be committed."""
    import tempfile
    files = a.files
    if not files:
        try:
            out = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"], capture_output=True, check=True)
        except (OSError, subprocess.CalledProcessError):
            print("myelin precommit: not a git repository (or git missing)", file=sys.stderr)
            return 2
        files = [f for f in out.stdout.decode().split("\0") if f]
    if not files:
        return 0
    with tempfile.TemporaryDirectory(prefix="myelin-precommit-") as tmp:
        for f in files:
            rel = os.path.normpath(f)
            if rel.startswith(".."):
                continue
            dest = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(dest) or tmp, exist_ok=True)
            blob = subprocess.run(["git", "show", f":{f}"], capture_output=True) if not a.files else None
            data = blob.stdout if blob is not None and blob.returncode == 0 else open(f, "rb").read()
            with open(dest, "wb") as fh:
                fh.write(data)
        os.environ.setdefault("MYELIN_OFFLINE", "1")
        res = orchestrator.scan(tmp, repo="pre-commit", engines=["sast", "secrets", "iac", "cicd", "aibom", "supply"], use_external=False)
    fs = [f for f in res["findings"] if f.get("engine") != "meta"]
    d = policy.evaluate(fs, policy.load(a.policy) if a.policy else policy.DEFAULT_POLICY)
    for f in fs[:30]:
        print(f"{C.get(f['severity'], '')}{f['severity']:<8}{C['end']} {f['rule_id']:<12} {f.get('file')}:{f.get('line') or ''}  {f['title']}")
    print(f"NERvvE DevSecOps pre-commit: {d['decision'].upper()} ({len(fs)} finding(s) in {len(files)} staged file(s))")
    return 1 if d["decision"] == "block" or (a.fail_on == "warn" and d["decision"] == "warn") else 0


def cmd_attest(a):
    gate_file = None
    if getattr(a, "gate", None):
        gate_file = _ext.gate_predicate(a, policy)
    if getattr(a, "dry_run", False):
        return 0
    if not shutil.which("cosign"):
        print("cosign not found — install sigstore/cosign or use the myelin-cli image", file=sys.stderr)
        return 2
    subprocess.check_call(["cosign", "sign", "--yes", a.image])
    if a.provenance:
        subprocess.check_call(["cosign", "attest", "--yes", "--type", "slsaprovenance", "--predicate", a.provenance, a.image])
    if a.sbom:
        subprocess.check_call(["cosign", "attest", "--yes", "--type", "cyclonedx", "--predicate", a.sbom, a.image])
    if gate_file:
        _ext.attach(gate_file, a.image)
    print(f"signed + attested {a.image}")
    return 0


def _safe_console():
    """Windows consoles and pipes often use cp1252, which cannot print '→', '─' or '—'. Never crash on output:
    unsupported characters are replaced instead."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def _load_cred(path):
    """Credential JSON from a file or MYELIN_CLOUD_CREDENTIAL (never from the command line, where it would be logged)."""
    raw = open(path).read() if path else os.getenv("MYELIN_CLOUD_CREDENTIAL", "")
    return json.loads(raw) if raw.strip() else None


def cmd_cloud(a):
    """Collect (read-only) or load an inventory, evaluate posture and identity rules, print and optionally upload."""
    from .cloud import collect_aws, collect_azure, collect_gcp, collect_k8s, evaluate, http, inventory, summary
    try:
        if a.inventory:
            with open(a.inventory, "rb") as fh:
                inv = inventory.load(fh.read(), a.provider or "", a.account or "")
        else:
            if not a.provider:
                print("--provider is required for live collection (or give --inventory)", file=sys.stderr)
                return 2
            cred = _load_cred(a.credential_file)
            if a.provider == "azure":
                inv = collect_azure.collect(cred or {}, [x.strip() for x in (a.subscriptions or "").split(",") if x.strip()], a.account or "")
            elif a.provider == "aws":
                inv = collect_aws.collect([x.strip() for x in (a.regions or "us-east-1").split(",") if x.strip()], cred, account=a.account or "")
            elif a.provider == "gcp":
                inv = collect_gcp.collect(cred or {}, a.parent or "", a.account or "")
            else:
                inv = collect_k8s.collect({**(cred or {}), "server": a.server_url or (cred or {}).get("server", "")}, a.account or "")
    except (http.CollectorError, ValueError, OSError, KeyError) as e:
        print(f"[NERvvE DevSecOps] cloud: {e}", file=sys.stderr)
        return 2
    except ImportError as e:
        print(f"[NERvvE DevSecOps] cloud: {e.name} is required for this collector (pip install boto3 / cryptography)", file=sys.stderr)
        return 2
    if a.out:
        with open(a.out, "w") as fh:
            json.dump(inv, fh, indent=1, default=str)
        print(f"inventory written to {a.out} (carry it to an offline platform and upload it there)")
    found = evaluate(inv)
    s = summary(inv)
    print(f"\n  NERvvE DevSecOps cloud posture · {inv['provider']} {inv['account']} · {s['resources']} resources, {s['identities']} identities")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(found, key=lambda x: order.get(x["severity"], 9))[:200]:
        print(f"  {f['severity'].upper():8} {f['rule_id']:11} {f['title'][:100]}")
    counts = {k: sum(1 for f in found if f["severity"] == k) for k in order}
    print("  " + "  ".join(f"{k}: {v}" for k, v in counts.items() if v) + f"  (total {len(found)})\n")
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"inventory": s, "findings": found}, fh, indent=1, default=str)
    server = a.server or os.getenv("MYELIN_SERVER")
    if server and a.upload:
        import base64
        res = upload(server, os.getenv("MYELIN_API_KEY"), {"content_base64": base64.b64encode(json.dumps(inv, default=str).encode()).decode(),
                                                         "provider": inv["provider"], "account": inv["account"]}, "/api/v1/cloud/inventory")
        print(f"uploaded to {server}: {res.get('received')} findings, {res.get('new')} new, {res.get('attack_paths')} attack paths ({res.get('key')})")
    if a.fail_on != "never" and any(order.get(f["severity"], 9) <= order[a.fail_on] for f in found):
        return 1
    return 0


def cmd_runtime(a):
    """Forward runtime detections (Falco JSON, Tetragon JSON lines) from a file or stdin to the platform."""
    from .cloud import runtime
    raw = open(a.file).read() if a.file != "-" else sys.stdin.read()
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = [json.loads(x) for x in raw.splitlines() if x.strip()]
    events = runtime.normalise(payload, a.cluster)
    print(f"{len(events)} runtime detections in {a.file}")
    for e in events[:50]:
        print(f"  {e['severity'].upper():8} {e['namespace']}/{e['workload'] or e['pod']}: {e['rule']}")
    server = a.server or os.getenv("MYELIN_SERVER")
    if server:
        res = upload(server, os.getenv("MYELIN_API_KEY"), {"cluster": a.cluster, "events": payload if isinstance(payload, list) else [payload]},
                     "/api/v1/runtime/events?cluster=" + urllib.parse.quote(a.cluster))
        print(f"sent to {server}: {res.get('received')} events, {res.get('findings')} findings ({res.get('new')} new)")
    return 0


def main():
    _safe_console()
    p = argparse.ArgumentParser(prog="myelin", description="NERvvE DevSecOps CLI")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--image", help="scan a container image (requires trivy or grype on PATH)")
    s.add_argument("--repo"); s.add_argument("--engines"); s.add_argument("--policy"); s.add_argument("--server")
    s.add_argument("--sarif"); s.add_argument("--sbom"); s.add_argument("--json")
    s.add_argument("--report", help="write a self-contained HTML assessment report for a repository")
    s.add_argument("--fail-on", choices=["block", "warn", "never"], default="block")
    s.add_argument("--builtin-only", action="store_true", help="skip third-party scanners even if installed")
    d = sub.add_parser("dast", help="test a running web API (read-only by default)")
    d.add_argument("--target", required=True, help="base URL of the API, e.g. https://api.example.com")
    d.add_argument("--openapi", help="OpenAPI/Swagger spec (file or URL) — enables per-operation authentication checks")
    d.add_argument("--header", action="append", help="extra request header 'Name: value' (repeatable); prefer MYELIN_DAST_AUTH for tokens")
    d.add_argument("--name", help="asset name shown in the console (default: host name)")
    d.add_argument("--criticality", choices=["low", "medium", "high", "critical"], default="medium")
    d.add_argument("--max-requests", type=int, default=300); d.add_argument("--delay", type=float, default=0.2)
    d.add_argument("--insecure", action="store_true", help="continue when the TLS certificate is untrusted (still reported)")
    d.add_argument("--zap", action="store_true", help="also run OWASP ZAP baseline (passive) in Docker")
    d.add_argument("--crawl", action="store_true", help="discover pages, forms, scripts and query parameters (read-only GET requests)")
    d.add_argument("--active", action="store_true", help="active checks (XSS, SQL injection, open redirect, path traversal, template injection); "
                                                          "with --zap also ZAP's active scan. Sends attack payloads: needs --authorized")
    d.add_argument("--authorized", action="store_true", help="confirm written authorisation for --active")
    d.add_argument("--identities", help="YAML/JSON with 2+ test users → cross-user (BOLA), role (BFLA) and data-exposure tests")
    d.add_argument("--report", help="write a self-contained HTML assessment report")
    d.add_argument("--customer", help="name printed on the report"); d.add_argument("--assessor")
    d.add_argument("--policy"); d.add_argument("--server"); d.add_argument("--sarif"); d.add_argument("--json")
    d.add_argument("--fail-on", choices=["block", "warn", "never"], default="block")
    v = sub.add_parser("vex", help="apply CycloneDX VEX or CSAF 2.0 evidence to saved scan results")
    v.add_argument("--results", required=True, help="scan JSON produced by myelin scan --json")
    v.add_argument("--document", action="append", required=True, help="VEX/CSAF JSON file; repeat to merge sources")
    v.add_argument("--policy", help="policy file to re-evaluate after evidence ingestion")
    v.add_argument("--output", help="output JSON (defaults to updating --results)")
    g = sub.add_parser("gate", help="block a deployment: evaluate --results, or ask the platform about --repo/--commit")
    g.add_argument("--results"); g.add_argument("--policy"); g.add_argument("--repo"); g.add_argument("--commit")
    g.add_argument("--environment", help="target environment, recorded in the audit trail"); g.add_argument("--server")
    g.add_argument("--fail-on", choices=["block", "warn"], default="block")
    g.add_argument("--allow-unscanned", action="store_true", help="do not fail when the commit was never scanned")
    g.add_argument("--scope", choices=["all", "new"], default="all", help="new: only findings this commit introduced can block")
    g.add_argument("--require", help="comma-separated engines that must have run, e.g. sast,sca,secrets (missing → block)")
    im = sub.add_parser("import", help="import another scanner's results (SARIF, CycloneDX, Trivy, Grype, Semgrep, Gitleaks, ZAP …)")
    im.add_argument("file"); im.add_argument("--repo", required=True); im.add_argument("--branch"); im.add_argument("--commit")
    im.add_argument("--format", default="auto"); im.add_argument("--server"); im.add_argument("--policy")
    im.add_argument("--fail-on", choices=["block", "never"], default="block")
    t = sub.add_parser("attest"); t.add_argument("--image", required=True); t.add_argument("--provenance"); t.add_argument("--sbom")
    if _ext:
        _ext.add_arguments(t)
    pc = sub.add_parser("precommit", help="scan the files staged for commit (git pre-commit hook)")
    pc.add_argument("--policy"); pc.add_argument("--fail-on", choices=["block", "warn"], default="block")
    pc.add_argument("files", nargs="*", help="files to check (default: git diff --cached)")
    sub.add_parser("mcp", help="run the NERvvE DevSecOps MCP server on stdio for AI coding assistants")
    adv = sub.add_parser("advisories", help="download OSV advisory exports for air-gapped scanning")
    adv.add_argument("action", choices=["download"]); adv.add_argument("dest")
    adv.add_argument("--ecosystems", default="PyPI,npm,Maven,Go,crates.io,NuGet,RubyGems,Packagist")
    cl = sub.add_parser("cloud", help="cloud and Kubernetes posture (CSPM / KSPM / CIEM): collect read-only or load an inventory")
    cl.add_argument("action", choices=["scan", "collect"])
    cl.add_argument("--provider", choices=["azure", "aws", "gcp", "kubernetes"])
    cl.add_argument("--inventory", help="NERvvE inventory, Azure Resource Graph JSON, Cloud Asset export or kubectl -o json List")
    cl.add_argument("--account", help="account / subscription / project / cluster label")
    cl.add_argument("--subscriptions", help="Azure: comma-separated subscription IDs")
    cl.add_argument("--regions", help="AWS: comma-separated regions (default us-east-1)")
    cl.add_argument("--parent", help="Google Cloud: projects/<id>, folders/<id> or organizations/<id>")
    cl.add_argument("--server-url", help="Kubernetes: API server URL")
    cl.add_argument("--credential-file", help="credential JSON (or set MYELIN_CLOUD_CREDENTIAL); AWS uses the boto3 chain when omitted")
    cl.add_argument("--out", help="write the normalised inventory (for air-gapped upload)")
    cl.add_argument("--json"); cl.add_argument("--server"); cl.add_argument("--upload", action="store_true", help="upload the inventory to MYELIN_SERVER")
    cl.add_argument("--fail-on", choices=["critical", "high", "medium", "never"], default="never")
    rt = sub.add_parser("runtime", help="forward Falco / Tetragon runtime detections to the platform")
    rt.add_argument("action", choices=["forward"]); rt.add_argument("file", help="JSON / JSON-lines file, or - for stdin")
    rt.add_argument("--cluster", required=True); rt.add_argument("--server")
    a = p.parse_args()
    if a.cmd == "mcp":
        from . import mcp_server
        sys.exit(mcp_server.serve())
    if a.cmd == "advisories":
        from . import vulndb
        for path in vulndb.download_exports(a.dest, [e.strip() for e in a.ecosystems.split(",") if e.strip()]):
            print(f"downloaded {path} ({os.path.getsize(path) // 1024} KB)")
        print(f"copy {a.dest} to the offline site and set MYELIN_OSV_EXPORT_DIR={a.dest} with MYELIN_OFFLINE=1")
        sys.exit(0)
    sys.exit({"precommit": cmd_precommit, "scan": cmd_scan, "dast": cmd_dast, "vex": cmd_vex, "gate": cmd_gate, "attest": cmd_attest, "import": cmd_import,
              "cloud": cmd_cloud, "runtime": cmd_runtime}[a.cmd](a))


if __name__ == "__main__":
    main()
