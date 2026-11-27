# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Drive an OWASP ZAP daemon (Apache-2.0) through its REST API for deep dynamic testing.

    MYELIN_ZAP_URL=http://zap:8090  MYELIN_ZAP_API_KEY=...

Safe mode (default): the spider explores the target and ZAP's passive scanner analyses every response (headers,
cookies, information disclosure, CSP, mixed content, ...). The spider does not submit forms, so nothing is written.
Active mode (only for a target whose owner proved control and enabled active checks): ZAP's active scanner sends attack
payloads (SQL injection, XSS, path traversal, command injection, SSRF, ...).

Scans are serialised (ZAP options are global) and every scan starts a fresh ZAP session, so results never mix between
targets or tenants. Requests stay inside a ZAP context limited to the target's origin.
"""
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request

LOCK = threading.Lock()
RISK = {"3": "high", "2": "medium", "1": "low", "0": "info", "High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}


class ZapError(RuntimeError):
    pass


def configured() -> bool:
    return bool(os.environ.get("MYELIN_ZAP_URL"))


class Zap:
    def __init__(self, url=None, key=None, timeout=60):
        self.base = (url or os.environ.get("MYELIN_ZAP_URL", "")).rstrip("/")
        self.key = key if key is not None else os.environ.get("MYELIN_ZAP_API_KEY", "")
        self.timeout = timeout
        if not self.base:
            raise ZapError("MYELIN_ZAP_URL is not set")

    def call(self, component, kind, name, **params):
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        req = urllib.request.Request(f"{self.base}/JSON/{component}/{kind}/{name}/" + (f"?{q}" if q else ""),
                                     headers={"X-ZAP-API-Key": self.key, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310  # myelin:ignore[NM-SAST-010] -- operator-configured ZAP daemon URL
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise ZapError(f"ZAP API {component}/{name}: HTTP {e.code} {e.read()[:200]!r}") from None
        except OSError as e:
            raise ZapError(f"ZAP is not reachable at {self.base}: {e}") from None

    def version(self):
        return self.call("core", "view", "version").get("version", "")

    def _wait(self, component, scan_id, limit_s, say):
        t0 = time.time()
        while time.time() - t0 < limit_s:
            pct = int(self.call(component, "view", "status", scanId=scan_id).get("status", "0"))
            say(f"ZAP {component} {pct}%")
            if pct >= 100:
                return True
            time.sleep(3)
        self.call(component, "action", "stop", scanId=scan_id)
        return False

    def scan(self, target, *, active=False, headers=None, spec_url=None, max_minutes=10, say=None):
        say = say or (lambda m: None)
        u = urllib.parse.urlsplit(target)
        origin = f"{u.scheme}://{u.netloc}"
        with LOCK:
            self.call("core", "action", "newSession", overwrite="true")
            ctx = "myelin"
            self.call("context", "action", "newContext", contextName=ctx)
            self.call("context", "action", "includeInContext", contextName=ctx, regex=re.escape(origin) + "(/.*)?")
            # nothing written in safe mode: the spider only follows links
            self.call("spider", "action", "setOptionPostForm", Boolean="false")
            self.call("spider", "action", "setOptionProcessForm", Boolean=str(bool(active)).lower())
            self.call("spider", "action", "setOptionMaxDuration", Integer=str(max_minutes))
            self.call("spider", "action", "setOptionMaxChildren", Integer="200")
            rules = []
            for i, (k, v) in enumerate((headers or {}).items()):
                desc = f"myelin-header-{i}"
                self.call("replacer", "action", "addRule", description=desc, enabled="true", matchType="REQ_HEADER",
                          matchRegex="false", matchString=k, replacement=v, initiators="")
                rules.append(desc)
            try:
                self.call("core", "action", "accessUrl", url=target, followRedirects="true")
                if spec_url:
                    say("ZAP importing the API definition")
                    self.call("openapi", "action", "importUrl", url=spec_url, hostOverride=u.netloc)
                sid = self.call("spider", "action", "scan", url=target, contextName=ctx, subtreeOnly="true").get("scan")
                complete = self._wait("spider", sid, max_minutes * 60 + 60, say)
                t0 = time.time()
                while time.time() - t0 < 300 and int(self.call("pscan", "view", "recordsToScan").get("recordsToScan", "0")) > 0:
                    time.sleep(2)
                if active:
                    cid = self.call("context", "view", "context", contextName=ctx).get("context", {}).get("id")
                    self.call("ascan", "action", "setOptionMaxScanDurationInMins", Integer=str(max_minutes * 3))
                    aid = self.call("ascan", "action", "scan", url=target, recurse="true", inScopeOnly="false", contextId=cid).get("scan")
                    complete = self._wait("ascan", aid, max_minutes * 3 * 60 + 120, say) and complete
                urls = self.call("core", "view", "urls", baseurl=origin).get("urls", [])
                alerts = self.call("alert", "view", "alerts", baseurl=origin, start="0", count="10000").get("alerts", [])
            finally:
                for desc in rules:
                    try:
                        self.call("replacer", "action", "removeRule", description=desc)
                    except ZapError:
                        pass
        return {"alerts": alerts, "urls": len(urls), "complete": complete, "version": self.version(), "mode": "active" if active else "passive"}


def affected_endpoints(instances, url_key="url"):
    """Keep report locations without URL query values, which can contain secrets."""
    endpoints = set()
    for item in instances:
        url = item.get(url_key)
        if url:
            try:
                endpoints.add(f'{item.get("method") or "GET"} {urllib.parse.urlsplit(url).path or "/"}')
            except ValueError:
                continue
    return sorted(endpoints)


def normalize(alerts, f_builder):
    """ZAP alerts (API format) -> RAT Flea findings, one per rule with every affected URL counted as an instance."""
    groups = {}
    for a in alerts or []:
        if str(a.get("confidence") or "").lower() in {"false positive", "falsepositive"}:
            continue
        groups.setdefault((a.get("pluginId"), a.get("name") or a.get("alert")), []).append(a)
    out = []
    for (pid, name), items in groups.items():
        a = items[0]
        cwe = a.get("cweid")
        f = f_builder(f"ZAP-{pid}", name or "ZAP alert", RISK.get(str(a.get("risk")), "info"), a.get("url", ""), "API8",
                      re.sub("<[^>]+>", "", a.get("solution", ""))[:400], (a.get("evidence") or a.get("param") or "")[:300],
                      f"CWE-{cwe}" if cwe not in (None, "", "-1", "0") else None, a.get("method", "GET"))
        f["source_tool"], f["instances"] = "zap", len(items)
        f["confidence"] = (a.get("confidence") or "").lower() or None
        f["affected_urls"] = sorted({i.get("url") for i in items if i.get("url")})[:20]
        f["affected_endpoints"] = affected_endpoints(items)
        out.append(f)
    return out
