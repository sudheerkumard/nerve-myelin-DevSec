# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Measure connected, verified offline and read-only web checks against local fixtures."""
import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit
from zipfile import ZipFile

from scan_benchmark import measure
from myelin_engine import __version__, assessment, orchestrator, vulndb

NPM = "pkg:npm/fixture-library@"
PYPI = "pkg:pypi/fixture-helper@1.0"
# Expected findings use package URLs so false positives on unaffected versions are measured.
ADVISORY_LABELS = {("GHSA-fixture-first", NPM + "1.0.0"), ("GHSA-fixture-second", NPM + "1.0.0")}
SBOM_LABELS = {NPM + "1.0.0", NPM + "2.0.0", PYPI}
LICENSE_LABELS = {("NM-LIC-001", NPM + "1.0.0")}
ADVISORIES = {
    ident: {"id": ident, "summary": "Labelled fixture advisory",
            "affected": [{"package": {"ecosystem": "npm", "name": "fixture-library"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]}
    for ident in ("GHSA-fixture-first", "GHSA-fixture-second")
}
ADVISORIES["GHSA-fixture-withdrawn"] = {**ADVISORIES["GHSA-fixture-first"], "id": "GHSA-fixture-withdrawn",
                                       "withdrawn": "2025-01-01T00:00:00Z"}


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "Benchmark"
    sys_version = ""

    def log_message(self, *args):
        pass

    def _send(self, status, payload=b"", *, content_type="application/json", headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.path != "/v1/querybatch":
            return self._send(404)
        queries = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["queries"]
        results = []
        for query in queries:
            if query["package"]["name"] != "fixture-library" or query["version"] != "1.0.0":
                results.append({})
            elif query.get("page_token") == "fixture-next":
                results.append({"vulns": [{"id": "GHSA-fixture-second"}, {"id": "GHSA-fixture-withdrawn"}]})
            else:
                results.append({"vulns": [{"id": "GHSA-fixture-first"}], "next_page_token": "fixture-next"})
        self._send(200, json.dumps({"results": results}).encode())

    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith("/v1/vulns/") and path.rsplit("/", 1)[1] in ADVISORIES:
            return self._send(200, json.dumps(ADVISORIES[path.rsplit("/", 1)[1]]).encode())
        if path == "/pypi/fixture-helper/1.0/json":
            data = {"info": {"license_expression": "MIT"}, "vulnerabilities": [
                {"id": "PYSEC-fixture", "summary": "Labelled registry advisory", "fixed_in": ["1.1"]}]}
            return self._send(200, json.dumps(data).encode())
        if path in {"/web/missing-headers", "/web/with-headers"}:
            headers = (("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY")) if path.endswith("/with-headers") else ()
            return self._send(200, b"<title>Local fixture</title>", content_type="text/html", headers=headers)
        self._send(404)

    def do_OPTIONS(self):
        self._send(204, headers=(("Allow", "GET, OPTIONS"),))


def _fixtures(root):
    repo = root / "repository"
    export = root / "export"
    export.mkdir()
    for version, licence in (("1.0.0", "(GPL-3.0-only AND MIT) OR AGPL-3.0-only"), ("2.0.0", "MIT OR GPL-3.0-only")):
        project = repo / version
        project.mkdir(parents=True)
        (project / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/fixture-library": {"version": version, "license": licence}}}), encoding="utf-8")
    # The lock pins the same inventory whether online services are reachable or unavailable.
    (repo / "Pipfile.lock").write_text(json.dumps({"default": {"fixture-helper": {"version": "==1.0"}}}), encoding="utf-8")
    archives = []
    for eco in ("npm", "PyPI"):
        filename = eco + ".zip"
        path = export / filename
        with ZipFile(path, "w") as archive:
            if eco == "npm":
                for ident, record in ADVISORIES.items():
                    archive.writestr(ident + ".json", json.dumps(record))
        data = path.read_bytes()
        archives.append({"ecosystem": eco, "file": filename, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)})
    manifest = {"schema_version": 1, "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "archives": archives}
    (export / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return repo, export


def _repository_profile(profile, scan, expected_advisories, statuses, source):
    def keys(engine):
        return {(f["rule_id"], f.get("purl")) for f in scan["findings"] if f["engine"] == engine}

    # Licence findings also carry a component identity for traceability.
    components = [c["purl"] for c in scan["sbom"]["components"]]
    metrics = {"advisories": measure(expected_advisories, keys("sca")),
               "licences": measure(LICENSE_LABELS, keys("license")),
               "sbom": measure(SBOM_LABELS, set(components))}
    coverage = {domain: scan["coverage"][domain]["status"] for domain in statuses}
    passed = (coverage == statuses and source in scan["intelligence"]["sources"] and len(components) == len(set(components))
              and all(not (m["missed"] or m["unexpected"]) for m in metrics.values()))
    return {"profile": profile, "metrics": metrics, "coverage": coverage, "expected_coverage": statuses,
            "advisory_sources": scan["intelligence"]["sources"], "duplicate_components": len(components) - len(set(components)),
            "passed": passed}


def _web_profile(base):
    expected = {("missing-headers", rule) for rule in ("NM-DAST-001", "NM-DAST-004", "NM-DAST-012")}
    expected.add(("with-headers", "NM-DAST-001"))  # Both fixtures intentionally use loopback HTTP.
    observed = set()
    for case in ("missing-headers", "with-headers"):
        scan = assessment.run(f"{base}/web/{case}", delay=0, max_requests=30)
        observed.update((case, f["rule_id"]) for f in scan["findings"])
    metric = measure(expected, observed)
    return {"profile": "web-baseline-loopback", "metrics": {"dast": metric},
            "passed": not (metric["missed"] or metric["unexpected"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="myelin-profiles-") as tmp:
        root = Path(tmp)
        repo, export = _fixtures(root)
        os.environ["MYELIN_CACHE_DIR"] = str(root / "cache")
        os.environ["MYELIN_OFFLINE"] = "0"
        os.environ["MYELIN_OSV_MAX_AGE_DAYS"] = "1"
        with ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler) as server:
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                # Keep every feed URL on the fixture server, even if upstream normalization adds a CVE alias.
                vulndb.OSV_URL = vulndb.PYPI_URL = vulndb.NPM_URL = vulndb.NVD_API_URL = base
                vulndb.EPSS_URL, vulndb.CISA_KEV_URL = base + "/epss", base + "/kev"
                # A benchmark should not inherit proxy settings or send data outside loopback.
                os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1"
                online = orchestrator.scan(str(repo), engines=["sca", "license"], use_external=False)
                os.environ.update(MYELIN_OFFLINE="1", MYELIN_OSV_EXPORT_DIR=str(export))
                offline = orchestrator.scan(str(repo), engines=["sca", "license"], use_external=False)
                profiles = [
                    _repository_profile("online-local-feeds", online, ADVISORY_LABELS | {("PYSEC-fixture", PYPI)},
                                        {"sca": "complete", "license": "complete"}, "OSV"),
                    _repository_profile("offline-verified-export", offline, ADVISORY_LABELS,
                                        {"sca": "complete", "license": "partial"}, "OSV export manifest verified"),
                    _web_profile(base),
                ]
            finally:
                server.shutdown()
                worker.join()
    result = {"schema_version": 1, "scanner_version": __version__,
              "scope": "Synthetic loopback services and a verified local OSV export; no production targets, public feeds or active scans.",
              "profiles": profiles, "passed": all(profile["passed"] for profile in profiles)}
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
