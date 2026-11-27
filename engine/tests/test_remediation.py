from myelin_engine.remediation import enrich_finding


def test_tls_certificate_verification_has_actionable_remediation():
    finding = {"engine": "sast", "title": "TLS certificate verification disabled", "cwe": "CWE-295"}
    result = enrich_finding(finding)
    assert "certificate-chain" in result["remediation"]
    assert "expired" in result["verification"]


def test_secret_finding_has_rotation_and_history_guidance():
    finding = {"engine": "secrets", "title": "Google API key committed to source"}
    result = enrich_finding(finding)
    assert "rotate" in result["remediation"].lower()
    assert "Git history" in result["remediation"]
    assert result["verification"]


def test_sca_finding_includes_fixed_version_and_lockfile_steps():
    finding = {"engine": "sca", "package": "example-lib", "version": "1.0.0",
               "fixed_version": "1.2.0", "dependency_type": "transitive"}
    result = enrich_finding(finding)
    assert "1.2.0" in result["remediation"]
    assert "lockfile" in result["remediation"]
    assert result["verification"]


def test_existing_scanner_remediation_is_preserved():
    text = "Use the vendor's documented upgrade procedure and validate the deployment."
    finding = {"engine": "sca", "remediation": text, "package": "example-lib", "fixed_version": "2.0"}
    result = enrich_finding(finding)
    assert result["remediation"] == text
    assert result["verification"]


def test_common_tls_title_without_cwe_still_gets_specific_guidance():
    result = enrich_finding({"engine": "sast", "title": "TLS certificate verification disabled"})
    assert "certificate-chain" in result["remediation"]


def test_pypi_advisories_are_queried_when_osv_returns_no_matches(monkeypatch):
    from myelin_engine import vulndb

    component = {"ecosystem": "pypi", "name": "sample-lib", "version": "1.0",
                 "file": "requirements.txt", "purl": "pkg:pypi/sample-lib@1.0", "scope": "required"}
    advisory = {"id": "PYSEC-2026-1", "aliases": ["CVE-2026-1234"], "summary": "Example advisory",
                "details": "", "_fixed": ["1.1"], "severity": [], "database_specific": {}}
    monkeypatch.setenv("MYELIN_OFFLINE", "0")          # the backend suite defaults to offline
    monkeypatch.delenv("MYELIN_OSV_EXPORT_DIR", raising=False)
    monkeypatch.setattr(vulndb, "_osv", lambda comps: {})
    monkeypatch.setattr(vulndb, "_pypi_vulns", lambda component: [advisory])
    vulndb.STATUS["sources"].clear()
    vulndb.STATUS["errors"].clear()

    results = vulndb.vulnerabilities([component])
    assert len(results) == 1
    assert results[0][1]["id"] == "PYSEC-2026-1"
    assert results[0][1]["fixed"] == "1.1"


def test_osv_and_pypi_duplicate_advisories_are_deduplicated(monkeypatch):
    from myelin_engine import vulndb
    monkeypatch.setenv("MYELIN_OFFLINE", "0")
    monkeypatch.delenv("MYELIN_OSV_EXPORT_DIR", raising=False)

    component = {"ecosystem": "pypi", "name": "sample-lib", "version": "1.0",
                 "file": "requirements.txt", "purl": "pkg:pypi/sample-lib@1.0", "scope": "required"}
    advisory = {"id": "PYSEC-2026-1", "aliases": ["CVE-2026-1234"], "summary": "Example advisory",
                "details": "", "_fixed": ["1.1"], "severity": [], "database_specific": {}}
    osv_doc = {"id": "PYSEC-2026-1", "aliases": ["CVE-2026-1234"], "summary": "Example advisory",
               "details": "", "affected": [], "severity": [], "database_specific": {}}
    monkeypatch.setattr(vulndb, "_osv", lambda comps: {0: [osv_doc]})
    monkeypatch.setattr(vulndb, "_pypi_vulns", lambda component: [advisory])

    results = vulndb.vulnerabilities([component])
    assert len(results) == 1
