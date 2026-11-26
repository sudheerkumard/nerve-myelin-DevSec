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
