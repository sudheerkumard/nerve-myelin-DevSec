# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Central, evidence-aware developer remediation for normalized scanner findings.

Scanner output is untrusted evidence: recommendations are selected from stable rule/CWE
identifiers and package metadata, never generated from a finding title alone.
"""
from __future__ import annotations

CWE_GUIDANCE = {
    "CWE-295": ("Improper certificate validation", "Enable TLS certificate-chain and hostname verification. Remove insecure options such as verify=False, trust-all managers, and permissive callbacks. Install the correct CA bundle instead.", "Test with an expired, self-signed and hostname-mismatched certificate; each connection must fail."),
    "CWE-798": ("Hard-coded credentials", "Revoke or rotate the exposed credential immediately. Remove it from source and repository history, load it from an approved secret manager, and restrict its permissions and lifetime.", "Verify the old credential is invalid, scan the full Git history, and confirm the application obtains the replacement from the secret manager."),
    "CWE-522": ("Insufficiently protected credentials", "Remove credentials from source, examples and configuration defaults. Use a secret manager or runtime injection, enforce unique strong credentials, and rotate any value that may have been exposed.", "Test a clean deployment and confirm no shared or default credential authenticates."),
    "CWE-327": ("Use of a broken or risky cryptographic algorithm", "Replace obsolete algorithms and modes with current, vetted cryptographic primitives. Use authenticated encryption (for example AES-GCM) and a cryptographically secure random generator.", "Add cryptographic tests and verify algorithm, key size, nonce handling and authentication-tag validation."),
    "CWE-328": ("Use of a weak hash", "Do not use MD5 or SHA-1 for security-sensitive integrity or password storage. Use SHA-256 or stronger for integrity, and Argon2id, scrypt or bcrypt for password hashing with unique salts.", "Review all call sites and verify password hashes use a slow password-hashing function."),
    "CWE-89": ("SQL injection", "Use parameterized queries or prepared statements. Never concatenate untrusted input into SQL. Apply allowlists for dynamic identifiers and least-privilege database accounts.", "Add negative tests with SQL metacharacters and verify inputs remain data, not executable SQL."),
    "CWE-78": ("OS command injection", "Avoid shell execution. Call subprocess APIs with an argument array and shell=False; validate arguments against strict allowlists. Do not build shell command strings from untrusted input.", "Test metacharacter and command-substitution payloads and verify no secondary command executes."),
    "CWE-918": ("Server-side request forgery", "Allowlist destination hosts and schemes, block loopback, link-local and private address ranges where not required, validate DNS results after resolution, and disable redirects or revalidate every redirect.", "Test localhost, cloud metadata IPs, private ranges, alternate IP encodings and redirect-to-private-host cases."),
    "CWE-79": ("Cross-site scripting", "Use context-aware output encoding and framework auto-escaping. Avoid unsafe HTML insertion; sanitize intentionally supported HTML with a maintained allowlist sanitizer.", "Test stored, reflected and DOM payloads in every output context."),
    "CWE-22": ("Path traversal", "Resolve paths against a fixed trusted base directory, canonicalize before access, and verify the resolved path remains beneath that directory. Prefer opaque file identifiers over user-supplied paths.", "Test ../, encoded traversal, absolute paths, symlinks and platform-specific separators."),
    "CWE-502": ("Insecure deserialization", "Do not deserialize untrusted data using native object serializers. Prefer data-only formats with strict schemas; authenticate serialized data and restrict allowed types where unavoidable.", "Test unexpected object types and crafted payloads; confirm deserialization cannot instantiate arbitrary classes."),
    "CWE-327": ("Weak cryptography", "Use modern, vetted cryptographic algorithms and authenticated encryption. Avoid ECB, DES, 3DES and custom cryptography.", "Verify approved algorithms and authenticated decryption behavior."),
    "CWE-601": ("Open redirect", "Accept only relative redirect paths or validate destinations against an explicit host allowlist. Reject protocol-relative and encoded external URLs.", "Test external URLs, //host, backslash variants and encoded redirect targets."),
    "CWE-611": ("XML external entity processing", "Disable DTDs and external general/parameter entities in the XML parser. Disable external resource resolution and use hardened parser settings.", "Test external entity and remote DTD payloads; verify no file or network access occurs."),
    "CWE-306": ("Missing authentication", "Require authentication at the server-side boundary for every sensitive operation. Enforce authorization on each request and deny by default.", "Test unauthenticated and low-privilege access to every sensitive endpoint."),
    "CWE-862": ("Missing authorization", "Enforce object- and function-level authorization on the server for every request. Derive identity from the authenticated session, not client-supplied identifiers.", "Test horizontal and vertical privilege escalation using multiple test accounts."),
    "CWE-918": ("SSRF", "Use strict destination allowlists, block internal and metadata networks, validate resolved IPs and revalidate redirects.", "Test private, loopback, link-local and redirect destinations."),
}

ENGINE_GUIDANCE = {
    "secrets": ("Credential exposure", "Treat detected credentials as compromised until proven otherwise. Revoke or rotate first, then remove from current files and Git history. Store replacements in a secret manager and add pre-commit/CI secret scanning.", "Confirm revoked credentials fail, replacements are not present in repository history, and secret scanning passes."),
    "sca": ("Vulnerable dependency", "Upgrade the affected package to the vendor/advisory fixed version. If it is transitive, upgrade the introducing parent dependency or apply a supported override, regenerate the lockfile and rebuild. If no fix exists, apply the vendor workaround or replace the component.", "Rescan the exact lockfile and built artifact; verify the vulnerable package/version is absent and run regression tests."),
    "iac": ("Infrastructure misconfiguration", "Apply the least-privilege and secure-default configuration recommended by the rule. Review the affected resource and its environment before changing production settings.", "Run the relevant IaC validator and policy scan; verify the deployed resource configuration."),
    "container": ("Container vulnerability", "Rebuild from a supported minimal base image, apply OS package updates and upgrade affected application libraries. Pin the resulting image by digest and regenerate the SBOM.", "Rescan the rebuilt image by digest and confirm the affected package/version is removed."),
    "sast": ("Insecure source-code pattern", "Correct the unsafe code path using the secure implementation guidance for the identified weakness. Validate all callers and error paths; do not suppress the finding without documented risk acceptance.", "Add a regression test that exercises the vulnerable input and confirms the unsafe behavior is no longer possible."),
    "license": ("Open-source licence policy", "Review the component's exact licence and usage/distribution model with legal or compliance owners. Replace, isolate or obtain a compatible commercial licence where required.", "Record the approved licence decision and retain the component/version and licence evidence."),
}

def enrich_finding(finding: dict) -> dict:
    """Populate consistent remediation fields without overwriting richer scanner guidance."""
    engine = str(finding.get("engine") or "").lower()
    cwe = str(finding.get("cwe") or "").upper()
    title, action, verify = CWE_GUIDANCE.get(cwe, (None, None, None))
    if not action:
        title, action, verify = ENGINE_GUIDANCE.get(engine, ("Security finding", "Review the evidence and affected code/resource. Apply the vendor or rule-specific secure configuration, remove the root cause, and avoid suppressing the finding without an approved exception.", "Rerun the same scan and add a regression test or configuration validation proving the issue is resolved."))
    if engine == "sca":
        package = finding.get("package") or "the affected package"
        fixed = finding.get("fixed_version")
        via = finding.get("introduced_by")
        if fixed:
            action = f"Upgrade {package} to {fixed} or later. Regenerate and commit the lockfile, rebuild the application, and update the parent dependency{(' ' + str(via)) if via else ''} if this is transitive. " + action
        else:
            action = f"No fixed version is recorded in the current advisory data for {package}. Check the vendor advisory for a supported workaround, isolate or replace the component, and monitor for a fixed release. " + action
    # Preserve detailed scanner-provided instructions; add a stable verification step.
    existing = str(finding.get("remediation") or "").strip()
    finding["remediation"] = existing if len(existing) >= 40 else action
    finding["remediation_steps"] = [s.strip() for s in finding["remediation"].split(". ") if s.strip()]
    finding["verification"] = finding.get("verification") or verify
    finding["remediation_source"] = "scanner" if len(existing) >= 40 else ("CWE" if cwe in CWE_GUIDANCE else "NERvvE-engine-guidance")
    finding["remediation_version"] = "1"
    return finding
