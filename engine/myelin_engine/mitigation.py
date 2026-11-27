# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Developer mitigation guidance for every finding: numbered fix steps, how to verify the fix, and a reference.

Guidance is chosen from the most specific match: rule id, then weakness (CWE), then engine. The finding's own
remediation sentence (from the rule) stays the summary; these steps tell a developer how to do it.
"""
from __future__ import annotations

import re

OWASP_CS = "https://cheatsheetseries.owasp.org/cheatsheets/"

# --------------------------------------------------------------------------- by weakness (CWE)
CWE = {
    "CWE-89": (["Replace string concatenation or formatting in the query with bound parameters: PreparedStatement "
                "with ? (Java), SqlParameter (C#), cursor.execute(sql, params) (Python), parameterised queries in the "
                "ORM or driver (Node.js).",
                "Pass table and column names only from a fixed allow-list in code, never from the request.",
                "Run the application with a database account that has only the rights it needs (no DDL, no admin).",
                "Search the code base for the same pattern (other queries built with + or string formatting) and fix "
                "them together."],
               "Re-run the scan; add a test that sends ' OR '1'='1 and confirms the query returns no extra rows.",
               OWASP_CS + "SQL_Injection_Prevention_Cheat_Sheet.html"),
    "CWE-78": (["Avoid the shell: call the program directly with an argument list (ProcessBuilder(\"ping\", \"-c\", "
                "\"1\", host), subprocess.run([...], shell=False), execFile).",
                "Validate the user value against a strict allow-list or pattern (for example a host name regex) before "
                "using it.",
                "Prefer a library call over running an operating-system command where one exists.",
                "Run the process with the least privilege and a fixed working directory."],
               "Re-run the scan; a test with input `127.0.0.1; id` must not run the second command.",
               OWASP_CS + "OS_Command_Injection_Defense_Cheat_Sheet.html"),
    "CWE-94": (["Remove eval / new Function / exec / setTimeout(string) on request data.",
                "Parse data with a data parser instead (JSON.parse, int(), a schema validator).",
                "If dynamic behaviour is needed, map the input to a fixed set of functions in a dictionary."],
               "Re-run the scan; confirm no code path passes request data to an evaluator.",
               OWASP_CS + "Injection_Prevention_Cheat_Sheet.html"),
    "CWE-22": (["Do not build file paths from request data. Map an identifier to a file name on the server instead.",
                "If a name must be accepted, keep only the base name (FilenameUtils.getName, os.path.basename, "
                "path.basename) and reject '..', '/', '\\' and absolute paths.",
                "Resolve the final path and check it is inside the allowed folder (Path.normalize().startsWith(base), "
                "os.path.realpath(p).startswith(base)).",
                "Give the process read/write access only to that folder."],
               "Re-run the scan; a request for ../../etc/passwd must be rejected.",
               OWASP_CS + "File_Upload_Cheat_Sheet.html"),
    "CWE-918": (["Do not fetch URLs taken from the request. If you must, parse the URL and allow only https and an "
                 "allow-list of host names.",
                 "Resolve the host name and refuse private, loopback, link-local and metadata addresses (10/8, "
                 "172.16/12, 192.168/16, 127/8, 169.254.169.254, ::1).",
                 "Disable redirects in the HTTP client or re-check each redirect target.",
                 "Send outbound requests through an egress proxy that enforces the allow-list."],
                "Re-run the scan; a request with http://169.254.169.254/ must be refused.",
                OWASP_CS + "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"),
    "CWE-601": (["Redirect only to relative paths that start with a single '/', or to a fixed allow-list of URLs.",
                 "Use an identifier (for example ?next=orders) mapped to a URL on the server instead of a URL "
                 "parameter."],
                "Re-run the scan; ?url=https://evil.example must not redirect off-site.",
                OWASP_CS + "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"),
    "CWE-79": (["Encode output for its context: HTML body (Encode.forHtml, html.escape, escape-html), attribute, "
                "JavaScript or URL.",
                "Render through the template engine with auto-escaping on; remove |safe, mark_safe, <%-, {{{ }}}, "
                "v-html, dangerouslySetInnerHTML, @Html.Raw or th:utext unless the value is sanitised HTML.",
                "If users may submit HTML, sanitise it with a vetted library (DOMPurify, OWASP Java HTML Sanitizer, "
                "bleach).",
                "Add a Content-Security-Policy header that blocks inline scripts as a second line of defence."],
               "Re-run the scan; the input <script>alert(1)</script> must appear escaped in the page.",
               OWASP_CS + "Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
    "CWE-643": (["Use XPath variables (XPathVariableResolver / parameterised XPath) instead of concatenating input.",
                 "Validate the value against an allow-list pattern before use."],
                "Re-run the scan; input ' or '1'='1 must not return other nodes.",
                OWASP_CS + "Injection_Prevention_Cheat_Sheet.html"),
    "CWE-90": (["Escape every value placed in an LDAP filter (LdapEncoder.filterEncode, ESAPI encodeForLDAP, "
                "ldap3.utils.conv.escape_filter_chars).",
                "Use parameterised filters ({0} placeholders with filter arguments) where the API supports them."],
               "Re-run the scan; input *)(uid=* must not match every user.",
               OWASP_CS + "LDAP_Injection_Prevention_Cheat_Sheet.html"),
    "CWE-943": (["Never use $where or server-side JavaScript with dynamic values.",
                 "Make sure request values are plain strings or numbers before they go into a query (reject objects "
                 "such as {\"$ne\": null}); use a schema validator or mongo-sanitize.",
                 "Use the driver's typed query operators."],
                "Re-run the scan; a body of {\"user\": {\"$ne\": null}} must be rejected.",
                OWASP_CS + "Injection_Prevention_Cheat_Sheet.html"),
    "CWE-501": (["Validate request data (type, length, allow-list) before storing it in the session.",
                 "Store only server-derived values (user id after authentication, role from the database) in the "
                 "session, never raw request parameters."],
                "Re-run the scan.", OWASP_CS + "Session_Management_Cheat_Sheet.html"),
    "CWE-614": (["Set the Secure flag on the cookie (cookie.setSecure(true), secure: true, SESSION_COOKIE_SECURE = "
                 "True, CookieSecurePolicy.Always).",
                 "Also set HttpOnly and SameSite=Lax or Strict for session cookies.",
                 "Serve the site only over HTTPS and enable HSTS."],
                "In the browser developer tools, the cookie shows Secure and HttpOnly.",
                OWASP_CS + "Session_Management_Cheat_Sheet.html"),
    "CWE-1004": (["Set HttpOnly on cookies that scripts do not need to read."], "The cookie shows HttpOnly in the browser.",
                 OWASP_CS + "Session_Management_Cheat_Sheet.html"),
    "CWE-327": (["Replace DES, 3DES, RC2, RC4, Blowfish and ECB mode with AES-256-GCM (or ChaCha20-Poly1305) and a "
                 "unique random nonce for every message.",
                 "Name the full transformation (\"AES/GCM/NoPadding\"); \"AES\" alone means ECB.",
                 "Re-encrypt stored data with the new algorithm and plan key rotation.",
                 "Keep keys in a key management service, not in code or configuration files."],
                "Re-run the scan; the cryptography inventory shows no weak algorithms.",
                OWASP_CS + "Cryptographic_Storage_Cheat_Sheet.html"),
    "CWE-328": (["Use SHA-256 or stronger for integrity and signatures.",
                 "For passwords use a password hashing function: Argon2id, bcrypt or PBKDF2 with a high iteration count "
                 "and a per-user salt. Re-hash on the user's next login."],
                "Re-run the scan.", OWASP_CS + "Password_Storage_Cheat_Sheet.html"),
    "CWE-330": (["Generate tokens, session ids, passwords and keys with a cryptographic generator: SecureRandom (Java), "
                 "secrets.token_urlsafe (Python), crypto.randomBytes / crypto.randomUUID (Node.js), "
                 "RandomNumberGenerator (.NET).",
                 "Use at least 128 bits of randomness for tokens."],
                "Re-run the scan.", OWASP_CS + "Session_Management_Cheat_Sheet.html"),
    "CWE-502": (["Do not deserialise untrusted data with native serialisers (ObjectInputStream, pickle, "
                 "BinaryFormatter, unserialize, YAML.load, node-serialize).",
                 "Use a data-only format (JSON) mapped to fixed types; disable polymorphic typing in JSON libraries.",
                 "If native deserialisation cannot be removed, apply an allow-list filter (ObjectInputFilter) and sign "
                 "the data."],
                "Re-run the scan.", OWASP_CS + "Deserialization_Cheat_Sheet.html"),
    "CWE-611": (["Disable DOCTYPE declarations in the XML parser (disallow-doctype-decl = true) or, if DTDs are needed, "
                 "disable external entities and external DTD loading.",
                 "Use defusedxml in Python; in .NET set DtdProcessing = Prohibit."],
                "Re-run the scan; a test document with an external entity must be rejected.",
                OWASP_CS + "XML_External_Entity_Prevention_Cheat_Sheet.html"),
    "CWE-295": (["Remove the trust-all certificate or host-name verifier (requests verify set to False, Node.js "
                 "rejectUnauthorized set to false, Go InsecureSkipVerify, a .NET certificate callback that always "
                 "returns true).",
                 "If the server uses a private CA, add that CA to the trust store or pass it explicitly "
                 "(verify='/path/ca.pem', ca: fs.readFileSync(...)).",
                 "Keep verification on in test code too, so it is not copied to production."],
                "Re-run the scan; connecting to a server with a self-signed certificate must fail.",
                OWASP_CS + "Transport_Layer_Security_Cheat_Sheet.html"),
    "CWE-1333": (["Rewrite the regular expression without nested quantifiers such as (a+)+ or (.*)*.",
                  "Limit the input length before matching, or use a linear-time engine (RE2, re2j, Go regexp).",
                  "Set a match timeout where the platform supports it (.NET Regex timeout)."],
                 "Re-run the scan; matching a 50 000-character input completes quickly.",
                 "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"),
    "CWE-352": (["Re-enable the framework's CSRF protection and send the token from forms and AJAX calls.",
                 "For token-authenticated APIs that do not use cookies, document why CSRF protection is not needed and "
                 "keep it on for cookie-based routes.",
                 "Set SameSite=Lax or Strict on session cookies."],
                "Re-run the scan; a cross-site POST without the token must be rejected.",
                OWASP_CS + "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"),
    "CWE-942": (["Replace the wildcard origin with an explicit list of trusted origins.",
                 "Never combine a reflected or wildcard origin with Access-Control-Allow-Credentials: true."],
                "A request with Origin: https://evil.example must not get Access-Control-Allow-Origin back.",
                OWASP_CS + "HTML5_Security_Cheat_Sheet.html"),
    "CWE-306": (["Require authentication by default (anyRequest().authenticated(), [Authorize] globally) and open only "
                 "the specific public endpoints.",
                 "Add authorisation checks for each sensitive action."],
                "Call a protected endpoint without a session or token; it must return 401/403.",
                OWASP_CS + "Authorization_Cheat_Sheet.html"),
    "CWE-117": (["Remove CR and LF characters from user data before logging, or log it as a structured field "
                 "(JSON logger).", "Do not log secrets or personal data."],
                "Re-run the scan.", OWASP_CS + "Logging_Cheat_Sheet.html"),
    "CWE-915": (["Copy only the allowed fields from the request into the model (an explicit DTO or a pick/allow-list).",
                 "Mark sensitive fields (role, isAdmin, balance, ownerId) as not bindable."],
                "Re-run the scan; a request that adds \"isAdmin\": true must not change the field.",
                OWASP_CS + "Mass_Assignment_Cheat_Sheet.html"),
    "CWE-489": (["Turn debug mode off in production configuration and read it from an environment variable that "
                 "defaults to off."], "The production error page shows no stack trace.",
                OWASP_CS + "Error_Handling_Cheat_Sheet.html"),
    "CWE-338": (["Use a cryptographically secure generator for security values (see CWE-330)."], "Re-run the scan.",
                OWASP_CS + "Session_Management_Cheat_Sheet.html"),
    "CWE-1336": (["Do not render templates built from user input; pass the input as a variable to a fixed template.",
                  "Use a sandboxed template environment if users must author templates."],
                 "Re-run the scan.", OWASP_CS + "Injection_Prevention_Cheat_Sheet.html"),
}

# --------------------------------------------------------------------------- secrets (by provider)
_ROTATE = ["Rotate first: create a new credential, deploy it, then revoke the leaked one. Deleting the line does not "
           "make the old value safe; it is still in every clone and in the git history.",
           "Move the value to a secrets manager (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, GitHub/GitLab "
           "secrets) and read it at runtime from the environment.",
           "Remove it from the git history with git filter-repo (or BFG), force-push, and ask everyone to re-clone. Ask "
           "the hosting provider to purge cached views if the repository was ever public.",
           "Check the provider's access logs for use of the leaked credential between the commit date and the "
           "rotation.",
           "Turn on a pre-commit secret check and push protection so it does not happen again."]
SECRET_PROVIDER = [
    (re.compile(r"(?i)google|gcp|NM-SEC-007"), [
        "In Google Cloud Console > APIs & Services > Credentials, regenerate (rotate) the key and delete the old one.",
        "Restrict the new key: application restriction (HTTP referrers, Android package/SHA-1, iOS bundle id or IP "
        "addresses) and API restriction (only the APIs it needs). A key in a mobile or web app cannot be secret, "
        "so it must be restricted.",
        "For server-side calls, use a service account with Workload Identity instead of an API key."]),
    (re.compile(r"(?i)aws|NM-SEC-001"), [
        "In AWS IAM, deactivate the access key, create a new one for the workload, then delete the old key.",
        "Prefer IAM roles (instance profile, IRSA, OIDC from CI) so no long-lived key is needed.",
        "Review CloudTrail for activity by the leaked key id."]),
    (re.compile(r"(?i)github|NM-SEC-00[23]"), [
        "Revoke the token in GitHub > Settings > Developer settings (or the organisation's token policy).",
        "Use the built-in GITHUB_TOKEN or a GitHub App with fine-grained, short-lived tokens."]),
    (re.compile(r"(?i)private-key|NM-SEC-005"), [
        "Treat the key pair as compromised: issue a new key/certificate and revoke the old certificate.",
        "Store private keys in a key vault or HSM and mount them at runtime; never commit them, even for tests "
        "(generate test keys during the test run)."]),
    (re.compile(r"(?i)azure|NM-SEC-006|NM-SEC-015"), [
        "Regenerate the key in the Azure portal (storage account Access keys / resource Keys and Endpoint).",
        "Use Managed Identity with RBAC instead of account keys, and disable shared-key access where possible."]),
    (re.compile(r"(?i)NM-SEC-011|default.*password|demo password"), [
        "Change the password on every system that uses it now.",
        "Remove the password from code, comments, README files and login pages.",
        "Ship without default accounts: create the first administrator at install time with a one-time password that "
        "must be changed at first login."]),
    (re.compile(r"(?i)jwt|NM-SEC-009"), [
        "If the token is real, revoke it (rotate the signing key so it no longer validates).",
        "Use short-lived tokens and never commit tokens, even from test environments."]),
    (re.compile(r"(?i)generic|NM-SEC-010|NM-SAST-045|hardcoded-session-secret"), [
        "Identify which system the value belongs to (database, API, signing secret) and rotate it there.",
        "Replace the literal with an environment variable or secrets-manager lookup; fail at start-up if it is "
        "missing instead of falling back to a default."]),
]

# --------------------------------------------------------------------------- by engine
ENGINE = {
    "sca": (["Upgrade the package to the fixed version shown (or the newest release) in the manifest, then refresh the "
             "lock file.",
             "If it is a transitive dependency, upgrade the direct dependency that pulls it in, or pin it: npm "
             "\"overrides\", yarn \"resolutions\", Maven <dependencyManagement>, Gradle constraints, NuGet central "
             "package management, pip constraints file.",
             "Run the test suite, then re-scan to confirm the advisory is gone.",
             "If no fix exists, check whether the vulnerable function is used; document a VEX statement or "
             "compensating control, and set a review date."],
            "Re-run the scan; the component appears with the fixed version and no advisory.",
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
    "license": (["Check the licence obligations with your legal or open-source office.",
                 "Replace the component with one under an approved licence, or record an approved exception."],
                "Re-run the scan.", "https://spdx.org/licenses/"),
    "iac": (["Change the resource definition as the finding describes (for example enable encryption, remove public "
             "access, restrict the network rule) in the Terraform/Bicep/Kubernetes/Dockerfile source, not in the "
             "portal, so the fix is not undone.",
             "Apply the change through the normal pipeline and confirm the deployed resource matches."],
            "Re-run the scan and the cloud posture check.", "https://www.cisecurity.org/cis-benchmarks"),
    "cicd": (["Update the pipeline file: pin actions and images to a full commit SHA or digest, give the job token "
              "least privilege (permissions: contents: read), and never run untrusted pull-request code with "
              "secrets.",
              "Protect the default branch and require review for pipeline changes (CODEOWNERS)."],
             "Re-run the scan.", "https://owasp.org/www-project-top-10-ci-cd-security-risks/"),
    "container": (["Rebuild the image on a current, minimal base (distroless, -slim or alpine) and upgrade the listed "
                   "packages.", "Run as a non-root user and rebuild regularly so OS patches are picked up."],
                  "Re-scan the rebuilt image.", "https://docs.docker.com/develop/security-best-practices/"),
    "supply": (["Verify the package is the one you intended (name, publisher, download count, repository).",
                "If it is malicious or a typosquat, remove it, rotate any credentials on machines that installed it and "
                "rebuild from a clean environment.",
                "Use a lock file and an internal registry proxy with allow-listing."],
               "Re-run the scan.", "https://slsa.dev/"),
    "aibom": (["Treat model output and retrieved content as untrusted input: validate and encode it before it reaches "
               "code execution, queries, tools or HTML.",
               "Limit tool permissions for agents and require human approval for destructive actions."],
              "Re-run the scan.", "https://genai.owasp.org/llm-top-10/"),
    "dast": (["Reproduce the issue with the request in the evidence, fix it in the application code or web server "
              "configuration, and deploy.", "Add the missing security header or setting at the framework level so "
              "every route gets it."],
             "Re-run the dynamic scan against the fixed deployment.", "https://owasp.org/www-project-web-security-testing-guide/"),
    "sast": (["Fix the code at the reported line as described, and check for the same pattern elsewhere."],
             "Re-run the scan.", "https://owasp.org/Top10/"),
}


def guidance(f: dict) -> dict:
    """{'summary', 'steps': [...], 'verify', 'reference'} for one finding."""
    eng = f.get("engine") or "sast"
    rule = str(f.get("rule_id") or "")
    summary = f.get("remediation") or ""
    if eng == "secrets":
        steps = []
        for rx, extra in SECRET_PROVIDER:
            if rx.search(rule) or rx.search(str(f.get("title") or "")):
                steps = list(extra)
                break
        steps += _ROTATE if "NM-SEC-011" not in rule else _ROTATE[1:2] + _ROTATE[4:]
        if f.get("context") == "test":
            steps.insert(0, "This is in a test or fixture file. If it is a real credential, rotate it as below; if it is a "
                            "dummy value, replace it with an obviously fake value or generate it during the test, or "
                            "suppress the finding with a reason.")
        if f.get("occurrences", 1) > 1:
            steps.insert(0, f"The same secret appears in {f['occurrences']} places (see locations); one rotation fixes all.")
        return {"summary": summary or "Rotate the credential, remove it from the code and history, and load it from a secrets manager.",
                "steps": steps,
                "verify": "Re-run the scan (including git history) and confirm the old credential is rejected by the provider.",
                "reference": OWASP_CS + "Secrets_Management_Cheat_Sheet.html"}
    if eng in ("sca", "container") and f.get("fixed_version"):
        summary = summary or f"Upgrade {f.get('package')} to {f['fixed_version']} or later."
    hit = CWE.get(str(f.get("cwe") or "")) if eng in ("sast", "dast", "aibom", "iac") or not ENGINE.get(eng) else None
    steps, verify, ref = hit or ENGINE.get(eng) or ENGINE["sast"]
    steps = list(steps)
    if eng in ("sca", "container") and f.get("fixed_version"):
        steps[0] = f"Upgrade {f.get('package')} from {f.get('version')} to {f['fixed_version']} or later, then refresh the lock file."
    return {"summary": summary or steps[0], "steps": steps, "verify": verify, "reference": ref}


def as_text(f: dict) -> str:
    g = guidance(f)
    return " ".join(f"{i}. {s}" for i, s in enumerate(g["steps"], 1))


def plan_html(findings: list[dict], organisation: str = "", scope: str = "") -> str:
    """A remediation plan: findings grouped into fix items (same rule and package/secret), ordered by priority,
    each with the numbered steps, how to verify and every affected location."""
    import html
    import time
    from collections import OrderedDict
    e = lambda x: html.escape("" if x is None else str(x), quote=True)  # noqa: E731
    pri = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fs = sorted(findings, key=lambda f: (pri.get(f.get("priority"), 5), sev.get(f.get("severity"), 5), -(f.get("mrs") or 0)))
    groups: OrderedDict = OrderedDict()
    for f in fs:
        key = (f.get("engine"), f.get("rule_id"), f.get("package") or f.get("secret_id") or f.get("title"),
               f.get("fixed_version") if f.get("engine") in ("sca", "container") else None)
        groups.setdefault(key, []).append(f)
    items = []
    for n, (key, gs) in enumerate(groups.items(), 1):
        f = gs[0]
        g = guidance(f)
        repos = sorted({x.get("repo") or "" for x in gs})
        locs = []
        for x in gs[:40]:
            loc = f"{x.get('repo')}: {x.get('file') or x.get('package') or ''}" + (f":{x['line']}" if x.get("line") else "")
            locs.append(f"<li class=mono>{e(loc)}</li>")
        more = f"<li>… and {len(gs) - 40} more</li>" if len(gs) > 40 else ""
        steps = "".join(f"<li>{e(s)}</li>" for s in g["steps"])
        items.append(f"""<section class=item><h3><span class="chip {e(f.get('severity'))}">{e(f.get('severity'))}</span>
{e(f.get('priority') or '')} · {n}. {e(f.get('title'))}</h3>
<div class=meta>{e(f.get('engine'))} · rule {e(f.get('rule_id'))}{' · ' + e(f.get('cve')) if f.get('cve') else ''}
{' · CWE ' + e(f.get('cwe')) if f.get('cwe') else ''} · {len(gs)} occurrence(s) in {len(repos)} repositor{'y' if len(repos) == 1 else 'ies'}
{' · fix within ' + e(f.get('sla_days')) + ' days' if f.get('sla_days') else ''}</div>
<p><b>What to do:</b> {e(g['summary'])}</p><ol>{steps}</ol>
<p><b>Verify:</b> {e(g['verify'])} · <a href="{e(g['reference'])}">guidance</a></p>
<details><summary>Affected locations ({len(gs)})</summary><ul>{''.join(locs)}{more}</ul></details></section>""")
    counts = {k: sum(1 for f in fs if f.get("priority") == k) for k in ("P0", "P1", "P2", "P3")}
    gen = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    return f"""<!DOCTYPE html><html lang=en><head><meta charset=utf-8><title>Remediation plan</title><style>
body{{font:13px/1.5 system-ui,Segoe UI,Arial,sans-serif;color:#0f172a;margin:28px;max-width:1100px}}h1{{font-size:22px;margin:0}}
.item{{border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;margin:12px 0;break-inside:avoid}}h3{{font-size:15px;margin:0 0 4px}}
.meta{{color:#64748b;font-size:12px}}.mono{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}ol{{margin:6px 0;padding-left:20px}}
.chip{{display:inline-block;padding:0 8px;border-radius:10px;font-size:11px;border:1px solid #cbd5e1;text-transform:uppercase}}
.critical,.high{{background:#fef2f2;color:#b91c1c}}.medium{{background:#fffbeb;color:#b45309}}.low,.info{{background:#f1f5f9}}
.kpis{{display:flex;gap:10px;margin:12px 0}}.kpis div{{border:1px solid #e2e8f0;border-radius:8px;padding:8px 14px}}.kpis b{{font-size:20px;display:block}}
</style></head><body><h1>Remediation plan</h1><div class=meta>{e(organisation)} · {e(scope)} · generated {gen} ·
{len(fs)} findings grouped into {len(groups)} fix items</div>
<div class=kpis><div><b>{counts['P0']}</b>P0 · fix today</div><div><b>{counts['P1']}</b>P1 · 7 days</div><div><b>{counts['P2']}</b>P2 · 30 days</div>
<div><b>{counts['P3']}</b>P3 · 90 days</div></div>{''.join(items) or '<p>No findings match.</p>'}
<p class=meta>RAT Flea DevSec Product designed and developed by Sudheer Kumar — https://github.com/sudheerkumard/nervve-devsecops</p>
</body></html>"""
