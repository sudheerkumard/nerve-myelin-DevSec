# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""RAT Flea DevSec AI assistant.

Four capabilities, each with a deterministic built-in engine that always works (including air-gapped) and an optional
large-language-model provider that the tenant configures:

  explain(finding)       what it is, why it matters here, step-by-step fix, how to verify, references
  triage(finding)        suggested verdict (likely real / likely false positive / needs review) with the evidence used
  ask(question)          plain-language questions over findings ("critical secrets in payments older than 30 days")
  briefing(summary)      executive narrative of the security posture

Provider (environment):
  MYELIN_AI_PROVIDER     none (default) | anthropic | openai | azure_openai
  MYELIN_AI_MODEL        model / deployment name
  MYELIN_AI_ENDPOINT     base URL for azure_openai or an OpenAI-compatible gateway (e.g. a private model server)
  MYELIN_AI_KEY_REF      secret reference for the API key (env://NAME, vault://…), resolved by app.secrets
  MYELIN_AI_SEND_CODE    false (default): code evidence is never sent; true: the matched line only, with secrets redacted

Data handling: secret values are never sent (secrets findings are described by rule and location only), long tokens are
redacted from every field, and the model only ever proposes — nothing it says changes a finding without a person.
"""
import json
import os
import re
from collections import Counter

import httpx

from . import secrets as sm

TRANSPORT = None          # tests inject an httpx.MockTransport
TIMEOUT = 30.0
_TOKEN = re.compile(r"(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.-]+|"
                    r"[A-Za-z0-9+/=_-]{32,})")


def provider() -> dict:
    p = (os.environ.get("MYELIN_AI_PROVIDER") or "none").lower()
    return {"provider": p if p in ("anthropic", "openai", "azure_openai") else "none",
            "model": os.environ.get("MYELIN_AI_MODEL") or {"anthropic": "claude-sonnet-5-5", "openai": "gpt-4.1"}.get(p, ""),
            "endpoint": os.environ.get("MYELIN_AI_ENDPOINT") or "", "send_code": os.environ.get("MYELIN_AI_SEND_CODE", "false").lower() == "true"}


def status() -> dict:
    p = provider()
    return {**p, "configured": p["provider"] != "none" and bool(os.environ.get("MYELIN_AI_KEY_REF")),
            "built_in": True,
            "data_handling": ["Secret values are never sent to a model.", "Tokens and long random strings are redacted from every field.",
                              "Code evidence is sent only when MYELIN_AI_SEND_CODE=true, and only the matched line.",
                              "Model answers are suggestions: they never change a finding without a person."]}


def redact(v):
    if isinstance(v, str):
        return _TOKEN.sub("[redacted]", v)
    if isinstance(v, list):
        return [redact(x) for x in v]
    if isinstance(v, dict):
        return {k: redact(x) for k, x in v.items()}
    return v


def _context(f: dict) -> dict:
    keep = ("rule_id", "title", "engine", "severity", "priority", "mrs", "cwe", "cve", "cvss", "epss", "kev", "reachable", "exposure",
            "package", "version", "fixed_version", "dependency_type", "file", "line", "owasp_llm", "owasp_cicd", "owasp_api", "remediation")
    ctx = {k: f.get(k) for k in keep if f.get(k) not in (None, "")}
    if provider()["send_code"] and f.get("engine") != "secrets" and f.get("evidence"):
        ctx["evidence"] = str(f["evidence"])[:300]
    return redact(ctx)


def _llm(system: str, user: str, max_tokens: int = 900) -> str | None:
    """One model call. Returns None when no provider is configured or the call fails (callers fall back)."""
    p = provider()
    ref = os.environ.get("MYELIN_AI_KEY_REF")
    if p["provider"] == "none" or not ref:
        return None
    try:
        key = sm.resolve(ref)
    except Exception:  # noqa: BLE001
        return None
    try:
        with httpx.Client(timeout=TIMEOUT, transport=TRANSPORT) as h:
            if p["provider"] == "anthropic":
                r = h.post((p["endpoint"] or "https://api.anthropic.com").rstrip("/") + "/v1/messages",
                           headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                           json={"model": p["model"], "max_tokens": max_tokens, "system": system,
                                 "messages": [{"role": "user", "content": user}]})
                r.raise_for_status()
                return "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text")
            if p["provider"] == "azure_openai":
                url = f"{p['endpoint'].rstrip('/')}/openai/deployments/{p['model']}/chat/completions?api-version=2024-10-21"
                hdr = {"api-key": key}
            else:
                url = (p["endpoint"] or "https://api.openai.com").rstrip("/") + "/v1/chat/completions"
                hdr = {"Authorization": f"Bearer {key}"}
            r = h.post(url, headers=hdr, json={"model": p["model"], "max_tokens": max_tokens,
                                               "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
    except (httpx.HTTPError, KeyError, ValueError, IndexError):
        return None


def _json(text: str | None):
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.S)
    try:
        return json.loads(m.group(0)) if m else None
    except json.JSONDecodeError:
        return None


# ─── built-in knowledge ─────────────────────────────────────────────────────────────────────────────────────────
KB = {
    "CWE-89": ("SQL injection: untrusted input becomes part of a SQL statement.", "Attackers read, change or delete data, or bypass login.",
               ["Use parameterised queries / prepared statements for every value.", "Never build SQL with f-strings, + or format().",
                "Run the application with a least-privilege database account."]),
    "CWE-78": ("OS command injection: untrusted input reaches a shell command.", "Remote code execution on the server.",
               ["Call the program with an argument list and shell=False.", "Validate input against an allow-list.", "Avoid the shell entirely where a library call exists."]),
    "CWE-79": ("Cross-site scripting: untrusted data is inserted into HTML without encoding.", "Session theft and actions performed as the victim.",
               ["Use textContent or framework auto-escaping instead of innerHTML.", "Sanitise any HTML you must render (e.g. DOMPurify).", "Set a strict Content-Security-Policy."]),
    "CWE-94": ("Code injection: data is executed as code.", "Full compromise of the process and its credentials.",
               ["Never pass untrusted data to eval/exec/Function.", "Parse data with a safe parser (json.loads) and validate it.", "Run any generated code in an isolated sandbox."]),
    "CWE-502": ("Unsafe deserialisation: a format that can execute code on load is read from an untrusted source.", "Remote code execution.",
                ["Use data-only formats (JSON, safetensors).", "For PyTorch use torch.load(..., weights_only=True).", "Verify signatures/checksums of artefacts before loading."]),
    "CWE-798": ("Hard-coded credential: a secret is committed to source control.", "Anyone with repository access, or any leak of it, can use the credential.",
                ["Revoke and rotate the credential now — deleting the line is not enough (it stays in git history).",
                 "Move it to a secret manager or environment variable.", "Add the pattern to pre-commit scanning."]),
    "CWE-295": ("TLS certificate verification is disabled.", "Traffic can be intercepted and modified (man-in-the-middle).",
                ["Remove verify=False / rejectUnauthorized:false.",  # myelin:ignore[NM-SAST-004] -- remediation text, not a call
                 "Trust a private CA through its certificate bundle instead."]),
    "CWE-327": ("Weak or broken cryptography.", "Data or signatures can be forged or decrypted.", ["Use SHA-256+ for hashing, AES-GCM or ChaCha20-Poly1305 for encryption, and a password KDF (Argon2/bcrypt) for passwords."]),
    "CWE-918": ("Server-side request forgery: the server fetches a URL the caller controls.", "Access to internal services and cloud metadata credentials.",
                ["Allow-list destination hosts.", "Block private and link-local addresses after DNS resolution.", "Disable redirects to untrusted hosts."]),
    "CWE-639": ("Broken object-level authorisation: one user can access another user's object by changing an identifier.",
                "Data of other customers is read or changed.", ["Check ownership of the object on every request, server-side.", "Use unguessable identifiers only as a defence in depth."]),
    "CWE-1427": ("Prompt injection: untrusted text is mixed into the model's instructions.", "The model can be told to ignore its rules, leak data or misuse tools.",
                 ["Keep instructions in the system message and untrusted input in a separate user message.", "Constrain tools and outputs with allow-lists and schemas.",
                  "Treat the model's output as untrusted."]),
    "CWE-250": ("Excessive privilege: a component runs with more rights than it needs.", "A single flaw gives the attacker those rights.",
                ["Run as a non-root user.", "Grant only the capabilities and tools required.", "Require human approval for side-effecting agent tools."]),
    "CWE-1104": ("Unmaintained or unpinned third-party component.", "A compromised or changed upstream release runs in your environment.",
                 ["Pin exact versions or digests.", "Review upgrades through pull requests."]),
}
ENGINE_KB = {
    "sca": ("A third-party package version with a published vulnerability.", "Attackers use public exploit details against unpatched versions.",
            ["Upgrade to the fixed version (or later).", "If no fix exists, check whether the vulnerable function is used and add a compensating control.",
             "Record a VEX statement if the vulnerability does not affect your product."]),
    "iac": ("An infrastructure or container setting that weakens isolation or exposes a service.", "Easier lateral movement, privilege escalation or data exposure.",
            ["Apply the secure setting in the template, not by hand in the console.", "Add a policy check so it cannot regress."]),
    "cicd": ("A pipeline weakness that can let an attacker change what is built or deployed.", "A backdoored build or a deployment without review.",
             ["Pin third-party actions to a commit SHA.", "Pass untrusted values through environment variables, never inline in run:.", "Use least-privilege tokens."]),
    "secrets": KB["CWE-798"],
    "license": ("A third-party licence that conflicts with your policy.", "Legal and commercial obligations, up to releasing your source code.",
                ["Replace the component, obtain a commercial licence, or record a reviewed exception."]),
    "aibom": KB["CWE-1427"],
    "dast": ("A weakness found by testing the running application.", "Directly exploitable from the network.",
             ["Fix the server-side control (authorisation, header, transport) and re-run the test."]),
    "supply": ("A software supply-chain attack path: a malicious or look-alike package, an unlocked or unverified dependency source, "
               "or a pipeline pattern used by npm/PyPI worms.",
               "Code an attacker controls runs on developer machines and CI runners and can steal tokens, publish backdoored "
               "releases and move into cloud accounts.",
               ["Follow the rule's remediation (remove the package, lock dependencies, pin sources, set a cooldown).",
                "If a malicious release was installed, rotate every secret the install could read and rebuild runners.",
                "Add the check as a required status so it cannot regress."]),
}


def _references(f):
    refs = []
    cve = f.get("cve")
    if cve:
        refs.append({"label": cve, "url": f"https://nvd.nist.gov/vuln/detail/{cve}"})
    cwe = str(f.get("cwe") or "").upper().replace("CWE-", "")
    if cwe.isdigit():
        refs.append({"label": f"CWE-{cwe}", "url": f"https://cwe.mitre.org/data/definitions/{cwe}.html"})
    if f.get("owasp_llm"):
        refs.append({"label": "OWASP Top 10 for LLM Applications", "url": "https://genai.owasp.org/llm-top-10/"})
    return refs


def _signals(f):
    why = []
    if f.get("kev"):
        why.append("listed in CISA KEV — exploited in the wild")
    if f.get("epss"):
        why.append(f"EPSS {float(f['epss']):.0%} probability of exploitation in the next 30 days")
    if f.get("reachable"):
        why.append("the vulnerable code is reachable from your application code")
    if f.get("exposure") == "internet":
        why.append("the service is internet-facing")
    if f.get("validated"):
        why.append("the credential pattern is high-confidence — treat it as live")
    if f.get("dependency_type") == "transitive" and f.get("introduced_by"):
        why.append(f"pulled in transitively by {f['introduced_by']}")
    return why or [f"severity {f.get('severity')} with risk score {f.get('mrs')}"]


def explain(f: dict) -> dict:
    what, impact, steps = KB.get(str(f.get("cwe") or "").upper()) or ENGINE_KB.get(f.get("engine")) or (
        "A security weakness reported by a RAT Flea DevSec rule.", "Depends on how the affected code is used.", ["Apply the remediation shown."])
    steps = list(steps)
    if f.get("fixed_version") and f.get("package"):
        steps.insert(0, f"Upgrade {f['package']} from {f.get('version')} to {f['fixed_version']} or later.")
    if f.get("remediation") and f["remediation"] not in steps:
        steps.append(f["remediation"])
    base = {"finding": f.get("id"), "summary": f"{f.get('title')} in {f.get('repo')} — {f.get('priority')} (risk score {f.get('mrs')}).",
            "what": what, "impact": impact, "why_it_matters": _signals(f), "steps": steps[:6], "fix": steps[0],
            "verify": "Push the fix or run `myelin scan`: the finding closes automatically when a scan of the same engine no longer reports it.",
            "references": _references(f), "source": "built-in", "model": "RAT Flea DevSec knowledge base"}
    out = _json(_llm("You are RAT Flea DevSec, an application security assistant for DevOps engineers. Answer with JSON only: "
                     '{"what": str, "impact": str, "steps": [str], "verify": str}. Be specific to the finding; at most 6 short steps; '
                     "do not invent CVE details that are not in the input.", json.dumps(_context(f))))
    if out and isinstance(out.get("steps"), list):
        base.update(what=str(out.get("what") or what)[:600], impact=str(out.get("impact") or impact)[:600],
                    steps=[str(x)[:300] for x in out["steps"]][:6] or base["steps"], verify=str(out.get("verify") or base["verify"])[:400],
                    source="llm", model=f"{provider()['provider']} · {provider()['model']}")
        base["fix"] = base["steps"][0]
    return base


TEST_PATH = re.compile(r"(^|/)(tests?|spec|__tests__|fixtures?|examples?|samples?|docs?|testdata|mocks?)(/|$)|(_test|\.test|\.spec|_spec)\.\w+$", re.I)
PLACEHOLDER = re.compile(r"(?i)(example|sample|dummy|placeholder|changeme|your[_-]?(key|token|password)|xxx+|<[^>]+>|\$\{[^}]+\}|test(ing)?[_-]?(key|token|secret))")


def triage(f: dict) -> dict:
    """Evidence-based suggestion. Never applied automatically."""
    fp, tp = [], []
    path = str(f.get("file") or "")
    if TEST_PATH.search(path):
        fp.append("the file is test, fixture, example or documentation code")
    if f.get("engine") == "secrets" and PLACEHOLDER.search(str(f.get("evidence") or "")):
        fp.append("the value looks like a placeholder or reference, not a real credential")
    if f.get("reachable") is False:
        fp.append("no import of the vulnerable package was found in first-party code")
    if f.get("dependency_type") in ("development", "dev", "test"):
        fp.append("development-only dependency (not shipped)")
    if path.endswith((".md", ".rst", ".txt", ".adoc")):
        fp.append("the match is in documentation")
    if f.get("kev"):
        tp.append("known exploited in the wild (CISA KEV)")
    if f.get("validated"):
        tp.append("high-confidence credential pattern")
    if f.get("reachable"):
        tp.append("reachable from first-party code")
    if f.get("exposure") == "internet":
        tp.append("internet-facing service")
    if float(f.get("epss") or 0) >= 0.1:
        tp.append(f"high exploit probability (EPSS {float(f['epss']):.0%})")
    if f.get("engine") in ("dast",):
        tp.append("confirmed against the running application")
    if f.get("engine") in ("sast", "aibom", "iac", "cicd", "secrets") and not TEST_PATH.search(path) and not path.endswith((".md", ".rst", ".txt")):
        tp.append("in first-party production code or configuration (not tests or docs)")
    if f.get("severity") in ("critical", "high") and f.get("engine") in ("sast", "aibom"):
        tp.append("the rule matched a dangerous data flow on the same line (" + str(f.get("cwe") or f.get("rule_id")) + ")")
    if tp and len(tp) >= len(fp):
        verdict, conf = "likely_true_positive", min(0.95, 0.6 + 0.1 * len(tp))
    elif fp and not tp:
        verdict, conf = "likely_false_positive", min(0.9, 0.55 + 0.1 * len(fp))
    else:
        verdict, conf = "needs_review", 0.5
    action = {"likely_true_positive": "Fix within the SLA, or accept the risk with an expiry if a compensating control exists.",
              "likely_false_positive": "Review the evidence and, if you agree, mark it as a false positive with this reason.",
              "needs_review": "Assign an owner to confirm whether the code path is used in production."}[verdict]
    out = {"finding": f.get("id"), "verdict": verdict, "confidence": round(conf, 2), "for_real": tp, "against": fp,
           "suggested_action": action, "suggested_reason": "; ".join(fp) if verdict == "likely_false_positive" else None,
           "source": "built-in", "note": "A suggestion only: nothing is changed until a person records the decision."}
    llm = _json(_llm("You are an application security triage assistant. Given a finding and the evidence signals, answer JSON only: "
                     '{"verdict": "likely_true_positive"|"likely_false_positive"|"needs_review", "reason": str}. Be conservative: '
                     "prefer needs_review when unsure.", json.dumps({"finding": _context(f), "signals_for": tp, "signals_against": fp})))
    if llm and llm.get("verdict") in ("likely_true_positive", "likely_false_positive", "needs_review"):
        out.update(model_verdict=llm["verdict"], model_reason=str(llm.get("reason") or "")[:500], source="built-in + llm",
                   model=f"{provider()['provider']} · {provider()['model']}")
    return out


ENGINE_WORDS = {"secrets": ("secret", "credential", "password", "token", "api key", "key leak"), "sast": ("code", "sast", "injection", "xss"),
                "sca": ("dependenc", "package", "library", "cve", "vulnerab", "sca", "open source", "open-source"),
                "iac": ("iac", "terraform", "kubernetes", "k8s", "docker", "infrastructure", "helm"),
                "cicd": ("pipeline", "ci/cd", "cicd", "workflow", "github action", "deploy", "gitops", "argo"),
                "dast": ("api", "dast", "running app", "live app", "web app"), "aibom": ("ai", "llm", "model", "prompt", "agent", "mcp"),
                "license": ("licen",),
                "supply": ("supply-chain", "supply chain", "malicious", "typosquat", "worm", "slopsquat", "hallucinat", "install script",
                           "dependency confusion", "lockfile")}


def parse_question(q: str, repos: list[str]) -> dict:
    t = " " + q.lower() + " "
    flt = {}
    sev = [s for s in ("critical", "high", "medium", "low") if re.search(rf"\b{s}\b", t)]
    if sev:
        flt["severity"] = sev
    pri = re.findall(r"\bp([0-3])\b", t)
    if pri:
        flt["priority"] = [f"P{x}" for x in pri]
    eng = [e for e, ws in ENGINE_WORDS.items() if any(re.search(r"\b" + re.escape(w), t) for w in ws)]
    if "cve" in t and "sca" not in eng:
        eng.append("sca")
    if eng:
        flt["engine"] = eng
    if re.search(r"\b(kev|exploited|in the wild)\b", t):
        flt["kev"] = True
    m = re.search(r"\bssvc\s+(act|attend|track\*?)\b|\b(act now|act immediately)\b", t)
    if m:
        flt["ssvc"] = {"act": "Act", "attend": "Attend", "track": "Track", "track*": "Track*"}.get(m.group(1) or "act", "Act")
    if re.search(r"\breachable\b", t):
        flt["reachable"] = True
    if re.search(r"\b(internet|public|exposed)\b", t):
        flt["exposure"] = "internet"
    m = re.search(r"(older|more) than (\d+) ?(day|week|month)", t)
    if m:
        flt["min_age_days"] = int(m.group(2)) * {"day": 1, "week": 7, "month": 30}[m.group(3)]
    if re.search(r"\b(overdue|past (the )?sla|breach)", t):
        flt["sla_breached"] = True
    if re.search(r"\b(fixed|closed|resolved)\b", t):
        flt["status"] = "fixed"
    elif re.search(r"\b(accepted)\b", t):
        flt["status"] = "risk_accepted"
    cve = re.findall(r"cve-\d{4}-\d{4,}", t)
    if cve:
        flt["cve"] = [c.upper() for c in cve]
    for r in sorted(repos, key=len, reverse=True):
        rl = r.lower()
        if rl and (rl in t or rl.replace("-", " ") in t):
            flt.setdefault("repo", []).append(r)
    m = re.search(r"\b(?:in|for|of) (?:the )?package ([\w@/.:-]+)|\b([\w.-]+) package\b", t)
    if m:
        flt["package"] = (m.group(1) or m.group(2)).strip(".")
    return flt


def apply_filters(findings, flt):
    out = []
    for f in findings:
        if f.get("status", "open") != flt.get("status", "open"):
            continue
        if "severity" in flt and f.get("severity") not in flt["severity"]:
            continue
        if "priority" in flt and f.get("priority") not in flt["priority"]:
            continue
        if "engine" in flt and f.get("engine") not in flt["engine"] and not (f.get("engine") == "container" and "sca" in flt["engine"]):
            continue
        if flt.get("kev") and not f.get("kev"):
            continue
        if flt.get("ssvc") and (f.get("ssvc") or {}).get("decision") != flt["ssvc"]:
            continue
        if flt.get("reachable") and not f.get("reachable"):
            continue
        if flt.get("exposure") and f.get("exposure") != flt["exposure"]:
            continue
        if "min_age_days" in flt and (f.get("age_days") or 0) < flt["min_age_days"]:
            continue
        if flt.get("sla_breached") and not ((f.get("age_days") or 0) > (f.get("sla_days") or 10 ** 6)):
            continue
        if "cve" in flt and str(f.get("cve") or "").upper() not in flt["cve"]:
            continue
        if "repo" in flt and f.get("repo") not in flt["repo"]:
            continue
        if "package" in flt and flt["package"] not in str(f.get("package") or "").lower():
            continue
        out.append(f)
    return out


def describe(flt):
    parts = []
    if flt.get("status", "open") != "open":
        parts.append(flt["status"].replace("_", " "))
    else:
        parts.append("open")
    for k, lab in (("priority", None), ("severity", None)):
        if flt.get(k):
            parts.append("/".join(flt[k]))
    if flt.get("engine"):
        parts.append({"sca": "dependency", "sast": "code", "iac": "infrastructure", "cicd": "pipeline", "dast": "live-app", "aibom": "AI",
                      "license": "licence", "secrets": "secret", "supply": "supply-chain"}.get(flt["engine"][0], flt["engine"][0]) + (" (+ more areas)" if len(flt["engine"]) > 1 else ""))
    parts.append("findings")
    if flt.get("kev"):
        parts.append("that are known exploited")
    if flt.get("ssvc"):
        parts.append(f"with SSVC decision {flt['ssvc']}")
    if flt.get("reachable"):
        parts.append("reachable from code")
    if flt.get("exposure"):
        parts.append("on internet-facing services")
    if flt.get("repo"):
        parts.append("in " + ", ".join(flt["repo"]))
    if flt.get("package"):
        parts.append(f"in package {flt['package']}")
    if flt.get("cve"):
        parts.append("for " + ", ".join(flt["cve"]))
    if flt.get("min_age_days"):
        parts.append(f"older than {flt['min_age_days']} days")
    if flt.get("sla_breached"):
        parts.append("past their SLA")
    return " ".join(parts)


def ask(question: str, findings: list[dict], repos: list[str]) -> dict:
    flt, source = parse_question(question, repos), "built-in"
    llm = _json(_llm("Translate the user's question about security findings into a JSON filter. Allowed keys: severity [critical|high|medium|low], "
                     "priority [P0..P3], engine [sca|sast|secrets|iac|cicd|dast|aibom|license|supply], kev bool, ssvc Act|Attend|Track*|Track, reachable bool, exposure 'internet', "
                     "min_age_days int, sla_breached bool, status open|fixed|risk_accepted, cve [str], repo [str from the list], package str. "
                     "Answer JSON only.", json.dumps({"question": redact(question)[:500], "repositories": repos[:200]}), max_tokens=300))
    if isinstance(llm, dict) and llm:
        clean = {k: v for k, v in llm.items() if k in {"severity", "priority", "engine", "kev", "reachable", "exposure", "min_age_days",
                                                       "sla_breached", "status", "cve", "repo", "package", "ssvc"}}
        if "repo" in clean:
            clean["repo"] = [r for r in (clean["repo"] if isinstance(clean["repo"], list) else [clean["repo"]]) if r in repos]
            if not clean["repo"]:
                clean.pop("repo")
        if clean:
            flt, source = clean, "llm"
    hits = sorted(apply_filters(findings, flt), key=lambda f: -(f.get("mrs") or 0))
    by_repo = Counter(f.get("repo") for f in hits).most_common(5)
    by_sev = Counter(f.get("severity") for f in hits)
    answer = (f"{len(hits)} {describe(flt)}." + (f" Most are in {', '.join(f'{r} ({n})' for r, n in by_repo[:3])}." if hits else "")
              + (f" {by_sev.get('critical', 0)} critical, {by_sev.get('high', 0)} high." if hits else ""))
    if hits:
        top = hits[0]
        answer += f" Start with {top.get('id')}: {top.get('title')} in {top.get('repo')} (risk score {top.get('mrs')})."
    return {"question": question, "interpretation": describe(flt), "filters": flt, "count": len(hits), "answer": answer,
            "findings": hits[:25], "source": source}


def briefing(s: dict) -> dict:
    k = s.get("kpis", {})
    sla = s.get("sla") or {}
    t = s.get("trend") or []
    first, last = (t[0]["open"], t[-1]["open"]) if len(t) >= 2 else (None, None)
    trend = (f"Open findings went from {first} to {last} over the last {len(t)} days "
             f"({'down' if last < first else 'up' if last > first else 'flat'} {abs(last - first)})." if first is not None else "")
    gaps = [f["name"] for f in (s.get("frameworks") or []) if f.get("gaps")][:4]
    cves = [c["id"] for c in (s.get("top_cves") or []) if c.get("kev")][:3]
    paras = [
        f"Security posture is {k.get('posture_score')}/100 with {k.get('open_findings')} open findings, {k.get('p0')} of them P0 (fix today) and "
        f"{k.get('p1')} P1. {trend}".strip(),
        f"{sla.get('compliance_pct', 100)}% of open findings are within their remediation SLA; {sla.get('breached', 0)} are past target. "
        f"Mean time to remediate is {k.get('mttr_days') or '—'} days and {k.get('fixed_30d', 0)} findings were fixed in the last 30 days.",
        (f"{s.get('kev_open', 0)} known-exploited vulnerabilities are open" + (f", led by {', '.join(cves)}" if cves else "") + ". "
         + (f"Framework gaps remain against {', '.join(gaps)}." if gaps else "No framework gaps are open.")),
        ("Recommended focus: close the P0 queue, apply the top upgrades in the DevOps upgrade plan"
         + (f" (starting with {s['upgrades'][0]['package']} → {s['upgrades'][0]['to']}, which closes {s['upgrades'][0]['closes']} findings)" if s.get("upgrades") else "")
         + ", and bring SLA breaches to zero."),
    ]
    out = {"paragraphs": paras, "source": "built-in", "generated_from": "stored scan data"}
    figures = {"posture": k.get("posture_score"), "open": k.get("open_findings"), "p0": k.get("p0"), "p1": k.get("p1"),
               "sla_pct": sla.get("compliance_pct"), "breached": sla.get("breached"), "mttr_days": k.get("mttr_days"),
               "kev_open": s.get("kev_open"), "framework_gaps": gaps, "trend": trend, "top_upgrade": (s.get("upgrades") or [None])[0]}
    llm = _json(_llm("Write a short executive security briefing for a CISO from these figures. Use only the numbers given; do not invent any. "
                     'Answer JSON only: {"paragraphs": [str, str, str]}.', json.dumps(figures, default=str), max_tokens=600))
    if llm and isinstance(llm.get("paragraphs"), list) and llm["paragraphs"]:
        out.update(paragraphs=[str(p)[:800] for p in llm["paragraphs"]][:4], source="llm", model=f"{provider()['provider']} · {provider()['model']}")
    return out
