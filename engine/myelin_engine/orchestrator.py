# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Scan orchestrator: runs built-in engines + any installed OSS scanners, normalises, de-dupes, scores."""
import json
from collections import defaultdict
import os
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import coverage, eol, licence_scan, platform_scan, precision, vulndb, remediation
from . import (ai_security, builtin_rules, cd_posture, cicd_posture, crypto_inventory, iac_checks, normalize, repo_posture, sbom,
               secrets, suppress, supply_chain)
from .scoring import enrich

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules", "sast")
CACHE_DIR = os.environ.get("MYELIN_CACHE_DIR") or os.path.join(tempfile.gettempdir(), "myelin-cache")
TRIVY_CACHE = os.environ.get("MYELIN_TRIVY_CACHE") or os.path.join(CACHE_DIR, "trivy")


def _tool_env():
    """Scanners need a writable home and cache (Opengrep unpacks itself, Trivy keeps its vulnerability database); the
    platform image has a read-only root file system, so both live in the cache volume."""
    home = os.path.join(CACHE_DIR, "home")
    os.makedirs(home, exist_ok=True)
    return {**os.environ, "HOME": home, "XDG_CACHE_HOME": CACHE_DIR, "SEMGREP_SEND_METRICS": "off",
            "OPENGREP_SEND_METRICS": "off", "CHECKOV_RUN_SCA_PACKAGE_SCAN_V2": "false", "BC_SKIP_MAPPING": "TRUE"}
SAST_EXCLUDES = ["tests", "test", "__tests__", "spec", "testdata", "fixtures", "node_modules", "vendor", "dist", "build",
                 ".venv", "venv", "*.min.js", "*.bundle.js", "*.map"]


def _trivy_domains(engines):
    domains = {"sca", "iac", "secrets"} & set(engines)
    if vulndb.offline() and not os.path.exists(os.path.join(TRIVY_CACHE, "db", "trivy.db")):
        domains.discard("sca")
    return sorted(domains)


def _trivy_argv(p, domains=None):
    domains = _trivy_domains(DEFAULT_ENGINES) if domains is None else domains
    scanners = ",".join({"sca": "vuln", "iac": "misconfig", "secrets": "secret"}[d] for d in domains)
    argv = ["trivy", "fs", "--quiet", "--format", "json", "--cache-dir", TRIVY_CACHE,
            "--timeout", "15m", "--skip-dirs", "**/node_modules", "--skip-dirs", "**/.git"]
    if vulndb.offline():
        argv += ["--skip-db-update", "--skip-java-db-update", "--offline-scan", "--skip-check-update"]
    return argv + ["--scanners", scanners, p]


def _sast_argv(binary):
    """Opengrep (or the Semgrep CE engine) with RAT Flea's own rule pack, plus any rule set the customer owns or has
    licensed (MYELIN_SAST_RULES). Never `--config auto` or the Semgrep Registry: those rules are under the Semgrep
    Rules License v1.0, which forbids use in competing commercial products and SaaS."""
    def build(p):
        argv = [binary, "scan", "--json", "--quiet", "--config", RULES_DIR, "--timeout", "30", "--timeout-threshold", "3",
                "--max-target-bytes", "2000000", "--jobs", str(max(1, min(4, os.cpu_count() or 1)))]
        if binary == "opengrep":
            argv += ["--taint-intrafile", "--dataflow-traces"]      # follow data through functions within a file
        else:
            argv += ["--metrics=off", "--disable-version-check"]
        if SAST_RULES:
            argv += ["--config", SAST_RULES]
        for x in SAST_EXCLUDES:
            argv += ["--exclude", x]
        return argv + [p]
    return build


def _gitleaks_argv(p):
    out = os.path.join(tempfile.mkdtemp(prefix="myelin-gl-"), "report.json")
    mode = ["git", p] if os.path.isdir(os.path.join(p, ".git")) else ["dir", p]
    return ["gitleaks", *mode, "--no-banner", "--no-color", "--report-format", "json", "--report-path", out,
            "--exit-code", "0", "--max-target-megabytes", "5"], out


EXTERNAL = {
    # tool: (argv builder, normaliser)
    "trivy": (_trivy_argv, normalize.trivy),
    "grype": (lambda p: ["grype", f"dir:{p}", "--output", "json", "--quiet"], normalize.grype),
    "gitleaks": (_gitleaks_argv, normalize.gitleaks),
    "checkov": (lambda p: ["checkov", "-d", p, "-o", "json", "--quiet", "--skip-download", "--compact",
                           "--skip-path", "node_modules", "--skip-path", "tests"], normalize.checkov),   # never contacts a vendor service
    # Bandit (Apache-2.0) ships with RAT Flea DevSec for Python analysis; tests, virtualenvs and vendored code excluded
    "bandit": (lambda p: ["bandit", "-r", p, "-f", "json", "-q", "-x",
                          ",".join(f"{p}/{d}" for d in ("tests", "test", ".venv", "venv", "node_modules", "vendor", "build", "dist"))
                          + ",*/tests/*,*/test/*,*/.venv/*,*/node_modules/*"], normalize.bandit),
}
SAST_RULES = os.getenv("MYELIN_SAST_RULES")
# deep SAST: Opengrep preferred (LGPL-2.1, intra-file taint across functions); the Semgrep CE engine works too
for _bin in ("opengrep", "semgrep"):
    if shutil.which(_bin):
        EXTERNAL[_bin] = (_sast_argv(_bin), normalize.semgrep)
        break


def _applies(tool, inv, engines):
    """Run a scanner only when the repository has something it analyses and one of its areas is selected."""
    langs = inv.get("languages") or {}
    if tool == "bandit":
        return "sast" in engines and "Python" in langs
    if tool in ("opengrep", "semgrep"):
        return "sast" in engines and bool(set(langs) & coverage.DEEP_SAST)
    if tool == "checkov":
        return "iac" in engines and bool(inv.get("iac"))
    if tool == "gitleaks":
        return "secrets" in engines
    if tool == "grype":
        return "sca" in engines and bool(inv.get("manifests"))
    if tool == "trivy":
        return bool(_trivy_domains(engines))
    return True


def rule_count() -> int:
    n = 0
    for fn in os.listdir(RULES_DIR) if os.path.isdir(RULES_DIR) else []:
        if fn.endswith((".yaml", ".yml")):
            with open(os.path.join(RULES_DIR, fn), encoding="utf-8") as fh:
                n += sum(1 for line in fh if line.startswith("  - id: "))
    return n


# A syntactically valid JSON object is not necessarily a scanner report.
_RESULT_ARRAY = {"opengrep": "results", "semgrep": "results", "bandit": "results", "grype": "matches"}


def _scanner_error(tool, repo, message):
    return {"engine": "meta", "rule_id": f"tool-error:{tool}", "title": f"{tool} failed: {message}",
            "severity": "high", "scanner_status": "required_error", "required": True, "repo": repo}


def _run_external(tool, path, repo, timeout=1800, *, run_info=None):
    argv, norm = EXTERNAL[tool]
    report = None
    try:
        built = _trivy_argv(path, run_info["domains"]) if tool == "trivy" and run_info and "domains" in run_info else argv(path)
        if isinstance(built, tuple):                     # (argv, report file) for tools that write a report file
            built, report = built
        cp = subprocess.run(built, capture_output=True, text=True, timeout=timeout, env=_tool_env())
        text = cp.stdout
        if report:
            text = open(report, encoding="utf-8").read() if os.path.exists(report) else ""
        if not text.strip():
            raise RuntimeError(f"scanner returned no machine-readable output (exit {cp.returncode}): {(cp.stderr or '').strip()[-300:]}")
        document = json.loads(text)
        if document is None:
            raise ValueError("scanner returned JSON null instead of a result document")
        array = _RESULT_ARRAY.get(tool)
        if array and (not isinstance(document, dict) or not isinstance(document.get(array), list)):
            raise ValueError(f"scanner report has no {array} array")
        if tool == "trivy" and (not isinstance(document, dict) or "SchemaVersion" not in document):
            raise ValueError("scanner report has no Trivy schema version")
        if tool == "gitleaks" and not isinstance(document, list):
            raise ValueError("scanner report is not a Gitleaks findings array")
        if tool in ("opengrep", "semgrep") and isinstance(document, dict):
            document = precision.refine(document, path)  # drop flows proven infeasible; resolve configured algorithms
        if tool == "gitleaks" and isinstance(document, list):
            document = secrets.consolidate_gitleaks(document, path)  # one finding per secret, not per commit
        findings = norm(document, repo)
        if tool in ("bandit", "opengrep", "semgrep"):
            errors = document.get("errors") or []
            if errors:
                findings.append(_scanner_error(tool, repo, f"{len(errors)} errors reported while analyzing files"))
            if run_info is not None and tool in ("opengrep", "semgrep"):
                paths = document.get("paths") or {}
                if isinstance(paths.get("scanned"), list):
                    run_info["scanned_files"] = len(paths["scanned"])
        if tool == "semgrep":
            for f in findings:
                if f.get("source_tool") == "opengrep":
                    f["source_tool"] = tool
        # Bandit and Checkov use exit 1 for findings. The other configured
        # scanners use zero even when they find issues.
        if (tool in _RESULT_ARRAY or tool in ("trivy", "gitleaks", "checkov")) and cp.returncode not in (
            (0, 1) if tool in ("bandit", "checkov") else (0,)
        ):
            findings.append(_scanner_error(tool, repo, f"scanner exited with code {cp.returncode}"))
        return findings
    except Exception as e:  # noqa: BLE001
        # A scanner error is a first-class gate input. It must not look like a clean scan.
        return [_scanner_error(tool, repo, f"{type(e).__name__}: {e}")]
    finally:
        if report:
            shutil.rmtree(os.path.dirname(report), ignore_errors=True)


DEFAULT_ENGINES = ("sca", "license", "sast", "secrets", "iac", "cicd", "aibom", "supply")


def scan(path: str, repo: str = "local", engines: list[str] | None = None, use_external: bool = True,
         criticality: float = 1.0, *, advisory_lookup=None) -> dict:
    with vulndb.scan_intelligence():
        return _scan(path, repo, engines, use_external, criticality, advisory_lookup)


def _scan(path, repo, engines, use_external, criticality, advisory_lookup):
    t0 = time.time()
    started = datetime.now(timezone.utc)
    engines = engines or list(DEFAULT_ENGINES)
    comps = sbom.inventory(path, use_external) if {"sca", "license"} & set(engines) else sbom.parse_manifests(path)
    inv = coverage.inventory(path)
    findings: list[dict] = []
    jobs = []
    run_info = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        if "secrets" in engines:
            jobs.append(ex.submit(secrets.scan_path, path, repo))
        if "cicd" in engines:
            jobs.append(ex.submit(cicd_posture.scan_path, path, repo))
            jobs.append(ex.submit(cd_posture.scan_path, path, repo))
        if {"sast", "iac", "aibom"} & set(engines):
            jobs.append(ex.submit(builtin_rules.scan_path, path, repo))
        if "iac" in engines:
            jobs.append(ex.submit(iac_checks.scan_path, path, repo))
        if "aibom" in engines:
            jobs.append(ex.submit(ai_security.scan, path, repo))
        if "supply" in engines:
            jobs.append(ex.submit(supply_chain.scan, path, repo, comps))
        tools_used = ["myelin-builtin"]
        if use_external:
            for tool in EXTERNAL:
                if shutil.which(tool) and _applies(tool, inv, engines):
                    tools_used.append(tool)
                    run_info[tool] = {"domains": _trivy_domains(engines)} if tool == "trivy" else {}
                    jobs.append(ex.submit(_run_external, tool, path, repo, run_info=run_info[tool]))
        for j in jobs:
            findings += j.result()
    if {"sca", "license"} & set(engines):
        # reachability hint: packages imported in first-party code
        findings += sbom.match_advisories(comps, repo, reachable_hint=_imported_packages(path, comps),
                                           advisory_lookup=advisory_lookup if "sca" in engines else None)
    licensing = None
    platform_notes = []
    if "sca" in engines:
        findings += eol.scan(path, repo, comps)                      # end-of-life runtimes, images and frameworks
        # operating-system packages, native binaries, firmware, drivers, databases and middleware in IaC
        plat = platform_scan.scan(path, repo)
        findings += plat["findings"]
        if plat["language_components"]:                              # Go/Rust/Android components inside binaries
            findings += sbom.match_advisories(plat["language_components"], repo)
        comps = comps + plat["language_components"] + plat["components"]
        platform_notes = plat["notes"]
    if "license" in engines:
        licensing = licence_scan.inventory(path)                     # licence texts, SPDX headers, project licence
        lic_found = licence_scan.findings(path, repo, comps, licensing)
        conflicted = {f.get("package") for f in lic_found if f["rule_id"] == "NM-LIC-103"}
        findings = [f for f in findings if not (f.get("rule_id") == "NM-LIC-001" and f.get("package") in conflicted)]
        findings += lic_found
    findings = [f for f in findings if f.get("engine") in engines or f.get("engine") == "meta"]
    raw_count = sum(1 for f in findings if f.get("engine") != "meta")
    # Capture coverage evidence before deduplication or suppressions can hide it.
    detected = findings
    findings = _merge_duplicates(path, findings)
    merged_count = sum(1 for f in findings if f.get("engine") != "meta")
    findings, ignored = suppress.apply(path, findings)      # .myelinignore + governed inline suppressions
    seen, uniq = set(), []
    for f in findings:
        remediation.enrich_finding(f)
        enrich(f, criticality)
        if f["fingerprint"] not in seen:
            seen.add(f["fingerprint"])
            uniq.append(f)
    uniq.sort(key=lambda f: -f["mrs"])
    crypto = crypto_inventory.scan(path)
    posture = repo_posture.assess(path, uniq)
    bom = sbom.cyclonedx(comps, repo)
    bom["metadata"]["properties"] += [
        {"name": "myelin:posture", "value": json.dumps({"score": posture["score"], "grade": posture["grade"]})},
    ]
    inv["git_history"] = "gitleaks" in tools_used and os.path.isdir(os.path.join(path, ".git"))
    intel_status = vulndb.scan_status()
    intel = {"offline": vulndb.offline(), "sources": sorted(intel_status["sources"] | (
        {"bundled advisory pack"} if "sca" in engines and comps else set())), "errors": sorted(intel_status["errors"]),
             "resolution": sorted(intel_status.get("resolution") or []), "notes": platform_notes}
    cov = coverage.build(inv, engines, tools_used, uniq, len(comps), intel,
                         deep_rules=rule_count() if {"opengrep", "semgrep"} & set(tools_used) else 0,
                         run_info=run_info, detected=detected, use_external=use_external)
    return {"repo": repo, "path": path, "started_at": started.isoformat(timespec="seconds"),
            "duration_s": round(time.time() - t0, 2), "tools": tools_used,
            "coverage": cov, "engines": coverage.assessed(cov),
            "tool_versions": {t: coverage.tool_version(t) for t in tools_used if t != "myelin-builtin"},
            "components": len(comps), "ignored_by_path": ignored,
            "stats": {"raw": raw_count, "after_dedup": merged_count, "reported": sum(1 for f in uniq if f.get("engine") != "meta")},
            "sbom": attach_extensions(bom, posture, crypto), "findings": uniq, "posture": posture, "crypto": crypto, "licensing": licensing,
            "intelligence": intel}


def attach_extensions(bom: dict, posture: dict | None, crypto: list | None) -> dict:
    """Carry the repository posture and cryptography inventory inside the stored SBOM (CycloneDX metadata properties),
    so every ingestion path (CLI upload, one-click scan, import) keeps them without a schema change."""
    props = [p for p in (bom.get("metadata") or {}).get("properties", []) if p.get("name") not in ("myelin:posture-detail", "myelin:crypto")]
    if posture is not None:
        props.append({"name": "myelin:posture-detail", "value": json.dumps(posture, separators=(",", ":"))})
    if crypto is not None:
        props.append({"name": "myelin:crypto", "value": json.dumps(crypto, separators=(",", ":"))})
    bom.setdefault("metadata", {})["properties"] = props
    return bom


def extensions(bom: dict | None) -> dict:
    """{"posture": ..., "crypto": [...]} read back from a stored SBOM (empty when the scan predates them)."""
    out = {"posture": None, "crypto": None}
    for p in ((bom or {}).get("metadata") or {}).get("properties", []) or []:
        try:
            if p.get("name") == "myelin:posture-detail":
                out["posture"] = json.loads(p["value"])
            elif p.get("name") == "myelin:crypto":
                out["crypto"] = json.loads(p["value"])
        except (ValueError, TypeError, KeyError):
            continue
    return out


CHECKOV_EQUIVALENT = {   # Checkov checks that RAT Flea DevSec's own IaC rules already report (same file)
    "CKV_DOCKER_2": ("NM-IAC-011",), "CKV_DOCKER_3": ("NM-IAC-010",), "CKV_DOCKER_8": ("NM-IAC-010",),
    "CKV_DOCKER_7": ("NM-IAC-012",), "CKV2_DOCKER_16": ("NM-IAC-013",), "CKV2_DOCKER_2": ("NM-IAC-013",),
    "CKV_K8S_43": ("NM-IAC-039",), "CKV_K8S_14": ("NM-IAC-039",), "CKV_K8S_38": ("NM-IAC-032",),
    "CKV_K8S_16": ("NM-IAC-033",), "CKV_K8S_20": ("NM-IAC-034",), "CKV_K8S_23": ("NM-IAC-035",), "CKV_K8S_40": ("NM-IAC-035",),
    "CKV_K8S_22": ("NM-IAC-036",), "CKV_K8S_28": ("NM-IAC-037",), "CKV_K8S_37": ("NM-IAC-037",),
    "CKV_K8S_10": ("NM-IAC-038",), "CKV_K8S_11": ("NM-IAC-038",), "CKV_K8S_12": ("NM-IAC-038",), "CKV_K8S_13": ("NM-IAC-038",),
    "CKV_K8S_17": ("NM-IAC-030",), "CKV_K8S_18": ("NM-IAC-030",), "CKV_K8S_19": ("NM-IAC-030",),
}


def _merge_duplicates(path, findings):
    """External tools report paths their own way and overlap with built-in rules: normalise paths and keep one
    finding per (file, line, weakness), preferring RAT Flea DevSec's own rule (richer remediation and autofix)."""
    root = os.path.abspath(path)
    for f in findings:
        fp = f.get("file") or ""
        if fp and os.path.isabs(fp) and os.path.normcase(os.path.abspath(fp)).startswith(os.path.normcase(root.rstrip(os.sep) + os.sep)):
            f["file"] = os.path.relpath(fp, root)
        elif fp.startswith(path.rstrip("/") + "/"):
            f["file"] = fp[len(path.rstrip("/")) + 1:]
    for f in findings:
        if (f.get("file") or "").startswith("/") and not os.path.exists(f["file"]):     # checkov: "/backend/Dockerfile"
            f["file"] = f["file"].lstrip("/")
    own_rules = {(f.get("file"), f.get("rule_id")) for f in findings if f.get("engine") == "iac"}
    findings = [f for f in findings if not str(f.get("rule_id", "")).startswith("CKV_SECRET")
                and not any((f.get("file"), r) in own_rules for r in CHECKOV_EQUIVALENT.get(f.get("rule_id"), ()))]
    own = {(f.get("file"), f.get("line"), f.get("cwe")) for f in findings
           if f.get("engine") == "sast" and not f.get("source_tool") and f.get("cwe")}
    # Deep (taint) SAST results replace a pattern match for the same weakness on the same line; the pattern rule id is
    # kept as an alias so existing suppressions still apply
    deep = {}
    for f in findings:
        if f.get("source_tool") in ("opengrep", "semgrep") and f.get("cwe"):
            deep.setdefault((f.get("file"), f.get("line"), f.get("cwe")), f)
    by_alias = {(f.get("file"), f.get("line"), a): f for f in findings if f.get("source_tool") == "opengrep"
                for a in f.get("rule_aliases") or []}
    out = []
    for f in findings:
        key = (f.get("file"), f.get("line"), f.get("cwe"))
        akey = (f.get("file"), f.get("line"), f.get("rule_id"))
        if f.get("engine") == "sast" and not f.get("source_tool") and (key in deep or akey in by_alias):
            d = deep.get(key) or by_alias[akey]
            d["rule_aliases"] = sorted(set(d.get("rule_aliases") or []) | {f.get("rule_id")})
            if f.get("autofix") and not d.get("autofix"):
                d["autofix"] = f["autofix"]
            continue
        if f.get("source_tool") == "bandit" and (key in own or key in deep):
            continue
        out.append(f)
    # Secrets: one finding per line; RAT Flea's own rule carries validation and the rotation workflow
    own_secret = {(f.get("file"), f.get("line")) for f in out if f.get("engine") == "secrets" and not f.get("source_tool")}
    gl_secret = {(f.get("file"), f.get("line")) for f in out if f.get("source_tool") == "gitleaks"}
    near = lambda f, pool: any(f.get("file") == p[0] and abs((f.get("line") or 0) - (p[1] or 0)) <= 2 for p in pool)  # noqa: E731
    out = [f for f in out if not (f.get("engine") == "secrets" and f.get("source_tool") in ("gitleaks", "trivy")
                                  and (near(f, own_secret)
                                       or (f.get("source_tool") == "trivy" and (f.get("file"), f.get("line")) in gl_secret)))]
    # Correlate OSV, Trivy and Grype by package identity, exact version and advisory aliases.
    # Keep the richest RAT Flea/OSV record, while retaining all contributing scanner names.
    def _ids(f):
        # advisory identities only: RAT Flea rule ids (NM-OS-001, NM-EOL-001, ...) name a check, not an advisory
        return {str(x).upper() for x in [f.get("cve"), f.get("rule_id"), f.get("advisory"),
                                         *(f.get("aliases") or [])] if x and not str(x).startswith("NM-")}

    def _package_key(f):
        purl = str(f.get("purl") or "").lower().split("?", 1)[0]
        if purl:
            return purl
        return (str(f.get("ecosystem") or "").lower(),
                str(f.get("package") or "").strip().lower(),
                str(f.get("version") or ""))

    sca_groups = defaultdict(list)
    for f in out:
        if f.get("engine") == "sca":
            sca_groups[(_package_key(f), str(f.get("version") or ""))].append(f)
    duplicate_ids = set()
    for group in sca_groups.values():
        group.sort(key=lambda f: {"": 0, "osv": 0, "myelin": 0, "grype": 1, "trivy": 2}.get(
            str(f.get("source_tool") or "").lower(), 3))
        retained = []
        for finding in group:
            ids = _ids(finding)
            match = next((prior for prior in retained if ids and ids & _ids(prior)), None)
            if match is None:
                retained.append(finding)
                continue
            sources = set(match.get("scanner_sources") or [])
            sources.add(finding.get("source_tool") or "RAT Flea advisory engine")
            sources.update(finding.get("scanner_sources") or [])
            match["scanner_sources"] = sorted(sources)
            duplicate_ids.add(id(finding))
    out = [f for f in out if id(f) not in duplicate_ids]
    # an AI-specific rule explains the same line better than the generic SAST rule (the input is model output);
    # a secret in an MCP config is reported once, by the secrets engine (rotation workflow, validation)
    ai_lines = {(f.get("file"), f.get("line")) for f in out if f.get("engine") == "aibom" and f.get("rule_id") != "NM-AI-024"}
    secret_lines = {(f.get("file"), f.get("line")) for f in out if f.get("engine") == "secrets"}
    ioc_lines = {(f.get("file"), f.get("line")) for f in out if f.get("rule_id") == "NM-SUP-010"}
    merged = []
    for f in out:
        key = (f.get("file"), f.get("line"))
        if f.get("rule_id") == "NM-CICD-013" and key in ioc_lines:     # the exfiltration indicator explains it
            continue
        if f.get("engine") == "sast" and key in ai_lines and not f.get("source_tool"):
            continue
        if f.get("rule_id") == "NM-AI-024" and key in secret_lines:
            continue
        merged.append(f)
    for f in merged:                                     # the secret carries its AI context
        if f.get("engine") == "secrets" and str(f.get("file", "")).endswith("mcp.json"):
            f.setdefault("owasp_llm", "LLM02")
    return merged


def _imported_packages(path, comps):
    """Return conservative import evidence across common source ecosystems.

    This is a static import signal, not a complete call graph or proof of exploitability.
    Missing or ambiguous evidence remains unknown, never unreachable.
    """
    import os
    import re

    lang_eco = {
        ".py": "pypi",
        ".js": "npm", ".jsx": "npm", ".mjs": "npm", ".cjs": "npm",
        ".ts": "npm", ".tsx": "npm",
        ".java": "maven", ".kt": "maven", ".kts": "maven",
        ".scala": "maven", ".groovy": "maven",
        ".go": "go", ".rs": "cargo", ".cs": "nuget",
        ".php": "composer", ".rb": "gem", ".swift": "swift",
    }
    excluded = {
        ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "vendor",
        "dist", "build", "target", "bin", "obj", "__pycache__", ".next",
    }
    aliases = {
        "pyyaml": {"yaml"}, "scikit-learn": {"sklearn"},
        "pillow": {"PIL"}, "beautifulsoup4": {"bs4"},
        "python-dateutil": {"dateutil"}, "opencv-python": {"cv2"},
        "protobuf": {"google"}, "ruamel.yaml": {"ruamel"},
    }
    patterns = {
        "pypi": lambda t: rf"(?m)^\s*(?:from\s+{t}(?:\.|\s+import)\b|import\s+{t}\b)",
        "npm": lambda t: rf"""(?:from\s*|import\s*\(|require\s*\()\s*['"]{t}(?:/[^'"]*)?['"]""",
        "maven": lambda t: rf"(?m)^\s*import\s+(?:static\s+)?{t}(?:\.|\s*;)",
        "go": lambda t: rf"""(?m)import\s*(?:\(\s*)?['"]{t}(?:/[^'"]*)?['"]""",
        "cargo": lambda t: rf"(?m)^\s*(?:use|extern\s+crate)\s+{t}\b",
        "nuget": lambda t: rf"(?m)^\s*using\s+(?:static\s+)?{t}(?:\.|\s*;)",
        "composer": lambda t: rf"""(?m)^\s*(?:use\s+{t}(?:\\|\s*;)|require(?:_once)?\s*\(\s*['"][^'"]*{t}[^'"]*['"])""",
        "gem": lambda t: rf"""require(?:_relative)?\s*['"]{t}['"]""",
        "swift": lambda t: rf"(?m)^\s*import\s+(?:class\s+|struct\s+|enum\s+|protocol\s+)?{t}\b",
    }

    sources = {eco: [] for eco in set(lang_eco.values())}
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in excluded and not d.startswith(".")]
        for filename in files:
            ecosystem = lang_eco.get(os.path.splitext(filename)[1].lower())
            if not ecosystem:
                continue
            try:
                with open(os.path.join(root, filename), encoding="utf-8", errors="ignore") as stream:
                    sources[ecosystem].append(stream.read(2_000_000))
            except OSError:
                continue

    present = {eco for eco, files in sources.items() if files}
    hit, unknown = set(), set()
    for component in comps:
        name = str(component.get("name") or "").strip()
        ecosystem = str(component.get("ecosystem") or "").lower()
        if not name or ecosystem not in present:
            unknown.add(name)
            continue

        candidates = set(aliases.get(name.lower(), set()))
        tail = name.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
        candidates.add(tail)
        if ecosystem in {"npm", "cargo", "pypi"}:
            candidates.add(tail.replace("-", "_"))
        if ecosystem == "maven" and ":" in name:
            group, artifact = name.split(":", 1)
            candidates.add(group)
            candidates.add(group + "." + artifact.replace("-", "_"))
        if ecosystem == "nuget" and "." in name:
            candidates.add(name)

        matched = False
        factory = patterns.get(ecosystem)
        if factory:
            for candidate in candidates:
                if not candidate or len(candidate) < 2:
                    continue
                token = re.escape(candidate)
                if any(re.search(factory(token), source) for source in sources[ecosystem]):
                    hit.add(name)
                    matched = True
                    break
        if not matched:
            # Dynamic imports, reflection, generated bindings and namespace/package
            # mismatches make a negative text match insufficient to prove non-reachability.
            unknown.add(name)
    return hit, unknown

def scan_image_archive(archive: str, criticality: float = 1.0) -> dict:
    """Built-in image scan without Docker or Trivy: unpack a docker-save/OCI archive (or OCI layout directory) and scan
    its root filesystem (OS packages, language packages, binaries, secrets), offline or online."""
    import tempfile

    from . import image_tar
    t0 = time.time()
    tmp = tempfile.mkdtemp(prefix="myelin-image-")
    try:
        meta = image_tar.unpack(archive, tmp)
        name = next((t for t in meta.get("repo_tags") or [] if t), os.path.basename(archive.rstrip("/")))
        res = scan(tmp, repo=name, engines=["sca", "secrets", "supply", "iac"], use_external=False, criticality=criticality)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for f in res["findings"]:
        if f.get("engine") == "sca":
            f["engine"] = "container"
        f["image"] = name
    res.update(path=archive, duration_s=round(time.time() - t0, 2), image_layers=meta.get("layers"),
               tools=["myelin-builtin (image archive)"])
    res["engines"] = sorted({f["engine"] for f in res["findings"] if f.get("engine")} | {"container"})
    return res


def scan_image(image: str, criticality: float = 1.0) -> dict:
    """Container image scan (OS + language packages, and embedded secrets with Trivy) via Trivy or Grype, normalised and scored.
    An image archive file or OCI layout directory is scanned with the built-in scanners when neither tool is installed
    (or when MYELIN_IMAGE_BUILTIN=1)."""
    t0 = time.time()
    if os.path.exists(image) and (os.environ.get("MYELIN_IMAGE_BUILTIN") == "1" or not (shutil.which("trivy") or shutil.which("grype"))):
        return scan_image_archive(image, criticality)
    if shutil.which("trivy"):
        tool = "trivy"
        cp = subprocess.run(["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln,secret", image],
                            capture_output=True, text=True, timeout=900)
        fs = normalize.trivy(json.loads(cp.stdout or "{}"), image)
    elif shutil.which("grype"):
        tool = "grype"
        cp = subprocess.run(["grype", image, "-o", "json", "-q"], capture_output=True, text=True, timeout=900)
        fs = normalize.grype(json.loads(cp.stdout or "{}"), image)
    else:
        raise SystemExit("neither trivy nor grype found on PATH: install one of them to scan images from a registry, or scan "
                         "an image archive (docker save -o image.tar IMAGE) with the built-in scanner")
    for f in fs:
        f["engine"] = "container" if f["engine"] == "sca" else f["engine"]
        f["image"] = image
        enrich(f, criticality)
    fs.sort(key=lambda f: -f["mrs"])
    return {"repo": image, "path": image, "duration_s": round(time.time() - t0, 2), "tools": [tool], "components": 0,
            "sbom": None, "findings": fs}
