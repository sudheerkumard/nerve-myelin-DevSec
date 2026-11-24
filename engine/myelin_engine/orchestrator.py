# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Scan orchestrator: runs built-in engines + any installed OSS scanners, normalises, de-dupes, scores."""
import json
import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from . import vulndb
from . import (ai_security, builtin_rules, cd_posture, cicd_posture, crypto_inventory, iac_checks, normalize, repo_posture, sbom,
               secrets, suppress, supply_chain)
from .scoring import enrich

EXTERNAL = {
    # tool: (argv builder, normaliser)
    "trivy": (lambda p: ["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,misconfig,secret", p], normalize.trivy),
    "gitleaks": (lambda p: ["gitleaks", "detect", "--no-banner", "--source", p, "--report-format", "json", "--report-path", "/dev/stdout"], normalize.gitleaks),
    "checkov": (lambda p: ["checkov", "-d", p, "-o", "json", "--quiet", "--skip-download"], normalize.checkov),   # never contacts a vendor service
    # Bandit (Apache-2.0) ships with NERvvE DevSecOps for Python analysis; tests, virtualenvs and vendored code excluded
    "bandit": (lambda p: ["bandit", "-r", p, "-f", "json", "-q", "-x",
                          ",".join(f"{p}/{d}" for d in ("tests", "test", ".venv", "venv", "node_modules", "vendor", "build", "dist"))
                          + ",*/tests/*,*/test/*,*/.venv/*,*/node_modules/*"], normalize.bandit),
}


# Semgrep/Opengrep run ONLY with a rule set NERvvE or the customer owns or has licensed, passed via
# MYELIN_SAST_RULES (file or directory). Never use `--config auto` or the Semgrep Registry: those rules are
# under the Semgrep Rules License v1.0, which forbids use in competing commercial products and SaaS.
SAST_RULES = os.getenv("MYELIN_SAST_RULES")
if SAST_RULES:
    for _bin in ("opengrep", "semgrep"):
        EXTERNAL[_bin] = (lambda p, b=_bin: [b, "--config", SAST_RULES, "--json", "--quiet", "--metrics=off", p], normalize.semgrep)


def _run_external(tool, path, repo, timeout=600):
    argv, norm = EXTERNAL[tool]
    try:
        cp = subprocess.run(argv(path), capture_output=True, text=True, timeout=timeout)
        if not cp.stdout.strip():
            raise RuntimeError(f"scanner returned no machine-readable output (exit {cp.returncode})")
        document = json.loads(cp.stdout)
        if document is None:
            raise ValueError("scanner returned JSON null instead of a result document")
        return norm(document, repo)
    except Exception as e:  # noqa: BLE001
        # A scanner error is a first-class gate input. It must not look like a clean scan.
        return [{"engine": "meta", "rule_id": f"tool-error:{tool}",
                 "title": f"{tool} failed: {type(e).__name__}: {e}", "severity": "high",
                 "scanner_status": "required_error", "required": True, "repo": repo}]


DEFAULT_ENGINES = ("sca", "license", "sast", "secrets", "iac", "cicd", "aibom", "supply")


def scan(path: str, repo: str = "local", engines: list[str] | None = None, use_external: bool = True,
         criticality: float = 1.0) -> dict:
    t0 = time.time()
    engines = engines or list(DEFAULT_ENGINES)
    comps = sbom.inventory(path) if {"sca", "license"} & set(engines) else sbom.parse_manifests(path)
    findings: list[dict] = []
    jobs = []
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
                if shutil.which(tool):
                    tools_used.append(tool)
                    jobs.append(ex.submit(_run_external, tool, path, repo))
        for j in jobs:
            findings += j.result()
    if {"sca", "license"} & set(engines):
        # reachability hint: packages imported in first-party code
        findings += sbom.match_advisories(comps, repo, reachable_hint=_imported_packages(path, comps))
    findings = [f for f in findings if f.get("engine") in engines or f.get("engine") == "meta"]
    raw_count = sum(1 for f in findings if f.get("engine") != "meta")
    findings = _merge_duplicates(path, findings)
    merged_count = sum(1 for f in findings if f.get("engine") != "meta")
    findings, ignored = suppress.apply(path, findings)      # .myelinignore + governed inline suppressions
    seen, uniq = set(), []
    for f in findings:
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
    return {"repo": repo, "path": path, "duration_s": round(time.time() - t0, 2), "tools": tools_used,
            "components": len(comps), "ignored_by_path": ignored,
            "stats": {"raw": raw_count, "after_dedup": merged_count, "reported": sum(1 for f in uniq if f.get("engine") != "meta")},
            "sbom": attach_extensions(bom, posture, crypto), "findings": uniq, "posture": posture, "crypto": crypto,
            "intelligence": {"offline": vulndb.offline(), "sources": sorted(vulndb.STATUS["sources"]) or ["bundled advisory pack"],
                             "errors": sorted(vulndb.STATUS["errors"])[:10]}}


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


CHECKOV_EQUIVALENT = {   # Checkov checks that NERvvE DevSecOps's own IaC rules already report (same file)
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
    finding per (file, line, weakness), preferring NERvvE DevSecOps's own rule (richer remediation and autofix)."""
    root = os.path.abspath(path)
    for f in findings:
        fp = f.get("file") or ""
        if fp and os.path.isabs(fp) and os.path.abspath(fp).startswith(root):
            f["file"] = os.path.relpath(fp, root)
        elif fp.startswith(path.rstrip("/") + "/"):
            f["file"] = fp[len(path.rstrip("/")) + 1:]
    for f in findings:
        if f.get("file", "").startswith("/") and not os.path.exists(f["file"]):     # checkov: "/backend/Dockerfile"
            f["file"] = f["file"].lstrip("/")
    own_rules = {(f.get("file"), f.get("rule_id")) for f in findings if f.get("engine") == "iac"}
    findings = [f for f in findings if not str(f.get("rule_id", "")).startswith("CKV_SECRET")
                and not any((f.get("file"), r) in own_rules for r in CHECKOV_EQUIVALENT.get(f.get("rule_id"), ()))]
    own = {(f.get("file"), f.get("line"), f.get("cwe")) for f in findings
           if f.get("engine") == "sast" and not f.get("source_tool")}
    own_lines = {(f.get("file"), f.get("line")) for f in findings
                 if f.get("engine") in ("sast", "aibom", "secrets") and not f.get("source_tool")}
    out = []
    for f in findings:
        if f.get("source_tool") == "bandit" and ((f.get("file"), f.get("line"), f.get("cwe")) in own or
                                                  (f.get("file"), f.get("line")) in own_lines):
            continue
        out.append(f)
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

def scan_image(image: str, criticality: float = 1.0) -> dict:
    """Container image scan (OS + language packages, and embedded secrets with Trivy) via Trivy or Grype, normalised and scored."""
    t0 = time.time()
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
        raise SystemExit("neither trivy nor grype found on PATH — install one of them to scan container images")
    for f in fs:
        f["engine"] = "container" if f["engine"] == "sca" else f["engine"]
        f["image"] = image
        enrich(f, criticality)
    fs.sort(key=lambda f: -f["mrs"])
    return {"repo": image, "path": image, "duration_s": round(time.time() - t0, 2), "tools": [tool], "components": 0,
            "sbom": None, "findings": fs}
