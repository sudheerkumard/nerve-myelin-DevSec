# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Emit reproducible precision/recall for the curated repository and SBOM benchmark."""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

from myelin_engine import __version__, orchestrator  # noqa: E402

BENCHMARK = ROOT / "engine" / "tests" / "benchmark"
LABEL_DOMAINS = {"NM-AI": "aibom", "NM-CD": "cicd", "NM-CICD": "cicd", "NM-IAC": "iac",
                 "NM-LIC": "license", "NM-SAST": "sast", "NM-SEC": "secrets", "NM-SUP": "supply"}


def label_domain(rule):
    prefix = rule.rsplit("-", 1)[0]
    return LABEL_DOMAINS[prefix] if prefix in LABEL_DOMAINS else "sca"


def measure(expected, observed):
    tp, fp, fn = len(expected & observed), len(observed - expected), len(expected - observed)
    return {
        "true_positive": tp, "false_positive": fp, "false_negative": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "unexpected": sorted(observed - expected, key=str),
        "missed": sorted(expected - observed, key=str),
    }


def report():
    labels = json.loads((BENCHMARK / "expected.json").read_text(encoding="utf-8"))
    res = orchestrator.scan(str(BENCHMARK / "corpus"), "benchmark", use_external=False)
    expected = {(row["rule"], row["file"], row["line"]) for row in labels["expected"]}
    observed = {}
    for f in res["findings"]:
        if f["engine"] != "meta":
            key = (f["rule_id"], (f.get("file") or "").replace("\\", "/"), f.get("line"))
            observed.setdefault(f["engine"], set()).add(key)
    findings = measure(expected, set().union(*observed.values()))
    domains = {domain: measure({key for key in expected if label_domain(key[0]) == domain}, observed.get(domain, set()))
               for domain in orchestrator.DEFAULT_ENGINES}
    purls = [c["purl"] for c in res["sbom"]["components"]]
    sbom = measure(set(labels["sbom"]), set(purls))
    sbom["duplicate_components"] = len(purls) - len(set(purls))
    errors = [f["title"] for f in res["findings"] if f["engine"] == "meta"]
    passed = not (findings["unexpected"] or findings["missed"] or sbom["unexpected"] or sbom["missed"]
                  or sbom["duplicate_components"] or errors
                  or any(d["unexpected"] or d["missed"] for d in domains.values()))
    return {"schema_version": 1, "scanner_version": __version__, "profile": "builtin-offline-bundled",
            "scope": "Labelled repository corpus only; external, runtime and cloud engines are excluded.",
            "findings": findings, "findings_by_domain": domains, "sbom_components": sbom, "scanner_errors": errors, "passed": passed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.environ["MYELIN_OFFLINE"] = "1"
    os.environ.pop("MYELIN_OSV_EXPORT_DIR", None)
    result = report()
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
