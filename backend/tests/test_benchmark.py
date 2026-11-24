# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Accuracy gate. A labelled corpus of real weaknesses and safe look-alikes (engine/tests/benchmark/corpus):
  * every expected finding must be reported (no false negatives),
  * nothing else may be reported (no false positives),
  * no finding may land on a line marked `SAFE`, in a hardened file or in a test file — whichever engines run.
Changing a rule that alters these results requires a reviewed update of expected.json."""
import json
import os
import shutil
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))
from myelin_engine import orchestrator  # noqa: E402

CORPUS = os.path.join(ROOT, "engine", "tests", "benchmark", "corpus")
EXPECTED = json.load(open(os.path.join(ROOT, "engine", "tests", "benchmark", "expected.json")))["expected"]


def _key(f):
    return (f["rule_id"], (f.get("file") or "").replace("\\", "/"), f.get("line"))


def _scan(external):
    res = orchestrator.scan(CORPUS, "benchmark", use_external=external)
    return [f for f in res["findings"] if f["engine"] != "meta"]


def test_builtin_engines_exact_precision_and_recall(monkeypatch):
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    got = {_key(f) for f in _scan(external=False)}
    want = {(e["rule"], e["file"], e["line"]) for e in EXPECTED}
    missed, extra = sorted(want - got, key=str), sorted(got - want, key=str)
    tp = len(want & got)
    precision, recall = tp / max(1, len(got)), tp / max(1, len(want))
    print(f"\nbenchmark: {tp} true positives, {len(extra)} false positives, {len(missed)} false negatives; "
          f"precision {precision:.2%}, recall {recall:.2%}")
    assert not missed, f"false negatives (expected but not reported): {missed}"
    assert not extra, f"false positives (reported but not expected): {extra}"


def _safe_lines():
    marks = set()
    for dp, _, files in os.walk(CORPUS):
        for fn in files:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, CORPUS).replace("\\", "/")
            for i, ln in enumerate(open(p, encoding="utf-8", errors="ignore"), 1):
                if "SAFE" in ln:
                    marks.add((rel, i))
    return marks


@pytest.mark.skipif(not shutil.which("bandit"), reason="bandit not installed")
def test_bundled_engines_never_flag_safe_code(monkeypatch):
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    fs = _scan(external=True)
    safe = _safe_lines()
    bad = [_key(f) for f in fs if ((f.get("file") or "").replace("\\", "/"), f.get("line")) in safe
           or (f.get("file") or "").replace("\\", "/").startswith(("tests/", "deploy/Dockerfile.hardened"))]
    assert not bad, f"findings on code marked SAFE / hardened / tests: {bad}"
    hardened = [f for f in fs if "Deployment/hardened" in f.get("title", "")]
    assert not hardened, hardened
