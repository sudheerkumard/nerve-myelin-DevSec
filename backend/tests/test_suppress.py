# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from engine.myelin_engine import suppress  # noqa: E402


def _repo(files):
    d = tempfile.mkdtemp()
    for p, body in files.items():
        os.makedirs(os.path.dirname(os.path.join(d, p)) or d, exist_ok=True)
        open(os.path.join(d, p), "w").write(body)
    return d


def test_path_ignore_and_counts():
    d = _repo({".myelinignore": "# c\nfixtures/\n*.snap\n", "src/a.py": "x\n"})
    fs = [{"file": "fixtures/x.py", "rule_id": "R"}, {"file": "src/a.py", "rule_id": "R", "line": 1}, {"file": "t/b.snap", "rule_id": "R"}]
    kept, ignored = suppress.apply(d, fs)
    assert ignored == 2 and [f["file"] for f in kept] == ["src/a.py"]


def test_inline_requires_rule_and_reason():
    d = _repo({"a.py": "x = 1  # myelin:ignore[NM-1] -- documented test vector\n"
                       "y = 2  # myelin:ignore[NM-1]\n"
                       "# myelin:ignore[NM-2,NM-3] -- fixed by upstream WAF rule 991\n"
                       "z = 3\n"})
    fs = [{"file": "a.py", "line": 1, "rule_id": "NM-1"}, {"file": "a.py", "line": 2, "rule_id": "NM-1"},
          {"file": "a.py", "line": 4, "rule_id": "NM-3"}, {"file": "a.py", "line": 1, "rule_id": "NM-9"}]
    kept, _ = suppress.apply(d, fs)
    assert [f.get("status") for f in kept] == ["suppressed", None, "suppressed", None]
    assert kept[0]["suppression"]["reason"] == "documented test vector" and kept[2]["suppression"]["location"] == "a.py:3"


def test_suppressed_findings_do_not_block_gate():
    from engine.myelin_engine import policy
    f = {"severity": "critical", "status": "suppressed", "engine": "sast", "rule_id": "X", "kev": False, "mrs": 99}
    assert policy.evaluate([f])["decision"] == "pass"
