# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""A secret is reported as live only after its provider accepted it; validation is opt-in."""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))
from myelin_engine import secret_validation as SV, secrets  # noqa: E402
from myelin_engine.scoring import enrich  # noqa: E402

TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def _repo(tmp_path):
    (tmp_path / "deploy.sh").write_text(f"export GH_TOKEN={TOKEN}\n")
    return str(tmp_path)


def test_off_by_default_no_live_claim(tmp_path, monkeypatch):
    monkeypatch.delenv("MYELIN_VALIDATE_SECRETS", raising=False)
    f = next(x for x in secrets.scan_path(_repo(tmp_path)) if x["rule_id"] == "NM-SEC-002")
    assert f["validated"] is False and f["validation"] == "not_checked" and f["high_confidence"] is True
    enrich(f)
    assert f["ssvc"]["exploitation"] == "none"


def test_live_and_revoked(tmp_path, monkeypatch):
    monkeypatch.setenv("MYELIN_VALIDATE_SECRETS", "1")
    monkeypatch.delenv("MYELIN_OFFLINE", raising=False)
    seen = []
    monkeypatch.setattr(SV, "TRANSPORT", lambda m, u, h: (seen.append((u, h)), (200, b"{}"))[1])
    f = next(x for x in secrets.scan_path(_repo(tmp_path)) if x["rule_id"] == "NM-SEC-002")
    assert f["validated"] is True and "live" in f["evidence"] and TOKEN not in f["evidence"]
    assert seen == [("https://api.github.com/user", {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"})]
    enrich(f)
    assert f["ssvc"]["exploitation"] == "active"
    monkeypatch.setattr(SV, "TRANSPORT", lambda m, u, h: (401, b""))
    g = next(x for x in secrets.scan_path(_repo(tmp_path)) if x["rule_id"] == "NM-SEC-002")
    assert g["validated"] is False and g["validation"] == "revoked"
    monkeypatch.setattr(SV, "TRANSPORT", lambda m, u, h: (_ for _ in ()).throw(OSError("down")))
    assert SV.validate("NM-SEC-002", TOKEN) == "error" and SV.validate("NM-SEC-001", "AKIAX") == "unsupported"
    monkeypatch.setattr(SV, "TRANSPORT", lambda m, u, h: (200, b'{"ok": false}'))
    assert SV.validate("NM-SEC-004", "xoxb-1") == "revoked"
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    assert SV.validate("NM-SEC-002", TOKEN) == "not_checked"          # never leaves an air-gapped install
