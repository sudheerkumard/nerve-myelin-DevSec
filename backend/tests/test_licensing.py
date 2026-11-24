# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import licensing as L  # noqa: E402

SK = Ed25519PrivateKey.generate()
KEYS = {"t1": SK.public_key()}
NOW = datetime(2026, 11, 14, tzinfo=timezone.utc)


def lic(**kw):
    p = {"lid": "x", "kid": "t1", "licensee": "Acme", "plan": "business", "issued_at": "2026-11-01T00:00:00+00:00",
         "expires_at": "2027-11-01T00:00:00+00:00", **kw}
    return L.sign(p, SK)


def test_valid_and_features():
    st = L.evaluate(lic(addons=["aibom"]), now=NOW, keys=KEYS)
    assert st.state == "valid" and st.usable and "aibom" in st.features and "sast" in st.features


def test_tamper_wrong_key_garbage_and_missing():
    t = lic()
    head, body, sig = t.split(".")
    forged = L.sign({**L.decode(t, KEYS), "plan": "sovereign"}, Ed25519PrivateKey.generate())
    for bad in (f"{head}.{body[:-2]}xx.{sig}", forged, "hello"):
        st = L.evaluate(bad, now=NOW, keys=KEYS)
        assert st.state == "restricted" and not st.usable
    for missing in ("", None):                      # no key: the open-source Community edition, fully usable
        st = L.evaluate(missing, now=NOW, keys=KEYS)
        assert st.state == "community" and st.usable and st.features is None


def test_expiring_grace_restricted():
    t = lic(expires_at="2026-11-30T00:00:00+00:00", grace_days=30)
    assert L.evaluate(t, now=NOW, keys=KEYS).state == "expiring"
    assert L.evaluate(t, now=NOW + timedelta(days=20), keys=KEYS).state == "grace"
    st = L.evaluate(t, now=NOW + timedelta(days=60), keys=KEYS)
    assert st.state == "restricted" and "grace" in st.reason


def test_not_before_and_deployment_binding():
    assert L.evaluate(lic(not_before="2027-01-01T00:00:00+00:00"), now=NOW, keys=KEYS).state == "restricted"
    t = lic(deployment_id="dep-1")
    assert L.evaluate(t, "dep-1", now=NOW, keys=KEYS).usable
    assert not L.evaluate(t, "dep-2", now=NOW, keys=KEYS).usable


VENDOR_TOOL = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "licensing", "myelin_license.py")


@pytest.mark.skipif(not os.path.exists(VENDOR_TOOL), reason="vendor licence tool is not part of this edition")
def test_vendor_tool_keygen_issue_inspect():
    d = tempfile.mkdtemp()
    tool = VENDOR_TOOL
    kid = "pytest-tmp"
    pub = os.path.join(L.KEY_DIR, f"{kid}.pem")
    try:
        r = subprocess.run([sys.executable, tool, "keygen", "--kid", kid, "--out", os.path.join(d, f"{kid}.key")], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        r = subprocess.run([sys.executable, tool, "keygen", "--kid", kid, "--out", os.path.join(L.KEY_DIR, "x.key")], capture_output=True, text=True)
        assert r.returncode != 0 and "inside the repository" in (r.stderr + r.stdout)
        out = os.path.join(d, "acme.lic")
        r = subprocess.run([sys.executable, tool, "issue", "--key", os.path.join(d, f"{kid}.key"), "--licensee", "Acme",
                            "--plan", "enterprise", "--max-developers", "400", "--out", out], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        r = subprocess.run([sys.executable, tool, "inspect", out], capture_output=True, text=True)
        assert r.returncode == 0 and '"state": "valid"' in r.stdout
        assert os.path.exists(os.path.join(d, f"{kid}.key.ledger.jsonl"))
        assert oct(os.stat(os.path.join(d, f"{kid}.key")).st_mode & 0o777) == "0o600"
    finally:
        if os.path.exists(pub):
            os.remove(pub)
