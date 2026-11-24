"""Benchmark: each VULN line must be reported; each SAFE line must not."""
import hashlib, random, secrets, subprocess, tempfile, urllib.request

import jwt, requests, yaml


def find_order(db, oid):
    db.execute(f"SELECT * FROM orders WHERE id = {oid}")                       # VULN NM-SAST-001
    db.execute("SELECT * FROM orders WHERE id = %s", (oid,))                   # SAFE parameterised


def run(name):
    subprocess.run(f"convert {name} out.png", shell=True)                      # VULN NM-SAST-003
    subprocess.run(["convert", name, "out.png"], check=True)                   # SAFE argument list


def fetch(url):
    requests.get("https://api.partner.example/v1/rates", verify=False)         # VULN NM-SAST-004
    with urllib.request.urlopen(url) as r:                                     # VULN NM-SAST-010
        return r.read()


def fetch_fixed():
    with urllib.request.urlopen("https://status.partner.example/health") as r:  # SAFE constant https URL
        return r.read()


def load(text):
    cfg = yaml.load(text)                                                       # VULN NM-SAST-006
    return cfg, yaml.safe_load(text), yaml.load(text, Loader=yaml.SafeLoader)   # SAFE safe loaders


def fingerprint(b):
    return hashlib.md5(b).hexdigest()                                           # VULN NM-SAST-005


def strong(b):
    return hashlib.sha256(b).hexdigest()                                        # SAFE


def session(tok):
    return jwt.decode(tok, options={"verify_signature": False})                 # VULN NM-SAST-009


def verify(tok, key):
    return jwt.decode(tok, key, algorithms=["RS256"], audience="myelin")        # SAFE


def reset_token():
    token = "".join(random.choice("abcdef0123456789") for _ in range(32))     # VULN NM-SAST-014
    return token, secrets.token_urlsafe(32)                                     # SAFE


def scratch():
    return tempfile.mktemp(), tempfile.mkstemp()                                # VULN NM-SAST-013
