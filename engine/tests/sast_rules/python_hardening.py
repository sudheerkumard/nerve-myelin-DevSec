# Fixture for engine/myelin_engine/rules/sast/python_hardening.yaml (opengrep --test).
import random, ssl, tarfile
from flask_cors import CORS

def unpack(path):
    t = tarfile.open(path)
    # ruleid: nervve.python.archive-extraction
    t.extractall("/srv/data")
    # ok: nervve.python.archive-extraction
    t.extractall("/srv/data", filter="data")

# ruleid: nervve.python.cors-any-origin-with-credentials
CORS(app, origins="*", supports_credentials=True)
# ok: nervve.python.cors-any-origin-with-credentials
CORS(app, origins=["https://app.example.com"], supports_credentials=True)
# ruleid: nervve.python.insecure-session-cookie
SESSION_COOKIE_SECURE = False
# ruleid: nervve.python.debug-enabled
DEBUG = True
# ruleid: nervve.python.csrf-exempt
WTF_CSRF_ENABLED = False

def make_reset_token():
    # ruleid: nervve.python.weak-random-token
    return "".join(random.choice("abcdef0123456789") for _ in range(32))

def shuffle_cards(cards):
    # ok: nervve.python.weak-random-token
    return random.sample(cards, len(cards))

# ruleid: nervve.python.insecure-tls-version
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
# ruleid: nervve.python.bind-all-interfaces
sock.bind(("0.0.0.0", 8080))
