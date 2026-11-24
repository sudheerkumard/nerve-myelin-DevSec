# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Start the fictional insecure demo API (demo/vulnerable-api) in-process for tests."""
import importlib.util
import os
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def start(port):
    import uvicorn
    spec = importlib.util.spec_from_file_location("orion_vulnerable_api", os.path.join(ROOT, "demo", "vulnerable-api", "app.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    server = uvicorn.Server(uvicorn.Config(mod.app, host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    return server, th


IDENTITIES = [{"name": "alice", "role": "customer", "headers": {"Authorization": "Bearer alice-token"}},
              {"name": "bob", "role": "customer", "headers": {"Authorization": "Bearer bob-token"}},
              {"name": "admin", "role": "admin", "headers": {"Authorization": "Bearer admin-token"}}]
