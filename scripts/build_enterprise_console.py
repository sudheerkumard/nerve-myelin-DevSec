#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Build the enterprise console without demo fixtures or demo credentials."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
template = (ROOT / "console" / "console.template.html").read_text(encoding="utf-8")
config = json.loads((ROOT / "config" / "frontend" / "console.config.json").read_text(encoding="utf-8"))
config["api"] = {**config.get("api", {}), "demoApiKey": ""}
config["defaultCustomer"] = {"customer": "Your Organisation", "industry": "Technology", "devs": 0, "presenter": ""}
output = template.replace("/*__SNAPSHOT__*/null", "null")
output = output.replace("/*__CONFIG__*/null", json.dumps(config, separators=(",", ":")).replace("</", "<\\/"))
(ROOT / "console" / "index.html").write_text(output, encoding="utf-8")
if "nm_demo_9f2c41e7b8" in output:
    raise SystemExit("Refusing to build enterprise console with a demo API key")
if "Orion Financial Group" in output:
    raise SystemExit("Refusing to embed demo tenant branding in the enterprise console")
print(f"Enterprise console built: {len(output)} bytes; demo snapshot and demo API key excluded")
