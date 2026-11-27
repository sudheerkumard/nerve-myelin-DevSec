# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Tests are deterministic: no calls to public vulnerability or package services. Network paths are tested
against local fake servers (see test_engine_intel.py)."""
import os

os.environ.setdefault("MYELIN_OFFLINE", "1")
os.environ.setdefault("MYELIN_ADVISORY_INLINE", "0")

# Always test the engine from this checkout, never an older copy installed in site-packages.
import sys  # noqa: E402
from pathlib import Path  # noqa: E402

_ENGINE = str(Path(__file__).resolve().parents[2] / "engine")
if _ENGINE not in sys.path:
    sys.path.insert(0, _ENGINE)
