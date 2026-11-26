# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Engine tests import the engine from this checkout, never an installed copy."""
import os
import sys

_ENGINE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ENGINE not in sys.path:
    sys.path.insert(0, _ENGINE)
